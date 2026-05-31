# VULCAN

LLM-based autonomous web vulnerability analysis system.

**Author:** Gülşah Şahin — Gazi University, Faculty of Engineering, Computer Engineering Department
**Course:** BM496 Graduation Project (2025–2026 Spring) — *"Effectiveness, Limitations, and Improvement of Large Language Models for Specialized Reporting in Web Application Vulnerability Analysis."*

VULCAN intercepts HTTP/HTTPS traffic between a client and a target web application, then uses an Agno-framework ReAct agent backed by Milvus semantic memory to detect business-logic vulnerabilities (IDOR, privilege escalation, broken access control) and selected technical flaws (SQLi).

## Architecture

```
Client ──HTTP──▶ mitmproxy (ProxyScanner) ──HTTP──▶ TestApp
                       │
                       │ Janus Queue (sync ↔ async)
                       ▼
              Agno SecurityAgent (ReAct)
              ├── OpenAIChat / Gemini (OpenAI-compatible)
              ├── Milvus knowledge store (1536-dim, COSINE, top-5)
              ├── Tools: search_similar_requests, mask_pii, repair_json
              └── 3-stage JSON repair pipeline
                       │
                       ▼
              vulnerabilities.jsonl ──▶ ReportAgent
                                          ├── Markdown / JSON report
                                          └── SFT dataset export (FG-RA-03)
```

Three-layer design:
1. **Network & UI** — `mitmproxy` interceptor with MCP filter; Textual TUI dashboard
2. **Autonomous Analysis** — Agno agent with persona, memory, and tool use
3. **Semantic Memory & Verification** — Milvus Lite (vectors) + Trace-ID correlation with TestApp ground truth

## Setup

```bash
cd vulcan
uv sync
cp config.example.yaml config.yaml
```

Pick one provider and export the matching API key:

```bash
# OpenAI (default, also used for embeddings)
export OPENAI_API_KEY="sk-..."

# Google Gemini (OpenAI-compatible endpoint) - optional alternative
export GOOGLE_API_KEY="..."
```

Embeddings always use OpenAI `text-embedding-3-small`, so `OPENAI_API_KEY` must be set even when chat goes through Gemini.

## Usage

Interactive wizard (default):

```bash
uv run vulcan
```

Direct scan:

```bash
uv run vulcan scan --target http://localhost:5001 --no-wizard
uv run vulcan scan --target http://localhost:5001 \
  --model gpt-4o-mini --confidence 90 --top-k 5 --verbose
```

Other commands:

```bash
uv run vulcan report      # generate JSON + Markdown report from findings
uv run vulcan stats       # show counts by type / risk
uv run vulcan settings    # show resolved configuration
```

## Scan workflow

1. Start [TestApp](../testapp/README.md) on `http://localhost:5001`
2. Run `uv run vulcan scan --target http://localhost:5001`
3. Route browser traffic through `127.0.0.1:8080` (or your `proxy.port`) — see [Browser proxy setup](#browser-proxy-setup) below
4. Browse / drive traffic to TestApp; the TUI shows a green **PROXY ACTIVE** indicator once requests start flowing, and live findings appear as the agent analyzes them
5. Press `q` to stop the scan and finalize the report

### Browser proxy setup

The scanner is a man-in-the-middle proxy: it only sees traffic that is explicitly routed through it. `curl -x http://127.0.0.1:8080 <url>` works out of the box, but browsers ignore the proxy until you configure them.

**Recommended — FoxyProxy (Firefox/Chrome):**
1. Install the **FoxyProxy Standard** extension.
2. Open FoxyProxy → **Options** → **Add**:
   - Title: `Vulcan`
   - Proxy Type: `HTTP`
   - Hostname: `127.0.0.1`
   - Port: `8080` (or your configured `proxy.port`)
3. Click the toolbar icon and select **Vulcan** to enable; select **Turn Off** when done.

**Firefox built-in:** Settings → Network Settings → Manual proxy configuration → HTTP Proxy `127.0.0.1` Port `8080` → "Also use this proxy for HTTPS".

**Firefox localhost note:** by default Firefox bypasses the proxy for `localhost`. Open `about:config`, set `network.proxy.allow_hijacking_localhost` to `true`.

**Chrome with isolated profile:**
```bash
open -na "Google Chrome" --args \
  --user-data-dir=/tmp/chrome-vulcan \
  --proxy-server=http://127.0.0.1:8080 \
  http://localhost:5001/
```

**macOS system-wide:**
```bash
networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8080
networksetup -setwebproxystate "Wi-Fi" on
# disable when finished:
networksetup -setwebproxystate "Wi-Fi" off
```

**HTTPS targets:** install `~/.mitmproxy/mitmproxy-ca-cert.pem` into your browser/system trust store. The bundled TestApp is plain HTTP, so this step is not required for the default validation flow.

### TUI shortcuts

| Key | Action |
|---|---|
| `q` | Quit and generate report |
| `p` | Pause / resume analysis |
| `r` | Generate report now |
| `c` | Clear request log |
| `h` | Help screen |

## Configuration

`config.yaml` controls all runtime behavior. Key sections:

```yaml
provider: openai            # openai | gemini

openai:
  model: gpt-4o-mini
  temperature: 0.2
  embedding_model: text-embedding-3-small

milvus:
  uri: ./data/milvus/milvus.db
  collection: http_traffic

agent:
  num_history_runs: 5
  confidence_threshold: 90  # findings below this are demoted to non-vulnerable
  top_k: 5                  # similar-request retrieval size

proxy:
  port: 8080

pii_patterns: [...]         # regex masks applied before LLM call (FG-PS-08)
static_extensions: [...]    # MCP filter (FG-PS-02)
```

CLI flags override config values (`--model`, `--milvus-uri`, `--confidence`, `--top-k`, etc.).

## Tests

```bash
uv run pytest tests/ -v
```

68 unit + integration tests covering JSON repair, PII masking, retry handler, token counter, ground-truth metrics, and the utils pipeline.

## End-to-end validation

`scripts/full_validation.py` is the consolidated thesis-grade harness. It runs 17 scenarios against TestApp through the live proxy with real LLM calls and computes a confusion matrix, precision/recall/F1, latency percentiles, token usage, MCP filter rate, and PII masker throughput.

```bash
# 1. TestApp
cd ../testapp && uv run python -m testapp.app

# 2. VULCAN proxy (separate terminal)
cd vulcan && uv run vulcan scan --target http://localhost:5001 --no-wizard

# 3. Validation driver
cd vulcan && uv run python scripts/full_validation.py
```

Outputs land in `vulcan/reports/` as timestamped JSON + Markdown. The latest measured run is summarised in [`reports/VERIFICATION_REPORT.md`](../reports/VERIFICATION_REPORT.md).

## Requirements traceability

| SRS / SDD ID | Implementation |
|---|---|
| FG-PS-01..02 | `proxy_scanner/interceptor.py`, `mcp_manager.py` |
| FG-PS-03 / FG-VDB-01 | `agent/knowledge_store.py` (Milvus 1536-dim COSINE top-5) |
| FG-PS-08 | `utils/pii_masker.py`, applied in `proxy_scanner/runner.py` |
| FG-AJ-01 | `agent/security_agent.py` (Agno ReAct + tools + JSON Mode) |
| FG-RA-01..04 | `report_agent/report_generator.py`, `dataset_builder.py`, `utils/json_repair.py` |
| FOG-PM-02 | Async Janus queue + per-flow latency counters in `interceptor.py` |
| HA-03 | API keys read from environment variables only |

## Project layout

```
vulcan/
├── config.example.yaml
├── pyproject.toml
├── data/                       # Milvus DB + JSONL findings (gitignored)
├── reports/                    # Generated reports (timestamped)
├── scripts/                    # Validation utilities
├── src/vulcan/
│   ├── cli.py                  # Click + Questionary entrypoint
│   ├── config.py
│   ├── agent/                  # SecurityAgent, knowledge store, tools
│   ├── proxy_scanner/          # mitmproxy interceptor + MCP filter
│   ├── report_agent/           # Report + SFT dataset builder
│   ├── tui/                    # Textual dashboard
│   └── utils/                  # PII mask, JSON repair, token counter, ...
└── tests/                      # 68 unit + integration tests
```

## License

Academic use. Author: **Gülşah Şahin**, Gazi University, Faculty of Engineering, Computer Engineering Department. See thesis documents under `project_documents/` in the repository root.
