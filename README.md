# VULCAN — LLM-Powered Web Vulnerability Scanner

**Author:** Gülşah Şahin — Gazi University, Faculty of Engineering, Computer Engineering Department
**Course:** BM496 Graduation Project (2025–2026 Spring)

VULCAN is a graduation-project (BM496) research prototype that combines an
**HTTP intercepting proxy** with an **LLM agent** to detect authorisation
flaws — primarily IDOR / Broken Access Control — in modern web applications.
HTTP traffic is captured by `mitmproxy`, embedded into a Milvus vector store,
analysed by an [Agno](https://github.com/agno-agi/agno) ReAct agent
(`gpt-4o-mini` by default), and reported to a Textual TUI.

This repository contains three top-level packages plus the thesis artefacts:

| Path | Purpose |
|---|---|
| [`vulcan/`](vulcan/) | The scanner itself: proxy, agent, vector store, report generator, Textual TUI, validation harness |
| [`testapp/`](testapp/) | Intentionally vulnerable Flask target with a labelled ground-truth log |
| [`reports/`](reports/) | Thesis-grade verification report ([VERIFICATION_REPORT.md](reports/VERIFICATION_REPORT.md)) |

## Measured performance

Latest run, 17 scenarios, real `gpt-4o-mini` calls, confidence threshold 70:

| Metric | Value |
|---|---|
| Precision | **84.6 %** |
| Recall | **100 %** |
| F1 | **0.917** |
| Accuracy | **88.2 %** |
| Mean LLM latency | 7 453 ms (p95 9 758 ms) |
| Tokens / request | mean 116, max 123 (10 000 cap) |
| MCP-filter rate | 53.3 % of flows skipped before LLM |
| PII masker | ≈ 8 µs / request |

Full breakdown and methodology: [`reports/VERIFICATION_REPORT.md`](reports/VERIFICATION_REPORT.md).

## Quick start

```bash
# 1. Bring up the vulnerable target
cd testapp
uv sync
uv run python -m testapp.app   # http://localhost:5001

# 2. Configure VULCAN
cd ../vulcan
uv sync
cp config.example.yaml config.yaml
cp .env.example .env            # add your OPENAI_API_KEY

# 3. Run the scanner against TestApp
uv run vulcan scan --target http://localhost:5001 --no-wizard

# 4. (Optional) Reproduce the verification numbers
uv run python scripts/full_validation.py
```

See [`vulcan/README.md`](vulcan/README.md) and [`vulcan/USAGE.md`](vulcan/USAGE.md)
for architecture, configuration, and CLI details.

## Repository layout

```
Vulcan_Project/
├── vulcan/               # Scanner (Python 3.11+, uv, agno, mitmproxy, Milvus Lite)
│   ├── src/vulcan/       # Source: proxy_scanner, agent, report_agent, tui, utils
│   ├── scripts/          # full_validation.py — thesis-grade harness
│   ├── tests/            # 68 unit + integration tests
│   └── config.example.yaml
├── testapp/              # Flask vulnerable target with ground-truth logger
└── reports/              # VERIFICATION_REPORT.md (thesis verification)
```

## Tests

```bash
cd vulcan && uv run pytest -v
```

68 tests covering JSON repair, PII masking, retry handling, token counting,
ground-truth metrics, and the utils pipeline.

## Security & responsible use

VULCAN is a research artefact intended **only** for use against systems you own
or are explicitly authorised to test. The bundled `testapp/` is the supported
target. Running VULCAN against third-party systems without permission may be
illegal.

API keys are read from environment variables (`.env`) only — no secrets are
committed to the repository (see [`vulcan/.env.example`](vulcan/.env.example)).

## License & attribution

This project is published as part of the BM496 graduation-project deliverables
at Gazi University, Faculty of Engineering, Computer Engineering Department.

Author: **Gülşah Şahin**. Released under the [MIT License](LICENSE).
