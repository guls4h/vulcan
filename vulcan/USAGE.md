# Vulcan Usage Guide

## Quick Start

1. **Install Dependencies**
   ```bash
   uv sync
   export OPENAI_API_KEY="sk-your-key-here"
   ```

2. **Run Vulcan**
   ```bash
   uv run vulcan
   ```

3. **Interactive Menu**
   ```
   🔥 Vulcan Security Scanner
   Web Application Vulnerability Analysis with LLM Agents

   ? What would you like to do?
     🔍 Start Vulnerability Scan
     ⚙️  Configure Settings
     📊 Generate Report
     📈 View Statistics
     ❌ Exit
   ```

## Workflow Examples

### First Time Setup

1. Run `uv run vulcan`
2. Select **⚙️  Configure Settings**
3. Enter your preferences:
   - Target URL: `http://localhost:5000`
   - Proxy Port: `8080`
   - OpenAI Model: `gpt-4o-mini`
   - Confidence Threshold: `90`
4. Confirm to start scan immediately or exit to scan later

### Starting a Scan

1. Run `uv run vulcan`
2. Select **🔍 Start Vulnerability Scan**
3. Choose to use existing config or create new
4. Textual TUI will launch showing:
   - Statistics panel (requests, vulnerabilities)
   - Vulnerability list (real-time)
   - Request log
   - Vulnerability details

### During Scan (TUI Shortcuts)

- **q** - Quit and save report
- **p** - Pause/resume analysis
- **r** - Generate report without quitting
- **c** - Clear request log
- **h** - Show help

### Generating Reports

1. Run `uv run vulcan`
2. Select **📊 Generate Report**
3. Choose format (JSON, Markdown, or Both)
4. Enter output path
5. Reports generated in `./reports/` directory

### Viewing Statistics

1. Run `uv run vulcan`
2. Select **📈 View Statistics**
3. View:
   - Total vulnerabilities
   - Average confidence scores
   - Breakdown by type (IDOR, etc.)
   - Breakdown by risk level

## Configuration File

The `config.yaml` file can be edited manually or through the interactive CLI:

```yaml
openai:
  model: "gpt-4o-mini"
  temperature: 0.2

proxy:
  port: 8080

agent:
  confidence_threshold: 90
  num_history_runs: 5

pii_patterns:
  - name: email
    regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
    mask: "[EMAIL_REDACTED]"
```

## Browser Proxy Setup

### Firefox
1. Settings → Network Settings
2. Manual proxy configuration
3. HTTP Proxy: `localhost`, Port: `8080`
4. Check "Use this proxy server for all protocols"

### Chrome
1. Settings → System → Open proxy settings
2. Configure proxy: `localhost:8080`

### cURL
```bash
curl -x localhost:8080 http://target.com/api/endpoint
```

## Example Scan Session

```bash
$ uv run vulcan

🔥 Vulcan Security Scanner
Web Application Vulnerability Analysis with LLM Agents

? What would you like to do? 🔍 Start Vulnerability Scan

🔍 Vulnerability Scan Setup
? Use existing config.yaml? Yes
? Target URL: http://localhost:5000

🚀 Starting scanner...
Target: http://localhost:5000
Proxy: localhost:8080

📝 Configure your browser proxy to localhost:8080 and start testing

[Textual TUI launches showing real-time analysis]

Press 'q' to quit → Report saved to ./data/vulnerabilities.jsonl
```

## Troubleshooting

**OpenAI API Error**: Ensure `OPENAI_API_KEY` is set
**Proxy Connection Failed**: Check if port is already in use
**No Vulnerabilities Detected**: Adjust confidence threshold lower
**PII in Logs**: Verify PII patterns in config are active
