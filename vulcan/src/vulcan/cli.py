from dotenv import load_dotenv
load_dotenv()

import asyncio
import os
import warnings
from datetime import datetime
from pathlib import Path

import click
import janus
import questionary
import yaml

warnings.filterwarnings('ignore', category=UserWarning, module='milvus_lite')

from vulcan.agent.security_agent import SecurityAgent
from vulcan.config import Config
from vulcan.proxy_scanner.runner import ProxyRunner
from vulcan.report_agent.report_generator import ReportGenerator
from vulcan.tui.app import VulcanApp
from vulcan.utils.pii_masker import PIIMasker


@click.command()
@click.option('--target', '-t', help='Target URL to scan (e.g., http://localhost:5000)')
@click.option('--port', '-p', type=int, default=8080, help='Proxy port')
@click.option('--config', '-c', 'config_path', type=click.Path(exists=True), help='Path to config.yaml')
@click.option('--model', '-m', help='Override LLM model id')
@click.option('--embedding-model', help='Override embedding model id')
@click.option('--milvus-uri', help='Override Milvus URI')
@click.option('--top-k', type=int, help='Override semantic search top-k')
@click.option('--confidence', type=int, help='Override confidence threshold (0-100)')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.option('--wizard/--no-wizard', default=True, help='Use interactive wizard menu')
@click.option('--report', '-r', is_flag=True, help='Generate report from existing scan data')
@click.option('--stats', '-s', is_flag=True, help='View statistics from previous scans')
def main(
    target: str,
    port: int,
    config_path: str,
    model: str,
    embedding_model: str,
    milvus_uri: str,
    top_k: int,
    confidence: int,
    verbose: bool,
    wizard: bool,
    report: bool,
    stats: bool,
) -> None:
    """Vulcan: LLM-powered web application vulnerability scanner."""
    overrides = _build_overrides(model, embedding_model, milvus_uri, top_k, confidence, verbose, port)

    if report:
        generate_report_only(config_path, overrides)
        return

    if stats:
        view_statistics(config_path, overrides)
        return

    if not wizard and target:
        run_scan_direct(target, port, config_path, overrides)
        return

    show_interactive_menu(config_path, overrides)


def _build_overrides(
    model: str,
    embedding_model: str,
    milvus_uri: str,
    top_k: int,
    confidence: int,
    verbose: bool,
    port: int,
) -> dict:
    overrides: dict = {}
    if model:
        overrides['model'] = model
    if embedding_model:
        overrides['embedding_model'] = embedding_model
    if milvus_uri:
        overrides['milvus_uri'] = milvus_uri
    if top_k is not None:
        overrides['top_k'] = top_k
    if confidence is not None:
        overrides['confidence_threshold'] = confidence
    if verbose:
        overrides['verbose'] = True
    if port:
        overrides['port'] = port
    return overrides


def _resolve_config_path(config_path: str | None) -> str:
    if config_path:
        return config_path
    return "config.yaml" if Path("config.yaml").exists() else "config.example.yaml"


def _load_config(config_path: str | None, overrides: dict) -> Config:
    cfg = Config(_resolve_config_path(config_path))
    if 'model' in overrides:
        provider = cfg.provider
        cfg.data.setdefault(provider, {})['model'] = overrides['model']
    if 'embedding_model' in overrides:
        cfg.data.setdefault('openai', {})['embedding_model'] = overrides['embedding_model']
    if 'milvus_uri' in overrides:
        cfg.data.setdefault('milvus', {})['uri'] = overrides['milvus_uri']
    if 'top_k' in overrides:
        cfg.data.setdefault('agent', {})['top_k'] = overrides['top_k']
    if 'confidence_threshold' in overrides:
        cfg.data.setdefault('agent', {})['confidence_threshold'] = overrides['confidence_threshold']
    if 'port' in overrides:
        cfg.data.setdefault('proxy', {})['port'] = overrides['port']
    if 'verbose' in overrides:
        cfg.data.setdefault('logging', {})['level'] = 'DEBUG'
    return cfg


def show_interactive_menu(config_path: str | None, overrides: dict) -> None:
    click.clear()
    click.secho("Vulcan Security Scanner", fg="red", bold=True)
    click.secho("Web Application Vulnerability Analysis with LLM Agents\n", fg="cyan")

    if not Path("config.yaml").exists() and not config_path:
        click.secho("No config.yaml found. Falling back to config.example.yaml.", fg="yellow")

    action = questionary.select(
        "What would you like to do?",
        choices=[
            "Start Vulnerability Scan",
            "Configure Settings",
            "View Current Settings",
            "Generate Report",
            "View Statistics",
            "Exit",
        ],
    ).ask()

    if action is None or action == "Exit":
        click.secho("Goodbye.", fg="green")
        return

    if action == "Configure Settings":
        configure_interactive(config_path, overrides)
        return

    if action == "View Current Settings":
        view_current_settings(config_path, overrides)
        return

    if action == "Generate Report":
        generate_report_interactive(config_path, overrides)
        return

    if action == "View Statistics":
        view_statistics(config_path, overrides)
        return

    if action == "Start Vulnerability Scan":
        run_scan_interactive(config_path, overrides)


def configure_interactive(config_path: str | None, overrides: dict) -> None:
    click.secho("\nInteractive Configuration", fg="cyan", bold=True)

    cfg = _load_config(config_path, overrides)
    data = cfg.data

    target_url = questionary.text("Target URL:", default="http://127.0.0.1:5001").ask()
    proxy_port = questionary.text(
        "Proxy Port:", default=str(data.get('proxy', {}).get('port', 8080))
    ).ask()

    provider = questionary.select(
        "LLM Provider:",
        choices=["openai", "gemini"],
        default=data.get('provider', 'openai'),
    ).ask()

    if provider == 'gemini':
        llm_model = questionary.select(
            "Gemini Model:",
            choices=[
                "gemini-1.5-flash",
                "gemini-1.5-pro",
                "gemini-2.0-flash",
            ],
            default=data.get('gemini', {}).get('model', 'gemini-1.5-flash'),
        ).ask()
        data.setdefault('gemini', {'base_url': 'https://generativelanguage.googleapis.com/v1beta/openai/'})
        data['gemini']['model'] = llm_model
    else:
        llm_model = questionary.select(
            "OpenAI Model:",
            choices=["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
            default=data.get('openai', {}).get('model', 'gpt-4o-mini'),
        ).ask()
        data['openai']['model'] = llm_model

    confidence = questionary.text(
        "Confidence Threshold (0-100):",
        default=str(data.get('agent', {}).get('confidence_threshold', 90)),
    ).ask()

    data['provider'] = provider
    data['proxy']['port'] = int(proxy_port)
    data['agent']['confidence_threshold'] = int(confidence)

    with open("config.yaml", 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    click.secho("Configuration saved to config.yaml", fg="green")

    if questionary.confirm("Start scan now?").ask():
        _start_scan(target_url, "config.yaml", int(proxy_port), overrides)


def run_scan_interactive(config_path: str | None, overrides: dict) -> None:
    click.secho("\nVulnerability Scan Setup", fg="cyan", bold=True)

    use_existing = questionary.confirm("Use existing config.yaml?", default=True).ask()

    if use_existing and Path("config.yaml").exists():
        resolved = "config.yaml"
        cfg = _load_config(resolved, overrides)

        target_url = questionary.text("Target URL:", default="http://localhost:5000").ask()

        port = cfg.proxy_port
        if questionary.confirm("Modify proxy port?", default=False).ask():
            port = int(questionary.text("Proxy Port:", default=str(port)).ask())

        _start_scan(target_url, resolved, port, overrides)
    else:
        configure_interactive(config_path, overrides)


def _validate_api_key(provider: str) -> bool:
    if provider == 'gemini':
        key = os.getenv('GOOGLE_API_KEY') or os.getenv('GEMINI_API_KEY', '')
        label = 'GOOGLE_API_KEY'
        hint = '...'
    else:
        key = os.getenv('OPENAI_API_KEY', '')
        label = 'OPENAI_API_KEY'
        hint = 'sk-...'

    if not key:
        click.secho(f"ERROR: {label} not found in environment.", fg="red", bold=True)
        click.secho(f"   Add it to .env or export {label}={hint}", fg="yellow")
        return False

    if len(key) < 20:
        click.secho(f"WARNING: {label} looks invalid (too short).", fg="yellow")
    else:
        click.secho(f"{label} loaded: {key[:8]}...{key[-4:]}", fg="green")

    return True


def _start_scan(target_url: str, config_path: str, port: int, overrides: dict) -> None:
    click.secho(f"\nStarting scanner...", fg="green", bold=True)
    click.secho(f"Target: {target_url}")
    click.secho(f"Proxy: 127.0.0.1:{port}")

    cfg = _load_config(config_path, {**overrides, 'port': port})

    if not _validate_api_key(cfg.provider):
        return

    pii_masker = PIIMasker(cfg.pii_patterns)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    queue = janus.Queue()

    agent = SecurityAgent(cfg, pii_masker=pii_masker)
    proxy_runner = ProxyRunner(cfg, pii_masker, queue.sync_q, loop, target_url)

    app = VulcanApp(cfg, agent, proxy_runner, queue.async_q, target_url, pii_masker)

    try:
        app.run()
    except KeyboardInterrupt:
        click.secho("\nScan interrupted by user.", fg="yellow")
    finally:
        proxy_runner.stop()


def generate_report_interactive(config_path: str | None, overrides: dict) -> None:
    click.secho("\nReport Generation", fg="cyan", bold=True)

    cfg = _load_config(config_path, overrides)

    report_format = questionary.select(
        "Report format:",
        choices=["JSON", "Markdown (Template)", "Markdown (LLM-Enhanced)", "All"],
    ).ask()

    output_path = questionary.text(
        "Output path:",
        default=f"./reports/vulcan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
    ).ask()

    generator = ReportGenerator(cfg.vulnerability_log)

    if report_format in ("JSON", "All"):
        json_path = output_path.replace('.md', '.json')
        generator.generate_json_report(json_path)
        click.secho(f"JSON report: {json_path}", fg="green")

    if report_format in ("Markdown (Template)", "All"):
        md_path = output_path if output_path.endswith('.md') else output_path.replace('.json', '.md')
        generator.generate_markdown_report(md_path)
        click.secho(f"Markdown report: {md_path}", fg="green")

    if report_format in ("Markdown (LLM-Enhanced)", "All"):
        llm_md_path = output_path.replace('.json', '_llm.md').replace('.md', '_llm.md')
        asyncio.run(generator.generate_llm_markdown_report(llm_md_path, cfg))
        click.secho(f"LLM-enhanced markdown report: {llm_md_path}", fg="green")


def view_statistics(config_path: str | None, overrides: dict) -> None:
    click.secho("\nVulnerability Statistics", fg="cyan", bold=True)

    from vulcan.report_agent.dataset_builder import DatasetBuilder

    cfg = _load_config(config_path, overrides)
    builder = DatasetBuilder(cfg.vulnerability_log)
    stats = builder.get_statistics()

    if not stats:
        click.secho("No vulnerability data found.", fg="yellow")
        return

    click.secho(f"\nTotal Vulnerabilities: {stats['total_vulnerabilities']}", bold=True)
    click.secho(f"Average Confidence: {stats['avg_confidence']:.1f}%\n")

    click.secho("By Type:", fg="cyan")
    for vuln_type, count in stats['by_type'].items():
        click.secho(f"  {vuln_type}: {count}")

    click.secho("\nBy Risk Level:", fg="cyan")
    for risk, count in stats['by_risk'].items():
        color = {'Critical': 'red', 'High': 'yellow', 'Medium': 'blue', 'Low': 'green'}.get(risk, 'white')
        click.secho(f"  {risk}: {count}", fg=color)


def run_scan_direct(target: str, port: int, config_path: str, overrides: dict) -> None:
    click.secho(f"\nStarting direct scan...", fg="green", bold=True)
    click.secho(f"Target: {target}")
    click.secho(f"Proxy: 127.0.0.1:{port}\n")

    resolved = _resolve_config_path(config_path)
    cfg = _load_config(resolved, {**overrides, 'port': port})

    if not _validate_api_key(cfg.provider):
        return

    click.secho("Configure your browser proxy:", fg="yellow")
    click.secho(f"   HTTP Proxy: 127.0.0.1:{port}")
    click.secho(f"   Then visit: {target}\n")

    pii_masker = PIIMasker(cfg.pii_patterns)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    queue = janus.Queue()

    agent = SecurityAgent(cfg, pii_masker=pii_masker)
    proxy_runner = ProxyRunner(cfg, pii_masker, queue.sync_q, loop, target)

    app = VulcanApp(
        config=cfg,
        agent=agent,
        proxy_runner=proxy_runner,
        analysis_queue=queue.async_q,
        target_url=target,
        pii_masker=pii_masker,
    )

    app.run()


def generate_report_only(config_path: str | None, overrides: dict) -> None:
    click.secho("\nGenerating Report", fg="cyan", bold=True)

    cfg = _load_config(config_path, overrides)

    report_format = click.prompt(
        "Report format",
        type=click.Choice(['json', 'markdown', 'both'], case_sensitive=False),
        default='both',
    )

    output_path = click.prompt("Output path", default="./reports/vulcan_report.json")

    generator = ReportGenerator(cfg.vulnerability_log)

    if report_format in ('json', 'both'):
        json_path = output_path if report_format == 'json' else output_path.replace('.md', '.json')
        generator.generate_json_report(json_path)
        click.secho(f"JSON report: {json_path}", fg="green")

    if report_format in ('markdown', 'both'):
        md_path = output_path if report_format == 'markdown' else output_path.replace('.json', '.md')
        generator.generate_markdown_report(md_path)
        click.secho(f"Markdown report: {md_path}", fg="green")


def view_current_settings(config_path: str | None, overrides: dict) -> None:
    click.secho("\nCurrent Configuration Settings", fg="cyan", bold=True)

    resolved = _resolve_config_path(config_path)
    cfg = Config(resolved)
    click.secho(f"Loaded from: {resolved}", fg="green" if resolved == "config.yaml" else "yellow")

    data = cfg.data
    provider = data.get('provider', 'openai')

    click.secho(f"\nLLM Provider: {provider.upper()}", fg="cyan", bold=True)
    if provider == 'gemini':
        g_cfg = data.get('gemini', {})
        click.secho(f"  Model: {g_cfg.get('model')}")
        click.secho(f"  Base URL: {g_cfg.get('base_url')}")
        click.secho(f"  Embedding Model: {data['openai']['embedding_model']}")
    else:
        click.secho(f"  Model: {data['openai']['model']}")
        click.secho(f"  Temperature: {data['openai']['temperature']}")
        click.secho(f"  Embedding Model: {data['openai']['embedding_model']}")

    click.secho("\nProxy Settings:", fg="cyan", bold=True)
    click.secho(f"  Port: {data['proxy']['port']}")

    click.secho("\nDatabase Settings:", fg="cyan", bold=True)
    click.secho(f"  SQLite Path: {data['database']['path']}")
    click.secho(f"  Milvus URI: {data['milvus']['uri']}")
    click.secho(f"  Milvus Collection: {data['milvus']['collection']}")

    click.secho("\nAgent Settings:", fg="cyan", bold=True)
    agent = data.get('agent', {})
    click.secho(f"  Confidence Threshold: {agent.get('confidence_threshold')}%")
    click.secho(f"  History Runs: {agent.get('num_history_runs')}")
    click.secho(f"  Top-K (semantic search): {agent.get('top_k', 5)}")

    click.secho("\nOutput Settings:", fg="cyan", bold=True)
    click.secho(f"  Log Directory: {data['output']['log_directory']}")
    click.secho(f"  Vulnerability Log: {data['output']['vulnerability_log']}")
    click.secho(f"  Report Format: {data['output']['report_format']}")

    click.secho("\nPII Masking Patterns:", fg="cyan", bold=True)
    for pattern in data.get('pii_patterns', []):
        click.secho(f"  {pattern['name']}: {pattern['mask']}")

    click.secho("\nFiltered Extensions:", fg="cyan", bold=True)
    extensions = data.get('static_extensions', [])
    preview = ", ".join(extensions[:10])
    if len(extensions) > 10:
        preview += f" ... ({len(extensions)} total)"
    click.secho(f"  {preview}")

    click.secho("")
    questionary.press_any_key_to_continue("Press any key to return to menu...").ask()
    show_interactive_menu(config_path, overrides)


if __name__ == '__main__':
    main()
