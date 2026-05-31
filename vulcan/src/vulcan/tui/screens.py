from textual.screen import Screen
from textual.widgets import Header, Footer, Static
from textual.containers import Container, Horizontal, Vertical
from textual.app import ComposeResult
from .widgets import StatsPanel, VulnListPanel, RequestLogPanel, VulnDetailsPanel, LLMOutputPanel, ConfigSummaryPanel

class ScanScreen(Screen):
    BINDINGS = [
        ("q", "quit", "Quit & Report"),
        ("p", "pause", "Pause"),
        ("r", "report", "Generate Report"),
        ("c", "clear", "Clear Logs"),
        ("h", "help", "Help"),
    ]
    
    def __init__(self, target_url: str, proxy_port: int) -> None:
        super().__init__()
        self.target_url = target_url
        self.proxy_port = proxy_port
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static("🔥 VULCAN SCANNER - Monitoring traffic...", id="main-title")
        with Container(id="main-container"):
            with Horizontal(id="top-section"):
                with Vertical(id="left-panel"):
                    yield Static("[b]Statistics[/b]", id="stats-header")
                    yield StatsPanel()
                    yield Static("[b]Configuration[/b]", id="config-header")
                    yield ConfigSummaryPanel(self.target_url, self.proxy_port)
                with Vertical(id="right-panel"):
                    yield Static("[b]Vulnerabilities[/b]", id="vuln-header")
                    yield VulnListPanel()
            with Horizontal(id="middle-section"):
                with Vertical(id="log-panel"):
                    yield Static("[b]Request Log[/b]", id="log-header")
                    yield RequestLogPanel()
                with Vertical(id="llm-panel"):
                    yield Static("[b]LLM Analysis[/b]", id="llm-header")
                    yield LLMOutputPanel()
            with Horizontal(id="bottom-section"):
                with Vertical(id="details-panel"):
                    yield Static("[b]Details[/b]", id="details-header")
                    yield VulnDetailsPanel()
        yield Footer()

class HelpScreen(Screen):
    BINDINGS = [("escape", "app.pop_screen", "Back")]
    
    def __init__(self, port: int = 8080) -> None:
        super().__init__()
        self.port = port
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(f"""
[b]Vulcan - Keyboard Shortcuts[/b]

[b]q[/b] - Quit and generate report
[b]p[/b] - Pause/resume analysis
[b]r[/b] - Generate report now
[b]c[/b] - Clear request log
[b]h[/b] - Show this help screen
[b]↑/↓[/b] - Navigate vulnerabilities

[b]Browser Setup (FoxyProxy recommended):[/b]
1. Install FoxyProxy Standard add-on (Firefox/Chrome)
2. Add proxy: HTTP -> 127.0.0.1:{self.port}
3. Toggle FoxyProxy ON, then browse target app
4. Watch the [b green]PROXY ACTIVE[/b green] indicator turn on

[b]Firefox localhost note:[/b]
about:config -> network.proxy.allow_hijacking_localhost -> true

[b]Quick test:[/b]
curl -x http://127.0.0.1:{self.port} <target-url>

[b]Workflow:[/b]
1. Browse target application through the proxy
2. Monitor vulnerabilities in real-time
3. Press 'q' to generate final report

[dim]Press ESC to return[/dim]
        """, id="help-text")
        yield Footer()

class ReportScreen(Screen):
    BINDINGS = [
        ("1", "template_report", "Template Report"),
        ("2", "llm_report", "LLM Report"),
        ("3", "both_reports", "Both"),
        ("escape", "dismiss", "Back"),
        ("q", "confirm_quit", "Quit")
    ]
    
    def __init__(self, report_path: str) -> None:
        super().__init__()
        self.report_path = report_path
        self.generated_files = []
    
    def action_dismiss(self) -> None:
        self.dismiss(False)
    
    def action_confirm_quit(self) -> None:
        self.dismiss(True)
    
    def action_template_report(self) -> None:
        self._generate_reports(llm=False)
    
    def action_llm_report(self) -> None:
        self._generate_reports(llm=True)
    
    def action_both_reports(self) -> None:
        self._generate_reports(template=True, llm=True)
    
    def _generate_reports(self, template: bool = False, llm: bool = False) -> None:
        from vulcan.report_agent.report_generator import ReportGenerator
        from vulcan.config import Config
        from pathlib import Path
        from datetime import datetime
        
        config = Config("config.yaml" if Path("config.yaml").exists() else "config.example.yaml")
        generator = ReportGenerator(config.vulnerability_log)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.generated_files = []
        
        if template:
            md_path = f"./reports/vulcan_report_{timestamp}.md"
            generator.generate_markdown_report(md_path)
            self.generated_files.append(md_path)
        
        if llm:
            llm_md_path = f"./reports/vulcan_llm_report_{timestamp}.md"
            self.run_worker(self._generate_llm_report(llm_md_path, generator, config), exclusive=True)
            return
        
        json_path = f"./reports/vulcan_report_{timestamp}.json"
        generator.generate_json_report(json_path)
        self.generated_files.append(json_path)
        
        self.query_one("#report-text", Static).update(self._get_success_message())
    
    async def _generate_llm_report(self, output_path: str, generator, config) -> None:
        await generator.generate_llm_markdown_report(output_path, config)
        self.generated_files.append(output_path)
        
        json_path = output_path.replace('_llm', '').replace('.md', '.json')
        generator.generate_json_report(json_path)
        self.generated_files.append(json_path)
        
        self.query_one("#report-text", Static).update(self._get_success_message())
    
    def _get_success_message(self) -> str:
        if self.generated_files:
            files_list = "\n".join([f"  • [green]{f}[/green]" for f in self.generated_files])
            return f"""[b]✅ Reports Generated[/b]

{files_list}

[dim]Generated files are ready for review[/dim]

[yellow]Press Q to quit[/yellow] | [dim]Press ESC to continue scanning[/dim]
            """
        return self._get_initial_message()
    
    def _get_initial_message(self) -> str:
        return """[b]📊 Generate Report[/b]

Choose report type:

[b]1[/b] - Template Report (Fast, structured format)
[b]2[/b] - LLM Report (AI-enhanced, narrative style) 🤖
[b]3[/b] - Both Reports

[yellow]Press Q to quit[/yellow] | [dim]Press ESC to go back[/dim]
        """
    
    def compose(self) -> ComposeResult:
        yield Header()
        yield Static(self._get_initial_message(), id="report-text")
        yield Footer()
