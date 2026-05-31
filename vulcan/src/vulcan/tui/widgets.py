from typing import Any
from textual.app import ComposeResult
from textual.widgets import Static, DataTable, Button
from textual.containers import Container, VerticalScroll
from textual.message import Message
from rich.text import Text
from vulcan.utils.logger import setup_logger

logger = setup_logger(__name__)

class StatsPanel(Static):
    def __init__(self) -> None:
        super().__init__()
        self.stats = {
            'total_requests': 0,
            'analyzed': 0,
            'vulnerabilities': 0,
            'filtered': 0
        }
    
    def update_stats(self, stats: dict[str, int]) -> None:
        self.stats.update(stats)
        self.update(self._render_stats())
    
    def _render_stats(self) -> str:
        return f"""[b]Total Requests:[/b] {self.stats['total_requests']}
[b]Analyzed:[/b] {self.stats['analyzed']}
[b]Filtered:[/b] {self.stats['filtered']}
[b]Vulnerabilities:[/b] {self.stats['vulnerabilities']}"""

class VulnListPanel(VerticalScroll):
    def __init__(self) -> None:
        super().__init__()
        self.vulnerabilities: list[dict[str, Any]] = []
    
    def add_vulnerability(self, vuln: dict[str, Any]) -> None:
        self.vulnerabilities.append(vuln)
        self._refresh_list()
    
    def _refresh_list(self) -> None:
        self.remove_children()
        for i, vuln in enumerate(self.vulnerabilities):
            risk = vuln.get('risk_level', 'Unknown')
            vuln_type = vuln.get('vulnerability_type', 'Unknown')
            confidence = vuln.get('confidence_score', 0)
            
            color = {
                'Critical': 'red',
                'High': 'orange1',
                'Medium': 'yellow',
                'Low': 'blue'
            }.get(risk, 'white')
            
            item = Static(f"[{color}][{i+1}] {risk}[/{color}] - {vuln_type} ({confidence}%)")
            self.mount(item)

class RequestLogPanel(VerticalScroll):
    class RequestClicked(Message):
        def __init__(self, packet: dict[str, Any]) -> None:
            super().__init__()
            self.packet = packet
    
    def __init__(self) -> None:
        super().__init__()
        self.max_logs = 100
        self.packets: list[dict[str, Any]] = []
        self.selected_widget: Static | None = None
    
    def add_log(self, method: str, url: str, status: int, packet: dict[str, Any]) -> None:
        status_color = 'green' if 200 <= status < 300 else 'yellow' if 300 <= status < 400 else 'red'
        log_entry = f"[{status_color}]{status}[/{status_color}] {method} {url}"
        
        index = len(self.packets)
        self.packets.append(packet)
        
        class ClickableLog(Static):
            def __init__(self, text: str, pkt: dict[str, Any], panel: 'RequestLogPanel') -> None:
                super().__init__(text)
                self.packet = pkt
                self.panel = panel
            
            def on_mouse_down(self, event) -> None:
                if self.panel.selected_widget:
                    self.panel.selected_widget.styles.background = "transparent"
                self.styles.background = "cyan 20%"
                self.panel.selected_widget = self
                self.panel.post_message(RequestLogPanel.RequestClicked(self.packet))
        
        log_widget = ClickableLog(log_entry, packet, self)
        log_widget.styles.width = "100%"
        log_widget.can_focus = True
        self.mount(log_widget)
        
        if len(self.children) > self.max_logs:
            self.children[0].remove()
            self.packets.pop(0)
    
    def clear_logs(self) -> None:
        self.remove_children()

class VulnDetailsPanel(VerticalScroll):
    def __init__(self) -> None:
        super().__init__()
        self.current_vuln: dict[str, Any] = {}
        self.border_title = "Details"
    
    def show_vulnerability(self, vuln: dict[str, Any]) -> None:
        self.current_vuln = vuln
        
        def escape_markup(text: str) -> str:
            return str(text).replace('[', r'\[')
        
        details = f"""[b]Type:[/b] {escape_markup(vuln.get('vulnerability_type', 'N/A'))}
[b]Risk:[/b] {escape_markup(vuln.get('risk_level', 'N/A'))}
[b]Confidence:[/b] {vuln.get('confidence_score', 0)}%

[b]Reasoning:[/b]
{escape_markup(vuln.get('reasoning', 'N/A'))}

[b]Proof of Concept:[/b]
{escape_markup(vuln.get('proof_of_concept', 'N/A'))}

[b]Remediation:[/b]
{escape_markup(vuln.get('remediation_suggestion', 'N/A'))}"""
        self.remove_children()
        self.mount(Static(details))
    
    def show_packet_details(self, packet: dict[str, Any]) -> None:
        from vulcan.utils.pii_masker import PIIMasker
        from vulcan.config import Config
        from pathlib import Path
        
        config = Config("config.yaml" if Path("config.yaml").exists() else "config.example.yaml")
        pii_masker = PIIMasker(config.pii_patterns)
        
        def escape_markup(text: str) -> str:
            return str(text).replace('[', r'\[')
        
        masked_headers_req = pii_masker.mask_headers(packet.get('request_headers', {}))
        masked_headers_res = pii_masker.mask_headers(packet.get('response_headers', {}))
        
        req_headers = "\n".join([f"  {k}: {escape_markup(v)}" for k, v in list(masked_headers_req.items())[:10]])
        res_headers = "\n".join([f"  {k}: {escape_markup(v)}" for k, v in list(masked_headers_res.items())[:10]])
        
        masked_req_body = pii_masker.mask(packet.get('request_body', 'N/A')[:500])
        masked_res_body = pii_masker.mask(packet.get('response_body', 'N/A')[:500])
        
        details = f"""[b]HTTP Flow Details[/b]

[b]Method:[/b] {escape_markup(packet.get('method', 'N/A'))}
[b]URL:[/b] {escape_markup(packet.get('url', 'N/A'))}
[b]Status:[/b] {packet.get('status_code', 'N/A')}
[b]Timestamp:[/b] {escape_markup(packet.get('timestamp', 'N/A'))}

[b]Request Headers:[/b]
{req_headers}

[b]Request Body:[/b]
{escape_markup(masked_req_body)}

[b]Response Headers:[/b]
{res_headers}

[b]Response Body:[/b]
{escape_markup(masked_res_body)}

[dim]Note: PII data is masked[/dim]"""
        self.remove_children()
        self.mount(Static(details))
    
    def show_llm_analysis(self, analysis: dict[str, Any]) -> None:
        logger.debug(f"Showing LLM analysis with keys: {list(analysis.keys())}")
        packet = analysis['packet']
        result = analysis['result']
        
        from vulcan.utils.pii_masker import PIIMasker
        from vulcan.config import Config
        from pathlib import Path
        
        config = Config("config.yaml" if Path("config.yaml").exists() else "config.example.yaml")
        pii_masker = PIIMasker(config.pii_patterns)
        
        def escape_markup(text: str) -> str:
            return str(text).replace('[', r'\[')
        
        masked_url = pii_masker.mask(packet['url'])
        masked_req_body = pii_masker.mask(packet['request_body'][:200])
        masked_res_body = pii_masker.mask(packet['response_body'][:200])
        
        prompt_body = f"""METHOD: {packet['method']}
URL: {masked_url}
STATUS: {packet['status_code']}
REQUEST_BODY: {escape_markup(masked_req_body)}
RESPONSE_BODY: {escape_markup(masked_res_body)}"""
        
        masked_packet_info = f"{packet['method']} {masked_url}"
        
        details = f"""[b]LLM Analysis Details[/b]

[b]Request:[/b] {escape_markup(masked_packet_info)}

[b]Prompt Sent to LLM:[/b]
{prompt_body}

[b]Analysis Result:[/b]
[b]Vulnerability Found:[/b] {result.get('vulnerability_found', False)}
[b]Type:[/b] {escape_markup(result.get('vulnerability_type', 'N/A'))}
[b]Confidence:[/b] {result.get('confidence_score', 0)}%
[b]Risk Level:[/b] {escape_markup(result.get('risk_level', 'N/A'))}

[b]Reasoning:[/b]
{escape_markup(result.get('reasoning', 'N/A'))}

[b]Proof of Concept:[/b]
{escape_markup(result.get('proof_of_concept', 'N/A'))}

[b]Remediation:[/b]
{escape_markup(result.get('remediation_suggestion', 'N/A'))}

[dim]Note: PII data (emails, IPs, etc.) is masked in the prompt sent to LLM[/dim]"""
        self.remove_children()
        self.mount(Static(details))
        logger.debug("LLM analysis details panel mounted")

class LLMOutputPanel(VerticalScroll):
    class AnalysisClicked(Message):
        def __init__(self, analysis: dict[str, Any]) -> None:
            super().__init__()
            self.analysis = analysis
    
    def __init__(self) -> None:
        super().__init__()
        self.max_outputs = 50
        self.analyses: list[dict[str, Any]] = []
        self.selected_widget: Static | None = None
    
    def add_output(self, packet_info: str, analysis_result: dict[str, Any], packet: dict[str, Any]) -> None:
        vuln_found = analysis_result.get('vulnerability_found', False)
        color = 'red' if vuln_found else 'green'
        status = 'VULN' if vuln_found else 'SAFE'
        confidence = analysis_result.get('confidence_score', 0)
        reasoning = analysis_result.get('reasoning', 'No reasoning provided')
        
        if len(reasoning) > 80:
            reasoning = reasoning[:80] + "..."
        
        output_entry = f"[{color}][{status}][/{color}] {packet_info} ({confidence}%) - {reasoning}"
        
        index = len(self.analyses)
        analysis_data = {
            'packet': packet,
            'result': analysis_result,
            'packet_info': packet_info
        }
        self.analyses.append(analysis_data)
        
        class ClickableAnalysis(Static):
            def __init__(self, text: str, analysis_data: dict[str, Any], panel: 'LLMOutputPanel') -> None:
                super().__init__(text)
                self.analysis_data = analysis_data
                self.panel = panel
            
            def on_mouse_down(self, event) -> None:
                logger.debug("LLM analysis widget clicked")
                if self.panel.selected_widget:
                    self.panel.selected_widget.styles.background = "transparent"
                self.styles.background = "cyan 20%"
                self.panel.selected_widget = self
                logger.debug("Handling click event")
                self.panel.handle_click(self.analysis_data)
        
        output_widget = ClickableAnalysis(output_entry, analysis_data, self)
        output_widget.styles.width = "100%"
        output_widget.can_focus = True
        self.mount(output_widget)
        
        if len(self.children) > self.max_outputs:
            self.children[0].remove()
            self.analyses.pop(0)
    
    def clear_outputs(self) -> None:
        self.remove_children()
    
    def handle_click(self, analysis_data: dict[str, Any]) -> None:
        logger.debug("Handling click event for analysis panel")
        try:
            details_panel = self.app.screen.query_one(VulnDetailsPanel)
            logger.debug("Found details panel, showing LLM analysis")
            details_panel.show_llm_analysis(analysis_data)
        except Exception as e:
            logger.error(f"Error handling click event: {e}", exc_info=True)

class ConfigSummaryPanel(Static):
    def __init__(self, target_url: str, proxy_port: int) -> None:
        content = f"""[b]🎯 Target:[/b] {target_url}
[b]🔌 Proxy:[/b] 127.0.0.1:{proxy_port}

[green]📝 Browser Setup (FoxyProxy):[/green]
[dim]1. Install FoxyProxy Standard add-on
2. Add proxy: HTTP → 127.0.0.1:{proxy_port}
3. Toggle FoxyProxy ON before browsing[/dim]

[yellow]⚠️  Firefox localhost note:[/yellow]
[dim]about:config → network.proxy.allow_hijacking_localhost → true[/dim]

[dim]curl test: curl -x http://127.0.0.1:{proxy_port} {target_url}[/dim]"""
        super().__init__(content)
