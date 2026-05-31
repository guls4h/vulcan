from typing import Any
import asyncio
import json
from pathlib import Path
from textual.app import App
from textual.worker import Worker
from .screens import ScanScreen, HelpScreen, ReportScreen
from .widgets import StatsPanel, VulnListPanel, RequestLogPanel, VulnDetailsPanel, LLMOutputPanel
from textual.message import Message
from vulcan.utils.logger import setup_logger

logger = setup_logger(__name__)

class VulcanApp(App):
    CSS_PATH = "vulcan.tcss"
    TITLE = "Vulcan Security Scanner"
    
    BINDINGS = [
        ("q", "quit", "Quit & Report"),
        ("p", "pause", "Pause"),
        ("r", "report", "Generate Report"),
        ("c", "clear", "Clear Logs"),
        ("h", "help", "Help"),
    ]
    
    def __init__(
        self,
        config: Any,
        agent: Any,
        proxy_runner: Any,
        analysis_queue: asyncio.Queue,
        target_url: str,
        pii_masker: Any
    ) -> None:
        super().__init__()
        self.config = config
        self.agent = agent
        self.proxy_runner = proxy_runner
        self.queue = analysis_queue
        self.target_url = target_url
        self.pii_masker = pii_masker
        self.paused = False
        self.vulnerabilities: list[dict[str, Any]] = []
    
    def on_mount(self) -> None:
        try:
            logger.info("Initializing TUI")
            self.push_screen(ScanScreen(self.target_url, self.config.proxy_port))
            logger.info("Starting proxy runner")
            self.proxy_runner.start()
            logger.info("Starting analysis worker")
            self.start_analysis_worker()
            logger.info("TUI initialization complete")
        except Exception as e:
            logger.error(f"Failed to initialize TUI: {e}", exc_info=True)
            self.exit(message=f"Failed to start: {e}")
    
    def start_analysis_worker(self) -> None:
        self.run_worker(self.analysis_loop(), exclusive=True)
    
    async def analysis_loop(self) -> None:
        logger.info("Analysis loop started")
        logger.debug(f"Queue object: {self.queue}")
        self.log("Analysis loop started")
        while True:
            try:
                logger.debug("Waiting for packet from queue")
                self.log("Waiting for packet...")
                packet = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                logger.info(f"Received packet: {packet['method']} {packet['url']}")
                self.log(f"Received packet: {packet['method']} {packet['url']}")

                if not self.paused:
                    try:
                        self.screen.query_one(RequestLogPanel).add_log(
                            packet['method'],
                            packet['url'],
                            packet['status_code'],
                            packet
                        )
                    except Exception as e:
                        logger.error(f"Failed to update RequestLogPanel: {e}", exc_info=True)

                    self.run_worker(self._analyze_packet(packet), exclusive=False)

            except asyncio.TimeoutError:
                stats = self.proxy_runner.get_stats()
                stats['vulnerabilities'] = len(self.vulnerabilities)
                try:
                    self.screen.query_one(StatsPanel).update_stats(stats)
                except:
                    pass
                continue
            except Exception as e:
                logger.error(f"Analysis loop error: {e}", exc_info=True)
                self.log(f"Analysis error: {e}")
    
    async def _analyze_packet(self, packet: dict[str, Any]) -> None:
        logger.info(f"Starting analysis for {packet['url']}")
        try:
            logger.debug("Masking PII in packet")

            masked_packet = {
                **packet,
                'url': self.pii_masker.mask(packet['url']),
                'request_headers': self.pii_masker.mask_headers(packet['request_headers']),
                'response_headers': self.pii_masker.mask_headers(packet['response_headers']),
                'request_body': self.pii_masker.mask(packet['request_body']),
                'response_body': self.pii_masker.mask(packet['response_body']),
            }

            logger.debug(f"PII masked. Original URL: {packet['url']}, Masked URL: {masked_packet['url']}")
            logger.debug("Calling agent.analyze_request")
            result = await self.agent.analyze_request(masked_packet)
            logger.info(f"Analysis result: vulnerability_found={result.get('vulnerability_found', False)}")

            packet_info = f"{packet['method']} {packet['url']}"
            self.screen.query_one(LLMOutputPanel).add_output(packet_info, result, packet)

            if result.get('vulnerability_found'):
                vuln_entry = {
                    **result,
                    'url': packet['url'],
                    'method': packet['method'],
                    'timestamp': packet['timestamp']
                }
                self.vulnerabilities.append(vuln_entry)

                self.screen.query_one(VulnListPanel).add_vulnerability(vuln_entry)
                self._save_vulnerability(vuln_entry)

                stats = self.proxy_runner.get_stats()
                stats['vulnerabilities'] = len(self.vulnerabilities)
                self.screen.query_one(StatsPanel).update_stats(stats)
        except Exception as e:
            logger.error(f"Analysis error for {packet['url']}: {e}", exc_info=True)
            self.log(f"Analysis error for {packet['url']}: {e}")
    
    def _save_vulnerability(self, vuln: dict[str, Any]) -> None:
        log_path = Path(self.config.vulnerability_log)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, 'a') as f:
            f.write(json.dumps(vuln) + '\n')
    
    def action_quit(self) -> None:
        def check_quit(should_quit: bool) -> None:
            if should_quit:
                self.proxy_runner.stop()
                self.exit(message=f"Report saved to: {self.config.vulnerability_log}")
        
        self.push_screen(ReportScreen(self.config.vulnerability_log), check_quit)
    
    def action_pause(self) -> None:
        self.paused = not self.paused
        status = "⏸ Paused" if self.paused else "▶ Running"
        self.notify(status)
    
    def action_report(self) -> None:
        self.push_screen(ReportScreen(self.config.vulnerability_log))
    
    def action_clear(self) -> None:
        try:
            self.screen.query_one(RequestLogPanel).clear_logs()
            self.screen.query_one(LLMOutputPanel).clear_outputs()
            self.notify("🗑 Logs cleared")
        except Exception as e:
            self.log(f"Clear error: {e}")
    
    def action_help(self) -> None:
        self.push_screen(HelpScreen(self.config.proxy_port))
    
    def on_request_log_panel_request_clicked(self, message: RequestLogPanel.RequestClicked) -> None:
        try:
            self.screen.query_one(VulnDetailsPanel).show_packet_details(message.packet)
        except Exception as e:
            self.log(f"Error showing packet details: {e}")
    
    def on_llm_output_panel_analysis_clicked(self, message: LLMOutputPanel.AnalysisClicked) -> None:
        logger.debug(f"Analysis panel clicked with keys: {list(message.analysis.keys())}")
        try:
            logger.debug(f"Showing LLM analysis: {message.analysis.get('packet_info', 'no info')}")
            self.screen.query_one(VulnDetailsPanel).show_llm_analysis(message.analysis)
            logger.debug("LLM analysis displayed successfully")
        except Exception as e:
            logger.error(f"Error showing analysis: {e}", exc_info=True)
            self.log(f"Error showing analysis: {e}")

    async def on_message(self, message) -> None:
        logger.debug(f"Received message: {type(message).__name__}")
        if isinstance(message, LLMOutputPanel.AnalysisClicked):
            logger.debug("AnalysisClicked message caught")
            self.on_llm_output_panel_analysis_clicked(message)