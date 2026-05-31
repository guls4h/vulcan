from typing import Any, Optional
import asyncio
import threading
import time
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from .interceptor import Interceptor
from .mcp_manager import MCPManager
from vulcan.utils.logger import setup_logger

logger = setup_logger(__name__)


class ProxyRunner:
    def __init__(
        self,
        config: Any,
        pii_masker: Any,
        analysis_queue: Any,
        event_loop: asyncio.AbstractEventLoop,
        target_url: str = ""
    ) -> None:
        self.config = config
        self.pii_masker = pii_masker
        self.queue = analysis_queue
        self.loop = event_loop
        self.target_url = target_url
        self.mcp_manager = MCPManager(config.static_extensions)
        self.interceptor = Interceptor(
            self.mcp_manager,
            self.pii_masker,
            self.queue,
            self.loop,
            target_url
        )
        self.proxy_thread: Optional[threading.Thread] = None
        self.running = False

    def start(self) -> None:
        logger.info("Starting proxy runner")
        self.running = True
        self.proxy_thread = threading.Thread(target=self._run_proxy, daemon=True)
        self.proxy_thread.start()
        time.sleep(2)
        if not self.proxy_thread.is_alive():
            logger.error("Proxy thread failed to start")

    def _run_proxy(self) -> None:
        async def run_master() -> None:
            opts = options.Options(
                listen_host='127.0.0.1',
                listen_port=self.config.proxy_port
            )
            try:
                master = DumpMaster(opts)
                master.addons.add(self.interceptor)
                logger.info(f"Proxy server starting on 127.0.0.1:{self.config.proxy_port}")
                await master.run()
            except Exception as e:
                logger.error(f"Proxy server error: {e}", exc_info=True)

        try:
            asyncio.run(run_master())
        except KeyboardInterrupt:
            logger.info("Proxy server stopped by user")

    def stop(self) -> None:
        logger.info("Stopping proxy runner")
        self.running = False

    def get_stats(self) -> dict[str, Any]:
        return {
            **self.interceptor.get_stats(),
            **self.mcp_manager.get_filter_stats()
        }
