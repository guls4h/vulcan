from typing import Any, Callable
import asyncio
import time
import uuid
from mitmproxy import http
from mitmproxy.addonmanager import Loader
from datetime import datetime
from vulcan.utils.logger import setup_logger

logger = setup_logger(__name__)

TRACE_HEADER = "X-Vulcan-Trace-Id"
LATENCY_BUDGET_MS = 100.0


class Interceptor:
    def __init__(
        self, 
        mcp_manager: Any,
        pii_masker: Any,
        analysis_queue: Any,
        loop: asyncio.AbstractEventLoop,
        target_url: str = ""
    ) -> None:
        self.mcp_manager = mcp_manager
        self.pii_masker = pii_masker
        self.queue = analysis_queue
        self.loop = loop
        self.target_url = target_url
        self.target_host = self._extract_host(target_url)
        self.request_count = 0
        self.filtered_count = 0
        self.overhead_samples_ms: list[float] = []
        self.overhead_breaches = 0
    
    def _extract_host(self, url: str) -> str:
        if not url:
            return ""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc or parsed.path
    
    def _matches_target(self, request_host: str) -> bool:
        if not self.target_host:
            return True
        
        target_host_no_port = self.target_host.split(':')[0]
        request_host_no_port = request_host.split(':')[0]
        
        localhost_aliases = ['localhost', '127.0.0.1', '0.0.0.0', '::1']
        
        if target_host_no_port in localhost_aliases and request_host_no_port in localhost_aliases:
            return True
        
        return target_host_no_port == request_host_no_port or self.target_host == request_host
    
    def load(self, loader: Loader) -> None:
        pass
    
    def request(self, flow: http.HTTPFlow) -> None:
        self.request_count += 1
        if TRACE_HEADER not in flow.request.headers:
            flow.request.headers[TRACE_HEADER] = str(uuid.uuid4())

    def response(self, flow: http.HTTPFlow) -> None:
        start = time.perf_counter()

        if self.target_host and not self._matches_target(flow.request.host):
            self.filtered_count += 1
            self._record_overhead(start)
            return

        if not self.mcp_manager.should_analyze(flow):
            self.filtered_count += 1
            self._record_overhead(start)
            return

        packet = self._create_packet(flow)
        self.queue.put(packet)
        self._record_overhead(start)

    def _record_overhead(self, start: float) -> None:
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.overhead_samples_ms.append(elapsed_ms)
        if elapsed_ms > LATENCY_BUDGET_MS:
            self.overhead_breaches += 1
            logger.warning(
                f"Proxy overhead {elapsed_ms:.1f}ms exceeds {LATENCY_BUDGET_MS:.0f}ms budget (FOG-PM-02)"
            )

    def _create_packet(self, flow: http.HTTPFlow) -> dict[str, Any]:
        request_body = flow.request.content.decode('utf-8', errors='ignore')[:10000]
        response_body = flow.response.content.decode('utf-8', errors='ignore')[:10000] if flow.response else ''
        trace_id = flow.request.headers.get(TRACE_HEADER, str(uuid.uuid4()))

        return {
            'trace_id': trace_id,
            'timestamp': datetime.now().isoformat(),
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'path': flow.request.path,
            'status_code': flow.response.status_code if flow.response else 0,
            'request_headers': dict(flow.request.headers),
            'response_headers': dict(flow.response.headers) if flow.response else {},
            'request_body': request_body,
            'response_body': response_body,
            'request_size': len(flow.request.content),
            'response_size': len(flow.response.content) if flow.response else 0,
        }
    
    def get_stats(self) -> dict[str, Any]:
        samples = self.overhead_samples_ms
        avg_ms = sum(samples) / len(samples) if samples else 0.0
        max_ms = max(samples) if samples else 0.0
        return {
            'total_requests': self.request_count,
            'filtered': self.filtered_count,
            'analyzed': self.request_count - self.filtered_count,
            'overhead_avg_ms': round(avg_ms, 2),
            'overhead_max_ms': round(max_ms, 2),
            'overhead_breaches': self.overhead_breaches,
        }
