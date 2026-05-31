from typing import Any
from mitmproxy import http

class MCPManager:
    def __init__(self, static_extensions: list[str]) -> None:
        self.static_extensions = set(ext.lower() for ext in static_extensions)
    
    def should_analyze(self, flow: http.HTTPFlow) -> bool:
        path = flow.request.path.lower()
        
        for ext in self.static_extensions:
            if path.endswith(ext):
                return False
        
        if flow.request.method in ('OPTIONS', 'HEAD'):
            return False
        
        content_type = flow.response.headers.get('content-type', '') if flow.response else ''
        if any(ct in content_type.lower() for ct in ['image/', 'font/', 'video/', 'audio/']):
            return False
        
        return True
    
    def get_filter_stats(self) -> dict[str, int]:
        return {
            'filtered': getattr(self, '_filtered_count', 0),
            'analyzed': getattr(self, '_analyzed_count', 0)
        }
