from typing import Any
import re
from dataclasses import dataclass

@dataclass
class PIIPattern:
    name: str
    regex: str
    mask: str
    compiled: re.Pattern

class PIIMasker:
    def __init__(self, patterns: list[dict[str, str]]) -> None:
        self.patterns = [
            PIIPattern(
                name=p['name'],
                regex=p['regex'],
                mask=p['mask'],
                compiled=re.compile(p['regex'], re.IGNORECASE)
            )
            for p in patterns
        ]
    
    def mask(self, content: str) -> str:
        if not content:
            return content
        masked = content
        for pattern in self.patterns:
            masked = pattern.compiled.sub(pattern.mask, masked)
        return masked
    
    def mask_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        return {k: self.mask(v) if isinstance(v, str) else v for k, v in data.items()}
    
    def mask_headers(self, headers: dict[str, str]) -> dict[str, str]:
        sensitive_headers = {'authorization', 'cookie', 'x-api-key', 'x-auth-token'}
        return {
            k: '[REDACTED]' if k.lower() in sensitive_headers else self.mask(v)
            for k, v in headers.items()
        }
