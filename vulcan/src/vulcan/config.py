from typing import Any
import yaml
from pathlib import Path

class Config:
    def __init__(self, config_path: str = "config.yaml") -> None:
        self.config_path = Path(config_path)
        self.data = self._load()
    
    def _load(self) -> dict[str, Any]:
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")
        with open(self.config_path, 'r') as f:
            return yaml.safe_load(f)
    
    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split('.')
        value = self.data
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
        return value
    
    @property
    def provider(self) -> str:
        return self.get('provider', 'openai')

    @property
    def openai_model(self) -> str:
        return self.get('openai.model', 'gpt-4o-mini')

    @property
    def openai_temperature(self) -> float:
        return self.get('openai.temperature', 0.2)

    @property
    def openai_embedding_model(self) -> str:
        return self.get('openai.embedding_model', 'text-embedding-3-small')

    @property
    def gemini_model(self) -> str:
        return self.get('gemini.model', 'gemini-1.5-flash')

    @property
    def gemini_base_url(self) -> str:
        return self.get('gemini.base_url', 'https://generativelanguage.googleapis.com/v1beta/openai/')

    @property
    def llm_model(self) -> str:
        if self.provider == 'gemini':
            return self.gemini_model
        return self.openai_model

    @property
    def llm_base_url(self) -> str | None:
        if self.provider == 'gemini':
            return self.gemini_base_url
        return None
    
    @property
    def database_path(self) -> str:
        return self.get('database.path', './data/vulcan.db')
    
    @property
    def milvus_uri(self) -> str:
        return self.get('milvus.uri', './data/milvus/milvus.db')
    
    @property
    def milvus_collection(self) -> str:
        return self.get('milvus.collection', 'http_traffic')
    
    @property
    def proxy_port(self) -> int:
        return self.get('proxy.port', 8080)
    
    @property
    def confidence_threshold(self) -> int:
        return self.get('agent.confidence_threshold', 90)
    
    @property
    def num_history_runs(self) -> int:
        return self.get('agent.num_history_runs', 5)

    @property
    def top_k(self) -> int:
        return self.get('agent.top_k', 5)
    
    @property
    def pii_patterns(self) -> list[dict[str, str]]:
        return self.get('pii_patterns', [])
    
    @property
    def static_extensions(self) -> list[str]:
        return self.get('static_extensions', [])
    
    @property
    def vulnerability_log(self) -> str:
        return self.get('output.vulnerability_log', './data/vulnerabilities.jsonl')

    @property
    def log_level(self) -> str:
        return self.get('logging.level', 'INFO')

    @property
    def log_dir(self) -> str:
        return self.get('logging.log_dir', './logs')

    @property
    def log_max_size_mb(self) -> int:
        return self.get('logging.max_size_mb', 10)

    @property
    def log_backup_count(self) -> int:
        return self.get('logging.backup_count', 5)
