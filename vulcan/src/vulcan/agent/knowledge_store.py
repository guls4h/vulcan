from typing import Any, Optional
from pymilvus import MilvusClient, DataType
from datetime import datetime
import json
import time

from vulcan.utils.logger import setup_logger

logger = setup_logger(__name__)

SEARCH_BUDGET_MS = 100.0


class HTTPKnowledgeStore:
    def __init__(self, uri: str, collection_name: str) -> None:
        self.client = MilvusClient(uri=uri)
        self.collection_name = collection_name
        self.search_samples_ms: list[float] = []
        self.search_breaches = 0
        self._ensure_collection()
    
    def _ensure_collection(self) -> None:
        if self.client.has_collection(self.collection_name):
            return
        
        schema = self.client.create_schema(auto_id=True, enable_dynamic_field=True)
        schema.add_field("id", DataType.INT64, is_primary=True, auto_id=True)
        schema.add_field("embedding", DataType.FLOAT_VECTOR, dim=1536)
        schema.add_field("method", DataType.VARCHAR, max_length=16)
        schema.add_field("path", DataType.VARCHAR, max_length=512)
        schema.add_field("timestamp", DataType.VARCHAR, max_length=64)
        schema.add_field("metadata", DataType.JSON)
        
        index_params = self.client.prepare_index_params()
        index_params.add_index(field_name="embedding", index_type="FLAT", metric_type="COSINE")
        
        self.client.create_collection(
            collection_name=self.collection_name,
            schema=schema,
            index_params=index_params
        )
    
    def store_request(self, packet: dict[str, Any], embedding: list[float]) -> None:
        data = [{
            "embedding": embedding,
            "method": packet['method'],
            "path": packet['path'][:512],
            "timestamp": packet['timestamp'],
            "metadata": {
                "url": packet['url'][:512],
                "status_code": packet['status_code'],
                "request_body": packet['request_body'][:1000],
                "response_body": packet['response_body'][:1000]
            }
        }]
        self.client.insert(collection_name=self.collection_name, data=data)
    
    def search_similar(self, embedding: list[float], limit: int = 5) -> list[dict[str, Any]]:
        start = time.perf_counter()
        results = self.client.search(
            collection_name=self.collection_name,
            data=[embedding],
            limit=limit,
            output_fields=["method", "path", "timestamp", "metadata"]
        )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        self.search_samples_ms.append(elapsed_ms)
        if elapsed_ms > SEARCH_BUDGET_MS:
            self.search_breaches += 1
            logger.warning(
                f"Milvus top-{limit} search took {elapsed_ms:.1f}ms (>{SEARCH_BUDGET_MS:.0f}ms budget, FG-VDB-01)"
            )

        return [
            {
                "method": hit['entity']['method'],
                "path": hit['entity']['path'],
                "timestamp": hit['entity']['timestamp'],
                "metadata": hit['entity']['metadata'],
                "distance": hit['distance']
            }
            for hit in results[0]
        ] if results else []

    def get_search_stats(self) -> dict[str, Any]:
        samples = self.search_samples_ms
        avg_ms = sum(samples) / len(samples) if samples else 0.0
        max_ms = max(samples) if samples else 0.0
        return {
            'count': len(samples),
            'avg_ms': round(avg_ms, 2),
            'max_ms': round(max_ms, 2),
            'breaches': self.search_breaches,
        }
    
    def get_recent_requests(self, limit: int = 10) -> list[dict[str, Any]]:
        results = self.client.query(
            collection_name=self.collection_name,
            filter="",
            output_fields=["method", "path", "timestamp", "metadata"],
            limit=limit
        )
        return results
