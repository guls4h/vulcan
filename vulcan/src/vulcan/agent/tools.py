import json
import os
from typing import Any, Callable

from vulcan.utils.json_repair import JSONRepair
from vulcan.utils.logger import setup_logger

logger = setup_logger(__name__)


def build_agent_tools(
    knowledge_store: Any,
    pii_masker: Any,
    embed_text: Callable[[str], list[float]],
) -> list[Callable]:
    def search_similar_requests(query: str, limit: int = 5) -> str:
        """Search semantically similar past HTTP requests in Milvus via cosine similarity.

        Args:
            query: Text summary of the current request (method + URL + body excerpt).
            limit: Max number of similar entries to return.
        """
        try:
            vector = embed_text(query)
        except Exception as e:
            logger.warning(f"Embedding failed for tool query: {e}")
            return json.dumps({"error": f"embedding_failed: {e}"})
        try:
            hits = knowledge_store.search_similar(vector, limit=limit)
        except Exception as e:
            logger.warning(f"Milvus search failed: {e}")
            return json.dumps({"error": f"milvus_search_failed: {e}"})
        return json.dumps(hits[:limit], default=str)

    def mask_pii(text: str = "", **kwargs: Any) -> str:
        """Redact PII (emails, SSNs, credit cards, JWTs, IPs, API keys) from a text string.

        Args:
            text: Raw text potentially containing personal or secret data.
        """
        if not text:
            for key in ("text:", "input", "value", "content", "data"):
                if key in kwargs and isinstance(kwargs[key], str):
                    text = kwargs[key]
                    break
            if not text and kwargs:
                first = next(iter(kwargs.values()))
                if isinstance(first, str):
                    text = first
        if not isinstance(text, str):
            text = str(text)
        return pii_masker.mask(text)

    def repair_json(broken_text: str) -> str:
        """Extract and repair a malformed JSON object from arbitrary text.

        Args:
            broken_text: Text that may contain a JSON object inside markdown,
                with trailing commas, unquoted keys, or unclosed brackets.
        """
        try:
            parsed = JSONRepair.extract_json_from_text(broken_text)
            return json.dumps(parsed)
        except Exception as e:
            return json.dumps({"error": f"repair_failed: {e}"})

    def get_recent_requests(limit: int = 10) -> str:
        """Return the most recently captured HTTP requests from the knowledge store.

        Args:
            limit: Max number of entries to return.
        """
        try:
            rows = knowledge_store.get_recent_requests(limit=limit)
        except Exception as e:
            return json.dumps({"error": f"recent_lookup_failed: {e}"})
        return json.dumps(rows[:limit], default=str)

    return [search_similar_requests, mask_pii, repair_json, get_recent_requests]


def make_openai_embedder(config: Any) -> Callable[[str], list[float]]:
    import openai

    api_key = os.getenv('OPENAI_API_KEY', '')
    if not api_key:
        def _missing(_: str) -> list[float]:
            raise RuntimeError("OPENAI_API_KEY not set; embedder unavailable")
        return _missing

    client = openai.OpenAI(api_key=api_key)
    model = config.openai_embedding_model

    def embed(text: str) -> list[float]:
        if not text:
            text = " "
        response = client.embeddings.create(model=model, input=text[:8000])
        return response.data[0].embedding

    return embed
