import asyncio
import os
from typing import Any, Optional

from agno.agent import Agent
from agno.db.sqlite import SqliteDb
from agno.knowledge import Knowledge
from agno.knowledge.embedder.openai import OpenAIEmbedder
from agno.memory.manager import MemoryManager
from agno.models.openai import OpenAIChat
from agno.vectordb.milvus import Milvus

from vulcan.utils.json_repair import JSONRepair
from vulcan.utils.logger import setup_logger
from vulcan.utils.token_counter import TokenCounter

from .knowledge_store import HTTPKnowledgeStore
from .tools import build_agent_tools, make_openai_embedder

logger = setup_logger(__name__)

MAX_INPUT_TOKENS = 10000
ANALYSIS_TIMEOUT_SECONDS = 30.0

INSTRUCTIONS = [
    "You are an authorized cybersecurity auditor analyzing HTTP traffic in a controlled test environment.",
    "Focus on IDOR (Insecure Direct Object Reference), privilege escalation, broken access control, and SQL injection.",
    "Use the search_similar_requests tool to compare with semantically similar past traffic.",
    "Use mask_pii on any sensitive content before reasoning aloud.",
    "",
    "IDOR detection rules — flag a vulnerability ONLY when ALL of these hold:",
    "  1. The URL path or query contains a concrete object identifier referencing a specific record (e.g. ?id=3, /users/3, /orders/42, /api/profile?user_id=2). A path like /profile or /api/profile with NO id is NOT IDOR.",
    "  2. The response is 200/2xx and its body contains data clearly tied to that specific identifier (a different user's email, order, file, etc.).",
    "  3. There is positive evidence that the authenticated principal differs from the referenced object owner (e.g. session cookie decodes to user_id=1 but URL requests id=3, or the response leaks another user's PII).",
    "Do NOT flag IDOR when any of these hold:",
    "  - The endpoint is for authentication or registration: /login, /logout, /signup, /register, /auth/*, /oauth/*, /token, /password/reset, /sessions. These establish identity; they cannot be IDOR. (They CAN still be SQLi — see below.)",
    "  - There is no object identifier in the URL or body (e.g. /profile, /dashboard, /, /api/me).",
    "  - The request lacks a session/cookie entirely AND no protected data leaks in the response — the worst case is missing-auth, not IDOR.",
    "  - You only have suspicion but no evidence of an ownership mismatch. In that case set vulnerability_found=false and explain.",
    "A 200 response to /admin, /api/admin, /admin/* from a session whose decoded role is not 'admin' is privilege escalation.",
    "SQL injection: flag (with type \"SQLi\") whenever the request body or query parameter contains a SQL meta-pattern (', OR 1=1, UNION SELECT, --, ; DROP, /*) AND the response is 200 or leaks DB error / extra rows. SQLi applies to ANY endpoint, including /login and other auth endpoints — auth-endpoint exemption applies ONLY to IDOR, never to SQLi.",
    "",
    "CRITICAL CONSISTENCY RULES — the JSON fields MUST agree:",
    "  - If `vulnerability_type` is a real category (IDOR, SQLi, Privilege Escalation, etc.) AND your reasoning describes an actual flaw, then `vulnerability_found` MUST be true.",
    "  - Set `vulnerability_found` to false ONLY when `vulnerability_type` is exactly \"None\" or \"NotApplicable\" and the reasoning explains why the request is safe.",
    "  - `confidence_score` reflects how confident you are that a vulnerability EXISTS (higher = more confident a flaw is present). Never use it to express confidence that the request is safe.",
    "",
    "CRITICAL OUTPUT FORMAT: Respond with a single JSON object and nothing else.",
    "Do NOT include markdown code fences, prose, explanations, tool-call traces, or any text outside the JSON object.",
    "The very first character of your response must be '{' and the very last must be '}'.",
    "Never copy a previous PARSE_ERROR response from memory — always re-analyze the current request from scratch.",
]


class SecurityAgent:
    def __init__(self, config: Any, pii_masker: Optional[Any] = None) -> None:
        self.config = config
        self.pii_masker = pii_masker or _PassThroughMasker()
        self.token_counter = TokenCounter()

        self.knowledge_store = HTTPKnowledgeStore(
            uri=config.milvus_uri,
            collection_name=config.milvus_collection,
        )

        db = SqliteDb(db_file=config.database_path)

        chat_kwargs: dict[str, Any] = {
            'id': config.llm_model,
            'temperature': config.openai_temperature,
        }
        if config.provider == 'openai':
            chat_kwargs['request_params'] = {'response_format': {'type': 'json_object'}}
        memory_kwargs: dict[str, Any] = {'id': config.llm_model}
        embedder_kwargs: dict[str, Any] = {'id': config.openai_embedding_model}

        if config.llm_base_url:
            api_key = ''
            if config.provider == 'gemini':
                api_key = os.getenv('GOOGLE_API_KEY') or os.getenv('GEMINI_API_KEY', '')
            chat_kwargs['base_url'] = config.llm_base_url
            chat_kwargs['api_key'] = api_key
            memory_kwargs['base_url'] = config.llm_base_url
            memory_kwargs['api_key'] = api_key

        self.embed_text = make_openai_embedder(config)
        self.tools = build_agent_tools(
            knowledge_store=self.knowledge_store,
            pii_masker=self.pii_masker,
            embed_text=self.embed_text,
        )

        self.agent = Agent(
            name="VulcanSecurityAgent",
            model=OpenAIChat(**chat_kwargs),
            db=db,
            memory_manager=MemoryManager(model=OpenAIChat(**memory_kwargs), db=db),
            knowledge=Knowledge(
                vector_db=Milvus(
                    collection=config.milvus_collection,
                    uri=config.milvus_uri,
                    embedder=OpenAIEmbedder(**embedder_kwargs),
                ),
                max_results=getattr(config, 'top_k', 5) if hasattr(config, 'top_k') else 5,
            ),
            tools=self.tools,
            instructions=INSTRUCTIONS,
            markdown=False,
            add_history_to_context=False,
            num_history_runs=0,
            enable_agentic_memory=False,
            enable_user_memories=False,
            enable_session_summaries=False,
        )

    async def analyze_request(self, packet: dict[str, Any]) -> dict[str, Any]:
        prompt = self._build_prompt(packet)
        prompt = self._enforce_token_limit(prompt)

        try:
            response = await asyncio.wait_for(
                self.agent.arun(prompt, stream=False),
                timeout=ANALYSIS_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            logger.error("LLM analysis timeout")
            return {
                "vulnerability_found": False,
                "confidence_score": 0,
                "reasoning": "Analysis timeout (30s) - API may be slow or unresponsive",
            }
        except Exception as e:
            return self._error_response(e)

        content = response.content if hasattr(response, 'content') else str(response)

        guard = self._guard_known_errors(content)
        if guard is not None:
            return guard

        result = JSONRepair.extract_json_from_text(content)

        if result.get('vulnerability_type') == 'PARSE_ERROR':
            preview = (content or '')[:800].replace('\n', ' \\n ')
            logger.warning(f"LLM raw content unparseable. Preview: {preview}")

        if not JSONRepair.validate_analysis_response(result):
            logger.warning("LLM response failed validation; using safe defaults")
            result = {
                "vulnerability_found": False,
                "confidence_score": 0,
                "reasoning": "Response validation failed",
            }

        result = self._reconcile_finding(result)

        if result.get('vulnerability_found'):
            confidence = int(result.get('confidence_score', 0))
            if confidence < self.config.confidence_threshold:
                result['vulnerability_found'] = False

        logger.info(
            f"Analysis complete: found={result.get('vulnerability_found')}, "
            f"confidence={result.get('confidence_score')}%"
        )
        return result

    def _build_prompt(self, packet: dict[str, Any]) -> str:
        context = self._build_context(packet)
        request_headers_view = self._format_headers(packet.get('request_headers', {}))
        response_headers_view = self._format_headers(packet.get('response_headers', {}))
        return (
            "Analyze this HTTP request for security vulnerabilities (IDOR, privilege escalation, broken access control, SQLi):\n\n"
            f"METHOD: {packet['method']}\n"
            f"URL: {packet['url']}\n"
            f"STATUS: {packet['status_code']}\n"
            f"REQUEST_HEADERS:\n{request_headers_view}\n"
            f"REQUEST_BODY: {packet['request_body'][:2000]}\n"
            f"RESPONSE_HEADERS:\n{response_headers_view}\n"
            f"RESPONSE_BODY: {packet['response_body'][:2000]}\n\n"
            f"CONTEXT: {context}\n\n"
            "Reason step by step internally, but output ONLY the JSON object below. "
            "If the requester's authorization cannot be confirmed against the accessed resource, lean toward flagging a vulnerability.\n\n"
            "{\n"
            '  "vulnerability_found": bool,\n'
            '  "vulnerability_type": string,\n'
            '  "confidence_score": int (0-100),\n'
            '  "risk_level": "Low" | "Medium" | "High" | "Critical",\n'
            '  "reasoning": string,\n'
            '  "proof_of_concept": string,\n'
            '  "remediation_suggestion": string\n'
            "}"
        )

    @staticmethod
    def _reconcile_finding(result: dict[str, Any]) -> dict[str, Any]:
        """Force vulnerability_found to agree with vulnerability_type/confidence.

        The LLM sometimes returns a real vulnerability_type with high
        confidence but vulnerability_found=false. Treat the type+confidence
        as the source of truth.
        """
        vtype = str(result.get('vulnerability_type') or '').strip()
        confidence = int(result.get('confidence_score') or 0)
        non_findings = {'', 'none', 'notapplicable', 'n/a', 'na', 'parse_error', 'safe'}
        is_real_type = vtype.lower() not in non_findings
        if is_real_type and confidence >= 60 and not result.get('vulnerability_found'):
            logger.info(
                f"Reconciling: type={vtype} confidence={confidence}% -> setting vulnerability_found=True"
            )
            result['vulnerability_found'] = True
        if not is_real_type:
            result['vulnerability_found'] = False
        return result

    @staticmethod
    def _format_headers(headers: dict[str, Any]) -> str:
        if not headers:
            return "  (none)"
        relevant = (
            'cookie', 'authorization', 'x-user-id', 'x-vulcan-trace-id',
            'x-forwarded-for', 'x-api-key', 'user-agent', 'referer',
            'content-type', 'set-cookie',
        )
        kept: list[str] = []
        for k, v in headers.items():
            if k.lower() in relevant:
                kept.append(f"  {k}: {str(v)[:200]}")
        if not kept:
            return "  (no auth-relevant headers)"
        return "\n".join(kept)

    def _enforce_token_limit(self, prompt: str) -> str:
        over_limit, tokens = self.token_counter.check_limit(prompt, MAX_INPUT_TOKENS)
        if over_limit:
            logger.warning(f"Truncating prompt from {tokens} to {MAX_INPUT_TOKENS} tokens")
            return self.token_counter.truncate_to_limit(prompt, MAX_INPUT_TOKENS)
        return prompt

    @staticmethod
    def _build_context(packet: dict[str, Any]) -> str:
        parts: list[str] = []
        path = packet.get('path', '').lower()
        url = packet['url'].lower()
        if 'login' in path or 'auth' in path:
            parts.append("Authentication-related request.")
        if any(p in url for p in ('id=', 'user=', 'userid=')):
            parts.append("URL contains potential user/ID parameters.")
        return " ".join(parts) if parts else "Standard request."

    @staticmethod
    def _guard_known_errors(content: str) -> Optional[dict[str, Any]]:
        if "exceeded your current quota" in content:
            return {
                "vulnerability_found": False,
                "confidence_score": 0,
                "reasoning": "OpenAI API quota exceeded - add credits at platform.openai.com",
            }
        lowered = content.lower()
        if "invalid api key" in lowered or "incorrect api key" in lowered:
            return {
                "vulnerability_found": False,
                "confidence_score": 0,
                "reasoning": "Invalid OpenAI API key - check OPENAI_API_KEY env variable",
            }
        return None

    @staticmethod
    def _error_response(e: Exception) -> dict[str, Any]:
        error_msg = str(e)
        logger.error(f"Error during analysis: {error_msg}", exc_info=True)
        if "api" in error_msg.lower() and "key" in error_msg.lower():
            reasoning = "API key error - set OPENAI_API_KEY environment variable"
        elif "quota" in error_msg.lower():
            reasoning = "API quota exceeded"
        else:
            reasoning = f"Error: {error_msg[:60]}"
        return {
            "vulnerability_found": False,
            "confidence_score": 0,
            "reasoning": reasoning,
        }

    def store_request(self, packet: dict[str, Any]) -> None:
        try:
            text = f"{packet['method']} {packet['url']} {packet['request_body'][:500]}"
            vector = self.embed_text(text)
            self.knowledge_store.store_request(packet, vector)
        except Exception as e:
            logger.warning(f"Failed to store request embedding: {e}")

    def get_session_summary(self, session_id: str = "default") -> Optional[str]:
        try:
            runs = self.agent.session_state.get(session_id, {}).get('runs', [])
            if not runs:
                return None
            return f"Analyzed {len(runs)} requests in this session."
        except Exception:
            return None


class _PassThroughMasker:
    def mask(self, text: str) -> str:
        return text
