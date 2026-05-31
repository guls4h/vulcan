from typing import Optional, Tuple

from vulcan.utils.logger import setup_logger

logger = setup_logger(__name__)


class TokenCounter:
    def __init__(self) -> None:
        self.session_tokens = 0
        self.session_requests = 0
        self.token_encoder = self._init_encoder()

    @staticmethod
    def _init_encoder():
        try:
            import tiktoken
            return tiktoken.encoding_for_model("gpt-4o-mini")
        except ImportError:
            return None
        except Exception as e:
            logger.warning(f"Failed to initialize tiktoken: {e}")
            return None

    def count_tokens(self, text: str) -> int:
        if not text:
            return 0
        if self.token_encoder:
            try:
                return len(self.token_encoder.encode(text))
            except Exception as e:
                logger.warning(f"Token encoding failed: {e}")
        word_count = len(text.split())
        return max(int(word_count * 1.3), 1)

    def check_limit(self, prompt: str, limit: int = 10000) -> Tuple[bool, int]:
        tokens = self.count_tokens(prompt)
        return tokens > limit, tokens

    def truncate_to_limit(self, text: str, limit: int = 10000, preserve_start: bool = True) -> str:
        tokens = self.count_tokens(text)
        if tokens <= limit:
            return text

        logger.warning(f"Truncating text from {tokens} to {limit} tokens")

        left, right = 0, len(text)
        while left < right:
            mid = (left + right) // 2
            candidate = text[:mid] if preserve_start else text[-mid:]
            if self.count_tokens(candidate) <= limit:
                left = mid + 1
            else:
                right = mid

        return text[:left] if preserve_start else text[-left:]

    def log_usage(self, prompt_tokens: int, completion_tokens: int, endpoint: str = "generic") -> None:
        total = prompt_tokens + completion_tokens
        self.session_tokens += total
        self.session_requests += 1
        avg = self.session_tokens / self.session_requests
        logger.info(
            f"Token usage: request={total} "
            f"(prompt={prompt_tokens}, completion={completion_tokens}), "
            f"session_total={self.session_tokens}, requests={self.session_requests}, avg={avg:.0f}"
        )

    def get_session_summary(self) -> dict[str, int | float]:
        avg = self.session_tokens / self.session_requests if self.session_requests > 0 else 0
        return {
            'total_tokens': self.session_tokens,
            'total_requests': self.session_requests,
            'avg_tokens_per_request': int(avg),
            'estimated_cost_usd': self._estimate_cost(self.session_tokens),
        }

    @staticmethod
    def _estimate_cost(tokens: int) -> float:
        cost_per_million = 0.25
        return (tokens / 1_000_000) * cost_per_million

    def reset_session(self) -> None:
        self.session_tokens = 0
        self.session_requests = 0


class RequestTokenAnalyzer:
    @staticmethod
    def analyze_http_request(method: str, url: str, headers: dict, body: str) -> Tuple[int, int, int]:
        counter = TokenCounter()
        return (
            counter.count_tokens(method),
            counter.count_tokens(url),
            counter.count_tokens(body),
        )

    @staticmethod
    def get_request_size_breakdown(method: str, url: str, headers: dict, body: str) -> dict[str, int]:
        counter = TokenCounter()
        headers_text = '\n'.join(f"{k}: {v}" for k, v in headers.items())
        return {
            'method': counter.count_tokens(method),
            'url': counter.count_tokens(url),
            'headers': counter.count_tokens(headers_text),
            'body': counter.count_tokens(body),
            'total': counter.count_tokens(f"{method}\n{url}\n{headers_text}\n{body}"),
        }
