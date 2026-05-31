import asyncio
import random
import time
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

from vulcan.utils.logger import setup_logger

logger = setup_logger(__name__)

T = TypeVar('T')


class RetryConfig:
    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        exponential_base: float = 2.0,
        jitter: bool = True,
    ) -> None:
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.exponential_base = exponential_base
        self.jitter = jitter

    def calculate_delay(self, attempt: int) -> float:
        delay = min(self.base_delay * (self.exponential_base ** attempt), self.max_delay)
        if self.jitter:
            delay += random.uniform(0, delay * 0.1)
        return delay


class RetryableException(Exception):
    pass


class RateLimitError(RetryableException):
    def __init__(self, retry_after: Optional[float] = None) -> None:
        self.retry_after = retry_after
        super().__init__(f"Rate limited. Retry after: {retry_after}s")


class TimeoutError(RetryableException):
    pass


class ConnectionError(RetryableException):
    pass


class RetryHandler:
    def __init__(self, config: Optional[RetryConfig] = None) -> None:
        self.config = config or RetryConfig()

    async def async_retry(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        last_exception: Optional[BaseException] = None

        for attempt in range(self.config.max_retries):
            try:
                return await func(*args, **kwargs)
            except RateLimitError as e:
                last_exception = e
                if attempt == self.config.max_retries - 1:
                    raise
                delay = e.retry_after or self.config.calculate_delay(attempt)
                logger.warning(f"Rate limited, retrying in {delay:.1f}s")
                await asyncio.sleep(delay)
            except (TimeoutError, ConnectionError, asyncio.TimeoutError) as e:
                last_exception = e
                if attempt == self.config.max_retries - 1:
                    raise
                delay = self.config.calculate_delay(attempt)
                logger.warning(f"Transient error ({type(e).__name__}), retrying in {delay:.1f}s")
                await asyncio.sleep(delay)
            except Exception:
                raise

        raise last_exception or RuntimeError(f"Failed after {self.config.max_retries} attempts")

    def sync_retry(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        last_exception: Optional[BaseException] = None

        for attempt in range(self.config.max_retries):
            try:
                return func(*args, **kwargs)
            except RateLimitError as e:
                last_exception = e
                if attempt == self.config.max_retries - 1:
                    raise
                delay = e.retry_after or self.config.calculate_delay(attempt)
                logger.warning(f"Rate limited, retrying in {delay:.1f}s")
                time.sleep(delay)
            except (TimeoutError, ConnectionError) as e:
                last_exception = e
                if attempt == self.config.max_retries - 1:
                    raise
                delay = self.config.calculate_delay(attempt)
                logger.warning(f"Transient error ({type(e).__name__}), retrying in {delay:.1f}s")
                time.sleep(delay)
            except Exception:
                raise

        raise last_exception or RuntimeError(f"Failed after {self.config.max_retries} attempts")


def async_retry(max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 60.0) -> Callable:
    handler = RetryHandler(RetryConfig(max_retries, base_delay, max_delay))

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            return await handler.async_retry(func, *args, **kwargs)
        return wrapper

    return decorator


def sync_retry(max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 60.0) -> Callable:
    handler = RetryHandler(RetryConfig(max_retries, base_delay, max_delay))

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return handler.sync_retry(func, *args, **kwargs)
        return wrapper

    return decorator
