"""Tests for vulcan.utils.retry_handler module."""

import pytest
import asyncio
from unittest.mock import AsyncMock
from vulcan.utils.retry_handler import (
    RetryConfig, RetryHandler, RateLimitError, TimeoutError, ConnectionError,
    async_retry, sync_retry
)


class TestRetryConfig:
    """Tests for RetryConfig class."""

    def test_retry_config_defaults(self):
        """Test RetryConfig default values."""
        config = RetryConfig()
        assert config.max_retries == 3
        assert config.base_delay == 1.0
        assert config.max_delay == 60.0
        assert config.exponential_base == 2.0

    def test_calculate_delay_exponential_growth(self):
        """Test exponential growth of delay without jitter."""
        config = RetryConfig(jitter=False, exponential_base=2.0, base_delay=1.0)
        delay_0 = config.calculate_delay(0)
        delay_1 = config.calculate_delay(1)
        delay_2 = config.calculate_delay(2)
        assert delay_0 == 1.0  # 1.0 * 2^0
        assert delay_1 == 2.0  # 1.0 * 2^1
        assert delay_2 == 4.0  # 1.0 * 2^2

    def test_calculate_delay_capped_at_max_delay(self):
        """Test that delay is capped at max_delay."""
        config = RetryConfig(jitter=False, max_delay=10.0, base_delay=1.0)
        very_high_delay = config.calculate_delay(100)
        assert very_high_delay <= 10.0


class TestRetryHandlerSync:
    """Tests for RetryHandler sync retry logic."""

    def test_sync_retry_succeeds_on_first_attempt(self, mocker):
        """Test that sync_retry returns on first successful attempt."""
        mocker.patch("time.sleep")
        mock_func = lambda: "ok"
        handler = RetryHandler(RetryConfig(max_retries=3))
        result = handler.sync_retry(mock_func)
        assert result == "ok"

    def test_sync_retry_retries_on_timeout_error(self, mocker):
        """Test that sync_retry retries on TimeoutError."""
        sleep_mock = mocker.patch("time.sleep")
        call_count = 0
        def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise TimeoutError("timeout")
            return "success"

        handler = RetryHandler(RetryConfig(max_retries=3, jitter=False))
        result = handler.sync_retry(flaky_func)
        assert result == "success"
        assert call_count == 3
        assert sleep_mock.call_count == 2  # sleep called twice

    def test_sync_retry_raises_after_all_retries_exhausted(self, mocker):
        """Test that sync_retry raises after max retries."""
        mocker.patch("time.sleep")
        def always_fails():
            raise ConnectionError("connection lost")

        handler = RetryHandler(RetryConfig(max_retries=3))
        with pytest.raises(ConnectionError):
            handler.sync_retry(always_fails)

    def test_sync_retry_decorator_wraps_function(self):
        """Test that @sync_retry decorator preserves function name."""
        @sync_retry(max_retries=2)
        def my_function():
            return "result"

        assert my_function.__name__ == "my_function"


class TestRetryHandlerAsync:
    """Tests for RetryHandler async retry logic."""

    async def test_async_retry_succeeds_immediately(self):
        """Test that async_retry returns on first successful attempt."""
        mock_func = AsyncMock(return_value="ok")
        handler = RetryHandler(RetryConfig(max_retries=3))
        result = await handler.async_retry(mock_func)
        assert result == "ok"
        mock_func.assert_awaited_once()

    async def test_async_retry_on_rate_limit_uses_retry_after(self, mocker):
        """Test that RateLimitError with retry_after is respected."""
        mocker.patch("asyncio.sleep", new_callable=AsyncMock)
        call_count = 0
        async def rate_limited_func():
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RateLimitError(retry_after=2.5)
            return "success"

        handler = RetryHandler(RetryConfig(max_retries=3))
        result = await handler.async_retry(rate_limited_func)
        assert result == "success"

    async def test_async_retry_non_retryable_exception_raises_immediately(self):
        """Test that non-retryable exceptions raise immediately."""
        async def non_retryable_func():
            raise ValueError("not retryable")

        handler = RetryHandler(RetryConfig(max_retries=3))
        with pytest.raises(ValueError):
            await handler.async_retry(non_retryable_func)

    async def test_async_retry_decorator_preserves_return_value(self, mocker):
        """Test that @async_retry decorator preserves function behavior."""
        mocker.patch("asyncio.sleep", new_callable=AsyncMock)

        @async_retry(max_retries=2, base_delay=0.01)
        async def my_async_func():
            return {"status": "ok"}

        result = await my_async_func()
        assert result == {"status": "ok"}
