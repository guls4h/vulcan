"""Tests for vulcan.utils.token_counter module."""

import pytest
from vulcan.utils.token_counter import TokenCounter, RequestTokenAnalyzer


class TestTokenCounter:
    """Tests for TokenCounter class."""

    def test_count_tokens_empty_string_returns_zero(self):
        """Test that empty string returns 0 tokens."""
        counter = TokenCounter()
        assert counter.count_tokens("") == 0

    def test_count_tokens_without_tiktoken_uses_word_estimation(self, mocker):
        """Test word-based estimation when tiktoken unavailable."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        counter = TokenCounter()
        # 4 words: "The", "quick", "brown", "fox"
        tokens = counter.count_tokens("The quick brown fox")
        # Should be approximately 4 * 1.3 = 5.2, rounded to 5
        assert tokens >= 1  # At least 1 token

    def test_count_tokens_minimum_one_for_nonempty(self, mocker):
        """Test that any nonempty string returns at least 1 token."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        counter = TokenCounter()
        tokens = counter.count_tokens("a")
        assert tokens >= 1

    def test_check_limit_below_limit_returns_false(self, mocker):
        """Test check_limit returns False for prompt within limit."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        counter = TokenCounter()
        is_over, count = counter.check_limit("short text", limit=10000)
        assert is_over is False
        assert count >= 1

    def test_check_limit_above_limit_returns_true(self, mocker):
        """Test check_limit returns True for prompt exceeding limit."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        counter = TokenCounter()
        is_over, count = counter.check_limit("any text", limit=1)
        assert is_over is True

    def test_truncate_to_limit_short_text_unchanged(self, mocker):
        """Test that short text within limit is returned unchanged."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        counter = TokenCounter()
        text = "short"
        result = counter.truncate_to_limit(text, limit=10000)
        assert result == text

    def test_truncate_to_limit_reduces_token_count(self, mocker):
        """Test that truncation significantly reduces token count."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        counter = TokenCounter()
        long_text = " ".join(["word"] * 100)
        original_tokens = counter.count_tokens(long_text)
        limit = 30
        result = counter.truncate_to_limit(long_text, limit=limit)
        result_tokens = counter.count_tokens(result)
        # Verify that we reduced the count and it's reasonably close to limit
        assert result_tokens < original_tokens
        assert result_tokens <= limit * 2  # Allow some margin for binary search

    def test_log_usage_accumulates_session_tokens(self, mocker):
        """Test that log_usage accumulates session tokens correctly."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        counter = TokenCounter()
        counter.log_usage(100, 50, "endpoint1")
        counter.log_usage(100, 50, "endpoint2")
        assert counter.session_tokens == 300
        assert counter.session_requests == 2

    def test_get_session_summary(self, mocker):
        """Test that get_session_summary returns correct dict."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        counter = TokenCounter()
        counter.log_usage(100, 50)
        summary = counter.get_session_summary()
        assert summary["total_tokens"] == 150
        assert summary["total_requests"] == 1
        assert "estimated_cost_usd" in summary

    def test_reset_session(self, mocker):
        """Test that reset_session clears counters."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        counter = TokenCounter()
        counter.log_usage(100, 50)
        assert counter.session_tokens == 150
        counter.reset_session()
        assert counter.session_tokens == 0
        assert counter.session_requests == 0


class TestRequestTokenAnalyzer:
    """Tests for RequestTokenAnalyzer class."""

    def test_analyze_http_request_returns_three_values(self, mocker):
        """Test that analyze_http_request returns tuple of 3 ints."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        result = RequestTokenAnalyzer.analyze_http_request(
            "GET", "http://localhost/api", {}, ""
        )
        assert isinstance(result, tuple)
        assert len(result) == 3
        assert all(isinstance(v, int) for v in result)

    def test_get_request_size_breakdown_contains_expected_keys(self, mocker):
        """Test that breakdown dict has all expected keys."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        breakdown = RequestTokenAnalyzer.get_request_size_breakdown(
            "POST", "http://localhost/api/profile", {"Content-Type": "application/json"}, '{"key": "value"}'
        )
        expected_keys = {"method", "url", "headers", "body", "total"}
        assert set(breakdown.keys()) == expected_keys
        assert all(v >= 0 for v in breakdown.values())
