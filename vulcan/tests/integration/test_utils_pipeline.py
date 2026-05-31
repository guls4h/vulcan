"""Integration tests for VULCAN utility modules."""

import pytest
from unittest.mock import AsyncMock
from vulcan.utils.json_repair import JSONRepair
from vulcan.utils.ground_truth import GroundTruthValidator, AnalysisResult, AccuracyMetrics
from vulcan.utils.pii_masker import PIIMasker
from vulcan.utils.token_counter import TokenCounter, RequestTokenAnalyzer
from vulcan.utils.retry_handler import RetryHandler, RetryConfig, async_retry, ConnectionError


class TestJSONRepairToGroundTruthPipeline:
    """Tests for JSON repair → ground truth validation pipeline."""

    def test_repaired_json_creates_valid_analysis_result(self, populated_ground_truth_file):
        """Test full pipeline: repair → AnalysisResult → GroundTruthValidator."""
        raw = '```json\n{"vulnerability_found": true, "confidence_score": 85}\n```'
        repaired = JSONRepair.repair(raw)
        result = AnalysisResult(
            vulnerability_found=repaired["vulnerability_found"],
            confidence_score=repaired["confidence_score"]
        )
        validator = GroundTruthValidator(populated_ground_truth_file)
        tp, fp, tn = validator.validate("/api/profile", "GET", result, session_user_id=1, target_id=2)
        assert tp is True

    def test_fallback_json_produces_false_negative(self, populated_ground_truth_file):
        """Test that unparseable JSON produces false negative on IDOR endpoint."""
        fallback = JSONRepair.repair("completely unparseable garbage $$$ !!!")
        assert fallback["vulnerability_found"] is False
        result = AnalysisResult(
            vulnerability_found=fallback["vulnerability_found"],
            confidence_score=fallback["confidence_score"]
        )
        validator = GroundTruthValidator(populated_ground_truth_file)
        tp, fp, tn = validator.validate("/api/profile", "GET", result, session_user_id=1, target_id=2)
        assert tp is False  # False negative

    def test_accuracy_metrics_over_batch_of_results(self, populated_ground_truth_file):
        """Test computing accuracy metrics over a batch of scan results."""
        validator = GroundTruthValidator(populated_ground_truth_file)
        scenarios = [
            ("/api/profile", "GET", True, 1, 2),      # TP: vulnerable, detected
            ("/api/orders", "GET", True, 1, 2),       # TP: vulnerable, detected
            ("/api/admin/users", "GET", False, 1, 1), # TN: not vulnerable, not detected
            ("/api/profile", "GET", False, 1, 2),     # FN: vulnerable, missed
            ("/api/cart", "GET", True, 1, 2),         # TP: vulnerable, detected
        ]
        tp, fp, fn, tn = 0, 0, 0, 0
        for endpoint, method, detected, session_id, target_id in scenarios:
            result = AnalysisResult(
                vulnerability_found=detected,
                confidence_score=80 if detected else 0
            )
            t, f, n = validator.validate(endpoint, method, result, session_user_id=session_id, target_id=target_id)
            if t:
                tp += 1
            elif f:
                fp += 1
            elif n:
                tn += 1
            else:
                fn += 1

        metrics = AccuracyMetrics.calculate(tp, fp, fn, tn)
        assert metrics["precision"] > 0.0
        assert metrics["recall"] > 0.0


class TestPIIMaskerTokenCounterPipeline:
    """Tests for PII masking and token counting pipeline."""

    def test_pii_masked_body_token_count_is_consistent(self, sample_pii_patterns, mocker):
        """Test that PII masking produces valid tokens."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        masker = PIIMasker(sample_pii_patterns)
        counter = TokenCounter()
        original = "User email is alice@test.com and phone is +1234567890"
        masked = masker.mask(original)
        assert "[EMAIL]" in masked
        original_tokens = counter.count_tokens(original)
        masked_tokens = counter.count_tokens(masked)
        assert original_tokens > 0
        assert masked_tokens > 0

    def test_request_size_breakdown_after_pii_masking(self, sample_pii_patterns, mocker):
        """Test request analysis after PII masking."""
        mocker.patch.object(TokenCounter, "_init_encoder", return_value=None)
        masker = PIIMasker(sample_pii_patterns)
        headers = {"Authorization": "Bearer secret", "Content-Type": "application/json"}
        body = '{"email": "alice@test.com", "message": "hello"}'
        masked_headers = masker.mask_headers(headers)
        masked_body = masker.mask(body)
        breakdown = RequestTokenAnalyzer.get_request_size_breakdown(
            "POST", "/api/profile", masked_headers, masked_body
        )
        assert all(v >= 0 for v in breakdown.values())
        assert breakdown["total"] >= breakdown["body"]


class TestAsyncRetryPipeline:
    """Tests for async retry correctness in pipelines."""

    async def test_async_retry_handler_with_multiple_retries(self, mocker):
        """Test RetryHandler retries async function correct number of times."""
        mocker.patch("asyncio.sleep", new_callable=AsyncMock)
        call_count = 0
        async def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("temporary")
            return "success"

        config = RetryConfig(max_retries=3, base_delay=0.1, jitter=False)
        handler = RetryHandler(config)
        result = await handler.async_retry(flaky)
        assert result == "success"
        assert call_count == 3

    async def test_async_retry_decorator_preserves_return_value(self, mocker):
        """Test @async_retry decorator preserves function return."""
        mocker.patch("asyncio.sleep", new_callable=AsyncMock)

        @async_retry(max_retries=2, base_delay=0.01)
        async def my_func():
            return {"status": "ok"}

        result = await my_func()
        assert result == {"status": "ok"}
