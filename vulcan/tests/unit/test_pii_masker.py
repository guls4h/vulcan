"""Tests for vulcan.utils.pii_masker module."""

import pytest
from vulcan.utils.pii_masker import PIIMasker


class TestPIIMasker:
    """Tests for PIIMasker class."""

    def test_mask_email_in_body(self, sample_pii_patterns):
        """Test that email addresses are masked."""
        masker = PIIMasker(sample_pii_patterns)
        text = "Contact us at alice@test.com for support"
        result = masker.mask(text)
        assert "[EMAIL]" in result
        assert "alice@test.com" not in result

    def test_mask_phone_in_body(self, sample_pii_patterns):
        """Test that phone numbers are masked."""
        masker = PIIMasker(sample_pii_patterns)
        text = "Call +1234567890 during business hours"
        result = masker.mask(text)
        assert "[PHONE]" in result

    def test_mask_empty_string_returns_empty(self, sample_pii_patterns):
        """Test that empty string returns empty."""
        masker = PIIMasker(sample_pii_patterns)
        assert masker.mask("") == ""

    def test_mask_dict_only_masks_string_values(self, sample_pii_patterns):
        """Test that mask_dict only masks string values, not integers."""
        masker = PIIMasker(sample_pii_patterns)
        data = {
            "email": "alice@test.com",
            "count": 5,
            "name": "Alice"
        }
        result = masker.mask_dict(data)
        assert result["count"] == 5
        assert "[EMAIL]" in result["email"]

    def test_mask_headers_redacts_authorization(self, sample_pii_patterns):
        """Test that Authorization header is fully redacted."""
        masker = PIIMasker(sample_pii_patterns)
        headers = {"Authorization": "Bearer secret-token-12345"}
        result = masker.mask_headers(headers)
        assert result["Authorization"] == "[REDACTED]"

    def test_mask_headers_redacts_cookie(self, sample_pii_patterns):
        """Test that Cookie header is fully redacted."""
        masker = PIIMasker(sample_pii_patterns)
        headers = {"Cookie": "session_id=abc123xyz"}
        result = masker.mask_headers(headers)
        assert result["Cookie"] == "[REDACTED]"

    def test_mask_headers_does_not_redact_content_type(self, sample_pii_patterns):
        """Test that non-sensitive headers are not redacted."""
        masker = PIIMasker(sample_pii_patterns)
        headers = {"Content-Type": "application/json"}
        result = masker.mask_headers(headers)
        assert result["Content-Type"] == "application/json"
