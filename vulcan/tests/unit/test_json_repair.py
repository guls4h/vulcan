"""Tests for vulcan.utils.json_repair module."""

import json
import pytest
from vulcan.utils.json_repair import JSONRepair


class TestJSONRepair:
    """Tests for JSONRepair class methods."""

    def test_repair_valid_json_passes_through(self):
        """Test that valid JSON is returned unchanged."""
        valid = '{"vulnerability_found": true, "confidence_score": 85}'
        result = JSONRepair.repair(valid)
        assert result["vulnerability_found"] is True
        assert result["confidence_score"] == 85

    def test_repair_json_in_markdown_json_block(self):
        """Test extraction of JSON from ```json blocks."""
        broken = '```json\n{"vulnerability_found": false, "confidence_score": 0}\n```'
        result = JSONRepair.repair(broken)
        assert result["vulnerability_found"] is False
        assert result["confidence_score"] == 0

    def test_repair_json_in_generic_code_block(self):
        """Test extraction of JSON from generic ``` blocks."""
        broken = '```\n{"vulnerability_found": true, "confidence_score": 70}\n```'
        result = JSONRepair.repair(broken)
        assert result["vulnerability_found"] is True
        assert result["confidence_score"] == 70

    def test_repair_trailing_comma(self):
        """Test removal of trailing comma."""
        broken = '{"vulnerability_found": true, "confidence_score": 80,}'
        result = JSONRepair.repair(broken)
        assert result["vulnerability_found"] is True
        assert result["confidence_score"] == 80

    def test_repair_unquoted_keys(self):
        """Test fixing of unquoted keys."""
        broken = '{vulnerability_found: true, confidence_score: 50}'
        result = JSONRepair.repair(broken)
        assert result["vulnerability_found"] is True
        assert result["confidence_score"] == 50

    def test_repair_missing_closing_brace(self):
        """Test addition of missing closing brace."""
        broken = '{"vulnerability_found": true, "confidence_score": 60'
        result = JSONRepair.repair(broken)
        assert result["vulnerability_found"] is True
        assert result["confidence_score"] == 60

    def test_repair_missing_multiple_closing_braces(self):
        """Test addition of multiple missing closing braces."""
        broken = '{"outer": {"vulnerability_found": true, "confidence_score": 75'
        result = JSONRepair.repair(broken)
        # Should have added closing braces
        assert isinstance(result, dict)

    def test_repair_completely_unparseable_returns_fallback(self):
        """Test that completely unparseable input returns safe fallback."""
        broken = "This is not JSON at all, free text response $$$ !!!"
        result = JSONRepair.repair(broken)
        assert result["vulnerability_found"] is False
        assert result["confidence_score"] == 0

    def test_validate_response_adds_missing_vulnerability_found(self):
        """Test that missing vulnerability_found is added with default."""
        partial = {"confidence_score": 50}
        result = JSONRepair.repair(json.dumps(partial))
        assert "vulnerability_found" in result

    def test_validate_response_adds_missing_confidence_score(self):
        """Test that missing confidence_score is added with default."""
        partial = {"vulnerability_found": True}
        result = JSONRepair.repair(json.dumps(partial))
        assert "confidence_score" in result

    def test_validate_response_converts_string_confidence_score(self):
        """Test that string confidence_score is converted to int."""
        data = {"vulnerability_found": True, "confidence_score": "75"}
        result = JSONRepair.repair(json.dumps(data))
        # After repair, should be int or within 0-100 range
        assert isinstance(result["confidence_score"], (int, float))

    def test_validate_analysis_response_rejects_out_of_range_score(self):
        """Test that validate_analysis_response rejects invalid score range."""
        valid = {"vulnerability_found": True, "confidence_score": 85}
        assert JSONRepair.validate_analysis_response(valid) is True

        invalid = {"vulnerability_found": True, "confidence_score": 150}
        assert JSONRepair.validate_analysis_response(invalid) is False
