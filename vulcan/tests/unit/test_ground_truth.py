"""Tests for vulcan.utils.ground_truth module."""

import json
import pytest
from vulcan.utils.ground_truth import (
    GroundTruthEntry, AnalysisResult, GroundTruthValidator, AccuracyMetrics
)


class TestGroundTruthEntry:
    """Tests for GroundTruthEntry dataclass."""

    def test_entry_to_dict_roundtrip(self, sample_ground_truth_entry_dict):
        """Test to_dict → from_dict roundtrip."""
        entry = GroundTruthEntry(**sample_ground_truth_entry_dict)
        dict_form = entry.to_dict()
        entry2 = GroundTruthEntry.from_dict(dict_form)
        assert entry == entry2

    def test_entry_to_json_is_valid_json_line(self, sample_ground_truth_entry_dict):
        """Test that to_json() produces valid JSON."""
        entry = GroundTruthEntry(**sample_ground_truth_entry_dict)
        json_str = entry.to_json()
        parsed = json.loads(json_str)
        assert parsed["endpoint"] == "/api/profile"
        assert parsed["vulnerability_type"] == "IDOR"


class TestGroundTruthValidator:
    """Tests for GroundTruthValidator class."""

    def test_validator_loads_entries_from_jsonl(self, populated_ground_truth_file):
        """Test that validator loads all entries from JSONL file."""
        validator = GroundTruthValidator(populated_ground_truth_file)
        assert len(validator.entries) == 10

    def test_validator_with_nonexistent_file_empty_entries(self, tmp_ground_truth_file):
        """Test that validator handles nonexistent file gracefully."""
        validator = GroundTruthValidator(tmp_ground_truth_file)
        assert validator.entries == []

    def test_find_matching_entries_by_endpoint_and_method(self, populated_ground_truth_file):
        """Test finding entries by endpoint and method."""
        validator = GroundTruthValidator(populated_ground_truth_file)
        matches = validator.find_matching_entries("/api/profile", "GET")
        assert len(matches) >= 1
        assert all(m.endpoint == "/api/profile" and m.method == "GET" for m in matches)

    def test_validate_true_positive(self, populated_ground_truth_file):
        """Test validation returns true positive."""
        validator = GroundTruthValidator(populated_ground_truth_file)
        result = AnalysisResult(vulnerability_found=True, confidence_score=85)
        tp, fp, tn = validator.validate("/api/profile", "GET", result, session_user_id=1, target_id=2)
        assert tp is True

    def test_validate_true_negative(self, populated_ground_truth_file):
        """Test validation returns true negative."""
        validator = GroundTruthValidator(populated_ground_truth_file)
        result = AnalysisResult(vulnerability_found=False, confidence_score=0)
        # Line 9 of ground_truth.jsonl is a true negative case (/api/products GET public endpoint)
        tp, fp, tn = validator.validate("/api/products", "GET", result, session_user_id=0)
        assert tn is True

    def test_validate_false_positive(self, populated_ground_truth_file):
        """Test validation returns false positive."""
        validator = GroundTruthValidator(populated_ground_truth_file)
        result = AnalysisResult(vulnerability_found=True, confidence_score=80)
        tp, fp, tn = validator.validate("/api/admin/users", "GET", result, session_user_id=1)
        assert fp is True

    def test_add_entry_persists_to_file(self, tmp_ground_truth_file):
        """Test that add_entry persists to file."""
        validator = GroundTruthValidator(tmp_ground_truth_file)
        entry = GroundTruthEntry(
            timestamp="2026-01-04T20:00:00",
            endpoint="/api/test",
            method="POST",
            user_session=1,
            target_id=2,
            is_vulnerable=True,
            vulnerability_type="TEST",
            status_code=200,
            description="Test entry"
        )
        validator.add_entry(entry)
        validator2 = GroundTruthValidator(tmp_ground_truth_file)
        assert len(validator2.entries) == 1
        assert validator2.entries[0].endpoint == "/api/test"


class TestAccuracyMetrics:
    """Tests for AccuracyMetrics class."""

    def test_calculate_perfect_precision_recall(self):
        """Test metrics with perfect precision and recall."""
        metrics = AccuracyMetrics.calculate(
            true_positives=4,
            false_positives=0,
            false_negatives=0,
            true_negatives=2
        )
        assert metrics["precision"] == 1.0
        assert metrics["recall"] == 1.0
        assert metrics["f1_score"] == 1.0

    def test_calculate_handles_zero_division_gracefully(self):
        """Test that zero metrics don't cause ZeroDivisionError."""
        metrics = AccuracyMetrics.calculate(
            true_positives=0,
            false_positives=0,
            false_negatives=0,
            true_negatives=0
        )
        assert metrics["precision"] == 0.0
        assert metrics["recall"] == 0.0
        assert metrics["f1_score"] == 0.0

    def test_format_metrics_contains_key_labels(self):
        """Test that format_metrics output contains expected labels."""
        metrics = AccuracyMetrics.calculate(10, 2, 1, 5)
        formatted = AccuracyMetrics.format_metrics(metrics)
        assert "Precision" in formatted
        assert "Recall" in formatted
        assert "F1-Score" in formatted
        assert "Accuracy" in formatted
