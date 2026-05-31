"""Shared pytest fixtures for all tests."""

import pytest
from pathlib import Path


@pytest.fixture
def tmp_log_dir(tmp_path):
    """Isolated log directory for each test."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return str(log_dir)


@pytest.fixture
def tmp_ground_truth_file(tmp_path):
    """Empty ground truth JSONL file path (does not exist yet)."""
    return str(tmp_path / "ground_truth.jsonl")


@pytest.fixture
def populated_ground_truth_file(tmp_path):
    """Ground truth file pre-loaded from tests/data/ground_truth.jsonl."""
    source = Path(__file__).parent / "data" / "ground_truth.jsonl"
    dest = tmp_path / "ground_truth.jsonl"
    if source.exists():
        dest.write_bytes(source.read_bytes())
    return str(dest)


@pytest.fixture
def sample_pii_patterns():
    """Standard PII patterns matching config.example.yaml style."""
    return [
        {"name": "email", "regex": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "mask": "[EMAIL]"},
        {"name": "phone", "regex": r"\+?\d[\d\s\-]{7,}\d", "mask": "[PHONE]"},
        {"name": "ssn", "regex": r"\b\d{3}-\d{2}-\d{4}\b", "mask": "[SSN]"},
    ]


@pytest.fixture
def sample_ground_truth_entry_dict():
    """A single valid GroundTruthEntry as a dictionary."""
    return {
        "timestamp": "2026-01-04T20:00:00",
        "endpoint": "/api/profile",
        "method": "GET",
        "user_session": 1,
        "target_id": 2,
        "is_vulnerable": True,
        "vulnerability_type": "IDOR",
        "status_code": 200,
        "description": "User 1 accessed profile of user 2 via ?id=2 param",
    }
