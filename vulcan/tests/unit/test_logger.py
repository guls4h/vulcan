"""Tests for vulcan.utils.logger module."""

import logging
import pytest
from pathlib import Path
from vulcan.utils.logger import setup_logger, get_logger


class TestSetupLogger:
    """Tests for setup_logger function."""

    def test_setup_logger_creates_log_directory(self, tmp_path):
        """Test that setup_logger creates log directory if missing."""
        log_dir = tmp_path / "new_logs"
        logger = setup_logger("test_dir", log_dir=str(log_dir))
        assert log_dir.exists()
        assert log_dir.is_dir()

    def test_setup_logger_creates_log_file(self, tmp_log_dir):
        """Test that setup_logger creates a .log file."""
        logger = setup_logger("test_module", log_dir=tmp_log_dir)
        log_path = Path(tmp_log_dir) / "test_module.log"
        assert log_path.exists()

    def test_setup_logger_returns_logger_instance(self, tmp_log_dir):
        """Test that setup_logger returns a logging.Logger instance."""
        logger = setup_logger("test", log_dir=tmp_log_dir)
        assert isinstance(logger, logging.Logger)

    def test_setup_logger_dot_in_name_replaced_with_underscore(self, tmp_log_dir):
        """Test that dotted names become underscored in filenames."""
        logger = setup_logger("a.b.c", log_dir=tmp_log_dir)
        log_path = Path(tmp_log_dir) / "a_b_c.log"
        assert log_path.exists()

    def test_setup_logger_custom_level(self, tmp_log_dir):
        """Test that custom log level is respected."""
        logger = setup_logger("test", log_dir=tmp_log_dir, level=logging.DEBUG)
        assert logger.level == logging.DEBUG

    def test_setup_logger_idempotent_no_duplicate_handlers(self, tmp_log_dir):
        """Test that calling setup_logger twice doesn't add duplicate handlers."""
        name = f"test_idempotent_{id(tmp_log_dir)}"
        logger1 = setup_logger(name, log_dir=tmp_log_dir)
        handler_count_1 = len(logger1.handlers)
        logger2 = setup_logger(name, log_dir=tmp_log_dir)
        handler_count_2 = len(logger2.handlers)
        assert handler_count_1 == handler_count_2


class TestGetLogger:
    """Tests for get_logger function."""

    def test_get_logger_returns_same_instance(self, tmp_log_dir):
        """Test that get_logger returns the same logger instance after setup."""
        name = f"test_get_{id(tmp_log_dir)}"
        setup_logger(name, log_dir=tmp_log_dir)
        logger1 = get_logger(name)
        logger2 = get_logger(name)
        assert logger1 is logger2
