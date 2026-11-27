"""Unit tests for logging setup."""

from __future__ import annotations

from pathlib import Path

from wardline.core.logging_setup import reset_logging_for_tests, setup_logging
from wardline.core.paths import FILE_MODE, mode_octal


def test_setup_logging_creates_private_log(tmp_path: Path) -> None:
    reset_logging_for_tests()
    log_path = tmp_path / "logs" / "wardline.log"
    logger = setup_logging(log_path=log_path)
    logger.info("hello from test")
    for handler in logger.handlers:
        handler.flush()
    assert log_path.is_file()
    assert "hello from test" in log_path.read_text(encoding="utf-8")
    assert mode_octal(log_path) == FILE_MODE
    reset_logging_for_tests()
