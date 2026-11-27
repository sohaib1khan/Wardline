"""Application logging setup. Log file lives under the data directory."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from wardline.core.paths import ensure_file_perms, log_file_path

_CONFIGURED = False


def setup_logging(
    *,
    level: int = logging.INFO,
    log_path: Path | None = None,
    also_stderr: bool = False,
) -> logging.Logger:
    """Configure the ``wardline`` logger once; safe to call repeatedly."""
    global _CONFIGURED
    logger = logging.getLogger("wardline")
    logger.setLevel(level)

    if _CONFIGURED:
        return logger

    path = log_path if log_path is not None else log_file_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        path,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)
    ensure_file_perms(path)

    if also_stderr:
        stream = logging.StreamHandler()
        stream.setFormatter(formatter)
        stream.setLevel(level)
        logger.addHandler(stream)

    logger.propagate = False
    _CONFIGURED = True
    return logger


def reset_logging_for_tests() -> None:
    """Clear handlers so tests can reconfigure logging."""
    global _CONFIGURED
    logger = logging.getLogger("wardline")
    for handler in list(logger.handlers):
        handler.close()
        logger.removeHandler(handler)
    _CONFIGURED = False
