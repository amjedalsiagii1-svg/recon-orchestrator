"""Structured logging — structlog + per-session file."""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import structlog

_initialized = False


def setup_logging(
    log_dir: str | Path = "logs",
    session_id: str | None = None,
    level: int = logging.INFO,
) -> Path | None:
    """Configure structlog + stdlib logging. Returns log file path or None."""
    global _initialized
    log_path: Path | None = None

    if session_id:
        d = Path(log_dir)
        d.mkdir(parents=True, exist_ok=True)
        log_path = d / f"session_{session_id}.log"

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    if log_path:
        handlers.append(logging.FileHandler(log_path, encoding="utf-8"))

    logging.basicConfig(
        level=level, format="%(message)s", handlers=handlers, force=True
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    _initialized = True
    return log_path


def get_logger(name: str = "recon") -> structlog.stdlib.BoundLogger:
    if not _initialized:
        setup_logging()
    return structlog.get_logger(name)
