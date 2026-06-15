"""Logging configuration — stderr only.

stdout is reserved for MCP protocol traffic (JSON-RPC frames).  All log output
goes to stderr so it never corrupts the protocol stream.
"""

from __future__ import annotations

import logging
import sys


def configure_logging(level: int = logging.INFO) -> None:
    """Route all log output to stderr and silence any stdout handlers."""
    root = logging.getLogger()
    root.setLevel(level)

    # Remove any existing handlers that might write to stdout
    root.handlers = [h for h in root.handlers if getattr(h, "stream", None) is not sys.stdout]

    def _is_stderr(h: logging.Handler) -> bool:
        return isinstance(h, logging.StreamHandler) and h.stream is sys.stderr

    if not any(_is_stderr(h) for h in root.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
