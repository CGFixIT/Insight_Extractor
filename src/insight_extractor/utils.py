"""Utility functions for insight_extractor."""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure and return the package logger."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    return logging.getLogger("insight_extractor")


def truncate_text(text: str, max_length: int = 120, suffix: str = "...") -> str:
    """Truncate text to max_length, appending suffix if truncated."""
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)].rstrip() + suffix


def sanitize_filename(name: str) -> str:
    """Sanitize a string for use as a filename."""
    return re.sub(r"[^\w\s-]", "", name).strip().replace(" ", "_")


def format_timestamp(dt: datetime | None = None) -> str:
    """Return ISO 8601 UTC timestamp string."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def compute_text_hash(text: str, length: int = 16) -> str:
    """Return a truncated SHA-256 hash of text."""
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()[:length]
