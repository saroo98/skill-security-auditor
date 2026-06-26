"""Harmless fixture helper for scanner tests."""

from pathlib import Path


def heading_count(path: str) -> int:
    text = Path(path).read_text(encoding="utf-8")
    return sum(1 for line in text.splitlines() if line.startswith("#"))
