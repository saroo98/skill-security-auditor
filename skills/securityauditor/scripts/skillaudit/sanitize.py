"""Make untrusted text safe to show in a terminal or to an agent."""

from __future__ import annotations

import unicodedata

_ESCAPE_CATEGORIES = {"Cc", "Cf", "Co", "Cn", "Cs"}
_KEPT = {" ", "\t", "\n"}


def _escape(ch: str) -> str:
    code = ord(ch)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def escape_invisible(text: str) -> str:
    """Replace control, format, private-use and unassigned characters with visible escapes.

    Space, tab and newline are kept; ``\\r\\n`` becomes ``\\n``.
    """
    out: list[str] = []
    for ch in text.replace("\r\n", "\n"):
        if ch in _KEPT:
            out.append(ch)
        elif unicodedata.category(ch) in _ESCAPE_CATEGORIES:
            out.append(_escape(ch))
        else:
            out.append(ch)
    return "".join(out)


def sanitize(text: str, limit: int = 200) -> str:
    """Escape invisible characters, collapse whitespace to single spaces and clip to ``limit``."""
    escaped = escape_invisible(text)
    collapsed = " ".join(escaped.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "…"
