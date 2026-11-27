"""The review packet: a capped, sanitized view of a skill for the agent's model to judge."""

from __future__ import annotations

import re
import secrets

from .model import UnitResult
from .output import location, ordered
from .output.brief import can_line
from .sanitize import escape_invisible, sanitize

LIMIT = 12_000
_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_LINK = re.compile(r"\[[^\]]*\]\(([^)\s#]+)(?:#[^)]*)?\)")


def linked_markdown(text: str, available: set[str], base: str) -> list[str]:
    """Relative markdown files linked from ``text``, in link order, limited to ``available`` paths."""
    out: list[str] = []
    for target in _LINK.findall(text):
        if "://" in target or target.startswith("/"):
            continue
        parts: list[str] = [p for p in base.split("/") if p] if base else []
        for piece in target.split("/"):
            if piece in ("", "."):
                continue
            if piece == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(piece)
        rel = "/".join(parts)
        if rel in available and rel.lower().endswith((".md", ".mdx")) and rel not in out:
            out.append(rel)
    return out


def _body(text: str) -> tuple[str, list[str]]:
    hidden = [" ".join(m.split()) for m in _COMMENT.findall(text)]
    visible = _COMMENT.sub("", text)
    return _defuse(escape_invisible(visible).rstrip("\n")), [_defuse(escape_invisible(h)) for h in hidden if h]


def _defuse(text: str) -> str:
    """Skill text can never open or close the packet, whatever marker it guesses."""
    return text.replace("END>>>", "END>>[>]").replace("<<<SKILL-UNDER-REVIEW", "<<[<]SKILL-UNDER-REVIEW")


def build_packet(unit: UnitResult, instruction_files: list[tuple[str, str]], *, limit: int = LIMIT,
                 marker: str | None = None) -> tuple[str, list[str]]:
    marker = marker or secrets.token_hex(8)
    head = [f"<<<SKILL-UNDER-REVIEW {marker}", can_line(unit), f"static verdict: {unit.verdict}", "findings:"]
    findings = ordered(unit.findings)
    head += [f"- {f.severity} {sanitize(f.check_id, 40)} {location(f)} {f.evidence}" for f in findings[:20]] or ["- none"]
    if len(findings) > 20:
        head.append(f"- +{len(findings) - 20} more in the full report")
    tail = f"{marker} END>>>"
    parts = ["\n".join([head[0]] + [_defuse(line) for line in head[1:]])]
    used = len(parts[0]) + 1 + len(tail)
    cut: list[str] = []
    for rel, text in instruction_files:
        body, hidden = _body(text)
        section = "\n".join([f"--- {sanitize(rel, 200)} ---", body] + [f"[hidden: html-comment] {h}" for h in hidden])
        room = limit - used - 1
        if room <= 40:
            cut.append(rel)
            continue
        if len(section) > room:
            section = section[: room - 20].rstrip() + "\n[cut here]"
            cut.append(rel)
        parts.append(section)
        used += len(section) + 1
    parts.append(tail)
    return "\n".join(parts), cut
