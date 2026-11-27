"""Renderers. Every string that came from a scanned file passes through sanitize()."""

from __future__ import annotations

from ..model import SEVERITY_RANK, VERDICT_RANK, Finding, ScanResult, UnitResult
from ..sanitize import sanitize


def ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEVERITY_RANK[f.severity], f.file, f.line or 0, f.check_id, f.evidence))


def worst_unit(result: ScanResult) -> UnitResult | None:
    if not result.units:
        return None
    return max(result.units, key=lambda u: (VERDICT_RANK[u.verdict], len(u.findings)))


def location(f: Finding) -> str:
    loc = sanitize(f.file, 120)
    return f"{loc}:{f.line}" if f.line is not None else loc


__all__ = ["ordered", "worst_unit", "location", "sanitize"]
