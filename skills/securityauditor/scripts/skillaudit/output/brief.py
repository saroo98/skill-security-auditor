"""The short verdict the agent relays to the user."""

from __future__ import annotations

from ..model import VERDICTS, ScanResult, UnitResult
from . import location, ordered, sanitize, worst_unit

MAX_FINDINGS = 5
MAX_NAMES = 5
LINE_LIMIT = 160


def _names(items: list[str], limit: int = MAX_NAMES) -> str:
    shown = ", ".join(sanitize(i, 60) for i in items[:limit])
    return shown + (f" (+{len(items) - limit})" if len(items) > limit else "")


def can_line(unit: UnitResult) -> str:
    from .. import policy

    words = policy.can_summary(unit.capabilities)
    return "can: " + (", ".join(words) if words else "nothing notable found")


def unprompted_line(unit: UnitResult) -> str | None:
    from .. import policy

    items = policy.unprompted_summary(unit.capabilities)
    return ("runs without asking: " + _names(items, 4)) if items else None


def _unit_detail(unit: UnitResult, report_path: str | None) -> list[str]:
    lines = [can_line(unit)]
    extra = unprompted_line(unit)
    if extra:
        lines.append(extra)
    findings = [f for f in ordered(unit.findings) if f.severity != "info"]
    for f in findings[:MAX_FINDINGS]:
        line = f"{f.severity:<9} {sanitize(f.check_id, 40)}  {location(f)}  {sanitize(f.message, 100)}"
        lines.append(line[:LINE_LIMIT])
    if len(findings) > MAX_FINDINGS:
        more = f"+{len(findings) - MAX_FINDINGS} more"
        lines.append(f"{more}  full report: {report_path}" if report_path else more)
    gaps = [n.rel for n in unit.not_checked if n.severity != "info"]
    if gaps:
        lines.append("not analyzed: " + _names(gaps))
    return lines


def render_brief(result: ScanResult, *, report_path: str | None = None, used_external: str | None = None) -> str:
    total_files = sum(u.files for u in result.units)
    if not result.units:
        return f"PASS  (empty)  0 files  {result.elapsed:.1f}s\ncan: nothing found to check"
    worst = worst_unit(result)
    assert worst is not None
    if len(result.units) == 1:
        lines = [f"{worst.verdict}  {sanitize(worst.name, 60)}  {worst.files} files  {result.elapsed:.1f}s"]
        lines += _unit_detail(worst, report_path)
    else:
        lines = [f"{worst.verdict}  {len(result.units)} skills  {total_files} files  {result.elapsed:.1f}s"]
        for verdict in reversed(VERDICTS):
            names = [u.name for u in result.units if u.verdict == verdict]
            if names:
                lines.append(f"{verdict} {len(names)}: {_names(names)}")
        if worst.verdict != "PASS":
            lines.append(f"{sanitize(worst.name, 60)}:")
            lines += _unit_detail(worst, report_path)
    if used_external:
        lines.append(f"also checked with: {used_external}")
    return "\n".join(lines)
