"""Full human-readable report."""

from __future__ import annotations

from ..model import ScanResult
from . import location, ordered, sanitize
from .brief import can_line, unprompted_line


def render_text(result: ScanResult) -> str:
    lines = ["Skill install guard report", f"Skills: {len(result.units)}", f"Tree: {result.tree_hash or '-'}"]
    for unit in result.units:
        lines += ["", f"== {sanitize(unit.name, 80)} ({sanitize(unit.root_rel, 120) or '.'}): {unit.verdict}, {unit.files} files"]
        lines.append(can_line(unit))
        extra = unprompted_line(unit)
        if extra:
            lines.append(extra)
        for f in ordered(unit.findings):
            lines += [
                f"- {f.severity.upper()} [{sanitize(f.check_id, 60)}] {location(f)}",
                f"  {sanitize(f.message, 300)}",
                f"  Evidence: {f.evidence}",
            ]
        if unit.suppressed:
            lines.append(f"Suppressed by your config or baseline ({len(unit.suppressed)}):")
            lines += [f"- [{sanitize(f.check_id, 60)}] {location(f)}: {sanitize(r, 200)}" for f, r in unit.suppressed]
        if unit.not_checked:
            lines.append("Not checked:")
            lines += [f"- {sanitize(n.rel, 160)} ({n.severity}): {sanitize(n.reason, 160)}" for n in unit.not_checked]
    for error in result.errors:
        lines.append(f"Error: {sanitize(error, 300)}")
    lines += ["", "A PASS means nothing was found by these checks. It is not proof that a skill is safe."]
    return "\n".join(lines)
