"""Scan a directory: discover files, group them into skill units, analyze, decide."""

from __future__ import annotations

import re
import time
from pathlib import Path

from .analyzers import legacy
from .discovery import discover
from .model import FileEntry, NotChecked, ScanResult, UnitResult, verdict_for

REPOSITORY_UNIT = "(repository)"
_NAME = re.compile(r"^name:\s*['\"]?([^'\"\n]+?)['\"]?\s*$", re.MULTILINE)


def skill_name(text: str | None, fallback: str) -> str:
    if text and text.startswith("---"):
        end = text.find("\n---", 3)
        if end != -1:
            match = _NAME.search(text[3:end])
            if match and match.group(1).strip():
                return match.group(1).strip()
    return fallback


def _unit_of(rel: str, unit_roots: list[str]) -> str | None:
    for root in unit_roots:  # longest first
        if root == "" or rel == root or rel.startswith(root + "/"):
            return root
    return None


def scan_path(root: Path, *, max_file_size: int = 1_048_576) -> ScanResult:
    start = time.perf_counter()
    root = Path(root)
    files, not_checked = discover(root, max_file_size=max_file_size)

    unit_roots = sorted(
        {f.rel.rsplit("/", 1)[0] if "/" in f.rel else "" for f in files if f.rel.split("/")[-1] == "SKILL.md"},
        key=len,
        reverse=True,
    )
    grouped_files: dict[str | None, list[FileEntry]] = {}
    for entry in files:
        grouped_files.setdefault(_unit_of(entry.rel, unit_roots), []).append(entry)
    grouped_nc: dict[str | None, list[NotChecked]] = {}
    for item in not_checked:
        grouped_nc.setdefault(_unit_of(item.rel, unit_roots), []).append(item)

    units: list[UnitResult] = []
    keys: list[str | None] = sorted(unit_roots)
    if None in grouped_files or None in grouped_nc:
        keys.append(None)
    for key in keys:
        unit_files = grouped_files.get(key, [])
        unit_nc = grouped_nc.get(key, [])
        if key is None:
            name = REPOSITORY_UNIT
        else:
            skill_md = next((f for f in unit_files if f.rel == (f"{key}/SKILL.md" if key else "SKILL.md")), None)
            fallback = key.rsplit("/", 1)[-1] if key else (root.name or "skill")
            name = skill_name(skill_md.text if skill_md else None, fallback)
        findings = [f for entry in unit_files for f in legacy.findings(entry)]
        severities = [f.severity for f in findings] + [n.severity for n in unit_nc]
        units.append(UnitResult(
            name=name,
            root_rel=key if key is not None else "",
            files=len(unit_files) + sum(1 for n in unit_nc if n.severity != "info"),
            capabilities=[],
            findings=findings,
            not_checked=unit_nc,
            verdict=verdict_for(severities),
        ))
    return ScanResult(units=units, elapsed=time.perf_counter() - start, tree_hash="")
