"""Scan a directory: discover files, group them into skill units, analyze, decide."""

from __future__ import annotations

import re
import time
from dataclasses import replace
from pathlib import Path

from typing import Callable

from . import graph, policy
from .checks import CHECKS
from .analyzers import configs, generic, hidden, javascript, markdown, powershell, python_ast, shell
from .discovery import _role, discover
from .model import CapList, Capability, FileEntry, NotChecked, ScanResult, UnitResult, make_finding, verdict_for
from .quarantine import tree_hash

REPOSITORY_UNIT = "(repository)"
SCAN_BUDGET_SECONDS = 60
IN_TREE_SUPPRESSION_FILES = {".skillaudit.toml", "skillaudit-baseline.json", ".skillauditignore"}
_IGNORE_MARK = re.compile(r"\b(skillaudit|skillspector)\s*:\s*(ignore|disable|skip)", re.IGNORECASE)
ANALYZERS: dict[str, Callable[[FileEntry], list[Capability]]] = {
    "shell": shell.analyze,
    "python": python_ast.analyze,
    "javascript": javascript.analyze,
    "powershell": powershell.analyze,
    "other-source": generic.analyze,
    "markdown": markdown.analyze,
    "json": configs.analyze,
    "yaml": configs.analyze,
    "toml": configs.analyze,
}
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


def analyze_entry(entry: FileEntry) -> list[Capability]:
    if entry.text is None:
        return []
    analyzer = ANALYZERS.get(entry.kind)
    caps = CapList(analyzer(entry) if analyzer else [])
    for cap in hidden.analyze(entry):
        if cap not in caps:
            caps.append(cap)
    name = entry.rel.rsplit("/", 1)[-1]
    if name in IN_TREE_SUPPRESSION_FILES:
        caps.append(Capability("suppression", entry.rel, None, f"suppression file {name} inside the scanned tree"))
    for number, line in enumerate(entry.text.splitlines(), start=1):
        if _IGNORE_MARK.search(line):
            caps.append(Capability("suppression", entry.rel, number, line.strip()))
    return caps


def config_problems(entry: FileEntry) -> list[NotChecked]:
    if entry.text is None:
        return []
    if entry.role == "config" and entry.kind in ("json", "yaml", "toml"):
        return [NotChecked(entry.rel, f"unparsed {entry.kind}: {p}", "medium") for p in configs.problems(entry)[:1]]
    if entry.rel.split("/")[-1] == "SKILL.md":
        _, problems = configs.parse_frontmatter(entry.text)
        return [NotChecked(entry.rel, f"unparsed frontmatter: {problems[0]}", "medium")] if problems else []
    return []


def resolve_unprompted(caps: list[Capability], analyzed: set[str]) -> list[Capability]:
    """Decide for each unprompted item whether the code it runs was analyzed in this scan."""
    out: list[Capability] = []
    for cap in caps:
        if cap.kind != "unprompted" or cap.get("analyzed"):
            out.append(cap)
            continue
        script = cap.get("script")
        if cap.get("remote_package") == "yes":
            value = "no"
        elif script:
            base = cap.file.rsplit("/", 1)[0] + "/" if "/" in cap.file else ""
            value = "yes" if any(r == script or r == base + script or r.endswith("/" + script) for r in analyzed) else "no"
        else:
            value = "yes"
        out.append(replace(cap, detail=tuple(sorted(dict(cap.detail, analyzed=value).items()))))
    return out


def scan_path(root: Path, *, max_file_size: int = 1_048_576, include_deps: bool = False) -> ScanResult:
    """include_deps scans dependency and VCS folders too; check uses it, since anything in a downloaded
    skill can be installed with it."""
    start = time.perf_counter()
    root = Path(root)
    files, not_checked = discover(root, max_file_size=max_file_size, include_deps=include_deps)
    result = scan_entries(files, not_checked, root_name=root.name or "skill")
    result.tree_hash = tree_hash(root) if root.is_dir() else ""
    result.elapsed = time.perf_counter() - start
    return result


def scan_files(contents: dict[str, bytes], root_name: str = "skill") -> ScanResult:
    """Scan files held in memory, keyed by relative path. Nothing is written to disk."""
    from .discovery import classify

    files: list[FileEntry] = []
    not_checked: list[NotChecked] = []
    for rel in sorted(contents):
        classify(None, rel, contents[rel], files, not_checked)
    return scan_entries(files, not_checked, root_name=root_name)


def scan_entries(files: list[FileEntry], not_checked: list[NotChecked], *, root_name: str = "skill") -> ScanResult:
    start = time.perf_counter()

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
        skill_md = None
        if key is None:
            name = REPOSITORY_UNIT
        else:
            skill_md = next((f for f in unit_files if f.rel == (f"{key}/SKILL.md" if key else "SKILL.md")), None)
            fallback = key.rsplit("/", 1)[-1] if key else root_name
            name = skill_name(skill_md.text if skill_md else None, fallback)
        capabilities: list[Capability] = []
        for entry in unit_files:
            if time.perf_counter() - start > SCAN_BUDGET_SECONDS:
                unit_nc.append(NotChecked(entry.rel, f"scan time budget of {SCAN_BUDGET_SECONDS}s reached", "medium"))
                continue
            capabilities.extend(analyze_entry(entry))
            unit_nc.extend(config_problems(entry))
        capabilities = resolve_unprompted(capabilities, {f.rel for f in files if f.kind in ANALYZERS and f.text is not None})
        all_rels = {f.rel for f in unit_files} | {n.rel for n in unit_nc}
        refs = graph.references(unit_files, all_rels)
        reach = graph.reachable(unit_files, refs)
        # CI workflows never run when a skill is installed, and docs or tests nothing points at are not used
        # roles are judged relative to the skill's own folder: a whole skill under examples/ is still a skill
        def unit_role(f: FileEntry) -> str:
            inner = f.rel[len(key) + 1:] if key else f.rel
            return _role(inner, f.kind) if key is not None else f.role

        low_roles = {f.rel for f in unit_files if (unit_role(f) in ("docs", "test") and f.rel not in reach)
                     or f.rel.startswith(".github/workflows/") or "/.github/workflows/" in f.rel}
        declared = None
        if key is not None and skill_md is not None:
            values, _ = configs.parse_frontmatter(skill_md.text or "")
            declared = graph.declared(skill_md.text or "", values)
        findings = []
        findings += policy.decide(capabilities, unit_nc, declared=declared, unreferenced_low_roles=low_roles)
        pointed_at = graph.referenced_from_instructions(unit_files, refs) | {
            t for f in unit_files if f.role == "executable" for t in refs.get(f.rel, ())}
        for item in unit_nc:
            if item.reason.startswith("binary") and item.rel in pointed_at:
                check = CHECKS["binary-referenced"]
                findings.append(make_finding(check.id, check.severity, item.rel, None, check.title, item.rel))
        skipped = [n.rel for n in unit_nc if n.reason == "dependency or VCS directory"]
        texts = [f.text or "" for f in unit_files if f.role in ("instruction", "executable", "config")]
        for i, item in enumerate(unit_nc):
            if item.rel in skipped and any(item.rel.rsplit("/", 1)[-1] + "/" in t for t in texts):
                unit_nc[i] = NotChecked(item.rel, "dependency or VCS directory that the skill refers to; not checked", "medium")
        for source, target in graph.missing_references(unit_files, refs, all_rels):
            if any(target.startswith(s.rsplit("/", 1)[-1] + "/") or ("/" + s.rsplit("/", 1)[-1] + "/") in target for s in skipped):
                continue
            check = CHECKS["missing-reference"]
            findings.append(make_finding(check.id, check.severity, source, None, check.title, target))
        severities = [f.severity for f in findings] + [n.severity for n in unit_nc]
        units.append(UnitResult(
            name=name,
            root_rel=key if key is not None else "",
            files=len(unit_files) + sum(1 for n in unit_nc if n.severity != "info"),
            capabilities=capabilities,
            findings=findings,
            not_checked=unit_nc,
            verdict=verdict_for(severities),
        ))
    return ScanResult(units=units, elapsed=time.perf_counter() - start, tree_hash="")
