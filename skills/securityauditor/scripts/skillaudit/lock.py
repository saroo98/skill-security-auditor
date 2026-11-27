"""Lockfile: record exactly what was approved, and report later changes in terms a reviewer cares about."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from .checks import RULESET_VERSION
from .engine import scan_path
from .model import VERDICT_RANK, Finding, ScanResult
from .policy import can_summary, unprompted_summary
from .sanitize import sanitize

SCHEMA = 2
_HOSTS = re.compile(r"\(([^)]*)\)$")


@dataclass
class Drift:
    name: str
    added_files: list[str] = field(default_factory=list)
    removed_files: list[str] = field(default_factory=list)
    changed_files: list[str] = field(default_factory=list)
    added_capabilities: list[str] = field(default_factory=list)
    removed_capabilities: list[str] = field(default_factory=list)
    new_hosts: list[str] = field(default_factory=list)
    new_unprompted: list[str] = field(default_factory=list)
    new_findings: list[Finding] = field(default_factory=list)
    missing: bool = False
    path: str | None = None


def file_hashes(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:
                digest = f"unreadable:{exc.errno}"
            out[path.relative_to(root).as_posix()] = digest
    return out


def _tree(hashes: dict[str, str]) -> str:
    return hashlib.sha256("".join(f"{k}\0{v}\n" for k, v in sorted(hashes.items())).encode("utf-8", "surrogatepass")).hexdigest()


def _summary(result: ScanResult) -> dict:
    caps = [c for u in result.units for c in u.capabilities]
    words, hosts = [], set()
    for item in can_summary(caps):
        m = _HOSTS.search(item)
        if m:
            hosts.update(h.strip() for h in m.group(1).split(",") if h.strip() and not h.strip().startswith("+"))
        words.append(_HOSTS.sub("", item).strip())
    for cap in caps:
        if cap.get("host"):
            hosts.add(cap.get("host"))
    verdict = max((u.verdict for u in result.units), key=VERDICT_RANK.__getitem__, default="PASS")
    return {
        "capabilities": sorted(set(words)),
        "hosts": sorted(hosts),
        "unprompted": sorted(set(unprompted_summary(caps))),
        "findings": sorted({f.fingerprint for u in result.units for f in u.findings}),
        "static_verdict": verdict,
        "name": result.units[0].name if result.units else "skill",
    }


def _read(lock_path: Path) -> dict:
    try:
        return json.loads(Path(lock_path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"schema": SCHEMA, "skills": {}}


def _path_key(path: Path) -> str:
    return Path(os.path.normcase(path.resolve())).as_posix()


@contextmanager
def _exclusive_update(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_name(f".{path.name}.lck").open("a+b") as guard:
        if os.name == "nt":
            import msvcrt

            guard.seek(0)
            msvcrt.locking(guard.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(guard.fileno(), fcntl.LOCK_EX)
        yield


def _write(lock_path: Path, data: dict) -> None:
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = lock_path.with_suffix(lock_path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, lock_path)


def pin(unit_dir: Path, lock_path: Path, *, source: str = "", commit: str | None = None,
        model_reviewed: bool = False) -> dict:
    unit_dir = Path(unit_dir).resolve()
    result = scan_path(unit_dir)
    hashes = file_hashes(unit_dir)
    summary = _summary(result)
    entry = {
        "name": summary["name"],
        "path": unit_dir.as_posix(),
        "source": source,
        "commit": commit,
        "tree_hash": _tree(hashes),
        "files": hashes,
        "capabilities": summary["capabilities"],
        "hosts": summary["hosts"],
        "unprompted": summary["unprompted"],
        "findings": summary["findings"],
        "static_verdict": summary["static_verdict"],
        "model_reviewed": bool(model_reviewed),
        "tool_version": __version__,
        "ruleset": RULESET_VERSION,
    }
    lock_path = Path(lock_path).resolve()
    with _exclusive_update(lock_path):
        data = _read(lock_path)
        skills = data.setdefault("skills", {})
        if data.get("schema", 1) == 1:
            skills = {_path_key(Path(old["path"])): {"name": name, **old} for name, old in skills.items()}
        skills[_path_key(unit_dir)] = entry
        data.update(schema=SCHEMA, skills=skills)
        _write(lock_path, data)
    return entry


def _compare(name: str, old: dict, new_hashes: dict[str, str], new_result: ScanResult | None) -> Drift:
    old_files = old.get("files", {})
    drift = Drift(
        name=name,
        added_files=sorted(set(new_hashes) - set(old_files)),
        removed_files=sorted(set(old_files) - set(new_hashes)),
        changed_files=sorted(k for k in set(old_files) & set(new_hashes) if old_files[k] != new_hashes[k]),
    )
    if new_result is not None:
        now = _summary(new_result)
        drift.added_capabilities = sorted(set(now["capabilities"]) - set(old.get("capabilities", [])))
        drift.removed_capabilities = sorted(set(old.get("capabilities", [])) - set(now["capabilities"]))
        drift.new_hosts = sorted(set(now["hosts"]) - set(old.get("hosts", [])))
        drift.new_unprompted = sorted(set(now["unprompted"]) - set(old.get("unprompted", [])))
        known = set(old.get("findings", []))
        drift.new_findings = [f for u in new_result.units for f in u.findings if f.fingerprint not in known]
    return drift


def verify(lock_path: Path, *, quiet: bool = False) -> list[Drift]:
    data = _read(lock_path)
    drifts: list[Drift] = []
    entries = [(entry.get("name", key), entry) for key, entry in sorted(data.get("skills", {}).items())]
    names = Counter(name for name, _ in entries)
    for name, entry in entries:
        path = Path(entry["path"])
        location = path.as_posix() if names[name] > 1 else None
        if not path.is_dir():
            drifts.append(Drift(name=name, missing=True, path=location))
            continue
        hashes = file_hashes(path)
        if _tree(hashes) == entry.get("tree_hash"):
            continue
        drift = _compare(name, entry, hashes, None if quiet else scan_path(path))
        drift.path = location
        drifts.append(drift)
    return drifts


def diff_dirs(old: Path, new: Path) -> Drift:
    old_result = scan_path(Path(old))
    summary = _summary(old_result)
    baseline = {"files": file_hashes(Path(old)), "capabilities": summary["capabilities"], "hosts": summary["hosts"],
                "unprompted": summary["unprompted"], "findings": summary["findings"]}
    return _compare(summary["name"], baseline, file_hashes(Path(new)), scan_path(Path(new)))


def describe(drift: Drift, *, quiet: bool = False) -> list[str]:
    name = sanitize(drift.name, 120)
    if drift.path:
        name += f" ({sanitize(drift.path, 160)})"
    if drift.missing:
        return [f"changed: {name}: the installed folder is missing"]
    n = len(drift.added_files) + len(drift.removed_files) + len(drift.changed_files)
    lines = [f"changed: {name}: {n} files differ from the approved version"]
    if quiet:
        return lines
    for label, items in (("added files", drift.added_files), ("removed files", drift.removed_files),
                         ("changed files", drift.changed_files), ("new capabilities", drift.added_capabilities),
                         ("removed capabilities", drift.removed_capabilities), ("new hosts", drift.new_hosts),
                         ("new runs-without-asking", drift.new_unprompted)):
        if items:
            shown = ", ".join(sanitize(i, 160) for i in items[:10])
            lines.append(f"  {label}: {shown}" + (f" (+{len(items) - 10})" if len(items) > 10 else ""))
    for f in drift.new_findings[:10]:
        lines.append(f"  new {f.severity} {sanitize(f.check_id, 60)} {sanitize(f.file, 160)}:{f.line or ''} {sanitize(f.message, 200)}")
    return lines
