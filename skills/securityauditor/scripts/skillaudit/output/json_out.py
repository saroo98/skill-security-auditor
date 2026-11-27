"""Deterministic JSON report."""

from __future__ import annotations

import json
from dataclasses import asdict

from ..model import ScanResult
from . import ordered, sanitize

SCHEMA_VERSION = 1


def result_to_dict(result: ScanResult) -> dict:
    units = []
    for unit in result.units:
        units.append({
            "name": sanitize(unit.name, 200),
            "root": sanitize(unit.root_rel, 400),
            "files": unit.files,
            "verdict": unit.verdict,
            "capabilities": sorted(
                ({"kind": c.kind, "file": sanitize(c.file, 400), "line": c.line, "confidence": c.confidence,
                  "detail": {k: sanitize(v, 200) for k, v in c.detail}} for c in unit.capabilities),
                key=lambda c: (c["file"], c["line"] or 0, c["kind"], json.dumps(c["detail"], sort_keys=True)),
            ),
            "findings": [{**asdict(f), "file": sanitize(f.file, 400), "message": sanitize(f.message, 400)} for f in ordered(unit.findings)],
            "not_checked": sorted(
                ({"path": sanitize(n.rel, 400), "reason": sanitize(n.reason, 300), "severity": n.severity} for n in unit.not_checked),
                key=lambda n: (n["path"], n["reason"]),
            ),
        })
    return {"schema_version": SCHEMA_VERSION, "tree_hash": result.tree_hash, "units": units,
            "errors": [sanitize(e, 400) for e in result.errors]}


def result_from_dict(data: dict) -> ScanResult:
    """Rebuild a ScanResult from result_to_dict output (used by the verdict cache)."""
    from ..model import Capability, Finding, NotChecked, UnitResult

    units = []
    for u in data["units"]:
        units.append(UnitResult(
            name=u["name"], root_rel=u["root"], files=u["files"], verdict=u["verdict"],
            capabilities=[Capability(c["kind"], c["file"], c["line"], "", c["confidence"], tuple(sorted(c["detail"].items())))
                          for c in u["capabilities"]],
            findings=[Finding(**f) for f in u["findings"]],
            not_checked=[NotChecked(n["path"], n["reason"], n["severity"]) for n in u["not_checked"]],
        ))
    return ScanResult(units=units, elapsed=0.0, tree_hash=data["tree_hash"], errors=list(data.get("errors", [])))


def render_json(result: ScanResult) -> str:
    return json.dumps(result_to_dict(result), indent=2, sort_keys=True, ensure_ascii=False)
