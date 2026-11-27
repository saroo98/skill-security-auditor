"""SARIF 2.1.0 output for GitHub code scanning."""

from __future__ import annotations

import json

from .. import __version__
from ..checks import CHECKS
from ..model import ScanResult
from . import ordered, sanitize

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
DOCS = "https://github.com/saroo98/skill-security-auditor/blob/main/docs/checks/{}.md"


def render_sarif(result: ScanResult) -> str:
    rules = [{
        "id": c.id,
        "name": c.id,
        "shortDescription": {"text": c.title},
        "helpUri": DOCS.format(c.id),
        "defaultConfiguration": {"level": LEVEL[c.severity]},
        "properties": {"severity": c.severity, "tags": list(c.ast10)},
    } for c in CHECKS.values()]
    results = []
    for unit in result.units:
        for f in ordered(unit.findings):
            location = {"physicalLocation": {"artifactLocation": {"uri": sanitize(f.file, 400)}}}
            if f.line:
                location["physicalLocation"]["region"] = {"startLine": f.line}
            results.append({
                "ruleId": f.check_id,
                "level": LEVEL[f.severity],
                "message": {"text": f"{sanitize(f.message, 300)}: {f.evidence}"},
                "locations": [location],
                "partialFingerprints": {"skillaudit": f.fingerprint},
                "properties": {"severity": f.severity, "skill": sanitize(unit.name, 200)},
            })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "skill-security-auditor", "version": __version__, "rules": rules}},
                  "results": results}],
    }
    return json.dumps(sarif, indent=2, sort_keys=True)
