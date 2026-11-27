"""Use NVIDIA SkillSpector alongside this tool's own checks when it is installed.

It runs with its model stage off. SkillSpector looks up dependency names in a vulnerability database
during a scan, so check always says when it was used, and --no-external turns it off.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

MAPPING = {"DO_NOT_INSTALL": "BLOCK", "CAUTION": "REVIEW", "SAFE": "PASS"}
SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info"}


@dataclass(frozen=True)
class ExternalResult:
    tool: str
    version: str
    verdict: str
    top: list[tuple[str, str, str, int | None, str]] = field(default_factory=list)  # (id, severity, file, line, pattern)


class ExternalFailed(Exception):
    pass


def _binary() -> str | None:
    env = os.environ.get("SKILLSPECTOR_BIN")
    if env and Path(env).exists():
        return env
    return shutil.which("skillspector")


def _run(cmd: list[str], timeout: float) -> str:
    p = subprocess.run([*cmd], capture_output=True, text=True, encoding="utf-8", errors="replace",
                       env={**os.environ, "PYTHONUTF8": "1"}, timeout=timeout)
    return p.stdout


def run_skillspector(path: Path, *, timeout: float = 120.0) -> ExternalResult | None:
    """None when SkillSpector is not installed; raises ExternalFailed when it is installed but fails."""
    binary = _binary()
    if binary is None:
        return None
    try:
        version = " ".join(_run([binary, "--version"], 30).split()) or "skillspector"
        out = _run([binary, "scan", str(path), "--no-llm", "--format", "json"], timeout)
        data = json.loads(out[out.index("{"):])
        verdict = MAPPING[data["risk_assessment"]["recommendation"]]
    except (OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        raise ExternalFailed(type(exc).__name__) from None
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    issues = []
    for issue in data.get("issues", []):
        loc = issue.get("location") or {}
        sev = SEVERITY.get(str(issue.get("severity", "")).upper(), "medium")
        issues.append((str(issue.get("id", "?")), sev, str(loc.get("file", "")), loc.get("start_line"), str(issue.get("pattern", ""))))
    issues.sort(key=lambda i: order[i[1]])
    return ExternalResult("skillspector", version, verdict, issues[:3])
