"""Cisco AI Defense skill-scanner (package cisco-ai-skill-scanner), default static analyzers only.

Command: skill-scanner scan <path> --format json --compact
Mapping: max_severity CRITICAL or HIGH -> BLOCK, MEDIUM -> REVIEW, anything else -> PASS.
Set CISCO_SKILL_SCANNER_BIN to use an install outside PATH. Checked against skill-scanner 2.3.2.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from bench.adapters import AdapterResult

TIMEOUT = 180


def _binary() -> str | None:
    env = os.environ.get("CISCO_SKILL_SCANNER_BIN")
    if env and Path(env).exists():
        return env
    return shutil.which("skill-scanner")


def _run(cmd: list[str]) -> str:
    p = subprocess.run([*cmd], capture_output=True, text=True, encoding="utf-8", errors="replace",
                       env={**os.environ, "PYTHONUTF8": "1"}, timeout=TIMEOUT)
    return p.stdout


class CiscoAdapter:
    NAME = "cisco-skill-scanner"

    def available(self) -> bool:
        return _binary() is not None

    def version(self) -> str:
        binary = _binary()
        if not binary:
            return "not installed"
        try:
            return " ".join(_run([binary, "--version"]).split()) or "unknown"
        except (OSError, subprocess.SubprocessError):
            return "unknown"

    def scan(self, path: Path) -> AdapterResult:
        binary = _binary() or "skill-scanner"
        start = time.perf_counter()
        try:
            out = _run([binary, "scan", str(path), "--format", "json", "--compact"])
            data = json.loads(out[out.index("{"):])
            severity = str(data.get("max_severity", "NONE")).upper()
        except (OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
            return AdapterResult("PASS", time.perf_counter() - start, None, {"error": f"{type(exc).__name__}: {exc}"[:300]})
        verdict = "BLOCK" if severity in ("CRITICAL", "HIGH") else "REVIEW" if severity == "MEDIUM" else "PASS"
        rules = sorted({str(f.get("rule_id")) for f in data.get("findings", [])})
        return AdapterResult(verdict, time.perf_counter() - start, None, {"max_severity": severity, "rules": rules})


ADAPTER = CiscoAdapter()
