"""NVIDIA SkillSpector, run with its model stage off.

Command: skillspector scan <path> --no-llm --format json
Mapping: DO_NOT_INSTALL -> BLOCK, CAUTION -> REVIEW, SAFE -> PASS.
Set SKILLSPECTOR_BIN to use an install outside PATH.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from bench.adapters import AdapterResult

MAPPING = {"DO_NOT_INSTALL": "BLOCK", "CAUTION": "REVIEW", "SAFE": "PASS"}
TIMEOUT = 180


def _binary() -> str | None:
    env = os.environ.get("SKILLSPECTOR_BIN")
    if env and Path(env).exists():
        return env
    return shutil.which("skillspector")


def _env() -> dict:
    return {**os.environ, "PYTHONUTF8": "1"}


def parse(stdout: str) -> dict:
    start = stdout.find("{")
    if start == -1:
        raise ValueError("no JSON object in output")
    return json.loads(stdout[start:])


class SkillSpectorAdapter:
    NAME = "skillspector"

    def available(self) -> bool:
        return _binary() is not None

    def version(self) -> str:
        binary = _binary()
        if not binary:
            return "not installed"
        try:
            p = subprocess.run([binary, "--version"], capture_output=True, text=True, encoding="utf-8",
                               errors="replace", env=_env(), timeout=60)
            return " ".join(p.stdout.split()) or "unknown"
        except (OSError, subprocess.SubprocessError):
            return "unknown"

    def scan(self, path: Path) -> AdapterResult:
        binary = _binary() or "skillspector"
        start = time.perf_counter()
        try:
            p = subprocess.run([binary, "scan", str(path), "--no-llm", "--format", "json"], capture_output=True,
                               text=True, encoding="utf-8", errors="replace", env=_env(), timeout=TIMEOUT)
            data = parse(p.stdout)
            rec = data["risk_assessment"]["recommendation"]
            verdict = MAPPING[rec]
            ids = sorted({str(i.get("id")) for i in data.get("issues", [])})
            raw = {"recommendation": rec, "score": data["risk_assessment"].get("score"), "issues": ids}
        except (OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
            return AdapterResult("PASS", time.perf_counter() - start, None, {"error": f"{type(exc).__name__}: {exc}"[:300]})
        return AdapterResult(verdict, time.perf_counter() - start, None, raw)


ADAPTER = SkillSpectorAdapter()
