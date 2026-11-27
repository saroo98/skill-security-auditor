"""This project's own checks, run in-process."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from bench.adapters import AdapterResult
from bench.corpus import REPO_ROOT

SCRIPTS = REPO_ROOT / "skills" / "securityauditor" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from skillaudit import __version__  # noqa: E402
from skillaudit.checks import RULESET_VERSION  # noqa: E402
from skillaudit.engine import scan_path  # noqa: E402
from skillaudit.model import VERDICT_RANK  # noqa: E402
from skillaudit.output.brief import render_brief  # noqa: E402


class SelfAdapter:
    NAME = "self"

    def available(self) -> bool:
        return True

    def version(self) -> str:
        return f"{__version__} (ruleset {RULESET_VERSION})"

    def scan(self, path: Path) -> AdapterResult:
        start = time.perf_counter()
        result = scan_path(path)
        seconds = time.perf_counter() - start
        verdict = max((u.verdict for u in result.units), key=VERDICT_RANK.__getitem__, default="PASS")
        brief = render_brief(result)
        ids = sorted({f.check_id for u in result.units for f in u.findings})
        return AdapterResult(verdict, seconds, len(brief), {"checks": ids})


ADAPTER = SelfAdapter()
