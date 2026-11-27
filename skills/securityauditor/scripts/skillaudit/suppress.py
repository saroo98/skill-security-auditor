"""Suppressions supplied by the person running the scan. Nothing inside a scanned tree can suppress."""

from __future__ import annotations

import fnmatch
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .model import Finding, ScanResult


@dataclass
class Suppressions:
    rules: list[tuple[str, str, str]] = field(default_factory=list)  # (check id, path glob, reason)
    fingerprints: dict[str, str] = field(default_factory=dict)  # fingerprint -> reason

    def reason_for(self, finding: Finding) -> str | None:
        if finding.fingerprint in self.fingerprints:
            return self.fingerprints[finding.fingerprint]
        for check, pattern, reason in self.rules:
            if check in (finding.check_id, "*") and fnmatch.fnmatch(finding.file, pattern):
                return reason
        return None


def load(config: Path | None, baseline: Path | None) -> Suppressions:
    s = Suppressions()
    if config is not None:
        with open(config, "rb") as fh:
            data = tomllib.load(fh)
        for entry in data.get("suppress", []):
            reason = str(entry.get("reason", "")).strip()
            if not reason or not entry.get("check") or not entry.get("path"):
                raise ValueError(f"{config}: every [[suppress]] needs check, path and a written reason")
            s.rules.append((str(entry["check"]), str(entry["path"]), reason))
    if baseline is not None:
        data = json.loads(Path(baseline).read_text(encoding="utf-8"))
        for fingerprint, reason in data.get("fingerprints", {}).items():
            if not str(reason).strip():
                raise ValueError(f"{baseline}: fill in a reason for every fingerprint before using the baseline")
            s.fingerprints[fingerprint] = str(reason).strip()
    return s


def apply(findings: list[Finding], s: Suppressions) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    kept: list[Finding] = []
    suppressed: list[tuple[Finding, str]] = []
    for f in findings:
        reason = s.reason_for(f)
        if reason is None or f.check_id == "suppression-in-tree":
            kept.append(f)
        else:
            suppressed.append((f, reason))
    return kept, suppressed


def write_baseline(result: ScanResult, path: Path) -> None:
    fps = {f.fingerprint: "" for u in result.units for f in u.findings if f.severity not in ("info", "low")}
    Path(path).write_text(json.dumps({"fingerprints": dict(sorted(fps.items()))}, indent=2) + "\n", encoding="utf-8")
