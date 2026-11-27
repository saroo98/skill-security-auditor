"""Core data types shared by every part of skillaudit."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .sanitize import sanitize

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}
VERDICTS: tuple[str, ...] = ("PASS", "REVIEW", "BLOCK")
VERDICT_RANK: dict[str, int] = {v: i for i, v in enumerate(VERDICTS)}


def verdict_for(severities: Iterable[str]) -> str:
    worst = max((SEVERITY_RANK[s] for s in severities), default=-1)
    if worst >= SEVERITY_RANK["high"]:
        return "BLOCK"
    if worst >= SEVERITY_RANK["medium"]:
        return "REVIEW"
    return "PASS"


def stricter(a: str, b: str) -> str:
    return a if VERDICT_RANK[a] >= VERDICT_RANK[b] else b


@dataclass(frozen=True)
class FileEntry:
    path: Path
    rel: str
    kind: str
    role: str
    text: str | None
    encoding: str | None
    size: int


@dataclass(frozen=True)
class NotChecked:
    rel: str
    reason: str
    severity: str


@dataclass(frozen=True)
class Capability:
    kind: str
    file: str
    line: int | None
    snippet: str
    confidence: str = "high"
    detail: tuple[tuple[str, str], ...] = ()

    def get(self, key: str, default: str | None = None) -> str | None:
        return dict(self.detail).get(key, default)


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: str
    file: str
    line: int | None
    message: str
    evidence: str
    fingerprint: str


@dataclass
class UnitResult:
    name: str
    root_rel: str
    files: int
    capabilities: list[Capability]
    findings: list[Finding]
    not_checked: list[NotChecked]
    verdict: str
    suppressed: list[tuple[Finding, str]] = field(default_factory=list)


@dataclass
class ScanResult:
    units: list[UnitResult]
    elapsed: float
    tree_hash: str
    errors: list[str] = field(default_factory=list)


def fingerprint(check_id: str, file: str, evidence: str) -> str:
    normalized = " ".join(evidence.split())
    digest = hashlib.sha256(f"{check_id}\0{file}\0{normalized}".encode("utf-8", "surrogatepass"))
    return digest.hexdigest()[:16]


def make_finding(check_id: str, severity: str, file: str, line: int | None, message: str, evidence: str) -> Finding:
    if severity not in SEVERITY_RANK:
        raise ValueError(f"unknown severity: {severity}")
    clean = sanitize(evidence)
    return Finding(check_id, severity, file, line, message, clean, fingerprint(check_id, file, clean))
