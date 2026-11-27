"""Core data types shared by every part of skillaudit."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .sanitize import escape_invisible, sanitize

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}
VERDICTS: tuple[str, ...] = ("PASS", "REVIEW", "BLOCK")
VERDICT_RANK: dict[str, int] = {v: i for i, v in enumerate(VERDICTS)}
_SNIPPET_LIMIT = 300


def _normalize_evidence(evidence: str) -> str:
    return " ".join(escape_invisible(evidence).split())


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


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
    evidence_digest: str | None = None

    def __post_init__(self) -> None:
        if len(self.snippet) <= _SNIPPET_LIMIT:
            return
        normalized = _normalize_evidence(self.snippet)
        if len(normalized) > _SNIPPET_LIMIT:
            object.__setattr__(self, "evidence_digest", _hash_text(normalized))
        object.__setattr__(self, "snippet", normalized[:_SNIPPET_LIMIT])

    def get(self, key: str, default: str | None = None) -> str | None:
        return dict(self.detail).get(key, default)


class CapList(list):
    """A list of capabilities with constant-time membership tests (analyzers deduplicate often)."""

    def __init__(self, items=()) -> None:
        super().__init__()
        self._seen: set = set()
        for item in items:
            self.append(item)

    def append(self, item) -> None:  # type: ignore[override]
        self._seen.add(item)
        super().append(item)

    def extend(self, items) -> None:  # type: ignore[override]
        for item in items:
            self.append(item)

    def __contains__(self, item) -> bool:
        return item in self._seen


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


def fingerprint(check_id: str, file: str, evidence: str, *, evidence_digest: str | None = None) -> str:
    if evidence_digest is None:
        normalized = _normalize_evidence(evidence)
        if len(normalized) > _SNIPPET_LIMIT:
            evidence_digest = _hash_text(normalized)
    if evidence_digest is not None:
        normalized = "\0sha256:" + evidence_digest
    return _hash_text(f"{check_id}\0{file}\0{normalized}")[:16]


def make_finding(check_id: str, severity: str, file: str, line: int | None, message: str, evidence: str,
                 *, evidence_digest: str | None = None) -> Finding:
    if severity not in SEVERITY_RANK:
        raise ValueError(f"unknown severity: {severity}")
    clean = sanitize(evidence)
    return Finding(check_id, severity, file, line, message, clean,
                   fingerprint(check_id, file, evidence, evidence_digest=evidence_digest))
