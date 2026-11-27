"""Does a source name imitate a well-known skill repository under a different owner?"""

from __future__ import annotations

from pathlib import Path

KNOWN_FILE = Path(__file__).resolve().parents[2] / "references" / "known-sources.txt"
MIN_LENGTH = 8


def known_sources() -> list[str]:
    try:
        lines = KNOWN_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def _distance_at_most_one(a: str, b: str) -> bool:
    if a == b:
        return True
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(short) and short[i] == long_[i]:
        i += 1
    return short[i:] == long_[i + 1:]


def lookalike(owner_repo: str | None, known: list[str] | None = None) -> str | None:
    if not owner_repo or "/" not in owner_repo:
        return None
    known = known_sources() if known is None else known
    owner, repo = (p.lower() for p in owner_repo.split("/", 1))
    for entry in known:
        if "/" not in entry:
            continue
        k_owner, k_repo = (p.lower() for p in entry.split("/", 1))
        if owner == k_owner or len(k_repo) < MIN_LENGTH:
            continue
        if _distance_at_most_one(repo, k_repo):
            return entry
    return None
