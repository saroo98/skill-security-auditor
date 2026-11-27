"""Adapters map each scanner's own output to PASS, REVIEW or BLOCK."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class AdapterResult:
    verdict: str
    seconds: float
    output_chars: int | None
    raw: dict = field(default_factory=dict)


class Adapter(Protocol):
    NAME: str

    def available(self) -> bool: ...

    def version(self) -> str: ...

    def scan(self, path: Path) -> AdapterResult: ...


NAMES = ("self", "skillspector", "cisco-skill-scanner")


def get(name: str) -> Adapter:
    if name == "self":
        from bench.adapters import self_ as module
    elif name == "skillspector":
        from bench.adapters import skillspector as module
    elif name == "cisco-skill-scanner":
        from bench.adapters import cisco as module
    else:
        raise KeyError(f"unknown scanner: {name}; known: {', '.join(NAMES)}")
    return module.ADAPTER
