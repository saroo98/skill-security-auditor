"""Adapters map each scanner's own output to PASS, REVIEW or BLOCK."""

from __future__ import annotations

import importlib
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


MODULES = {"self": "self_", "skillspector": "skillspector", "cisco-skill-scanner": "cisco"}


def get(name: str) -> Adapter:
    if name not in MODULES:
        raise KeyError(f"unknown scanner: {name}; known: {', '.join(sorted(MODULES))}")
    module = importlib.import_module(f"bench.adapters.{MODULES[name]}")
    return module.ADAPTER
