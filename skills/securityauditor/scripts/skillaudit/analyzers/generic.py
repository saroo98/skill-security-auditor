"""Token-level checks for source in a language with no dedicated analyzer. Low confidence by design."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..data import is_secret_path
from ..model import CapList, Capability, FileEntry
from . import shell

_URL = re.compile(r"https?://[^\s'\"`<>()]+", re.IGNORECASE)
_STRING = re.compile(r"\"((?:[^\"\\\n]|\\.)*)\"|'((?:[^'\\\n]|\\.)*)'")
_EXEC = re.compile(r"\b(system|exec|popen|shell_exec|passthru|proc_open|spawn|Runtime\.getRuntime\(\)\.exec|exec\.Command|"
                   r"Process\.Start|ShellExecute|os\.execute|io\.popen|IO\.popen|Open3\.\w+)\s*\(", re.IGNORECASE)


def _home(p: str) -> str:
    return re.sub(r"^(\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE)", "~", p.replace("\\", "/"), flags=re.IGNORECASE)


def scan_text(text: str, rel: str, confidence: str = "low") -> list[Capability]:
    caps: list[Capability] = CapList()

    def add(kind: str, line: int, snippet: str, **detail: str | None) -> None:
        cap = Capability(kind, rel, line, snippet.strip()[:300], confidence, tuple(sorted((k, v) for k, v in detail.items() if v)))
        if cap not in caps:
            caps.append(cap)

    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "--", ";", "*", "/*")) and not stripped.startswith("#!"):
            continue
        for url in _URL.findall(line):
            try:
                host = urlparse(url).hostname
            except ValueError:
                host = None
            add("net.outbound", number, line, host=host)
        strings = [a or b for a, b in _STRING.findall(line)]
        for s in strings:
            if is_secret_path(_home(s)):
                add("secret.read", number, line)
        match = _EXEC.search(line)
        if match:
            add("exec.shell", number, line, constant="yes" if strings else "no")
            rest = line[match.end():]
            first = _STRING.match(rest.lstrip())
            if first:
                for cap in shell.analyze_command(first.group(1) or first.group(2), rel, number, confidence):
                    if cap not in caps:
                        caps.append(cap)
    return caps


def analyze(entry: FileEntry) -> list[Capability]:
    return scan_text(entry.text or "", entry.rel)
