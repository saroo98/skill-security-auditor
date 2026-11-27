"""Hidden content in any text file: tag characters, zero-width runs, bidi overrides, lookalike
hosts, and long encoded blobs that decode to text."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import replace
import unicodedata
from urllib.parse import urlparse

from ..model import CapList, Capability, FileEntry

ZERO_WIDTH = {0x200B, 0x2060, 0xFEFF, 0x200D}
BIDI_OVERRIDES = {0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
BIDI_EMBED = {0x202A, 0x202B, 0x202C}
CODE_KINDS = {"python", "shell", "powershell", "javascript", "other-source", "json", "yaml", "toml"}
_B64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){200,}(?![0-9A-Fa-f])")
_URL = re.compile(r"https?://[^\s'\"`<>()]+", re.IGNORECASE)


def _is_pictographic(ch: str) -> bool:
    if not ch:
        return False
    code = ord(ch)
    return unicodedata.category(ch) == "So" or 0x1F000 <= code <= 0x1FAFF or 0xFE00 <= code <= 0xFE0F or 0x1F3FB <= code <= 0x1F3FF


def _scripts(text: str) -> set[str]:
    found = set()
    for ch in text:
        if not ch.isalpha():
            continue
        name = unicodedata.name(ch, "")
        if name.startswith("LATIN"):
            found.add("latin")
        elif name.startswith("CYRILLIC"):
            found.add("cyrillic")
        elif name.startswith("GREEK"):
            found.add("greek")
    return found


def _decoded_text(blob: str, kind: str) -> str | None:
    try:
        data = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False) if kind == "b64" else binascii.unhexlify(blob)
    except (binascii.Error, ValueError):
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t\r")
    return text if text and printable / len(text) >= 0.9 else None


def analyze(entry: FileEntry, depth: int = 0) -> list[Capability]:
    text = entry.text or ""
    caps: list[Capability] = CapList()

    def add(kind: str, line: int | None, snippet: str, confidence: str = "high", **detail: str) -> None:
        cap = Capability(kind, entry.rel, line, snippet, confidence, tuple(sorted(detail.items())))
        if cap not in caps:
            caps.append(cap)

    for number, line in enumerate(text.split("\n"), start=1):
        tags = [c for c in line if 0xE0000 <= ord(c) <= 0xE007F]
        if tags:
            decoded = "".join(chr(ord(c) - 0xE0000) for c in tags if 0x20 <= ord(c) - 0xE0000 < 0x7F)
            add("instruction.hidden", number, f"decoded tag characters: {decoded}", why="unicode tag characters")
        count = 0
        for i, ch in enumerate(line):
            code = ord(ch)
            if code not in ZERO_WIDTH:
                continue
            if code == 0xFEFF and number == 1 and i == 0:
                continue
            if code == 0x200D and (_is_pictographic(line[i - 1] if i else "") or _is_pictographic(line[i + 1] if i + 1 < len(line) else "")):
                continue
            count += 1
        if count >= 3:
            add("instruction.hidden", number, f"{count} zero-width characters in one line", why="zero-width characters")
        overrides = [c for c in line if ord(c) in BIDI_OVERRIDES or (entry.kind in CODE_KINDS and ord(c) in BIDI_EMBED)]
        if overrides:
            add("obfuscation", number, "bidirectional control characters change how the line displays", why="bidi controls")
        for url in _URL.findall(line):
            try:
                host = urlparse(url).hostname or ""
            except ValueError:
                continue
            if len(_scripts(host)) > 1:
                add("obfuscation", number, f"host mixes alphabets: {host}", why="lookalike host")

    if depth < 2:
        for pattern, kind in ((_B64, "b64"), (_HEX, "hex")):
            for m in pattern.finditer(text):
                decoded = _decoded_text(m.group(0), kind)
                if decoded is None:
                    continue
                line = text.count("\n", 0, m.start()) + 1
                inner = _inner_caps(entry, decoded, line, depth)
                if inner:
                    add("obfuscation", line, f"encoded text decodes to: {decoded}", why="encoded payload")
                    for cap in inner:
                        if cap not in caps:
                            caps.append(cap)
    return caps


def _inner_caps(entry: FileEntry, decoded: str, line: int, depth: int) -> list[Capability]:
    from . import markdown, shell

    out: list[Capability] = []
    for cap in shell.analyze_command(decoded, entry.rel, line):
        out.append(cap)
    sub = FileEntry(entry.path, entry.rel, "markdown", entry.role, decoded, entry.encoding, len(decoded))
    for cap in markdown.prose_caps(sub, decoded, line):
        out.append(cap)
    for cap in analyze(sub, depth + 1):
        out.append(replace(cap, line=line))
    return out
