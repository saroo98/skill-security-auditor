"""JavaScript and TypeScript analyzer: a lexer that removes comments and isolates string literals,
then pattern checks on the remaining code. Medium confidence at most; there is no parser."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..data import is_secret_name, is_secret_path
from ..model import Capability, FileEntry
from . import shell

CONF = "medium"
_PH = re.compile(r"__S(\d+)__")


def lex(src: str) -> tuple[str, list[str]]:
    """Return code with comments removed and each string literal replaced by "__S<n>__"; newlines are kept."""
    out: list[str] = []
    strings: list[str] = []
    i, n = 0, len(src)
    prev_sig = ""
    while i < n:
        c = src[i]
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j == -1 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            chunk = src[i: n if j == -1 else j + 2]
            out.append("\n" * chunk.count("\n"))
            i = n if j == -1 else j + 2
            continue
        if c in "\"'`":
            j = i + 1
            buf: list[str] = []
            while j < n and src[j] != c:
                if src[j] == "\\" and j + 1 < n:
                    buf.append(src[j + 1])
                    j += 2
                    continue
                if c != "`" and src[j] == "\n":
                    break
                buf.append(src[j])
                j += 1
            value = "".join(buf)
            strings.append(value)
            out.append(f'"__S{len(strings) - 1}__"' + "\n" * value.count("\n"))
            i = j + 1
            prev_sig = '"'
            continue
        if c == "/" and prev_sig and prev_sig in "(,=:[!&|?{};" :
            j = i + 1
            while j < n and src[j] not in "/\n":
                j += 2 if src[j] == "\\" else 1
            if j < n and src[j] == "/":
                out.append("/__RE__/")
                i = j + 1
                prev_sig = '"'
                continue
        out.append(c)
        if not c.isspace():
            prev_sig = c
        i += 1
    return "".join(out), strings


def _close(code: str, start: int) -> int:
    depth = 0
    for j in range(start, len(code)):
        if code[j] in "([{":
            depth += 1
        elif code[j] in ")]}":
            depth -= 1
            if depth == 0:
                return j
    return len(code)


class _JS:
    NET = re.compile(r"\bfetch\s*\(|\bhttps?\.(?:request|get)\s*\(|\baxios(?:\.\w+)?\s*\(|\bgot(?:\.\w+)?\s*\(|"
                     r"new\s+XMLHttpRequest\b|new\s+WebSocket\s*\(|\bnavigator\.sendBeacon\s*\(|\bundici\.request\s*\(")
    EXEC = re.compile(r"\b(?:\w+\.)?(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)\s*\(")
    DYN = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runIn\w+|Script)\b|\bFunction\s*\(\s*\"__S")
    ENV_DUMP = re.compile(r"JSON\.stringify\(\s*process\.env\s*[,)]|Object\.(?:entries|keys|values|assign)\([^)]*process\.env\b|"
                          r"\.\.\.\s*process\.env\b|=\s*process\.env\s*[;\n]")
    ENV_KEY = re.compile(r"process\.env\.([A-Za-z_][A-Za-z0-9_]*)|process\.env\[\s*\"__S(\d+)__\"\s*\]")
    READ = re.compile(r"\b(?:fs\.)?(?:readFileSync|readFile|createReadStream|promises\.readFile)\s*\(")
    ASSIGN = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)")

    def __init__(self, entry: FileEntry) -> None:
        self.rel = entry.rel
        self.code, self.strings = lex(entry.text or "")
        self.caps: list[Capability] = []
        self.lines = (entry.text or "").splitlines()

    def line_of(self, pos: int) -> int:
        return self.code.count("\n", 0, pos) + 1

    def add(self, kind: str, pos: int, **detail: str | None) -> None:
        line = self.line_of(pos)
        snippet = self.lines[line - 1].strip()[:300] if line <= len(self.lines) else ""
        cap = Capability(kind, self.rel, line, snippet, CONF, tuple(sorted((k, v) for k, v in detail.items() if v)))
        if cap not in self.caps:
            self.caps.append(cap)

    def strs(self, text: str) -> list[str]:
        return [self.strings[int(m)] for m in _PH.findall(text)]

    def url_host(self, text: str) -> str | None:
        for s in self.strs(text):
            if s.lower().startswith(("http://", "https://", "ws://", "wss://")):
                try:
                    return urlparse(s).hostname
                except ValueError:
                    return None
        return None

    def sources(self, text: str, taint: dict[str, tuple[str, str | None]]) -> list[tuple[str, str | None]]:
        found: list[tuple[str, str | None]] = []
        if self.ENV_DUMP.search(text) or re.search(r"\bprocess\.env\b(?!\s*[.\[])", text):
            found.append(("env.dump", None))
        for m in self.ENV_KEY.finditer(text):
            key = m.group(1) or self.strings[int(m.group(2))]
            if is_secret_name(key):
                found.append(("secret.use", key))
        for m in self.READ.finditer(text):
            if self.secret_arg(text[m.end() - 1:_close(text, m.end() - 1) + 1]):
                found.append(("secret.read", None))
        for name, src in taint.items():
            if re.search(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", text):
                found.append(src)
        return found

    def secret_arg(self, args: str) -> bool:
        joined = "".join(self.strs(args))
        if re.search(r"homedir\(\)|process\.env\.HOME|process\.env\.USERPROFILE", args):
            joined = "~/" + joined.lstrip("/")
        return is_secret_path(joined.replace("\\", "/")) or any(is_secret_path(s.replace("\\", "/")) for s in self.strs(args))

    def run(self) -> list[Capability]:
        code = self.code
        cp_imported = any(s in ("child_process", "node:child_process") for s in self.strings) and re.search(
            r"require\s*\(|\bfrom\s+\"__S|import\s*\(", code)
        taint: dict[str, tuple[str, str | None]] = {}
        for m in self.ASSIGN.finditer(code):
            srcs = self.sources(m.group(2), taint)
            if srcs:
                taint[m.group(1)] = srcs[0]
        if cp_imported:
            for m in self.EXEC.finditer(code):
                start = m.end() - 1
                args = code[start + 1:_close(code, start)]
                first = re.match(r"\s*\"__S(\d+)__\"", args)
                self.add("exec.shell", m.start(), constant="yes" if first else "no")
                if first:
                    for cap in shell.analyze_command(self.strings[int(first.group(1))], self.rel, self.line_of(m.start()), CONF):
                        if cap not in self.caps:
                            self.caps.append(cap)
        for m in self.DYN.finditer(code):
            self.add("exec.dynamic", m.start())
        for m in self.ENV_DUMP.finditer(code):
            self.add("env.dump", m.start())
        for m in self.ENV_KEY.finditer(code):
            key = m.group(1) or self.strings[int(m.group(2))]
            self.add("secret.use" if is_secret_name(key) else "env.read", m.start())
        for m in self.READ.finditer(code):
            if self.secret_arg(code[m.end() - 1:_close(code, m.end() - 1) + 1]):
                self.add("secret.read", m.start())
        for m in self.NET.finditer(code):
            start = code.find("(", m.start())
            args = code[start:_close(code, start) + 1] if start != -1 else ""
            host = self.url_host(args) or self.url_host(code[m.start():code.find("\n", m.start())])
            self.add("net.outbound", m.start(), host=host)
            seen = set()
            for src, secret in self.sources(args, taint):
                if (src, secret) in seen:
                    continue
                seen.add((src, secret))
                self.add("flow", m.start(), source=src, sink="net.outbound", host=host,
                         secret=secret if src == "secret.use" else None)
        return self.caps


def analyze(entry: FileEntry) -> list[Capability]:
    return _JS(entry).run()
