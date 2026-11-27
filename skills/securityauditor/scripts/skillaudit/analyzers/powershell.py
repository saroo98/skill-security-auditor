"""PowerShell analyzer: line-level token checks."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..data import is_secret_path
from ..model import CapList, Capability, FileEntry
from . import shell

_EXECUTE = re.compile(r"\b(iex|invoke-expression)\b", re.IGNORECASE)
_DOWNLOAD = re.compile(r"\b(downloadstring|downloadfile|downloaddata|invoke-webrequest|iwr|invoke-restmethod|irm|"
                       r"net\.webclient|start-bitstransfer|curl|wget)\b", re.IGNORECASE)
_ENCODED = re.compile(r"\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{4,}", re.IGNORECASE)
_FROM_B64 = re.compile(r"frombase64string", re.IGNORECASE)
_DELETE = re.compile(r"\b(remove-item|rm|ri|del|rd|rmdir)\b(.*)", re.IGNORECASE)
_READ = re.compile(r"\b(get-content|gc|cat|type|copy-item|cp)\b(.*)", re.IGNORECASE)
_CRED = re.compile(r"\b(cmdkey|get-storedcredential|vaultcmd|convertfrom-securestring)\b", re.IGNORECASE)
_ENV_DUMP = re.compile(r"\b(get-childitem|gci|dir|ls)\s+env:\s*(\||$|>)|\[environment\]::getenvironmentvariables\(\)", re.IGNORECASE)
_PERSIST = re.compile(r"\b(register-scheduledtask|new-scheduledtask|schtasks\s+/create)\b|"
                      r"(add-content|set-content|out-file|>>?)\s*\$profile|currentversion\\run", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s'\"`<>()|;]+", re.IGNORECASE)
_TOKEN = re.compile(r"\"[^\"]*\"|'[^']*'|\S+")


def _args(rest: str) -> list[str]:
    return [t.strip("'\"") for t in _TOKEN.findall(rest)]


def analyze(entry: FileEntry) -> list[Capability]:
    caps: list[Capability] = CapList()

    def add(kind: str, number: int, line: str, **detail: str | None) -> None:
        cap = Capability(kind, entry.rel, number, line.strip()[:300], "high",
                         tuple(sorted((k, v) for k, v in detail.items() if v)))
        if cap not in caps:
            caps.append(cap)

    for number, line in enumerate((entry.text or "").splitlines(), start=1):
        code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
        if not code.strip():
            continue
        hosts = []
        for url in _URL.findall(code):
            try:
                hosts.append(urlparse(url).hostname)
            except ValueError:
                pass
        download = bool(_DOWNLOAD.search(code))
        if download:
            for h in hosts or [None]:
                add("net.outbound", number, line, host=h)
        if _EXECUTE.search(code) and download:
            add("exec.remote", number, line)
        elif _EXECUTE.search(code) and _FROM_B64.search(code):
            add("obfuscation", number, line, why="decoded content executed")
            add("exec.dynamic", number, line)
        elif _EXECUTE.search(code):
            add("exec.dynamic", number, line)
        if _ENCODED.search(" " + code) and re.search(r"\b(powershell|pwsh)\b", code, re.IGNORECASE):
            add("obfuscation", number, line, why="encoded command")
            add("exec.dynamic", number, line)
        m = _DELETE.search(code)
        if m and re.search(r"-recurse", m.group(2), re.IGNORECASE) and re.search(r"-force", m.group(2), re.IGNORECASE):
            targets = [a for a in _args(m.group(2)) if not a.startswith("-") and a not in ("|",)]
            if targets:
                worst = max((shell._delete_target(t) for t in targets), key=shell._RANK.__getitem__)
                add("fs.delete", number, line, target=worst)
        secret = False
        m = _READ.search(code)
        if m and any(is_secret_path(shell._norm_path(a)) for a in _args(m.group(2))):
            secret = True
        if _CRED.search(code):
            secret = True
        if secret:
            add("secret.read", number, line)
        dump = bool(_ENV_DUMP.search(code))
        if dump:
            add("env.dump", number, line)
        if _PERSIST.search(code):
            add("persist", number, line)
        if download and (secret or dump) and re.search(r"-(body|infile|data)\b|uploadstring|uploadfile|-method\s+post", code, re.IGNORECASE):
            for h in hosts or [None]:
                add("flow", number, line, source="secret.read" if secret else "env.dump", sink="net.outbound", host=h)
    return caps
