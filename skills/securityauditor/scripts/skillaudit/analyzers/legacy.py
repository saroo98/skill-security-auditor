"""The v0.1.0 line rules, kept only until the capability analyzers replace them."""

from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlparse

from ..model import FileEntry, Finding, make_finding

# (check_id, severity, pattern, message)
RULES: tuple[tuple[str, str, str, str], ...] = (
    ("prompt-ignore-instructions", "high",
     r"\bignore\b.{0,80}\b(previous|prior|system|developer|user|higher[- ]priority)\b.{0,40}\binstructions?\b"
     r"|\bdisregard\b.{0,80}\b(system|developer|user|previous|prior)\b.{0,40}\binstructions?\b",
     "Instruction text tells an agent to ignore higher-priority instructions."),
    ("prompt-hide-behavior", "high",
     r"\bdo not disclose\b|\bhide (this|the) behavior\b|\bkeep (this|the) behavior secret\b|\bdo not tell (the )?user\b",
     "Instruction text hides behavior from the user."),
    ("prompt-exfiltrate-secrets", "critical",
     r"\bexfiltrat(e|es|ing)\b.{0,80}\b(secrets?|credentials?|tokens?|keys?)\b"
     r"|\bsend\b.{0,80}\b(secrets?|credentials?|tokens?|keys?)\b|\bupload\b.{0,80}\b(secrets?|credentials?|tokens?|keys?)\b",
     "Instruction text requests secret or credential disclosure."),
    ("prompt-disable-safety", "high",
     r"\b(disable|bypass)\b.{0,50}\b(safety|guardrails?|sandbox|policy|permissions?)\b",
     "Instruction text weakens safety or permission controls."),
    ("shell-curl-pipe", "high", r"\bcurl\b[^\n|]*\|[ \t]*(sh|bash|zsh)\b", "Downloads content and pipes it into a shell."),
    ("shell-wget-pipe", "high", r"\bwget\b[^\n|]*\|[ \t]*(sh|bash|zsh)\b", "Downloads content and pipes it into a shell."),
    ("shell-powershell-download-exec", "high",
     r"\b(iex|invoke-expression)\b.*\b(downloadstring|downloadfile|iwr|irm|invoke-webrequest|invoke-restmethod)\b"
     r"|\b(downloadstring|downloadfile|iwr|irm|invoke-webrequest|invoke-restmethod)\b.*\b(iex|invoke-expression)\b",
     "PowerShell downloads and executes remote content."),
    ("shell-base64-exec", "high",
     r"\bbase64\b[^\n|]*(--decode|-d)[^\n|]*\|[ \t]*(sh|bash|zsh|python|perl|ruby|powershell)\b",
     "Decodes base64 content and executes it."),
    ("python-subprocess-shell-true", "high",
     r"\bsubprocess\.(run|call|Popen|check_output|check_call)\([^)\n]*shell[ \t]*=[ \t]*True",
     "Python subprocess call enables shell=True."),
    ("runtime-package-install", "medium",
     r"\b((python|python3|py)[ \t]+-m[ \t]+pip|pip|pip3|npm|pnpm|yarn)[ \t]+(install|add)\b",
     "Command installs packages at run time."),
    ("file-rm-rf", "high",
     r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\b|\bRemove-Item\b[^\n]*\b-Recurse\b[^\n]*\b-Force\b",
     "Recursive forced delete."),
    ("file-recursive-delete-root-or-home", "critical",
     r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+(/|~|\$HOME|%USERPROFILE%|[A-Za-z]:\\)|\bshutil\.rmtree\([\"'](/|~|[A-Za-z]:\\)",
     "Recursive delete targets root, home, or a drive."),
    ("credential-dotenv-read", "high", r"\b(open|read_text|cat|type|Get-Content|read)\b[^\n]*(\.env\b|\.env\.)",
     "Reads .env content."),
    ("credential-ssh-key-read", "critical", r"\.ssh[/\\](id_rsa|id_ed25519|config)", "References SSH key material."),
    ("credential-cloud-config-read", "critical",
     r"\.aws[/\\]credentials|\.config[/\\]gcloud|azure[/\\](credentials|profile)|AZURE_CLIENT_SECRET",
     "References cloud credential material."),
    ("credential-github-token-read", "critical", r"\bGITHUB_TOKEN\b|\bGH_TOKEN\b|\bghp_[A-Za-z0-9_]+",
     "References GitHub token material."),
    ("env-mass-dump", "high", r"\bos\.environ\b|\bprintenv\b|(^|[;&|` \t])env([ \t;&|`]|$)",
     "Dumps environment variables."),
    ("hidden-dotfile-write", "medium",
     r">\s*(~[/\\])?\.[A-Za-z0-9_-]+|\bopen\([\"'][^\"']*[/\\]?\.[A-Za-z0-9_-]+[\"']\s*,\s*[\"'][wa]",
     "Writes a hidden dotfile."),
)
_COMPILED = tuple((cid, sev, re.compile(pat, re.IGNORECASE), msg) for cid, sev, pat, msg in RULES)
_IGNORED_HIDDEN = (".cache", ".log", ".gitignore", ".env.example")
_SAFE_DOMAINS = {"example.com", "example.org", "example.net", "localhost"}
_SAFE_NETS = tuple(ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8"))
_URL = re.compile(r"https?://[^\s\"'`<>)]+", re.IGNORECASE)


def _safe_host(host: str) -> bool:
    host = host.lower().strip("[]")
    if host in _SAFE_DOMAINS or host.endswith(".example.com"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in net for net in _SAFE_NETS)


def findings(entry: FileEntry) -> list[Finding]:
    if entry.text is None:
        return []
    out: list[Finding] = []
    seen_hosts: set[str] = set()
    for number, line in enumerate(entry.text.splitlines(), start=1):
        for cid, sev, pattern, msg in _COMPILED:
            if not pattern.search(line):
                continue
            if cid == "hidden-dotfile-write" and any(m in line for m in _IGNORED_HIDDEN):
                continue
            out.append(make_finding(cid, sev, entry.rel, number, msg, line))
        for url in _URL.findall(line):
            try:
                host = urlparse(url).hostname
            except ValueError:
                continue
            if not host or _safe_host(host) or host in seen_hosts:
                continue
            seen_hosts.add(host)
            out.append(make_finding("network-call-unknown-domain", "medium", entry.rel, number,
                                    "References a network endpoint.", line))
    if entry.rel.split("/")[-1] == "package.json":
        out.extend(_package_hooks(entry))
    return out


def _package_hooks(entry: FileEntry) -> list[Finding]:
    try:
        data = json.loads(entry.text or "")
    except json.JSONDecodeError:
        return []
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    value = scripts.get("postinstall")
    if not isinstance(value, str):
        return []
    return [make_finding("npm-postinstall-hook", "high", entry.rel, None, "package.json defines a postinstall hook.",
                         f"scripts.postinstall: {value}")]
