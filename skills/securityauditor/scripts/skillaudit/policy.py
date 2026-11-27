"""Turn capabilities into findings, and summarize capabilities in plain words."""

from __future__ import annotations

from .model import Capability

_WORDS = {
    "net.outbound": "network",
    "net.listen": "open a remote shell",
    "exec.shell": "run shell commands",
    "exec.dynamic": "run generated code",
    "exec.remote": "download and run code",
    "secret.read": "read credential files",
    "secret.use": "use secret variables",
    "env.dump": "read the whole environment",
    "fs.delete": "delete files",
    "fs.write.outside": "write outside the workspace",
    "pkg.install": "install packages",
    "persist": "install startup items",
    "agent.config": "change agent settings",
}


def can_summary(caps: list[Capability]) -> list[str]:
    hosts: dict[str, list[str]] = {}
    order: list[str] = []
    for cap in caps:
        word = _WORDS.get(cap.kind)
        if word is None:
            continue
        if word not in hosts:
            hosts[word] = []
            order.append(word)
        host = cap.get("host")
        if host and host not in hosts[word]:
            hosts[word].append(host)
    out = []
    for word in order:
        hs = sorted(hosts[word])
        if hs:
            shown = ", ".join(hs[:3]) + (f", +{len(hs) - 3}" if len(hs) > 3 else "")
            out.append(f"{word} ({shown})")
        else:
            out.append(word)
    return out


def unprompted_summary(caps: list[Capability]) -> list[str]:
    seen: list[str] = []
    for cap in caps:
        if cap.kind != "unprompted":
            continue
        label = cap.get("trigger", "unprompted item") or "unprompted item"
        item = f"{label} -> {cap.file}" if cap.file else label
        if item not in seen:
            seen.append(item)
    return seen
