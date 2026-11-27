"""Turn capabilities into findings, and summarize capabilities in plain words."""

from __future__ import annotations

from .checks import CHECKS
from .data import host_matches, is_drop_host, is_raw_ip, vendor_hosts
from .model import SEVERITY_RANK, Capability, Finding, NotChecked, make_finding

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
_SIMPLE = {
    "exec.remote": "remote-exec",
    "net.listen": "reverse-shell",
    "instruction.override": "instruction-override",
    "instruction.conceal": "instruction-conceal",
    "instruction.noask": "instruction-no-ask",
    "instruction.bypass": "permission-bypass",
    "exec.load": "dynamic-load",
    "instruction.external": "instruction-external",
    "instruction.install-extra": "install-extra-component",
    "instruction.hidden": "hidden-instruction",
    "instruction.reviewer": "reviewer-directed",
    "exec.dynamic": "dynamic-exec",
    "obfuscation": "obfuscation",
    "persist": "persist-runtime",
    "agent.config": "agent-config-change",
    "pkg.install": "runtime-pkg-install",
    "fs.write.outside": "write-outside-workspace",
    "env.read": "env-read",
    "suppression": "suppression-in-tree",
    "unparsed": "not-checked",
}
DECLARABLE = {"net.outbound", "secret.read", "persist", "pkg.install", "fs.write.outside", "exec.shell"}
_UNDECLARED = {"secret.read": "undeclared-secret-read", "persist": "undeclared-persist"}
_CAP = "low"


def _flow_check(cap: Capability) -> str | None:
    source, sink = cap.get("source"), cap.get("sink")
    if sink != "net.outbound":
        return None
    if source == "secret.read":
        return "secret-to-network"
    if source == "env.dump":
        return "env-to-network"
    if source != "secret.use":
        return None
    host = cap.get("host") or ""
    if not host:
        return "secret-to-unknown-host"  # the destination could not be read from the code
    if is_raw_ip(host) or is_drop_host(host, cap.get("url")):
        return "secret-to-odd-host"
    vendors = vendor_hosts(cap.get("secret") or "")
    if vendors:
        return "secret-to-vendor" if host_matches(host, vendors) else "secret-to-odd-host"
    return "secret-to-unknown-host"


def _check_for(cap: Capability) -> str | None:
    if cap.kind == "flow":
        return _flow_check(cap)
    if cap.kind == "fs.delete":
        target = cap.get("target")
        if target in ("root", "home", "system"):
            return "delete-root-or-home"
        if target == "absolute":
            return "write-outside-workspace"
        return "project-delete"
    if cap.kind == "unprompted":
        return "unprompted-clean" if cap.get("analyzed") == "yes" else "unprompted-unanalyzed"
    if cap.kind == "exec.shell":
        return "shell-constant" if cap.get("constant") == "yes" else "shell-dynamic"
    return _SIMPLE.get(cap.kind)


def decide(caps: list[Capability], not_checked: list[NotChecked], *, declared: set[str] | frozenset[str] | None = None,
           unreferenced_low_roles: set[str] | frozenset[str] = frozenset()) -> list[Finding]:
    """Map capabilities to findings. ``declared`` is None until declarations are analyzed."""
    findings: list[Finding] = []
    seen: set[tuple[str, str, int | None, str, str | None]] = set()

    def add(check_id: str, cap: Capability, message: str | None = None, severity: str | None = None) -> None:
        check = CHECKS[check_id]
        severity = severity or check.severity
        if cap.file in unreferenced_low_roles and SEVERITY_RANK[severity] > SEVERITY_RANK[_CAP]:
            severity = _CAP
        # code shown in reference documents is mostly examples; code in SKILL.md is what the agent is told to run
        if cap.get("fenced") == "yes" and not cap.file.endswith("SKILL.md") and SEVERITY_RANK[severity] > SEVERITY_RANK["medium"]:
            severity = "medium"
        key = (check_id, cap.file, cap.line, cap.snippet, cap.evidence_digest)
        if key in seen:
            return
        seen.add(key)
        findings.append(make_finding(check_id, severity, cap.file, cap.line, message or check.title, cap.snippet,
                                     evidence_digest=cap.evidence_digest))

    def is_declared(cap: Capability) -> bool:
        return cap.kind in (declared or ()) or (cap.kind == "pkg.install" and cap.get("documented") == "yes")

    flows_by_file = {c.file for c in caps if c.kind == "flow" and c.get("source") == "secret.read"}
    for cap in caps:
        check_id = _check_for(cap)
        if not check_id:
            continue
        if declared is not None and cap.kind in ("pkg.install", "fs.write.outside") and is_declared(cap):
            add(check_id, cap, severity="low")  # the skill says it does this
        else:
            add(check_id, cap)

    files_with_secret = {c.file for c in caps if c.kind == "secret.read"}
    files_with_net = {c.file for c in caps if c.kind == "net.outbound"}
    for file in sorted((files_with_secret & files_with_net) - flows_by_file):
        cap = next(c for c in caps if c.kind == "secret.read" and c.file == file)
        add("secret-near-network", cap)

    if declared is not None:
        for cap in caps:
            if cap.kind not in DECLARABLE or cap.file in unreferenced_low_roles:
                continue
            if is_declared(cap):
                if cap.kind == "net.outbound":
                    add("declared-network", cap)
                continue
            check_id = _UNDECLARED.get(cap.kind, "undeclared-capability")
            # reading a project .env file is common; credential stores are not
            severity = "medium" if cap.kind == "secret.read" and cap.get("what") == "dotenv" else None
            add(check_id, cap, f"{CHECKS[check_id].title}: {_WORDS.get(cap.kind, cap.kind)}", severity=severity)
    return findings


def can_summary(caps: list[Capability]) -> list[str]:
    hosts: dict[str, list[str]] = {}
    order: list[str] = []

    def note(word: str, host: str | None) -> None:
        if word not in hosts:
            hosts[word] = []
            order.append(word)
        if host and host not in hosts[word]:
            hosts[word].append(host)

    for cap in caps:
        if cap.kind == "flow":
            if cap.get("sink") == "net.outbound":
                note(_WORDS["net.outbound"], cap.get("host"))
            source_word = _WORDS.get(cap.get("source") or "")
            if source_word:
                note(source_word, None)
            continue
        word = _WORDS.get(cap.kind)
        if word is not None:
            note(word, cap.get("host"))
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
        label = cap.get("trigger") or "unprompted item"
        item = f"{label} -> {cap.file}" if cap.file else label
        if item not in seen:
            seen.append(item)
    return seen
