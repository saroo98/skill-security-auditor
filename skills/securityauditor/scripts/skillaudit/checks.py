"""Check registry and ruleset version."""

from __future__ import annotations

from dataclasses import dataclass

RULESET_VERSION = "0"  # bump whenever a check's behavior changes; it keys the verdict cache


@dataclass(frozen=True)
class Check:
    id: str
    severity: str
    title: str
    ast10: tuple[str, ...] = ()


_TABLE: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("secret-to-network", "critical", "Credential file contents are sent over the network", ("AST01",)),
    ("env-to-network", "critical", "The whole environment is sent over the network", ("AST01",)),
    ("remote-exec", "critical", "Downloads code and runs it", ("AST01", "AST02")),
    ("reverse-shell", "critical", "Opens a remote shell", ("AST01",)),
    ("delete-root-or-home", "critical", "Deletes the home directory or the drive root", ("AST01",)),
    ("hidden-instruction", "critical", "Instructions hidden from a human reader", ("AST01", "AST04")),
    ("reviewer-directed", "critical", "Text addresses the reviewer or asks for a verdict", ("AST01", "AST08")),
    ("unprompted-unanalyzed", "high", "Runs without asking, and the command could not be checked", ("AST06",)),
    ("instruction-override", "high", "Tells the agent to ignore or replace its instructions", ("AST01", "AST05")),
    ("instruction-conceal", "high", "Tells the agent to hide an action from the user", ("AST01",)),
    ("instruction-no-ask", "high", "Tells the agent to act without asking", ("AST03", "AST06")),
    ("instruction-external", "high", "Tells the agent to fetch and follow outside instructions", ("AST05",)),
    ("install-extra-component", "high", "Tells the user or agent to install an extra component first", ("AST01", "AST02")),
    ("secret-to-odd-host", "high", "A secret is sent to a host that does not match it", ("AST01",)),
    ("secret-near-network", "high", "Reads credential files and uses the network in the same file", ("AST01",)),
    ("lookalike-source", "high", "Source name imitates a well-known skill repository", ("AST02",)),
    ("dynamic-exec", "high", "Runs code generated or decoded at run time", ("AST01",)),
    ("obfuscation", "high", "Behavior is encoded or disguised", ("AST01",)),
    ("persist-runtime", "high", "Installs startup items or shell profile changes", ("AST01", "AST06")),
    ("agent-config-change", "high", "Changes agent settings, permissions or other skills", ("AST03", "AST06")),
    ("undeclared-secret-read", "high", "Reads credential files without saying so", ("AST04",)),
    ("undeclared-persist", "high", "Installs startup items without saying so", ("AST04",)),
    ("binary-referenced", "high", "Instructions point at a binary or archive that cannot be checked", ("AST01",)),
    ("secret-to-unknown-host", "medium", "A secret is sent to a host with no known vendor", ("AST01",)),
    ("shell-dynamic", "medium", "Runs a shell command built at run time", ("AST03",)),
    ("runtime-pkg-install", "medium", "Installs packages at run time", ("AST02",)),
    ("write-outside-workspace", "medium", "Writes or deletes outside the workspace", ("AST03",)),
    ("undeclared-capability", "medium", "Does something the description does not mention", ("AST04",)),
    ("not-checked", "medium", "A file could not be checked", ("AST08",)),
    ("unprompted-clean", "low", "Runs without asking; the command was checked", ("AST06",)),
    ("declared-network", "low", "Uses the network, as the skill says", ()),
    ("shell-constant", "low", "Runs a fixed shell command", ()),
    ("secret-to-vendor", "info", "A secret is sent to its own vendor", ()),
    ("env-read", "info", "Reads a named environment variable", ()),
    ("project-delete", "info", "Deletes files inside the project", ()),
    ("inert-media", "info", "Image or font, not analyzed", ()),
)

CHECKS: dict[str, Check] = {cid: Check(cid, sev, title, ast) for cid, sev, title, ast in _TABLE}
