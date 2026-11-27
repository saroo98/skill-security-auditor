"""Config analyzer: finds everything a host runs without asking, and the commands it runs.

Covers Claude Code settings and hooks, plugin manifests and monitors, MCP server definitions (JSON
and Codex TOML), npm lifecycle scripts, SKILL.md allowed-tools, and GitHub workflow run steps.
"""

from __future__ import annotations

import json
import re
import tomllib

from ..model import Capability, FileEntry
from . import shell

INTERPRETERS = {"bash", "sh", "zsh", "node", "python", "python3", "py", "deno", "bun", "pwsh", "powershell", "ruby", "perl"}
REMOTE_RUNNERS = {"npx", "uvx", "bunx", "pipx", "dlx", "docker", "podman"}
ROOT_VARS = re.compile(r"^[\"']?(\$\{?(CLAUDE_PLUGIN_ROOT|CLAUDE_PROJECT_DIR|PLUGIN_ROOT|PWD)\}?)[\"']?/")
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare")
SHELL_TOOLS = {"bash", "shell", "write", "edit", "multiedit", "notebookedit", "*", "computer"}


# -- minimal YAML ---------------------------------------------------------------------------------

def _strip_comment(line: str) -> str:
    out, quote = [], None
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(c)
    return "".join(out).rstrip()


def _scalar(raw: str, problems: list[str]):
    v = raw.strip()
    if not v:
        return ""
    if v[0] in "&*!" or v.startswith("{"):
        problems.append(f"unsupported YAML feature: {v[:40]}")
        return v
    if v.startswith("[") and v.endswith("]"):
        return [_scalar(p, problems) for p in _split_commas(v[1:-1]) if p.strip()]
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        return v[1:-1]
    return v


def _split_commas(s: str) -> list[str]:
    parts, depth, cur, quote = [], 0, [], None
    for c in s:
        if quote:
            cur.append(c)
            if c == quote:
                quote = None
            continue
        if c in "'\"":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(c)
    parts.append("".join(cur))
    return [p.strip() for p in parts]


def parse_yaml(text: str) -> tuple[object, list[str]]:
    problems: list[str] = []
    lines: list[tuple[int, str]] = []
    raw_lines = text.split("\n")
    i = 0
    while i < len(raw_lines):
        raw = raw_lines[i]
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            problems.append(f"tab indentation on line {i + 1}")
        stripped = _strip_comment(raw)
        if stripped.strip() in ("---", "..."):
            if lines:
                problems.append("multiple YAML documents")
            i += 1
            continue
        if stripped.strip():
            lines.append((len(stripped) - len(stripped.lstrip()), stripped.strip()))
            # keep raw block scalar lines untouched
            m = re.match(r"^(?:- )?[^:]+:\s*([|>])[-+]?\s*$", stripped.strip()) or re.match(r"^-\s*([|>])[-+]?\s*$", stripped.strip())
            if m:
                base = len(stripped) - len(stripped.lstrip())
                block: list[str] = []
                j = i + 1
                while j < len(raw_lines) and (not raw_lines[j].strip() or len(raw_lines[j]) - len(raw_lines[j].lstrip()) > base):
                    block.append(raw_lines[j])
                    j += 1
                lines.append((-1, "\x00" + m.group(1) + "\n".join(block)))
                i = j
                continue
        i += 1

    def block_text(marker: str) -> str:
        kind, body = marker[1], marker[2:]
        rows = body.split("\n")
        indent = min((len(r) - len(r.lstrip()) for r in rows if r.strip()), default=0)
        rows = [r[indent:] for r in rows]
        while rows and not rows[-1].strip():
            rows.pop()
        if kind == "|":
            return "\n".join(rows) + "\n"
        return " ".join(r.strip() for r in rows if r.strip()) + "\n"

    def parse(idx: int, indent: int):
        if idx >= len(lines):
            return None, idx
        if lines[idx][1].startswith("- ") or lines[idx][1] == "-":
            out_list = []
            while idx < len(lines) and lines[idx][0] == indent and (lines[idx][1].startswith("- ") or lines[idx][1] == "-"):
                rest = lines[idx][1][2:].strip() if lines[idx][1] != "-" else ""
                idx += 1
                if idx < len(lines) and lines[idx][0] == -1:
                    out_list.append(block_text(lines[idx][1]))
                    idx += 1
                elif re.match(r"^[^'\"\[{][^:]*:(\s|$)", rest):
                    key, _, val = rest.partition(":")
                    item = {}
                    if val.strip():
                        item[key.strip()] = _scalar(val, problems)
                    elif idx < len(lines) and lines[idx][0] > indent:
                        item[key.strip()], idx = parse(idx, lines[idx][0])
                    else:
                        item[key.strip()] = ""
                    if idx < len(lines) and lines[idx][0] > indent:
                        more, idx = parse(idx, lines[idx][0])
                        if isinstance(more, dict):
                            item.update(more)
                    out_list.append(item)
                elif rest:
                    out_list.append(_scalar(rest, problems))
                elif idx < len(lines) and lines[idx][0] > indent:
                    value, idx = parse(idx, lines[idx][0])
                    out_list.append(value)
                else:
                    out_list.append("")
            return out_list, idx
        out: dict = {}
        while idx < len(lines) and lines[idx][0] == indent:
            line = lines[idx][1]
            m = re.match(r"^(\"[^\"]*\"|'[^']*'|[^:]+?):(\s+(.*)|)$", line)
            if not m:
                problems.append(f"cannot parse YAML line: {line[:60]}")
                idx += 1
                continue
            key = m.group(1).strip("'\"")
            value = (m.group(3) or "").strip()
            idx += 1
            if value in ("|", ">", "|-", ">-", "|+", ">+") and idx < len(lines) and lines[idx][0] == -1:
                out[key] = block_text(lines[idx][1])
                idx += 1
            elif value:
                out[key] = _scalar(value, problems)
            elif idx < len(lines) and lines[idx][0] > indent:
                out[key], idx = parse(idx, lines[idx][0])
            elif idx < len(lines) and lines[idx][0] == indent and lines[idx][1].startswith("- "):
                out[key], idx = parse(idx, indent)
            else:
                out[key] = ""
        if idx < len(lines) and lines[idx][0] > indent:
            problems.append(f"unexpected indentation: {lines[idx][1][:60]}")
        return out, idx

    if not lines:
        return {}, problems
    data, idx = parse(0, lines[0][0])
    while idx < len(lines):
        problems.append(f"unexpected YAML content: {lines[idx][1][:60]}")
        idx += 1
    return data, problems


def parse_frontmatter(text: str) -> tuple[dict, list[str]]:
    if not text.startswith("---"):
        return {}, []
    rows = text.split("\n")
    end = next((i for i in range(1, len(rows)) if rows[i].strip() == "---"), None)
    if end is None:
        return {}, ["frontmatter is not closed"]
    data, problems = parse_yaml("\n".join(rows[1:end]))
    return (data if isinstance(data, dict) else {}), problems


# -- JSON with comments -----------------------------------------------------------------------------

def _loads_jsonc(text: str):
    try:
        return json.loads(text)
    except ValueError:
        pass
    out, i, quote = [], 0, False
    while i < len(text):
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                quote = False
        elif c == '"':
            quote = True
            out.append(c)
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = len(text) if j == -1 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = len(text) if j == -1 else j + 2
            continue
        else:
            out.append(c)
        i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    return json.loads(cleaned)


def _load(entry: FileEntry):
    text = entry.text or ""
    if entry.kind == "json":
        return _loads_jsonc(text)
    if entry.kind == "toml":
        return tomllib.loads(text)
    if entry.kind == "yaml":
        data, problems = parse_yaml(text)
        if problems:
            raise ValueError("; ".join(problems[:3]))
        return data
    return None


def problems(entry: FileEntry) -> list[str]:
    try:
        _load(entry)
    except (ValueError, tomllib.TOMLDecodeError, RecursionError) as exc:
        return [" ".join(str(exc).split())[:200]]
    return []


# -- analysis -----------------------------------------------------------------------------------

class _Config:
    def __init__(self, entry: FileEntry) -> None:
        self.entry = entry
        self.caps: list[Capability] = []
        self.text = entry.text or ""

    def line_of(self, needle: str) -> int | None:
        if not needle:
            return None
        idx = self.text.find(needle[:60])
        if idx == -1:
            idx = self.text.find(json.dumps(needle)[1:61])
        return self.text.count("\n", 0, idx) + 1 if idx >= 0 else None

    def add(self, kind: str, line: int | None, snippet: str, **detail: str | None) -> None:
        cap = Capability(kind, self.entry.rel, line, " ".join(snippet.split())[:300], "high",
                         tuple(sorted((k, v) for k, v in detail.items() if v)))
        if cap not in self.caps:
            self.caps.append(cap)

    def command(self, command: str, trigger: str) -> None:
        command = (command or "").strip()
        line = self.line_of(command)
        script, remote = _script_of(command)
        self.add("unprompted", line, command or trigger, trigger=trigger, script=script,
                 remote_package="yes" if remote else None, analyzed=None if command else "no")
        for cap in shell.analyze_command(command, self.entry.rel, line):
            if cap not in self.caps:
                self.caps.append(cap)

    def hooks(self, hooks) -> None:
        if not isinstance(hooks, dict):
            return
        for event, groups in hooks.items():
            for group in groups if isinstance(groups, list) else [groups]:
                if not isinstance(group, dict):
                    continue
                inner = group.get("hooks") if isinstance(group.get("hooks"), list) else [group]
                for hook in inner:
                    if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                        self.command(hook["command"], f"{event} hook")

    def mcp(self, servers) -> None:
        if not isinstance(servers, dict):
            return
        for name, spec in servers.items():
            if not isinstance(spec, dict):
                continue
            if isinstance(spec.get("command"), str):
                args = spec.get("args") if isinstance(spec.get("args"), list) else []
                self.command(" ".join([spec["command"]] + [shell_quote(str(a)) for a in args]), f"MCP server {name}")
            url = spec.get("url") or spec.get("serverUrl")
            if isinstance(url, str) and url.lower().startswith(("http://", "https://")):
                host = re.sub(r"^https?://([^/:]+).*$", r"\1", url)
                self.add("net.outbound", self.line_of(url), url, host=host)

    def run(self) -> list[Capability]:
        name = self.entry.rel.rsplit("/", 1)[-1]
        if self.entry.kind == "yaml" and "/.github/workflows/" in "/" + self.entry.rel:
            self.workflow()
            return self.caps
        try:
            data = _load(self.entry)
        except (ValueError, tomllib.TOMLDecodeError, RecursionError):
            return self.caps
        if not isinstance(data, dict):
            return self.caps
        self.hooks(data.get("hooks"))
        self.mcp(data.get("mcpServers"))
        self.mcp(data.get("mcp_servers"))
        status = data.get("statusLine")
        if isinstance(status, dict) and isinstance(status.get("command"), str):
            self.command(status["command"], "status line")
        for monitor in data.get("monitors") or [] if isinstance(data.get("monitors"), list) else []:
            if isinstance(monitor, dict) and isinstance(monitor.get("command"), str):
                self.command(monitor["command"], f"plugin monitor {monitor.get('name', '')}".strip())
        perms = data.get("permissions")
        if isinstance(perms, dict):
            allow = perms.get("allow") if isinstance(perms.get("allow"), list) else []
            if any(isinstance(a, str) and (a.startswith(("Bash", "Shell")) or a == "*") for a in allow) or \
                    perms.get("defaultMode") in ("bypassPermissions", "acceptEdits"):
                self.add("agent.config", self.line_of("permissions"), "permissions: " + json.dumps(perms)[:200])
        if name == "package.json" and isinstance(data.get("scripts"), dict):
            for hook in LIFECYCLE:
                value = data["scripts"].get(hook)
                if isinstance(value, str):
                    self.command(value, f"npm {hook} script")
        return self.caps

    def workflow(self) -> None:
        rows = self.text.split("\n")
        i = 0
        while i < len(rows):
            m = re.match(r"^(\s*)(?:-\s+)?run:\s*(.*)$", rows[i])
            if not m:
                i += 1
                continue
            indent, value = len(m.group(1)), m.group(2).strip()
            if value in ("|", ">", "|-", ">-"):
                block = []
                j = i + 1
                while j < len(rows) and (not rows[j].strip() or len(rows[j]) - len(rows[j].lstrip()) > indent):
                    block.append(rows[j].strip())
                    j += 1
                for offset, line in enumerate(block):
                    for cap in shell.analyze_command(line, self.entry.rel, i + 2 + offset):
                        if cap not in self.caps:
                            self.caps.append(cap)
                i = j
                continue
            for cap in shell.analyze_command(value.strip("'\""), self.entry.rel, i + 1):
                if cap not in self.caps:
                    self.caps.append(cap)
            i += 1


def shell_quote(arg: str) -> str:
    return arg if re.fullmatch(r"[A-Za-z0-9_./:@%+=,-]+", arg) else "'" + arg.replace("'", "'\\''") + "'"


def _script_of(command: str) -> tuple[str | None, bool]:
    toks = [t.text for t in shell.lex(command) if t.kind == "word"]
    if not toks:
        return None, False
    first = re.split(r"[\\/]", toks[0])[-1].lower()
    if first in REMOTE_RUNNERS or (first in ("pnpm", "yarn") and len(toks) > 1 and toks[1] == "dlx") or \
            (first == "pipx" and len(toks) > 1 and toks[1] == "run"):
        return None, True
    candidate = None
    if first in INTERPRETERS:
        for t in toks[1:]:
            if t.startswith("-"):
                continue
            candidate = t
            break
    elif "/" in toks[0] or re.search(r"\.(sh|py|js|mjs|cjs|ts|ps1|rb|pl)$", toks[0]):
        candidate = toks[0]
    if not candidate:
        return None, False
    candidate = ROOT_VARS.sub("", candidate).strip("'\"")
    candidate = re.sub(r"^\./", "", candidate)
    if candidate.startswith(("/", "~", "$")) or not re.search(r"[./]", candidate):
        return None, False
    return candidate, False


def analyze(entry: FileEntry) -> list[Capability]:
    return _Config(entry).run()


def frontmatter_caps(entry: FileEntry) -> list[Capability]:
    values, _ = parse_frontmatter(entry.text or "")
    tools = values.get("allowed-tools") or values.get("allowed_tools")
    if isinstance(tools, str):
        items = _split_commas(tools)
    elif isinstance(tools, list):
        items = [str(t) for t in tools]
    else:
        return []
    caps: list[Capability] = []
    text = entry.text or ""
    for item in items:
        item = item.strip()
        base = item.split("(", 1)[0].strip().lower()
        if base in SHELL_TOOLS or item == "*":
            idx = text.find(item)
            line = text.count("\n", 0, idx) + 1 if idx >= 0 else 2
            cap = Capability("unprompted", entry.rel, line, f"allowed-tools: {item}", "high",
                             (("analyzed", "yes"), ("trigger", f"pre-approved tool {item}")))
            if cap not in caps:
                caps.append(cap)
    return caps
