"""Shell analyzer: lexes commands and pipelines and reports what they can do.

It understands quoting, command substitution, process substitution, ``sh -c`` strings, pipelines,
redirections, and simple variable and file tracking within one script. It never runs anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..data import is_secret_path
from ..model import Capability, FileEntry

FETCHERS = {"curl", "wget", "fetch", "iwr", "invoke-webrequest", "irm", "invoke-restmethod", "http", "https",
            "aria2c", "httpie", "xh"}
INTERPRETERS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python2", "python3", "node", "deno", "bun",
                "perl", "ruby", "php", "pwsh", "powershell", "lua"}
SOURCE_CMDS = {"source", "."}
NET_TOOLS = {"nc", "ncat", "netcat", "telnet", "socat"}
UPLOADERS = {"scp", "rsync", "sftp", "ftp"}
WRAPPERS = {"sudo", "exec", "command", "nohup", "time", "nice", "builtin", "doas"}
PKG = {"pip", "pip3", "npm", "pnpm", "yarn", "cargo", "gem", "go", "apt", "apt-get", "brew", "bun", "uv", "poetry",
       "conda", "pipx", "choco", "winget", "scoop"}
PKG_VERBS = {"install", "add", "get", "i"}
PROFILE_FILES = (".bashrc", ".zshrc", ".profile", ".bash_profile", ".zprofile", ".config/fish/config.fish",
                 "/etc/profile", "LaunchAgents/", "LaunchDaemons/", "autostart/")
AGENT_DIRS = (".claude/", ".codex/", ".cursor/", ".gemini/", ".agents/")
LIST_OPS = {";", "&&", "||", "&", ";;", "\n"}
PIPE_OPS = {"|", "|&"}
REDIRECT_OPS = {">", ">>", "<", "&>", ">&", "<<<", "<<", ">|"}
_URL = re.compile(r"https?://[^\s'\"`<>()|;]+", re.IGNORECASE)
_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_ASSIGN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_HOME = re.compile(r"^(\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE|~)", re.IGNORECASE)
MAX_DEPTH = 3


@dataclass
class Tok:
    kind: str  # "word" | "op" | "procsub"
    text: str
    subs: list[str] = field(default_factory=list)


def _capture(s: str, i: int, open_ch: str, close_ch: str) -> tuple[str, int]:
    """s[i] is just after the opening bracket. Return (inner, index after the closing bracket)."""
    depth, j, quote = 1, i, None
    while j < len(s):
        c = s[j]
        if quote:
            if c == "\\" and quote == '"':
                j += 2
                continue
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == "\\":
            j += 2
            continue
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return s[i:j], j + 1
        j += 1
    return s[i:], len(s)


def lex(s: str) -> list[Tok]:
    toks: list[Tok] = []
    word: list[str] = []
    subs: list[str] = []
    in_word = False
    i = 0

    def flush() -> None:
        nonlocal word, subs, in_word
        if in_word:
            toks.append(Tok("word", "".join(word), subs))
        word, subs, in_word = [], [], False

    ops = sorted({"&&", "||", ";;", "|&", "|", ";", "&", ">>", ">&", "&>", "<<<", "<<", ">", "<", ">|"}, key=len, reverse=True)
    while i < len(s):
        c = s[i]
        if c in " \t\r":
            flush()
            i += 1
        elif c == "\n":
            flush()
            toks.append(Tok("op", "\n"))
            i += 1
        elif c == "#" and not in_word:
            end = s.find("\n", i)
            i = len(s) if end == -1 else end
        elif c == "\\":
            if i + 1 < len(s) and s[i + 1] == "\n":
                i += 2
                continue
            word.append(s[i + 1] if i + 1 < len(s) else "")
            in_word = True
            i += 2
        elif c == "'":
            end = s.find("'", i + 1)
            end = len(s) if end == -1 else end
            word.append(s[i + 1:end])
            in_word = True
            i = end + 1
        elif c == '"':
            j = i + 1
            in_word = True
            while j < len(s) and s[j] != '"':
                if s[j] == "\\" and j + 1 < len(s):
                    word.append(s[j + 1])
                    j += 2
                elif s.startswith("$(", j):
                    inner, j = _capture(s, j + 2, "(", ")")
                    subs.append(inner)
                    word.append(f"$({inner})")
                elif s[j] == "`":
                    end = s.find("`", j + 1)
                    end = len(s) if end == -1 else end
                    subs.append(s[j + 1:end])
                    word.append(s[j:end + 1])
                    j = end + 1
                else:
                    word.append(s[j])
                    j += 1
            i = j + 1
        elif s.startswith("$(", i):
            inner, i = _capture(s, i + 2, "(", ")")
            subs.append(inner)
            word.append(f"$({inner})")
            in_word = True
        elif c == "`":
            end = s.find("`", i + 1)
            end = len(s) if end == -1 else end
            subs.append(s[i + 1:end])
            word.append(s[i:end + 1])
            in_word = True
            i = end + 1
        elif (s.startswith("<(", i) or s.startswith(">(", i)) and not in_word:
            inner, i = _capture(s, i + 2, "(", ")")
            toks.append(Tok("procsub", inner, [inner]))
        elif c in "(){}" and not in_word:
            toks.append(Tok("op", c))
            i += 1
        else:
            matched = next((op for op in ops if s.startswith(op, i)), None)
            if matched:
                if in_word and "".join(word).isdigit() and matched[0] in "<>":
                    word, subs, in_word = [], [], False
                else:
                    flush()
                toks.append(Tok("op", matched))
                i += len(matched)
            else:
                word.append(c)
                in_word = True
                i += 1
    flush()
    return toks


@dataclass
class Stage:
    words: list[Tok]
    redirects: list[tuple[str, Tok]]
    procsubs: list[str]
    assignments: list[tuple[str, Tok]]

    @property
    def name(self) -> str:
        if not self.words:
            return ""
        base = re.split(r"[\\/]", self.words[0].text)[-1].lower()
        return base[:-4] if base.endswith(".exe") else base

    @property
    def args(self) -> list[Tok]:
        return self.words[1:]

    def all_subs(self) -> list[str]:
        out = [s for w in self.words for s in w.subs] + self.procsubs
        out += [s for _, t in self.redirects for s in t.subs]
        out += [s for _, t in self.assignments for s in t.subs]
        return out


def _stages(toks: list[Tok]) -> list[list[Stage]]:
    """Split tokens into lists of pipelines; each pipeline is a list of stages."""
    lists: list[list[Stage]] = []
    pipeline: list[Stage] = []
    cur = Stage([], [], [], [])
    pending: str | None = None

    def end_stage() -> None:
        nonlocal cur
        if cur.words or cur.redirects or cur.procsubs or cur.assignments:
            pipeline.append(cur)
        cur = Stage([], [], [], [])

    for tok in toks:
        if pending:
            cur.redirects.append((pending, tok if tok.kind != "op" else Tok("word", "")))
            pending = None
            if tok.kind != "op":
                continue
        if tok.kind == "op":
            if tok.text in REDIRECT_OPS:
                pending = tok.text
            elif tok.text in PIPE_OPS:
                end_stage()
            elif tok.text in LIST_OPS or tok.text in "(){}":
                end_stage()
                if pipeline:
                    lists.append(pipeline)
                pipeline = []
            continue
        if tok.kind == "procsub":
            cur.procsubs.append(tok.text)
            cur.words.append(Tok("word", "<(...)", [tok.text]))
            continue
        m = _ASSIGN.match(tok.text) if not cur.words else None
        if m:
            cur.assignments.append((m.group(1), tok))
            continue
        cur.words.append(tok)
    end_stage()
    if pipeline:
        lists.append(pipeline)
    for pl in lists:
        for st in pl:
            _unwrap(st)
    return lists


def _unwrap(st: Stage) -> None:
    while st.words and st.name in WRAPPERS:
        st.words = st.words[1:]
        while st.words and st.words[0].text.startswith("-"):
            st.words = st.words[1:]
    if st.words and st.name == "env" and len(st.words) > 1:
        rest = st.words[1:]
        while rest and (_ASSIGN.match(rest[0].text) or rest[0].text.startswith("-")):
            rest = rest[1:]
        if rest:
            st.words = rest


def _norm_path(p: str) -> str:
    p = p.strip().strip("'\"")
    p = _HOME.sub("~", p)
    return p.replace("\\", "/")


def _delete_target(path: str) -> str:
    p = _norm_path(path)
    if p in ("/", "/*", "~", "~/", "~/*") or re.fullmatch(r"[A-Za-z]:/?\*?", p):
        return "root" if not p.startswith("~") else "home"
    if p.startswith("~"):
        return "home"
    if p.startswith("/") or re.match(r"[A-Za-z]:/", p):
        return "absolute"
    return "project"


_RANK = {"project": 0, "absolute": 1, "home": 2, "root": 3}


def _host(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _secret_tokens(text: str) -> bool:
    for piece in re.split(r"[\s=@,;:'\"]+", text):
        piece = _norm_path(piece)
        if piece and is_secret_path(piece):
            return True
    return False


class ShellAnalyzer:
    def __init__(self, file: str, confidence: str = "high") -> None:
        self.file = file
        self.confidence = confidence
        self.caps: list[Capability] = []
        self.downloaded: set[str] = set()
        self.tainted_vars: dict[str, str] = {}
        self.tainted_files: dict[str, str] = {}

    # -- helpers -------------------------------------------------------------------------
    def add(self, kind: str, line: int | None, snippet: str, **detail: str) -> None:
        cap = Capability(kind, self.file, line, snippet.strip()[:300], self.confidence,
                         tuple(sorted((k, v) for k, v in detail.items() if v)))
        if cap not in self.caps:
            self.caps.append(cap)

    def _inner_has_fetch(self, text: str, depth: int) -> bool:
        if depth > MAX_DEPTH:
            return False
        for pl in _stages(lex(text)):
            for st in pl:
                if st.name in FETCHERS:
                    return True
                if any(self._inner_has_fetch(s, depth + 1) for s in st.all_subs()):
                    return True
        return False

    def _sources(self, text: str, depth: int = 0) -> set[str]:
        """Which sensitive sources a piece of shell text reads: secret.read, env.dump."""
        found: set[str] = set()
        if depth > MAX_DEPTH:
            return found
        for pl in _stages(lex(text)):
            for st in pl:
                found |= self._stage_sources(st)
                for s in st.all_subs():
                    found |= self._sources(s, depth + 1)
        return found

    def _stage_sources(self, st: Stage) -> set[str]:
        found: set[str] = set()
        if self._is_env_dump(st):
            found.add("env.dump")
        texts = [w.text for w in st.args] + [t.text for op, t in st.redirects if op in ("<", "<<<")]
        if st.name not in FETCHERS and any(_secret_tokens(t) for t in texts):
            found.add("secret.read")
        for w in st.words:
            for var in _VAR.findall(w.text):
                if var in self.tainted_vars:
                    found.add(self.tainted_vars[var])
            norm = _norm_path(w.text)
            if norm in self.tainted_files:
                found.add(self.tainted_files[norm])
        return found

    @staticmethod
    def _is_env_dump(st: Stage) -> bool:
        if st.name in ("env", "printenv") and len(st.words) == 1:
            return True
        if st.name == "printenv" and not st.args:
            return True
        if st.name == "set" and not st.args:
            return True
        if st.name in ("export", "declare") and [a.text for a in st.args] in (["-p"], ["-x"], ["-px"]):
            return True
        return False

    # -- main ----------------------------------------------------------------------------
    def run(self, text: str, line: int | None, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            self.add("obfuscation", line, text, why="nesting too deep")
            return
        for pipeline in _stages(lex(text)):
            self._pipeline(pipeline, line, depth)

    def _pipeline(self, pipeline: list[Stage], line: int | None, depth: int) -> None:
        snippet = " | ".join(" ".join(w.text for w in st.words) for st in pipeline)
        upstream_sources: set[str] = set()
        upstream_fetch = False
        upstream_decode = False
        for idx, st in enumerate(pipeline):
            for s in st.all_subs():
                self.run(s, line, depth + 1)
            self._assignments(st, line)
            name = st.name
            sources_here = self._stage_sources(st) | {src for s in st.all_subs() for src in self._sources(s, depth + 1)}

            if st.words and re.search(r"[$`]", st.words[0].text):
                self.add("obfuscation", line, snippet, why="command name built at run time")
            if name in FETCHERS or name in NET_TOOLS or name in UPLOADERS:
                hosts = self._hosts(st)
                for h in hosts or [None]:
                    self.add("net.outbound", line, snippet, host=h)
                srcs = upstream_sources | sources_here
                if name in FETCHERS:
                    srcs |= self._upload_sources(st)
                for src in sorted(srcs):
                    for h in hosts or [None]:
                        self.add("flow", line, snippet, source=src, sink="net.outbound", host=h)
                if name in FETCHERS:
                    for target in self._download_targets(st):
                        self.downloaded.add(target)
            if name in NET_TOOLS and self._is_reverse(st):
                self.add("net.listen", line, snippet)
            if any("/dev/tcp/" in w.text or "/dev/udp/" in w.text for w in st.words) or any(
                    "/dev/tcp/" in t.text or "/dev/udp/" in t.text for _, t in st.redirects):
                self.add("net.listen", line, snippet)

            interp = name in INTERPRETERS or name in SOURCE_CMDS or name == "eval"
            if interp:
                if idx > 0 and upstream_fetch and not self._has_script_arg(st):
                    self.add("exec.remote", line, snippet)
                if idx > 0 and upstream_decode and not self._has_script_arg(st):
                    self.add("obfuscation", line, snippet, why="decoded content piped to an interpreter")
                    self.add("exec.dynamic", line, snippet)
                if any(self._inner_has_fetch(s, depth + 1) for s in st.all_subs()):
                    self.add("exec.remote", line, snippet)
                for arg in st.args:
                    if _norm_path(arg.text).lstrip("./") in self.downloaded:
                        self.add("exec.remote", line, snippet)
                inline = self._inline_script(st)
                if inline is not None:
                    self.run(inline, line, depth + 1)
                if name == "eval" and any(not a.subs and "$" in a.text for a in st.args):
                    self.add("exec.dynamic", line, snippet)
            if st.words and _norm_path(st.words[0].text).lstrip("./") in self.downloaded:
                self.add("exec.remote", line, snippet)
            if name == "chmod" and any(_norm_path(a.text).lstrip("./") in self.downloaded for a in st.args):
                self.add("exec.remote", line, snippet)

            self._deletes(st, line, snippet)
            if self._is_env_dump(st):
                self.add("env.dump", line, snippet)
            if "secret.read" in self._stage_sources(st):
                self.add("secret.read", line, snippet)
            self._installs(st, line, snippet)
            self._writes(st, line, snippet, sources_here | upstream_sources)

            upstream_sources |= sources_here
            upstream_fetch = upstream_fetch or name in FETCHERS
            upstream_decode = upstream_decode or (name in ("base64", "xxd", "openssl") and any(
                a.text in ("-d", "--decode", "-D", "-r", "enc") for a in st.args))

    def _assignments(self, st: Stage, line: int | None) -> None:
        for name, tok in st.assignments:
            srcs = {src for s in tok.subs for src in self._sources(s, 1)}
            if not srcs and _secret_tokens(tok.text) and tok.subs:
                srcs.add("secret.read")
            if srcs:
                self.tainted_vars[name] = sorted(srcs)[0]
                for src in srcs:
                    self.add(src, line, f"{name}={tok.text}")
            if any(self._inner_has_fetch(s, 1) for s in tok.subs):
                self.tainted_vars.setdefault(name, "")

    def _hosts(self, st: Stage) -> list[str]:
        hosts: list[str] = []
        for w in st.args:
            for url in _URL.findall(w.text):
                h = _host(url)
                if h and h not in hosts:
                    hosts.append(h)
        if not hosts and st.name in NET_TOOLS:
            for w in st.args:
                t = w.text
                if t.startswith("-") or t.isdigit() or "/" in t:
                    continue
                if re.fullmatch(r"(tcp|udp|tcp4|tcp6):[^:]+:\d+", t, re.IGNORECASE):
                    hosts.append(t.split(":")[1])
                    break
                if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z0-9-]+|\d+\.\d+\.\d+\.\d+", t):
                    hosts.append(t)
                    break
        if not hosts and st.name in UPLOADERS:
            for w in st.args:
                m = re.match(r"(?:[^@\s]+@)?([A-Za-z0-9.-]+\.[A-Za-z]{2,}|\d+\.\d+\.\d+\.\d+):", w.text)
                if m:
                    hosts.append(m.group(1))
                    break
        return hosts

    def _upload_sources(self, st: Stage) -> set[str]:
        found: set[str] = set()
        args = [a.text for a in st.args]
        for i, a in enumerate(args):
            value = None
            if a in ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form", "-T",
                     "--upload-file", "--post-file", "--body-file") and i + 1 < len(args):
                value = args[i + 1]
            elif a.startswith(("--data=", "--data-binary=", "--post-file=", "--body-file=")):
                value = a.split("=", 1)[1]
            if value is None:
                continue
            if _secret_tokens(value):
                found.add("secret.read")
            norm = _norm_path(value.split("@")[-1])
            if norm in self.tainted_files:
                found.add(self.tainted_files[norm])
        return found

    def _download_targets(self, st: Stage) -> list[str]:
        out: list[str] = []
        args = [a.text for a in st.args]
        for i, a in enumerate(args):
            if a in ("-o", "-O", "--output", "--output-document", "-OutFile", "-outfile") and i + 1 < len(args):
                if args[i + 1] != "-":
                    out.append(_norm_path(args[i + 1]).lstrip("./"))
            elif a.startswith("--output=") or a.startswith("--output-document="):
                out.append(_norm_path(a.split("=", 1)[1]).lstrip("./"))
        for op, t in st.redirects:
            if op in (">", ">>", ">|") and t.text:
                out.append(_norm_path(t.text).lstrip("./"))
        if st.name == "wget" and not out and "-O-" not in args and "-qO-" not in args:
            for a in args:
                for url in _URL.findall(a):
                    base = urlparse(url).path.rsplit("/", 1)[-1]
                    if base:
                        out.append(base)
        if st.name == "curl" and ("-O" in args or "--remote-name" in args):
            for a in args:
                for url in _URL.findall(a):
                    base = urlparse(url).path.rsplit("/", 1)[-1]
                    if base:
                        out.append(base)
        return out

    @staticmethod
    def _is_reverse(st: Stage) -> bool:
        args = [a.text.lower() for a in st.args]
        if st.name in ("nc", "ncat", "netcat") and any(a in ("-e", "-c", "--exec", "--sh-exec") for a in args):
            return True
        if st.name == "socat" and any(a.startswith(("exec:", "system:")) or ",exec:" in a for a in args):
            return True
        return False

    @staticmethod
    def _has_script_arg(st: Stage) -> bool:
        for a in st.args:
            t = a.text
            if t in ("-", "-s", "/dev/stdin"):
                return False
            if t.startswith("-"):
                if t in ("-c", "-e", "-m"):
                    return True
                continue
            return True
        return False

    @staticmethod
    def _inline_script(st: Stage) -> str | None:
        args = [a.text for a in st.args]
        if st.name in ("sh", "bash", "zsh", "dash", "ksh"):
            for i, a in enumerate(args):
                if a == "-c" and i + 1 < len(args):
                    return args[i + 1]
        if st.name == "eval":
            return " ".join(a.text for a in st.args if not a.subs) or None
        return None

    def _deletes(self, st: Stage, line: int | None, snippet: str) -> None:
        name = st.name
        args = [a.text for a in st.args]
        targets: list[str] = []
        if name == "rm":
            flags = "".join(a.lstrip("-") for a in args if a.startswith("-") and not a.startswith("--"))
            long = {a for a in args if a.startswith("--")}
            if ("r" in flags.lower() or "--recursive" in long) and ("f" in flags or "--force" in long):
                targets = [a for a in args if not a.startswith("-")]
        elif name == "remove-item" or name in ("rd", "rmdir", "del"):
            low = [a.lower() for a in args]
            if ("-recurse" in low and "-force" in low) or ("/s" in low and "/q" in low):
                targets = [a for a in args if not a.startswith(("-", "/s", "/q", "/S", "/Q"))]
        elif name == "find" and "-delete" in args:
            targets = [args[0]] if args and not args[0].startswith("-") else ["."]
        if not targets:
            return
        worst = max((_delete_target(t) for t in targets), key=_RANK.__getitem__)
        self.add("fs.delete", line, snippet, target=worst)

    def _installs(self, st: Stage, line: int | None, snippet: str) -> None:
        name = st.name
        args = [a.text.lower() for a in st.args]
        if name in PKG and args and args[0] in PKG_VERBS:
            self.add("pkg.install", line, snippet)
        elif name in PKG and len(args) >= 2 and args[0] == "pip" and args[1] in PKG_VERBS:
            self.add("pkg.install", line, snippet)
        elif name in ("python", "python3", "py") and args[:2] == ["-m", "pip"] and len(args) > 2 and args[2] in PKG_VERBS:
            self.add("pkg.install", line, snippet)
        elif name in ("npx", "bunx") and any(a in ("-y", "--yes") for a in args):
            self.add("pkg.install", line, snippet)
        elif name in ("uvx", "pipx") and args and (name == "uvx" or args[0] == "run"):
            self.add("pkg.install", line, snippet)

    def _writes(self, st: Stage, line: int | None, snippet: str, sources: set[str]) -> None:
        targets = [t.text for op, t in st.redirects if op in (">", ">>", "&>", ">|") and t.text]
        if st.name in ("cp", "mv", "install", "ln") and len(st.args) >= 2:
            targets.append(st.args[-1].text)
        if st.name == "tee":
            targets += [a.text for a in st.args if not a.text.startswith("-")]
        for target in targets:
            norm = _norm_path(target)
            if sources:
                self.tainted_files[norm] = sorted(sources)[0]
            if any(p in norm for p in PROFILE_FILES):
                self.add("persist", line, snippet)
            elif any(f"/{d}" in norm or norm.startswith(f"~/{d}") or norm.startswith(d) for d in AGENT_DIRS) and (
                    norm.startswith("~") or norm.startswith("/")):
                self.add("agent.config", line, snippet)
            elif norm.startswith("~") or (norm.startswith("/") and not norm.startswith(("/tmp", "/dev/", "/var/tmp"))):
                self.add("fs.write.outside", line, snippet)
        if st.name == "crontab" and [a.text for a in st.args] != ["-l"]:
            self.add("persist", line, snippet)
        args = [a.text.lower() for a in st.args]
        if (st.name == "systemctl" and "enable" in args) or (st.name == "launchctl" and ("load" in args or "bootstrap" in args)) \
                or (st.name == "schtasks" and "/create" in args) or (st.name == "reg" and args[:1] == ["add"] and any("\\run" in a for a in args)):
            self.add("persist", line, snippet)
        if st.name in ("claude", "codex") and args[:2] in (["mcp", "add"], ["config", "set"], ["plugin", "install"]):
            self.add("agent.config", line, snippet)


def logical_lines(text: str) -> list[tuple[int, str]]:
    """Join backslash continuations; return (first physical line number, text)."""
    out: list[tuple[int, str]] = []
    buf: list[str] = []
    start = 1
    for number, raw in enumerate(text.split("\n"), start=1):
        if not buf:
            start = number
        if raw.endswith("\\") and not raw.endswith("\\\\"):
            buf.append(raw[:-1])
            continue
        buf.append(raw)
        out.append((start, " ".join(buf)))
        buf = []
    if buf:
        out.append((start, " ".join(buf)))
    return out


def _skip_heredocs(lines: list[tuple[int, str]]) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    terminator: str | None = None
    for number, line in lines:
        if terminator is not None:
            if line.strip() == terminator:
                terminator = None
            continue
        m = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)['\"]?", line)
        if m and "<<<" not in line:
            terminator = m.group(1)
        out.append((number, line))
    return out


def analyze(entry: FileEntry) -> list[Capability]:
    analyzer = ShellAnalyzer(entry.rel)
    for number, line in _skip_heredocs(logical_lines(entry.text or "")):
        if line.strip():
            analyzer.run(line, number)
    return analyzer.caps


def analyze_command(text: str, file: str, line: int | None, confidence: str = "high") -> list[Capability]:
    analyzer = ShellAnalyzer(file, confidence)
    for offset, (_, part) in enumerate(logical_lines(text)):
        if part.strip():
            analyzer.run(part, line)
    return analyzer.caps
