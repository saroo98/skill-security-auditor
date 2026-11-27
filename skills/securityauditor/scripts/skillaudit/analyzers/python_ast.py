"""Python analyzer built on the ast module. Parses only; never imports or runs the code."""

from __future__ import annotations

import ast
from urllib.parse import urlparse

from ..data import is_secret_name, is_secret_path
from ..model import Capability, FileEntry
from . import shell

EXEC_SHELL = {
    "subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
    "subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen", "pty.spawn",
    "asyncio.create_subprocess_shell", "asyncio.create_subprocess_exec", "commands.getoutput",
}
EXEC_PREFIXES = ("os.exec", "os.spawn", "os.posix_spawn")
DYNAMIC = {"eval", "exec", "compile", "__import__", "importlib.import_module", "pickle.loads", "pickle.load",
           "marshal.loads", "dill.loads", "runpy.run_path", "runpy.run_module", "types.FunctionType"}
DECODERS = {"base64.b64decode", "base64.b32decode", "base64.b85decode", "base64.a85decode", "base64.decodebytes",
            "bytes.fromhex", "binascii.unhexlify", "binascii.a2b_base64", "codecs.decode", "zlib.decompress",
            "gzip.decompress", "lzma.decompress", "bz2.decompress"}
NET_FUNCS = {"urllib.request.urlopen", "urllib.request.Request", "urllib.request.urlretrieve", "urllib2.urlopen",
             "http.client.HTTPConnection", "http.client.HTTPSConnection", "socket.socket", "socket.create_connection",
             "ftplib.FTP", "ftplib.FTP_TLS", "smtplib.SMTP", "smtplib.SMTP_SSL", "aiohttp.ClientSession",
             "websocket.create_connection", "websockets.connect", "telnetlib.Telnet", "paramiko.SSHClient"}
NET_PREFIXES = ("requests.", "httpx.", "urllib3.", "aiohttp.")
HTTP_VERBS = {"get", "post", "put", "patch", "delete", "head", "request", "urlopen", "send", "fetch", "stream", "options"}
DELETE = {"shutil.rmtree"}
READ_METHODS = {"read_text", "read_bytes"}


def _dotted(node: ast.AST, aliases: dict[str, str]) -> str | None:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value, aliases)
        return f"{base}.{node.attr}" if base else None
    if isinstance(node, ast.Call):
        return _dotted(node.func, aliases)
    return None


class _Folder:
    def __init__(self, aliases: dict[str, str], consts: dict[str, str]) -> None:
        self.aliases, self.consts = aliases, consts

    def fold(self, node: ast.AST | None) -> str | None:
        if node is None:
            return None
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            v = node.value
            return v.decode("utf-8", "replace") if isinstance(v, bytes) else v
        if isinstance(node, ast.Name):
            return self.consts.get(node.id)
        if isinstance(node, ast.JoinedStr):
            parts = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    parts.append(str(v.value))
                elif isinstance(v, ast.FormattedValue):
                    inner = self.fold(v.value)
                    if inner is None:
                        return None
                    parts.append(inner)
            return "".join(parts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Div)):
            left, right = self.fold(node.left), self.fold(node.right)
            if left is None or right is None:
                return None
            return f"{left.rstrip('/')}/{right.lstrip('/')}" if isinstance(node.op, ast.Div) else left + right
        if isinstance(node, ast.Call):
            name = _dotted(node.func, self.aliases) or ""
            short = name.rsplit(".", 1)[-1]
            if name in ("pathlib.Path.home", "Path.home", "os.path.expanduser") and not node.args or name.endswith("Path.home"):
                return "~"
            if name in ("os.path.expanduser", "os.path.expandvars", "os.path.abspath", "os.path.realpath", "str") and node.args:
                return self.fold(node.args[0])
            if name in ("os.path.join", "posixpath.join", "ntpath.join") or name.endswith("PurePath") or short in ("Path", "PosixPath", "WindowsPath", "PurePosixPath"):
                parts = [self.fold(a) for a in node.args]
                if not parts or any(p is None for p in parts):
                    return None
                return "/".join(p.strip("/") if i else p.rstrip("/") for i, p in enumerate(parts))
            if isinstance(node.func, ast.Attribute) and node.func.attr in ("expanduser", "resolve", "absolute") and not node.args:
                return self.fold(node.func.value)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "joinpath":
                base = self.fold(node.func.value)
                parts = [self.fold(a) for a in node.args]
                if base is None or any(p is None for p in parts):
                    return None
                return "/".join([base.rstrip("/")] + [p.strip("/") for p in parts])
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join" and isinstance(node.func.value, ast.Constant) \
                    and node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                parts = [self.fold(e) for e in node.args[0].elts]
                if any(p is None for p in parts):
                    return None
                return str(node.func.value.value).join(parts)
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format" and isinstance(node.func.value, ast.Constant):
                try:
                    args = [self.fold(a) for a in node.args]
                    if any(a is None for a in args):
                        return None
                    return str(node.func.value.value).format(*args)
                except (IndexError, KeyError, ValueError):
                    return None
        return None


def _host_of(text: str | None) -> str | None:
    if not text:
        return None
    if "://" in text:
        try:
            return urlparse(text).hostname
        except ValueError:
            return None
    if "/" not in text and "." in text and " " not in text:
        return text
    return None


def _home_norm(path: str) -> str:
    p = path.replace("\\", "/")
    for prefix in ("$HOME", "${HOME}", "%USERPROFILE%"):
        if p.startswith(prefix):
            p = "~" + p[len(prefix):]
    return p


class _Analyzer:
    def __init__(self, entry: FileEntry, tree: ast.Module) -> None:
        self.entry = entry
        self.lines = (entry.text or "").splitlines()
        self.caps: list[Capability] = []
        self.aliases: dict[str, str] = {}
        self.consts: dict[str, str] = {}
        self.parents: dict[ast.AST, ast.AST] = {}
        self.tree = tree
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                self.parents[child] = node
        self._imports()
        self.folder = _Folder(self.aliases, self.consts)
        self._constants()

    def snippet(self, node: ast.AST) -> str:
        line = getattr(node, "lineno", None)
        return self.lines[line - 1].strip() if line and line <= len(self.lines) else ""

    def add(self, kind: str, node: ast.AST, **detail: str | None) -> None:
        cap = Capability(kind, self.entry.rel, getattr(node, "lineno", None), self.snippet(node)[:300], "high",
                         tuple(sorted((k, v) for k, v in detail.items() if v)))
        if cap not in self.caps:
            self.caps.append(cap)

    def _imports(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.aliases[a.asname] = a.name
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                for a in node.names:
                    self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"

    def _constants(self) -> None:
        for node in self.tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                value = self.folder.fold(node.value)
                if value is not None:
                    self.consts[node.targets[0].id] = value

    def name(self, call: ast.Call) -> str:
        return _dotted(call.func, self.aliases) or ""

    # -- classification of expressions -------------------------------------------------------
    def is_network(self, call: ast.Call) -> bool:
        n = self.name(call)
        if n in NET_FUNCS or n.startswith(NET_PREFIXES):
            return True
        if isinstance(call.func, ast.Attribute) and call.func.attr in HTTP_VERBS and call.args:
            target = self.folder.fold(call.args[0])
            return bool(target and target.lower().startswith(("http://", "https://")))
        return False

    def net_host(self, call: ast.Call) -> str | None:
        for arg in list(call.args[:1]) + [k.value for k in call.keywords if k.arg in ("url", "host")]:
            host = _host_of(self.folder.fold(arg))
            if host:
                return host
        return None

    def secret_read(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        n = self.name(node)
        if n in ("open", "io.open", "codecs.open", "builtins.open", "shutil.copy", "shutil.copyfile", "shutil.copy2") and node.args:
            p = self.folder.fold(node.args[0])
            return bool(p and is_secret_path(_home_norm(p)))
        if isinstance(node.func, ast.Attribute) and node.func.attr in READ_METHODS | {"open"}:
            p = self.folder.fold(node.func.value)
            return bool(p and is_secret_path(_home_norm(p)))
        return False

    def secret_use(self, node: ast.AST) -> str | None:
        key = self.env_key(node)
        return key if key and is_secret_name(key) else None

    def env_key(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Subscript) and _dotted(node.value, self.aliases) == "os.environ":
            return self.folder.fold(node.slice)
        if isinstance(node, ast.Call):
            n = self.name(node)
            if n in ("os.environ.get", "os.getenv", "os.environ.setdefault", "os.environ.pop") and node.args:
                return self.folder.fold(node.args[0])
        return None

    def is_env_dump(self, node: ast.AST) -> bool:
        if _dotted(node, self.aliases) != "os.environ" or not isinstance(node, (ast.Attribute, ast.Name)):
            return False
        parent = self.parents.get(node)
        if isinstance(parent, ast.Subscript) and parent.value is node:
            return False
        if isinstance(parent, ast.Attribute) and parent.attr in ("get", "setdefault", "pop", "__getitem__", "__setitem__", "update"):
            return False
        if isinstance(parent, ast.Compare):
            return False
        if isinstance(parent, ast.Assign) and node in parent.targets:
            return False
        cur = node
        while cur in self.parents:
            p = self.parents[cur]
            if isinstance(p, ast.keyword) and p.arg == "env":
                return False
            cur = p
        return True

    # -- scopes and taint --------------------------------------------------------------------
    def _scopes(self) -> list[list[ast.stmt]]:
        scopes = [self.tree.body]
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scopes.append(node.body)
        return scopes

    def _scope_nodes(self, body: list[ast.stmt]) -> list[ast.AST]:
        out: list[ast.AST] = []
        stack = list(reversed(body))
        while stack:
            node = stack.pop()
            out.append(node)
            for child in reversed(list(ast.iter_child_nodes(node))):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                    continue
                stack.append(child)
        return out

    def _sources_in(self, node: ast.AST, taint: dict[str, tuple[str, str | None]]) -> list[tuple[str, str | None]]:
        found: list[tuple[str, str | None]] = []
        for sub in ast.walk(node):
            if self.secret_read(sub):
                found.append(("secret.read", None))
            elif self.is_env_dump(sub):
                found.append(("env.dump", None))
            else:
                key = self.secret_use(sub)
                if key:
                    found.append(("secret.use", key))
            if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load) and sub.id in taint:
                found.append(taint[sub.id])
        return found

    def _contains_network(self, node: ast.AST, net_names: set[str]) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and self.is_network(sub):
                return True
            if isinstance(sub, ast.Name) and sub.id in net_names:
                return True
        return False

    def _contains_decode(self, node: ast.AST, decoded: set[str]) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and self.name(sub) in DECODERS:
                return True
            if isinstance(sub, ast.Name) and sub.id in decoded:
                return True
        return False

    def run(self) -> list[Capability]:
        for body in self._scopes():
            nodes = self._scope_nodes(body)
            taint: dict[str, tuple[str, str | None]] = {}
            net_names: set[str] = set()
            decoded: set[str] = set()
            assigns = sorted((n for n in nodes if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))),
                             key=lambda n: (n.lineno, n.col_offset))
            for _ in range(2):
                for a in assigns:
                    value = a.value
                    if value is None:
                        continue
                    targets = a.targets if isinstance(a, ast.Assign) else [a.target]
                    names = [t.id for t in targets if isinstance(t, ast.Name)]
                    srcs = self._sources_in(value, taint)
                    for n in names:
                        if srcs:
                            taint[n] = srcs[0]
                        if self._contains_network(value, net_names):
                            net_names.add(n)
                        if self._contains_decode(value, decoded):
                            decoded.add(n)
            for node in nodes:
                if isinstance(node, ast.Call):
                    self._call(node, taint, net_names, decoded)
                elif self.is_env_dump(node):
                    self.add("env.dump", node)
                elif isinstance(node, ast.Subscript):
                    key = self.env_key(node)
                    if key:
                        self.add("secret.use" if is_secret_name(key) else "env.read", node)
        return self.caps

    def _call(self, call: ast.Call, taint, net_names, decoded) -> None:
        n = self.name(call)
        short = n.rsplit(".", 1)[-1]
        if self.secret_read(call):
            self.add("secret.read", call)
        key = self.env_key(call)
        if key:
            self.add("secret.use" if is_secret_name(key) else "env.read", call)

        if n in EXEC_SHELL or n.startswith(EXEC_PREFIXES):
            first = call.args[0] if call.args else next((k.value for k in call.keywords if k.arg in ("args", "cmd")), None)
            command = self.folder.fold(first)
            if command is None and isinstance(first, (ast.List, ast.Tuple)):
                parts = [self.folder.fold(e) for e in first.elts]
                if all(p is not None for p in parts):
                    command = " ".join(parts)
            self.add("exec.shell", call, constant="yes" if command is not None else "no")
            if command:
                for cap in shell.analyze_command(command, self.entry.rel, call.lineno):
                    self.caps.append(Capability(cap.kind, cap.file, cap.line, self.snippet(call)[:300], cap.confidence, cap.detail))
        if n == "pip.main" or (short == "main" and n.startswith("pip.")):
            self.add("pkg.install", call)

        if n in DYNAMIC or short in ("eval", "exec") and n in ("builtins.eval", "builtins.exec"):
            arg = call.args[0] if call.args else None
            if arg is not None and self._contains_network(arg, net_names):
                self.add("exec.remote", call)
            elif arg is not None and self._contains_decode(arg, decoded):
                self.add("obfuscation", call, why="executes decoded data")
                self.add("exec.dynamic", call)
            elif arg is None or self.folder.fold(arg) is None:
                self.add("exec.dynamic", call)

        if n in DELETE and call.args:
            target = self.folder.fold(call.args[0])
            self.add("fs.delete", call, target=shell._delete_target(target) if target else "project")

        if self.is_network(call):
            host = self.net_host(call)
            self.add("net.outbound", call, host=host)
            seen: set[tuple[str, str | None]] = set()
            for node in list(call.args) + [k.value for k in call.keywords]:
                for src, secret in self._sources_in(node, taint):
                    if (src, secret) in seen:
                        continue
                    seen.add((src, secret))
                    self.add("flow", call, source=src, sink="net.outbound", host=host,
                             secret=secret if src == "secret.use" else None)


def analyze(entry: FileEntry) -> list[Capability]:
    text = entry.text or ""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return [Capability("obfuscation", entry.rel, None, "file does not parse as Python", "low", (("why", "unparseable"),))]
    try:
        return _Analyzer(entry, tree).run()
    except RecursionError:
        return [Capability("obfuscation", entry.rel, None, "file is too deeply nested to analyze", "low", (("why", "too deep"),))]
