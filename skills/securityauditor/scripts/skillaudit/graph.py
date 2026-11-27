"""Which files point at which: used to decide what is reachable from a skill's instructions and code,
and what a skill says about itself."""

from __future__ import annotations

import posixpath
import re

from .model import FileEntry

_LINK = re.compile(r"\]\(([^)\s#]+)(?:#[^)]*)?(?:\s+\"[^\"]*\")?\)")
_TICK = re.compile(r"`([^`\n]+)`")
_PATH = re.compile(r"(?:\$\{?[A-Z_]+\}?/|\./|\.\./)?(?:[\w.@-]+/)*[\w@-][\w.@-]*\.[A-Za-z0-9]{1,6}\b")
_ROOT_VAR = re.compile(r"^\$\{?[A-Z_]+\}?/")
_PY_IMPORT = re.compile(r"^\s*(?:from\s+(\.*)([\w.]*)\s+import\s+([\w, ]+)|import\s+([\w., ]+))", re.MULTILINE)
_JS_IMPORT = re.compile(r"(?:require\(\s*|from\s+|import\s*\(\s*)['\"](\.{1,2}/[^'\"]+)['\"]")
_URLISH = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)

LEXICON: dict[str, tuple[str, ...]] = {
    "net.outbound": ("network", "http", "https", "api", "download", "fetch", "upload", "web", "url", "online", "request",
                     "internet", "server", "endpoint", "webhook", "remote"),
    "exec.shell": ("shell", "command", "commands", "script", "scripts", "run", "runs", "execute", "cli", "terminal", "bash",
                   "subprocess"),
    "secret.read": ("credential", "credentials", "ssh key", "ssh keys", "token file", ".env", "keychain", "secrets"),
    "persist": ("hook", "hooks", "startup", "schedule", "scheduled", "cron", "background", "on session start", "autostart"),
    "pkg.install": ("install", "installs", "dependency", "dependencies", "pip", "npm", "package", "packages"),
    "fs.write.outside": ("home directory", "config file", "dotfile", "dotfiles", "profile", "settings file"),
}


def _candidates(token: str) -> list[str]:
    t = token.strip().strip("'\"(),;:")
    if not t or _URLISH.match(t) or t.startswith(("/", "~", "#", "mailto:")):
        return []
    t = _ROOT_VAR.sub("", t)
    return [t]


def _resolve(cand: str, base_dir: str, all_rels: set[str]) -> str | None:
    joined = posixpath.normpath(posixpath.join(base_dir, cand)) if base_dir else posixpath.normpath(cand)
    if joined in all_rels:
        return joined
    norm = posixpath.normpath(cand).lstrip("./")
    if norm in all_rels:
        return norm
    matches = [r for r in all_rels if r.endswith("/" + norm)]
    return matches[0] if len(matches) == 1 else (sorted(matches, key=len)[0] if matches else None)


def _tokens(entry: FileEntry) -> list[str]:
    text = entry.text or ""
    out: list[str] = []
    if entry.kind == "markdown":
        out += _LINK.findall(text)
        for span in _TICK.findall(text):
            out += span.split()
        out += _PATH.findall(text)
    else:
        out += _PATH.findall(text)
    if entry.kind == "javascript":
        out += _JS_IMPORT.findall(text)
    return out


def references(files: list[FileEntry], all_rels: set[str] | None = None) -> dict[str, set[str]]:
    rels = set(all_rels or ()) | {f.rel for f in files}
    refs: dict[str, set[str]] = {}
    for entry in files:
        base = posixpath.dirname(entry.rel)
        found: set[str] = set()
        for token in _tokens(entry):
            for cand in _candidates(token):
                target = _resolve(cand, base, rels)
                if target and target != entry.rel:
                    found.add(target)
        if entry.kind == "python":
            for dots, module, names, plain in _PY_IMPORT.findall(entry.text or ""):
                mods = [m.strip() for m in (plain or "").split(",") if m.strip()]
                if module:
                    mods.append(module)
                if dots and not module:
                    mods += [n.strip() for n in names.split(",") if n.strip()]
                for mod in mods:
                    path = mod.replace(".", "/")
                    for cand in (f"{path}.py", f"{path}/__init__.py"):
                        joined = posixpath.normpath(posixpath.join(base, cand)) if base else cand
                        if joined in rels:
                            found.add(joined)
        refs[entry.rel] = found
    return refs


def reachable(files: list[FileEntry], refs: dict[str, set[str]]) -> set[str]:
    roots = [f.rel for f in files if f.role in ("instruction", "executable", "config")]
    seen = set(roots)
    stack = list(roots)
    while stack:
        current = stack.pop()
        for target in refs.get(current, ()):
            if target not in seen:
                seen.add(target)
                stack.append(target)
    return seen


def referenced_from_instructions(files: list[FileEntry], refs: dict[str, set[str]]) -> set[str]:
    roots = [f.rel for f in files if f.role in ("instruction", "config")]
    out: set[str] = set()
    for r in roots:
        out |= refs.get(r, set())
    return out


def missing_references(files: list[FileEntry], refs: dict[str, set[str]], all_rels: set[str] | None = None) -> list[tuple[str, str]]:
    rels = set(all_rels or ()) | {f.rel for f in files}
    out: list[tuple[str, str]] = []
    for entry in files:
        if entry.role != "instruction":
            continue
        base = posixpath.dirname(entry.rel)
        text = entry.text or ""
        tokens = list(_LINK.findall(text))
        for span in _TICK.findall(text):
            tokens += [t for t in span.split() if "/" in t and re.search(r"\.[A-Za-z0-9]{1,6}$", t)]
        for token in tokens:
            for cand in _candidates(token):
                if "<" in cand or "*" in cand:
                    continue
                if _resolve(cand, base, rels) is None and (entry.rel, cand) not in out:
                    out.append((entry.rel, cand))
    return out


def declared(skill_md_text: str, frontmatter: dict) -> set[str]:
    text = " ".join([str(frontmatter.get("description", "")), skill_md_text or ""]).lower()
    words = set(re.findall(r"[a-z0-9.]+", text))
    out: set[str] = set()
    for kind, terms in LEXICON.items():
        for term in terms:
            if (" " in term and term in text) or term in words:
                out.add(kind)
                break
    return out
