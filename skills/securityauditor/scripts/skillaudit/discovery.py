"""Walk a target, decode and classify every file, and list what is not checked."""

from __future__ import annotations

import os
from pathlib import Path

from .model import FileEntry, NotChecked

MAX_LINE = 10_000

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
EXT_KIND = {
    ".py": "python",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell",
    ".ps1": "powershell", ".psm1": "powershell",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".jsx": "javascript",
    ".md": "markdown", ".mdx": "markdown",
    ".json": "json",
    ".yml": "yaml", ".yaml": "yaml",
    ".toml": "toml",
    ".txt": "text", ".cfg": "text", ".ini": "text", ".lock": "text", ".svg": "text",
    ".rb": "other-source", ".pl": "other-source", ".php": "other-source", ".go": "other-source",
    ".rs": "other-source", ".java": "other-source", ".lua": "other-source",
    ".bat": "other-source", ".cmd": "other-source",
    ".pdf": "document", ".docx": "document", ".xlsx": "document", ".pptx": "document",
    ".png": "media", ".jpg": "media", ".jpeg": "media", ".gif": "media", ".webp": "media",
    ".ico": "media", ".ttf": "media", ".otf": "media", ".woff": "media", ".woff2": "media",
}
BINARY_MAGIC = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"PK\x03\x04", b"\x1f\x8b")
CODE_KINDS = {"python", "shell", "powershell", "javascript", "other-source"}
INSTRUCTION_NAMES = {"SKILL.md", "AGENTS.md", "CLAUDE.md", ".cursorrules"}
CONFIG_NAMES = {"package.json", "settings.json", "settings.local.json", "hooks.json", ".mcp.json", "plugin.json", "openai.yaml"}
TEST_PARTS = {"tests", "test", "fixtures", "examples"}
NOT_CHECKED_SEVERITY = {"media": "info", "document": "medium", "other-source": "medium", "binary": "medium"}
NOT_CHECKED_REASON = {
    "media": "image or font, not analyzed",
    "document": "document format the tool cannot read",
    "other-source": "source language with no dedicated analyzer",
    "binary": "binary file, not analyzed",
}


def _decode(data: bytes) -> tuple[str | None, str | None]:
    if data.startswith(b"\xff\xfe"):
        return _try(data[2:], "utf-16-le")
    if data.startswith(b"\xfe\xff"):
        return _try(data[2:], "utf-16-be")
    if data.startswith(b"\xef\xbb\xbf"):
        return _try(data[3:], "utf-8-sig")
    head = data[:4096]
    if len(head) >= 4:
        even = head[0::2].count(0) / max(1, len(head[0::2]))
        odd = head[1::2].count(0) / max(1, len(head[1::2]))
        if odd > 0.3 and even < 0.05:
            return _try(data, "utf-16-le")
        if even > 0.3 and odd < 0.05:
            return _try(data, "utf-16-be")
    if b"\x00" in head:
        return None, None
    return _try(data, "utf-8")


def _try(data: bytes, encoding: str) -> tuple[str | None, str | None]:
    try:
        text = data.decode(encoding.replace("-sig", ""))
    except UnicodeDecodeError:
        return None, None
    return text.lstrip("﻿"), encoding


def _kind(name: str, data: bytes, text: str | None) -> str:
    if any(data.startswith(m) for m in BINARY_MAGIC):
        return "binary"
    suffix = os.path.splitext(name)[1].lower()
    if suffix in EXT_KIND:
        kind = EXT_KIND[suffix]
        if text is None and kind not in ("media", "document"):
            return "binary"
        return kind
    if text is None:
        return "binary"
    if text.startswith("#!"):
        first = text.split("\n", 1)[0]
        if "python" in first:
            return "python"
        if "node" in first:
            return "javascript"
        if "pwsh" in first or "powershell" in first:
            return "powershell"
        if any(sh in first for sh in ("bash", "zsh", "/sh", " sh", "dash")):
            return "shell"
        return "other-source"
    return "text"


def _role(rel: str, kind: str) -> str:
    parts = rel.split("/")
    name = parts[-1]
    if name in INSTRUCTION_NAMES:
        return "instruction"
    if any(p in TEST_PARTS for p in parts[:-1]):
        return "test"
    if name in CONFIG_NAMES or rel.startswith(".github/workflows/"):
        return "config"
    if kind in CODE_KINDS:
        return "executable"
    return "docs"


def _truncate_lines(text: str) -> tuple[str, list[int]]:
    if len(text) <= MAX_LINE and "\n" not in text:
        return text, []
    truncated: list[int] = []
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if len(line) > MAX_LINE:
            lines[i] = line[:MAX_LINE]
            truncated.append(i + 1)
    return ("\n".join(lines), truncated) if truncated else (text, [])


def discover(root: Path, *, max_file_size: int = 1_048_576, max_files: int = 2000) -> tuple[list[FileEntry], list[NotChecked]]:
    root = Path(root)
    files: list[FileEntry] = []
    not_checked: list[NotChecked] = []
    capped = False

    if root.is_file():
        candidates = [(root, root.name)]
        walk_root = None
    else:
        candidates = []
        walk_root = root

    def walk(directory: Path, prefix: str) -> None:
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError as exc:
            not_checked.append(NotChecked(prefix or ".", f"cannot list directory: {exc.strerror}", "medium"))
            return
        for entry in entries:
            rel = f"{prefix}{entry.name}"
            if entry.is_symlink():
                not_checked.append(NotChecked(rel, "symbolic link, not followed", "medium"))
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name in SKIP_DIRS:
                    not_checked.append(NotChecked(rel, "dependency or VCS directory", "info"))
                    continue
                walk(Path(entry.path), rel + "/")
            elif entry.is_file(follow_symlinks=False):
                candidates.append((Path(entry.path), rel))
            else:
                not_checked.append(NotChecked(rel, "special file, not read", "medium"))

    if walk_root is not None:
        walk(walk_root, "")

    for path, rel in candidates:
        if len(files) >= max_files:
            if not capped:
                not_checked.append(NotChecked(rel, f"file limit of {max_files} reached; remaining files not checked", "medium"))
                capped = True
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            not_checked.append(NotChecked(rel, f"cannot stat: {exc.strerror}", "medium"))
            continue
        if size > max_file_size:
            not_checked.append(NotChecked(rel, f"larger than {max_file_size} bytes", "medium"))
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            not_checked.append(NotChecked(rel, f"cannot read: {exc.strerror}", "medium"))
            continue
        text, encoding = _decode(data)
        kind = _kind(path.name, data, text)
        if kind in NOT_CHECKED_SEVERITY:
            not_checked.append(NotChecked(rel, NOT_CHECKED_REASON[kind], NOT_CHECKED_SEVERITY[kind]))
            if kind == "other-source" and text is not None:
                files.append(FileEntry(path, rel, kind, _role(rel, kind), text, encoding, size))
            continue
        assert text is not None
        text, truncated = _truncate_lines(text)
        for line in truncated:
            not_checked.append(NotChecked(rel, f"line {line} truncated at {MAX_LINE} characters", "medium"))
        files.append(FileEntry(path, rel, kind, _role(rel, kind), text, encoding, size))

    return files, not_checked
