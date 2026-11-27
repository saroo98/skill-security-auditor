"""Unpack a fetched skill into a quarantine folder, hash it, and cache verdicts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

from .fetch import Source

MAX_FILES = 2000
MAX_TOTAL = 100 * 1024 * 1024
_RESERVED = re.compile(r"^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$", re.IGNORECASE)
_DRIVE = re.compile(r"^[A-Za-z]:")


class UnsafeArchive(Exception):
    """The archive contains something that is not written to disk."""


def home() -> Path:
    env = os.environ.get("SKILLAUDIT_HOME")
    if env:
        return Path(env)
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        return Path(os.environ["LOCALAPPDATA"]) / "skillaudit"
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "skillaudit"


def _check_name(name: str) -> list[str]:
    if "\\" in name:
        raise UnsafeArchive(f"backslash in member name: {name!r}")
    if name.startswith("/") or _DRIVE.match(name):
        raise UnsafeArchive(f"absolute member path: {name!r}")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    for part in parts:
        if part == "..":
            raise UnsafeArchive(f"parent directory in member path: {name!r}")
        if _RESERVED.match(part):
            raise UnsafeArchive(f"reserved Windows name in member path: {name!r}")
        if part.endswith((".", " ")):
            raise UnsafeArchive(f"member name ends with a dot or space: {name!r}")
        if any(ord(c) < 32 for c in part) or any(c in part for c in '<>:"|?*'):
            raise UnsafeArchive(f"invalid character in member name: {name!r}")
    return parts


def _members(archive: Path, max_files: int, max_total: int) -> list[tuple[list[str], object, str]]:
    """Return (parts, handle, kind) for regular files; directories are implied. Raise on anything unsafe."""
    out: list[tuple[list[str], object, str]] = []
    total = 0
    name = archive.name.lower()
    if name.endswith(".zip"):
        zf = zipfile.ZipFile(archive)
        for info in zf.infolist():
            parts = _check_name(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise UnsafeArchive(f"symbolic link in archive: {info.filename!r}")
            if info.is_dir():
                continue
            total += info.file_size
            out.append((parts, (zf, info), "zip"))
    elif name.endswith((".tar.gz", ".tgz", ".tar")):
        tf = tarfile.open(archive, "r:*")
        for info in tf.getmembers():
            parts = _check_name(info.name)
            if info.issym() or info.islnk():
                raise UnsafeArchive(f"link in archive: {info.name!r}")
            if info.isdir():
                continue
            if not info.isfile():
                raise UnsafeArchive(f"special file in archive: {info.name!r}")
            total += info.size
            out.append((parts, (tf, info), "tar"))
    else:
        raise UnsafeArchive(f"unsupported archive type: {archive.name}")
    if len(out) > max_files:
        raise UnsafeArchive(f"archive has more than {max_files} files")
    if total > max_total:
        raise UnsafeArchive(f"archive expands past the size limit of {max_total} bytes")
    seen: dict[str, str] = {}
    for parts, _, _ in out:
        key = "/".join(parts).casefold()
        if key in seen:
            raise UnsafeArchive(f"two members differ only by case: {seen[key]!r}")
        seen[key] = "/".join(parts)
    return out


def extract(archive: Path, dest: Path, *, max_files: int = MAX_FILES, max_total_bytes: int = MAX_TOTAL) -> Path:
    archive, dest = Path(archive), Path(dest)
    try:
        members = _members(archive, max_files, max_total_bytes)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
        raise UnsafeArchive(f"cannot read archive: {exc}") from None
    tops = {parts[0] for parts, _, _ in members if len(parts) > 1}
    strip = len(tops) == 1 and all(len(parts) > 1 for parts, _, _ in members)
    staging = Path(tempfile.mkdtemp(prefix="extract-", dir=dest.parent if dest.parent.exists() else None))
    try:
        written = 0
        for parts, handle, kind in members:
            rel = parts[1:] if strip else parts
            target = staging.joinpath(*rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = handle[0].open(handle[1]) if kind == "zip" else handle[0].extractfile(handle[1])
            if source is None:
                raise UnsafeArchive(f"cannot read member: {'/'.join(parts)!r}")
            with source, open(target, "wb") as out:
                while chunk := source.read(65536):
                    written += len(chunk)
                    if written > max_total_bytes:
                        raise UnsafeArchive(f"archive expands past the size limit of {max_total_bytes} bytes")
                    out.write(chunk)
            os.chmod(target, 0o644)
        if dest.exists():
            shutil.rmtree(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        os.replace(staging, dest)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return dest


def tree_hash(root: Path) -> str:
    root = Path(root)
    lines: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            rel = path.relative_to(root).as_posix()
            lines.append(f"{rel}\0{hashlib.sha256(path.read_bytes()).hexdigest()}\n")
    lines.sort()
    return hashlib.sha256("".join(lines).encode("utf-8", "surrogatepass")).hexdigest()


def _copy_tree(src: Path, dest: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if not (here / d).is_symlink() and d != ".git")
        rel_dir = here.relative_to(src)
        (dest / rel_dir).mkdir(parents=True, exist_ok=True)
        for name in sorted(filenames):
            path = here / name
            if path.is_symlink() or not path.is_file():
                continue
            shutil.copyfile(path, dest / rel_dir / name)


def place(source: Source, fetched: Path | None) -> tuple[str, Path]:
    qroot = home() / "quarantine"
    qroot.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="incoming-", dir=qroot))
    try:
        if source.kind == "dir":
            _copy_tree(Path(source.location), staging / "t")
        else:
            archive = Path(fetched) if fetched is not None else Path(source.location)
            extract(archive, staging / "t")
        digest = tree_hash(staging / "t")
        check_id = digest[:12]
        final = qroot / check_id
        if final.exists():
            shutil.rmtree(staging, ignore_errors=True)
            return check_id, final
        os.replace(staging / "t", final)
        return check_id, final
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _cache_file(tree: str, ruleset: str) -> Path:
    return home() / "cache" / f"{tree}-{ruleset}.json"


def cache_get(tree: str, ruleset: str) -> dict | None:
    try:
        return json.loads(_cache_file(tree, ruleset).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def cache_put(tree: str, ruleset: str, payload: dict) -> None:
    path = _cache_file(tree, ruleset)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
