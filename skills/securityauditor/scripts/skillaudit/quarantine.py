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
_RESERVED = re.compile(r"(?:con|conin\$|conout\$|prn|aux|nul|(?:com|lpt)[1-9\u00b9\u00b2\u00b3])", re.IGNORECASE)
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
        if _RESERVED.fullmatch(part.partition(".")[0].rstrip(" ")):
            raise UnsafeArchive(f"reserved Windows name in member path: {name!r}")
        if part.endswith((".", " ")):
            raise UnsafeArchive(f"member name ends with a dot or space: {name!r}")
        if any(ord(c) < 32 for c in part) or any(c in part for c in '<>:"|?*'):
            raise UnsafeArchive(f"invalid character in member name: {name!r}")
    return parts


def _members(archive: Path, max_files: int, max_total: int,
             links: list[list[str]] | None = None) -> list[tuple[list[str], object, str]]:
    """Return (parts, handle, kind) for regular files; directories are implied. Raise on anything unsafe."""
    out: list[tuple[list[str], object, str]] = []
    seen: dict[str, tuple[str, bool]] = {}
    total = 0

    def register(parts: list[str], file: bool) -> None:
        if file and not parts:
            raise UnsafeArchive("archive file has an empty member path")
        prefix = ""
        for index, part in enumerate(parts):
            prefix = f"{prefix}/{part}" if prefix else part
            key = prefix.casefold()
            is_file = file and index == len(parts) - 1
            previous = seen.get(key)
            if previous is not None:
                old_path, old_is_file = previous
                if is_file != old_is_file:
                    raise UnsafeArchive(f"a file and directory share a path: {prefix!r}")
                if prefix != old_path:
                    raise UnsafeArchive(f"two members differ only by case: {old_path!r} and {prefix!r}")
                if is_file:
                    raise UnsafeArchive(f"duplicate archive member path: {prefix!r}")
            else:
                seen[key] = (prefix, is_file)

    name = archive.name.lower()
    if name.endswith(".zip"):
        zf = zipfile.ZipFile(archive)
        for info in zf.infolist():
            parts = _check_name(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                if links is None:
                    raise UnsafeArchive(f"symbolic link in archive: {info.filename!r}")
                links.append(parts)
                continue
            is_dir = info.is_dir()
            register(parts, file=not is_dir)
            if is_dir:
                continue
            total += info.file_size
            out.append((parts, (zf, info), "zip"))
    elif name.endswith((".tar.gz", ".tgz", ".tar")):
        tf = tarfile.open(archive, "r:*")
        for info in tf.getmembers():
            parts = _check_name(info.name)
            if info.issym() or info.islnk():
                if links is None:
                    raise UnsafeArchive(f"link in archive: {info.name!r}")
                links.append(parts)
                continue
            if info.isdir():
                register(parts, file=False)
                continue
            if not info.isfile():
                raise UnsafeArchive(f"special file in archive: {info.name!r}")
            register(parts, file=True)
            total += info.size
            out.append((parts, (tf, info), "tar"))
    else:
        raise UnsafeArchive(f"unsupported archive type: {archive.name}")
    if len(out) > max_files:
        raise UnsafeArchive(f"archive has more than {max_files} files")
    if total > max_total:
        raise UnsafeArchive(f"archive expands past the size limit of {max_total} bytes")
    return out


def extract(archive: Path, dest: Path, *, max_files: int = MAX_FILES, max_total_bytes: int = MAX_TOTAL) -> Path:
    """Extract regular files; any link, device or unsafe name refuses the whole archive."""
    return _extract(archive, dest, max_files, max_total_bytes, None)


def extract_skipping_links(archive: Path, dest: Path, *, max_files: int = MAX_FILES,
                           max_total_bytes: int = MAX_TOTAL) -> tuple[Path, list[str]]:
    """Like extract, but links are left out instead of refusing the archive; returns their paths."""
    links: list[list[str]] = []
    out = _extract(archive, dest, max_files, max_total_bytes, links)
    return out, sorted("/".join(p) for p in links)


def _extract(archive: Path, dest: Path, max_files: int, max_total_bytes: int, links: list[list[str]] | None) -> Path:
    archive, dest = Path(archive), Path(dest)
    try:
        members = _members(archive, max_files, max_total_bytes, links)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
        raise UnsafeArchive(f"cannot read archive: {exc}") from None
    tops = {parts[0] for parts, _, _ in members if len(parts) > 1}
    strip = len(tops) == 1 and all(len(parts) > 1 for parts, _, _ in members)
    if links is not None and strip:
        links[:] = [p[1:] if len(p) > 1 and p[0] in tops else p for p in links]
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


def archive_commit(archive: Path) -> str | None:
    """GitHub tarballs record the commit in a pax global header comment."""
    name = Path(archive).name.lower()
    if not name.endswith((".tar.gz", ".tgz", ".tar")):
        return None
    try:
        with tarfile.open(archive, "r:*") as tf:
            comment = tf.pax_headers.get("comment", "")
    except (tarfile.TarError, OSError, EOFError):
        return None
    return comment if re.fullmatch(r"[0-9a-f]{40}", comment or "") else None


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
            try:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError as exc:  # e.g. antivirus refused to open the file
                digest = f"unreadable:{exc.errno}"
            lines.append(f"{rel}\0{digest}\n")
    lines.sort()
    return hashlib.sha256("".join(lines).encode("utf-8", "surrogatepass")).hexdigest()


def _copy_tree(src: Path, dest: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if not (here / d).is_symlink())
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
    links: list[str] = []
    try:
        if source.kind == "dir":
            _copy_tree(Path(source.location), staging / "t")
        else:
            archive = Path(fetched) if fetched is not None else Path(source.location)
            _, links = extract_skipping_links(archive, staging / "t")
        digest = tree_hash(staging / "t")
        link_data = json.dumps(links)
        pending_links = staging / "links.json"
        pending_links.write_text(link_data, encoding="utf-8")
        alternate = hashlib.sha256(f"{digest}\0{link_data}".encode()).hexdigest()
        for check_id in (digest[:12], alternate):
            final = qroot / check_id
            link_record = qroot / f"{check_id}.links.json"
            if not final.exists() and not final.is_symlink():
                try:
                    os.rename(staging / "t", final)
                except OSError:
                    if not final.exists():
                        raise
                else:
                    os.replace(pending_links, link_record)
                    return check_id, final
            try:
                existing_links = link_record.read_text(encoding="utf-8")
            except (OSError, ValueError):
                continue
            if final.is_dir() and not final.is_symlink() and existing_links == link_data and tree_hash(final) == digest:
                return check_id, final
        raise UnsafeArchive("existing quarantine entries differ from the fetched files")
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def skipped_links(qdir: Path) -> list[str]:
    """Links that were in the archive but not extracted into this quarantine folder."""
    try:
        return list(json.loads((Path(qdir).parent / f"{Path(qdir).name}.links.json").read_text(encoding="utf-8")))
    except (OSError, ValueError):
        return []


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
