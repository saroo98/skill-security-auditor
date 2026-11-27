"""Resolve a skill address and download its archive. Nothing downloaded is ever run."""

from __future__ import annotations

import os
import re
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Generator
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from queue import Empty, Full, Queue
from threading import Event, Thread
from urllib.parse import ParseResult, urlparse

MAX_BYTES = 20 * 1024 * 1024
CHUNK = 64 * 1024
ARCHIVE_SUFFIXES = (".zip", ".tar.gz", ".tgz")
_SHORTHAND = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+(/[^\s]*)?$")


class FetchError(Exception):
    """A one-line, user-facing reason a skill could not be fetched."""


@dataclass(frozen=True)
class Source:
    kind: str  # "dir" | "archive" | "url"
    location: str
    subpath: str
    display: str
    owner_repo: str | None
    ambiguous_ref: bool = False


def _safe_subpath(parts: list[str], display: str) -> str:
    for part in parts:
        if part in (".", "..") or ".." in part or ":" in part or chr(92) in part or "%" in part or part.startswith("~"):
            raise FetchError(f"path inside the repository is not allowed: {display}")
    return "/".join(parts)


def _codeload(owner: str, repo: str, ref: str) -> str:
    return f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"


def _github(owner: str, repo: str, rest: list[str], display: str) -> Source:
    repo = repo[:-4] if repo.endswith(".git") else repo
    owner_repo = f"{owner}/{repo}"
    if len(rest) >= 2 and rest[0] in ("tree", "blob"):
        ref, path = rest[1], rest[2:]
        if rest[0] == "blob" and path and path[-1] == "SKILL.md":
            path = path[:-1]
        return Source("url", _codeload(owner, repo, ref), _safe_subpath(path, display), display, owner_repo,
                      ambiguous_ref=bool(path))
    if rest:
        raise FetchError(f"cannot tell what this address is: {display}")
    return Source("url", _codeload(owner, repo, "HEAD"), "", display, owner_repo)


def _parse_https(address: str) -> ParseResult:
    try:
        parsed = urlparse(address)
        if not parsed.hostname or parsed.port == 0 or any(c.isspace() or ord(c) < 32 for c in address):
            raise ValueError
    except ValueError:
        raise FetchError("invalid HTTPS address") from None
    if parsed.username is not None or parsed.password is not None:
        raise FetchError("credentials in HTTPS addresses are not supported")
    return parsed


def resolve(address: str) -> Source:
    address = address.strip()
    path = Path(address)
    if path.exists():
        if path.is_dir():
            return Source("dir", str(path), "", address, None)
        if address.lower().endswith(ARCHIVE_SUFFIXES):
            return Source("archive", str(path), "", address, None)
        raise FetchError(f"not a directory or a .zip/.tar.gz archive: {address}")
    if address.lower().startswith("http://"):
        raise FetchError("only https addresses are accepted")
    if address.lower().startswith("https://"):
        parsed = _parse_https(address)
        host = parsed.hostname
        parts = [p for p in parsed.path.split("/") if p]
        if host in ("github.com", "www.github.com") and len(parts) >= 2:
            return _github(parts[0], parts[1], parts[2:], address)
        if parsed.path.lower().endswith(ARCHIVE_SUFFIXES):
            return Source("url", address, "", address, None)
        raise FetchError(f"cannot tell what this address is: {address}")
    if _SHORTHAND.match(address) and "\\" not in address:
        parts = [p for p in address.split("/") if p]
        owner, repo, sub = parts[0], parts[1], _safe_subpath(parts[2:], address)
        repo = repo[:-4] if repo.endswith(".git") else repo
        return Source("url", _codeload(owner, repo, "HEAD"), sub, address, f"{owner}/{repo}")
    raise FetchError(f"cannot tell what this address is: {address}")


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise FetchError(f"refused redirect to a non-https address: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def default_opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_HttpsOnlyRedirect())


def _download_chunks(opener, request: urllib.request.Request, timeout: float) -> Generator[bytes, None, None]:
    """Apply one deadline across connection, redirects and reads. Only the caller writes to disk."""
    deadline = time.monotonic() + timeout
    received: Queue[bytes | Exception | None] = Queue(maxsize=2)
    cancelled = Event()

    def send(item: bytes | Exception | None) -> bool:
        while not cancelled.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                received.put(item, timeout=min(remaining, 0.1))
                return True
            except Full:
                continue
        return False

    def read_response() -> None:
        url = request.full_url
        try:
            with opener.open(request, timeout=timeout) as response:
                final = response.geturl() if hasattr(response, "geturl") else url
                if not str(final).lower().startswith("https://"):
                    raise FetchError(f"refused redirect to a non-https address: {final} (from {url})")
                read = getattr(response, "read1", response.read)
                while not cancelled.is_set():
                    chunk = read(CHUNK)
                    if not chunk or not send(chunk):
                        break
        except Exception as exc:
            send(exc)
        else:
            send(None)

    Thread(target=read_response, name="skillaudit-download", daemon=True).start()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("overall download deadline expired")
            try:
                item = received.get(timeout=remaining)
            except Empty:
                raise TimeoutError("overall download deadline expired") from None
            if item is None:
                return
            if isinstance(item, Exception):
                raise item
            yield item
    finally:
        cancelled.set()


def download(url: str, dest: Path, *, max_bytes: int = MAX_BYTES, timeout: float = 30.0, opener=None,
             source: Source | None = None) -> Path:
    if not url.lower().startswith("https://"):
        raise FetchError(f"only https addresses are accepted: {url}")
    _parse_https(url)
    opener = opener or default_opener()
    request = urllib.request.Request(url, headers={"User-Agent": "skillaudit"})
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=dest.parent, suffix=".part", delete=False) as out:
            tmp = Path(out.name)
            total = 0
            with closing(_download_chunks(opener, request, timeout)) as chunks:
                for chunk in chunks:
                    total += len(chunk)
                    if total > max_bytes:
                        raise FetchError(f"download larger than {max_bytes // (1024 * 1024)} MB: {url}")
                    out.write(chunk)
        os.replace(tmp, dest)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and source is not None and source.ambiguous_ref:
            raise FetchError(f'ref not found; if the branch name contains "/", pass the archive address instead: {url}') from None
        if exc.code == 404:
            raise FetchError(f"not found (404); the repository may be private or the address wrong: {url}") from None
        raise FetchError(f"server answered {exc.code} {exc.reason}: {url}") from None
    except urllib.error.URLError as exc:
        raise FetchError(f"could not connect ({_one_line(exc.reason)}): {url}") from None
    except (OSError, ValueError) as exc:
        raise FetchError(f"download failed ({_one_line(exc) or type(exc).__name__}): {url}") from None
    finally:
        if tmp is not None:
            _remove(tmp)
    return dest


def _one_line(value: object) -> str:
    return " ".join(str(value).split())


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
