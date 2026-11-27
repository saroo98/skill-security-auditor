"""Resolve a skill address and download its archive. Nothing downloaded is ever run."""

from __future__ import annotations

import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

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


def _codeload(owner: str, repo: str, ref: str) -> str:
    return f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"


def _github(owner: str, repo: str, rest: list[str], display: str) -> Source:
    repo = repo[:-4] if repo.endswith(".git") else repo
    owner_repo = f"{owner}/{repo}"
    if len(rest) >= 2 and rest[0] in ("tree", "blob"):
        ref, path = rest[1], rest[2:]
        if rest[0] == "blob" and path and path[-1] == "SKILL.md":
            path = path[:-1]
        return Source("url", _codeload(owner, repo, ref), "/".join(path), display, owner_repo, ambiguous_ref=bool(path))
    if rest:
        raise FetchError(f"cannot tell what this address is: {display}")
    return Source("url", _codeload(owner, repo, "HEAD"), "", display, owner_repo)


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
        raise FetchError(f"only https addresses are accepted: {address}")
    if address.lower().startswith("https://"):
        parsed = urlparse(address)
        host = (parsed.hostname or "").lower()
        parts = [p for p in parsed.path.split("/") if p]
        if host in ("github.com", "www.github.com") and len(parts) >= 2:
            return _github(parts[0], parts[1], parts[2:], address)
        if parsed.path.lower().endswith(ARCHIVE_SUFFIXES):
            return Source("url", address, "", address, None)
        raise FetchError(f"cannot tell what this address is: {address}")
    if _SHORTHAND.match(address) and "\\" not in address:
        parts = [p for p in address.split("/") if p]
        owner, repo, sub = parts[0], parts[1], "/".join(parts[2:])
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


def download(url: str, dest: Path, *, max_bytes: int = MAX_BYTES, timeout: float = 30.0, opener=None,
             source: Source | None = None) -> Path:
    if not url.lower().startswith("https://"):
        raise FetchError(f"only https addresses are accepted: {url}")
    opener = opener or default_opener()
    request = urllib.request.Request(url, headers={"User-Agent": "skillaudit"})
    dest = Path(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + ".part")
    try:
        with opener.open(request, timeout=timeout) as response:
            final = response.geturl() if hasattr(response, "geturl") else url
            if not str(final).lower().startswith("https://"):
                raise FetchError(f"refused redirect to a non-https address: {final} (from {url})")
            total = 0
            with open(tmp, "wb") as out:
                while True:
                    chunk = response.read(CHUNK)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise FetchError(f"download larger than {max_bytes // (1024 * 1024)} MB: {url}")
                    out.write(chunk)
    except FetchError:
        _remove(tmp)
        raise
    except urllib.error.HTTPError as exc:
        _remove(tmp)
        if exc.code == 404 and source is not None and source.ambiguous_ref:
            raise FetchError(f'ref not found; if the branch name contains "/", pass the archive address instead: {url}') from None
        if exc.code == 404:
            raise FetchError(f"not found (404); the repository may be private or the address wrong: {url}") from None
        raise FetchError(f"server answered {exc.code} {exc.reason}: {url}") from None
    except urllib.error.URLError as exc:
        _remove(tmp)
        raise FetchError(f"could not connect ({_one_line(exc.reason)}): {url}") from None
    except (TimeoutError, OSError) as exc:
        _remove(tmp)
        raise FetchError(f"download failed ({_one_line(exc) or type(exc).__name__}): {url}") from None
    os.replace(tmp, dest)
    return dest


def _one_line(value: object) -> str:
    return " ".join(str(value).split())


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
