"""python -m bench.fetch_real <dir>: download the public skill repositories in bench/sources.toml,
each pinned to a commit, into <dir> (outside the repository). Uses the same safe fetch and
extraction as the check command; nothing downloaded is run."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path

from bench.adapters import self_  # noqa: F401  (puts the skill scripts on sys.path)
from bench.corpus import BENCH, REPO_ROOT
from skillaudit.fetch import FetchError, download
from skillaudit.quarantine import UnsafeArchive, extract_skipping_links

SOURCES = BENCH / "sources.toml"


def load_sources() -> list[dict]:
    with open(SOURCES, "rb") as fh:
        return list(tomllib.load(fh).get("repo", []))


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print("usage: python -m bench.fetch_real <directory outside the repository>", file=sys.stderr)
        return 2
    out = Path(args[0]).resolve()
    if out == REPO_ROOT or REPO_ROOT in out.parents:
        print("choose a directory outside the repository", file=sys.stderr)
        return 2
    failures = 0
    for entry in load_sources():
        owner, repo = entry["url"].rstrip("/").split("/")[-2:]
        url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{entry['commit']}"
        target = out / f"{owner}__{repo}"
        archive = out / "_downloads" / f"{owner}__{repo}.tar.gz"
        try:
            download(url, archive, max_bytes=500 * 1024 * 1024, timeout=120)
            extract_skipping_links(archive, target, max_files=100_000, max_total_bytes=4 * 1024 ** 3)
            print(f"ok   {owner}/{repo}@{entry['commit'][:12]}")
        except (FetchError, UnsafeArchive, OSError) as exc:
            failures += 1
            print(f"fail {owner}/{repo}: {' '.join(str(exc).split())}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
