"""Load benchmark cases from TOML and write them out as real skill folders."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCH = REPO_ROOT / "bench"
CORPUS = BENCH / "corpus"
ENCODINGS = {"utf-8": ("utf-8", b""), "utf-16-le-bom": ("utf-16-le", b"\xff\xfe")}


@dataclass(frozen=True)
class Case:
    id: str
    cls: str
    technique: str
    source: str
    ast10: tuple[str, ...]
    expect: str
    files: tuple[tuple[str, str, str], ...]  # (path, content, encoding)
    malicious: bool
    av_sensitive: bool = False


def load_classes() -> dict[str, dict]:
    with open(BENCH / "classes.toml", "rb") as fh:
        return tomllib.load(fh)


def _load(path: Path, malicious: bool) -> Case:
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    files = tuple((f["path"], f["content"], f.get("encoding", "utf-8")) for f in data["files"])
    return Case(
        id=data["id"],
        cls=data["class"],
        technique=data["technique"],
        source=data["source"],
        ast10=tuple(data.get("ast10", ())),
        expect=data["expect"],
        files=files,
        malicious=malicious,
        av_sensitive=bool(data.get("av_sensitive", False)),
    )


def load_cases(root: Path = CORPUS) -> list[Case]:
    cases = [_load(p, True) for p in sorted((root / "malicious").rglob("*.toml"))]
    cases += [_load(p, False) for p in sorted((root / "benign").rglob("*.toml"))]
    return cases


def case_bytes(case: Case) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for rel, content, encoding in case.files:
        codec, bom = ENCODINGS[encoding]
        out[rel] = bom + content.encode(codec)
    return out


def scan_in_memory(case: Case) -> str:
    """Verdict of this project's checks on a case, without writing the case to disk."""
    from bench.adapters import self_  # noqa: F401  (puts the skill scripts on sys.path)
    from skillaudit.engine import scan_files
    from skillaudit.model import VERDICT_RANK

    result = scan_files(case_bytes(case), root_name=case.id)
    return max((u.verdict for u in result.units), key=VERDICT_RANK.__getitem__, default="PASS")


def materialize(cases: list[Case], out: Path, skip_av_sensitive: bool = False) -> dict[str, Path]:
    out = Path(out).resolve()
    if out == REPO_ROOT or REPO_ROOT in out.parents:
        raise ValueError("materialize writes hostile test skills; choose a directory outside the repository")
    written: dict[str, Path] = {}
    for case in cases:
        if skip_av_sensitive and case.av_sensitive:
            continue
        base = out / ("malicious" if case.malicious else "benign") / case.id
        for rel, content, encoding in case.files:
            codec, bom = ENCODINGS[encoding]
            path = base / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(bom + content.encode(codec))
        written[case.id] = base
    return written


def main(argv: list[str] | None = None) -> int:
    import sys

    args = list(sys.argv[1:] if argv is None else argv)
    include = "--include-av-sensitive" in args
    args = [a for a in args if a != "--include-av-sensitive"]
    if len(args) != 1:
        print("usage: python -m bench.materialize <directory outside the repository> [--include-av-sensitive]", file=sys.stderr)
        return 2
    try:
        written = materialize(load_cases(), Path(args[0]), skip_av_sensitive=not include)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 2
    print(f"wrote {len(written)} cases to {Path(args[0]).resolve()}")
    return 0
