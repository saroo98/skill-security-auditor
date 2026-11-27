"""Command line entry point."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

from . import __version__
from .checks import CHECKS, RULESET_VERSION
from .lookalike import lookalike
from .engine import scan_path
from .fetch import FetchError, download, resolve
from .model import SEVERITIES, SEVERITY_RANK, VERDICT_RANK, NotChecked, ScanResult, make_finding, verdict_for
from .output.brief import render_brief
from .output.json_out import render_json, result_from_dict, result_to_dict
from .output.text import render_text
from .packet import LIMIT, build_packet, linked_markdown
from .quarantine import UnsafeArchive, archive_commit, cache_get, cache_put, home, place, tree_hash

SUBCOMMANDS = ("scan", "check", "install", "pin", "verify", "diff")
CHECK_EXIT = {"PASS": 0, "BLOCK": 1, "REVIEW": 3}


def _fails(result: ScanResult, threshold: str) -> bool:
    rank = SEVERITY_RANK[threshold]
    for unit in result.units:
        if any(SEVERITY_RANK[f.severity] >= rank for f in unit.findings):
            return True
        if any(SEVERITY_RANK[n.severity] >= rank for n in unit.not_checked):
            return True
    return False


def _render(result: ScanResult, fmt: str, **kw) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "brief":
        return render_brief(result, **kw)
    return render_text(result)


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        print(f"Invalid input: target does not exist: {target}", file=sys.stderr)
        return 2
    if args.max_file_size < 1:
        print("Invalid input: --max-file-size must be greater than zero.", file=sys.stderr)
        return 2
    result = scan_path(target, max_file_size=args.max_file_size)
    fmt = "json" if args.json_output else args.format
    print(_render(result, fmt))
    if result.errors:
        return 2
    return 1 if _fails(result, args.fail_on) else 0


def _instruction_files(root: Path, unit_root: str) -> list[tuple[str, str]]:
    """SKILL.md of the unit, then the markdown files it links, in link order."""
    base = root / unit_root if unit_root else root
    skill = base / "SKILL.md"
    if not skill.is_file():
        return []
    available = {p.relative_to(root).as_posix() for p in root.rglob("*.md") if p.is_file() and not p.is_symlink()}
    skill_rel = skill.relative_to(root).as_posix()
    text = skill.read_text(encoding="utf-8", errors="replace")
    files = [(skill_rel, text)]
    for rel in linked_markdown(text, available, unit_root):
        files.append((rel, (root / rel).read_text(encoding="utf-8", errors="replace")))
    return files


def _packets(result: ScanResult, root: Path) -> list[str]:
    """Build one packet per unit that static analysis did not block; record cuts as not-checked items."""
    packets: list[str] = []
    candidates = [u for u in result.units if u.verdict != "BLOCK" and u.root_rel is not None]
    share = max(2000, LIMIT // max(1, len(candidates)))
    for unit in candidates:
        if unit.name == "(repository)":
            continue
        packet, cut = build_packet(unit, _instruction_files(root, unit.root_rel), limit=min(LIMIT, share))
        if cut:
            unit.not_checked.extend(NotChecked(rel, "not fully included in the review packet", "medium") for rel in cut)
            unit.verdict = verdict_for([f.severity for f in unit.findings] + [n.severity for n in unit.not_checked])
        packets.append(packet)
    return packets


def _final_verdict(result: ScanResult) -> str:
    return max((u.verdict for u in result.units), key=VERDICT_RANK.__getitem__, default="PASS")


def cmd_check(args: argparse.Namespace) -> int:
    try:
        source = resolve(args.address)
        fetched = None
        if source.kind == "url":
            name = hashlib.sha256(source.location.encode()).hexdigest()[:16] + ".tar.gz"
            if source.location.lower().endswith(".zip"):
                name = name.replace(".tar.gz", ".zip")
            fetched = download(source.location, home() / "downloads" / name, source=source)
        check_id, qdir = place(source, fetched)
    except (FetchError, UnsafeArchive, OSError) as exc:
        print(f"Cannot check {args.address}: {' '.join(str(exc).split())}", file=sys.stderr)
        return 2
    target = qdir / source.subpath if source.subpath else qdir
    if not target.is_dir():
        print(f"Cannot check {args.address}: path not found in the download: {source.subpath}", file=sys.stderr)
        return 2

    full_tree = tree_hash(qdir)
    cache_key = f"{full_tree}-{hashlib.sha256(source.subpath.encode()).hexdigest()[:8]}"
    cached = cache_get(cache_key, RULESET_VERSION)
    if cached is not None:
        result = result_from_dict(cached["result"])
    else:
        result = scan_path(target)
        commit = archive_commit(fetched) if fetched is not None else None
        cache_put(cache_key, RULESET_VERSION, {
            "result": result_to_dict(result),
            "source": source.display,
            "owner_repo": source.owner_repo,
            "commit": commit,
            "subpath": source.subpath,
            "verdict": _final_verdict(result),
            "unit_names": [u.name for u in result.units],
        })

    imitated = lookalike(source.owner_repo)
    if imitated:
        check = CHECKS["lookalike-source"]
        for unit in result.units:
            unit.findings.append(make_finding(check.id, check.severity, "(source)", None,
                                              f"Name matches well-known {imitated} under a different owner", source.display))
            unit.verdict = verdict_for([f.severity for f in unit.findings] + [n.severity for n in unit.not_checked])
    packets = [] if args.static else _packets(result, target)
    if source.subpath:
        check_id = hashlib.sha256(f"{full_tree}\0{source.subpath}".encode()).hexdigest()[:12]
    record = home() / "checks" / f"{check_id}.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps({
        "quarantine": qdir.name, "tree_hash": full_tree, "subpath": source.subpath, "source": source.display,
        "commit": archive_commit(fetched) if fetched is not None else None,
        "verdict": _final_verdict(result), "unit_names": [u.name for u in result.units],
    }, sort_keys=True), encoding="utf-8")
    report = home() / "reports" / f"{check_id}.txt"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(render_text(result), encoding="utf-8")
    verdict = _final_verdict(result)

    print(render_brief(result, report_path=str(report)))
    if packets and verdict != "BLOCK":
        print()
        print("\n\n".join(packets))
    print(f"check-id: {check_id}")
    return CHECK_EXIT[verdict]


def cmd_install(args: argparse.Namespace) -> int:
    from . import lock

    def fail(message: str) -> int:
        print(f"Cannot install {args.check_id}: {message}", file=sys.stderr)
        return 2

    if not re.fullmatch(r"[0-9a-f]{12}", args.check_id):
        return fail("not a check id; run check first and use the id it prints")
    record_path = home() / "checks" / f"{args.check_id}.json"
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return fail("unknown check id; run check first")
    if record.get("verdict") == "BLOCK":
        return fail("the check verdict was BLOCK; installing a blocked skill is not supported")
    if len(record.get("unit_names", [])) != 1:
        return fail("the checked folder holds several skills; check the path of one skill")
    qdir = home() / "quarantine" / record["quarantine"]
    if not qdir.is_dir() or tree_hash(qdir) != record["tree_hash"]:
        return fail("the quarantine was modified or removed since the check; run check again")
    source_dir = qdir / record["subpath"] if record["subpath"] else qdir
    name = re.sub(r"[^A-Za-z0-9._-]+", "-", record["unit_names"][0]).strip(".-") or "skill"
    target = Path(args.to) / name
    if target.exists():
        return fail(f"{target} already exists; remove it or choose another --to folder")
    expected = tree_hash(source_dir)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source_dir, target, symlinks=False)
    except OSError as exc:
        return fail(" ".join(str(exc).split()))
    if tree_hash(target) != expected:
        shutil.rmtree(target, ignore_errors=True)
        return fail("the copied files do not match the checked files; nothing was installed")
    lock.pin(target, Path(args.lock), source=record.get("source", ""), commit=record.get("commit"),
             model_reviewed=args.model_reviewed)
    print(f"installed {name} to {target}  tree {expected[:12]}")
    return 0


def cmd_pin(args: argparse.Namespace) -> int:
    from . import lock

    target = Path(args.target)
    if not target.is_dir():
        print(f"Invalid input: not a folder: {target}", file=sys.stderr)
        return 2
    entry = lock.pin(target, Path(args.lock))
    print(f"pinned {target} ({entry['static_verdict']}, tree {entry['tree_hash'][:12]}) in {args.lock}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    from . import lock

    try:
        drifts = lock.verify(Path(args.lock), quiet=args.quiet)
    except (OSError, ValueError) as exc:
        print(f"Cannot read lockfile {args.lock}: {' '.join(str(exc).split())}", file=sys.stderr)
        return 2
    for drift in drifts:
        print("\n".join(lock.describe(drift, quiet=args.quiet)))
    if not drifts and not args.quiet:
        print("no changes since approval")
    return 1 if drifts else 0


def cmd_diff(args: argparse.Namespace) -> int:
    from . import lock

    old, new = Path(args.old), Path(args.new)
    if not old.is_dir() or not new.is_dir():
        print("Invalid input: both arguments must be folders", file=sys.stderr)
        return 2
    drift = lock.diff_dirs(old, new)
    print("\n".join(lock.describe(drift)))
    changed = drift.added_files or drift.removed_files or drift.changed_files
    return 1 if changed else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skillaudit", description="Check agent skills before installing them.")
    parser.add_argument("--version", action="version", version=f"skillaudit {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="{" + ",".join(SUBCOMMANDS) + "}")

    check = sub.add_parser("check", help="fetch a skill into quarantine and give a PASS, REVIEW or BLOCK verdict")
    check.add_argument("address", help="local folder or archive, GitHub address, owner/repo[/path], or https archive link")
    check.add_argument("--static", action="store_true", help="static checks only; print no review packet")
    check.add_argument("--no-external", action="store_true", help="do not run other installed scanners")
    check.set_defaults(func=cmd_check)

    install = sub.add_parser("install", help="copy the files a check approved into a skills folder and pin them")
    install.add_argument("check_id")
    install.add_argument("--to", required=True, help="skills folder to install into")
    install.add_argument("--lock", default="skill.lock.json")
    install.add_argument("--model-reviewed", action="store_true")
    install.set_defaults(func=cmd_install)

    pin = sub.add_parser("pin", help="record a skill folder as approved in a lockfile")
    pin.add_argument("target")
    pin.add_argument("--lock", default="skill.lock.json")
    pin.set_defaults(func=cmd_pin)

    verify = sub.add_parser("verify", help="report skills that changed since they were pinned")
    verify.add_argument("--lock", default="skill.lock.json")
    verify.add_argument("--quiet", action="store_true", help="hash comparison only; print nothing when clean")
    verify.set_defaults(func=cmd_verify)

    diff = sub.add_parser("diff", help="compare two versions of a skill")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.set_defaults(func=cmd_diff)

    scan = sub.add_parser("scan", help="scan a local directory and report findings")
    scan.add_argument("target")
    scan.add_argument("--format", choices=("brief", "text", "json"), default="text")
    scan.add_argument("--json", action="store_true", dest="json_output", help="alias for --format json")
    scan.add_argument("--fail-on", choices=SEVERITIES, default="high")
    scan.add_argument("--max-file-size", type=int, default=1_048_576)
    scan.set_defaults(func=cmd_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in SUBCOMMANDS and not argv[0].startswith("-"):
        argv.insert(0, "scan")
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 2


__all__ = ["main", "build_parser"]
