"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .engine import scan_path
from .model import SEVERITIES, SEVERITY_RANK
from .output.brief import render_brief
from .output.json_out import render_json
from .output.text import render_text

SUBCOMMANDS = ("scan",)


def _fails(result, threshold: str) -> bool:
    rank = SEVERITY_RANK[threshold]
    for unit in result.units:
        if any(SEVERITY_RANK[f.severity] >= rank for f in unit.findings):
            return True
        if any(SEVERITY_RANK[n.severity] >= rank for n in unit.not_checked):
            return True
    return False


def _render(result, fmt: str, **kw) -> str:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="skillaudit", description="Check agent skills before installing them.")
    parser.add_argument("--version", action="version", version=f"skillaudit {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="{" + ",".join(SUBCOMMANDS) + "}")

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
