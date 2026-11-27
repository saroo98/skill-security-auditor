"""python -m bench.run: score scanners on the corpus and write results."""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import sys
import tempfile
import tomllib
from pathlib import Path

from bench.adapters import AdapterResult, get
from bench.corpus import BENCH, Case, load_cases, load_classes, materialize, scan_in_memory

THRESHOLDS = BENCH / "thresholds.toml"
RANK = {"PASS": 0, "REVIEW": 1, "BLOCK": 2}
COMMAND = "python -m bench.run"


def _empty_counts() -> dict:
    return {"BLOCK": 0, "REVIEW": 0, "PASS": 0, "caught": 0, "total": 0}


def score(cases: list[Case], results: dict[str, AdapterResult], classes: dict) -> dict:
    per_class: dict[str, dict] = {}
    benign = {"PASS": 0, "REVIEW": 0, "BLOCK": 0, "total": 0}
    errors = 0
    for c in cases:
        r = results.get(c.id)
        if r is None:
            continue
        if r.raw.get("error"):
            errors += 1
        if not c.malicious:
            benign[r.verdict] += 1
            benign["total"] += 1
            continue
        counts = per_class.setdefault(c.cls, _empty_counts())
        counts[r.verdict] += 1
        counts["total"] += 1
        counts["caught"] += int(RANK[r.verdict] >= RANK[c.expect])
    in_scope = {k: v for k, v in per_class.items() if classes.get(k, {}).get("static_scope", False)}
    out_scope = {k: v for k, v in per_class.items() if k not in in_scope}
    caught = sum(v["caught"] for v in in_scope.values())
    total = sum(v["total"] for v in in_scope.values())
    seconds = [r.seconds for r in results.values()]
    pass_chars = [r.output_chars for cid, r in results.items() if r.verdict == "PASS" and r.output_chars is not None]
    other_chars = [r.output_chars for cid, r in results.items() if r.verdict != "PASS" and r.output_chars is not None]
    return {
        "in_scope": {"caught": caught, "total": total, "rate": round(caught / total, 4) if total else 0.0},
        "per_class": dict(sorted(per_class.items())),
        "out_of_scope": dict(sorted(out_scope.items())),
        "benign": benign,
        "errors": errors,
        "max_pass_chars": max(pass_chars, default=0),
        "max_block_chars": max(other_chars, default=0),
        "timing": {"median_seconds": round(statistics.median(seconds), 2) if seconds else 0.0},
    }


def check_thresholds(scores: dict, path: Path = None) -> list[str]:
    path = path or THRESHOLDS
    with open(path, "rb") as fh:
        limits = tomllib.load(fh)
    problems = []
    for scanner, rules in limits.items():
        s = scores.get(scanner)
        if s is None:
            continue
        checks = {
            "min_in_scope_rate": (s["in_scope"]["rate"], lambda v, lim: v >= lim),
            "max_benign_block": (s["benign"]["BLOCK"], lambda v, lim: v <= lim),
            "max_pass_chars": (s["max_pass_chars"], lambda v, lim: v <= lim),
            "max_block_chars": (s["max_block_chars"], lambda v, lim: v <= lim),
            "max_median_seconds": (s["timing"]["median_seconds"], lambda v, lim: v <= lim),
        }
        for key, limit in rules.items():
            if key not in checks:
                continue
            value, ok = checks[key]
            if not ok(value, limit):
                problems.append(f"{scanner}: {key} is {value}, limit {limit}")
    return problems


def _markdown(scores: dict, versions: dict, date: str, cases: list[Case], classes: dict, argv: list[str]) -> str:
    malicious = [c for c in cases if c.malicious]
    lines = [
        "# Benchmark results",
        "",
        f"Date: {date or 'not recorded'}. Corpus: {len(malicious)} malicious and {len(cases) - len(malicious)} benign cases.",
        f"Reproduce: `{COMMAND} {' '.join(argv)}`".rstrip(),
        "",
        "Scanners: " + "; ".join(f"{n} {v}" for n, v in versions.items()) + ".",
        "Model stages are off for every scanner in this table.",
        "",
        "| Scanner | Static-scope cases caught | Benign passed | Benign blocked | Median seconds |",
        "| --- | --- | --- | --- | --- |",
    ]
    for name, s in scores.items():
        b = s["benign"]
        lines.append(f"| {name} | {s['in_scope']['caught']}/{s['in_scope']['total']} | {b['PASS']}/{b['total']} | "
                     f"{b['BLOCK']} | {s['timing']['median_seconds']} |")
    lines += ["", "Per class (BLOCK / REVIEW / PASS of total; * = outside static scope):", ""]
    header = "| Class | " + " | ".join(scores) + " |"
    lines += [header, "| --- |" + " --- |" * len(scores)]
    all_classes = sorted({k for s in scores.values() for k in s["per_class"]})
    for cls in all_classes:
        mark = "" if classes.get(cls, {}).get("static_scope") else " *"
        cells = []
        for s in scores.values():
            c = s["per_class"].get(cls)
            cells.append(f"{c['BLOCK']} / {c['REVIEW']} / {c['PASS']} of {c['total']}" if c else "-")
        lines.append(f"| {cls}{mark} | " + " | ".join(cells) + " |")
    lines += ["", "A case counts as caught when the verdict is at least as strict as the case expects."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="python -m bench.run")
    parser.add_argument("--scanner", action="append", dest="scanners")
    parser.add_argument("--out", default=str(BENCH / "results"))
    parser.add_argument("--date", default="")
    parser.add_argument("--check-thresholds", action="store_true")
    parser.add_argument("--include-av-sensitive", action="store_true",
                        help="also write cases that antivirus software flags (for CI runners without antivirus)")
    args = parser.parse_args(argv)
    scanners = args.scanners or ["self"]

    cases = load_cases()
    classes = load_classes()
    workdir = Path(tempfile.mkdtemp(prefix="skillaudit-bench-"))
    try:
        paths = materialize(cases, workdir, skip_av_sensitive=not args.include_av_sensitive)
        scores, versions = {}, {}
        for name in scanners:
            try:
                adapter = get(name)
            except KeyError as exc:
                print(f"skipping {name}: {exc}", file=sys.stderr)
                continue
            if not adapter.available():
                print(f"skipping {name}: not installed", file=sys.stderr)
                continue
            versions[name] = adapter.version()
            results = {c.id: adapter.scan(paths[c.id]) for c in cases if c.id in paths}
            if name == "self":
                for c in cases:
                    if c.id not in paths:
                        results[c.id] = AdapterResult(scan_in_memory(c), 0.0, None, {"in_memory": True})
            s = score(cases, results, classes)
            s["version"] = versions[name]
            s["verdicts"] = {cid: r.verdict for cid, r in sorted(results.items())}
            scores[name] = s
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    published_args: list[str] = []
    skip_next = False
    for a in argv:
        if skip_next:
            skip_next = False
            continue
        if a == "--out":
            skip_next = True
            continue
        if a != "--check-thresholds" and not a.startswith("--out="):
            published_args.append(a)
    (out / "results.json").write_text(json.dumps({"date": args.date, "scanners": scores}, indent=2, sort_keys=True) + "\n",
                                      encoding="utf-8")
    (out / "RESULTS.md").write_text(_markdown(scores, versions, args.date, cases, classes, published_args), encoding="utf-8")
    for name, s in scores.items():
        print(f"{name}: static-scope {s['in_scope']['caught']}/{s['in_scope']['total']}, "
              f"benign blocked {s['benign']['BLOCK']}/{s['benign']['total']}")
    if args.check_thresholds:
        problems = check_thresholds(scores, THRESHOLDS)
        for p in problems:
            print(f"threshold: {p}", file=sys.stderr)
        return 1 if problems else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
