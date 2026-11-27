# Contributing

Thanks for improving `skill-security-auditor`.

## Setup

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
python -m bench.run --scanner self --check-thresholds
```

The tool uses the Python standard library only at run time. Keep it that way.

## Adding a check

1. Add the check to the registry in `skills/securityauditor/scripts/skillaudit/checks.py` with a stable id, severity, title and OWASP Agentic Skills Top 10 mapping.
2. Teach an analyzer in `skillaudit/analyzers/` to report the capability, and map it in `skillaudit/policy.py`.
3. Add `docs/checks/<id>.md` with a flagged and a not-flagged example and a public source.
4. Add a positive and a negative test. The test suite fails if a check has no page or no test.
5. Add benchmark cases (below) and bump `RULESET_VERSION` when behavior changes.

## Adding a benchmark case

Cases live in `bench/corpus/` as ASCII TOML: id, class, technique, a public `source` for the technique, OWASP mapping, the expected verdict, and the files to create. Payloads use only `.test` or `.example` hosts and documentation address ranges, and must do nothing if run. Write invisible characters as `\u` escapes. Mark a case `av_sensitive = true` if antivirus software flags it when written to disk.

Never remove or weaken a case to improve a number, this project's included.

## Adding a scanner adapter

Add a module to `bench/adapters/` exposing `ADAPTER` with `available()`, `version()` and `scan(path)`, register it in `bench/adapters/__init__.py`, document the exact command it runs, and test the mapping with a faked subprocess.

## Reporting false positives

Open an issue with the check id, a minimal sanitized sample, and what you expected. Do not include credentials or private content.
