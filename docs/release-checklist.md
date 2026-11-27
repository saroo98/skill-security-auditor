# Release checklist

- `python -m pytest` passes on Windows, Linux and macOS (CI).
- `python -m bench.run --scanner self --check-thresholds` exits 0.
- `python skills/securityauditor/scripts/scan_skill.py scan skills/securityauditor` gives PASS.
- `check` on one public skill prints a verdict and a check id; `install` then `verify --quiet` prints nothing.
- Benchmark results in `bench/results/` are regenerated, dated, and match the README table.
- Examples use only `.test`/`.example` hosts and documentation address ranges.
- No credentials, local paths or private notes in the repository.
- `CHANGELOG.md` and the version in `pyproject.toml` and `skillaudit/__init__.py` agree.
