# Changelog

## 0.9.0

- Rebuilt as an install guard: `check` fetches a skill into quarantine, gives a PASS, REVIEW or BLOCK verdict with a capped review packet for the agent's model, and `install` copies the exact checked files and pins them.
- New analyzers for shell, Python (AST), JavaScript, PowerShell, markdown instructions, hidden content and agent config files, replacing the v0.1.0 line rules.
- Reports everything a host runs without asking: hooks, monitors, MCP servers, lifecycle scripts and pre-approved tools.
- Lockfile with `pin`, `verify` and `diff`; SARIF output; reasoned suppressions; GitHub Action and pre-commit hook.
- Optional pairing with NVIDIA SkillSpector.
- Benchmark corpus and runner with adapters for this tool and SkillSpector.
- Breaking: rule ids and JSON fields changed; Python 3.11 or newer is required.

## 0.1.0

- Initial public release.
