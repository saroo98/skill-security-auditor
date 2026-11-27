# Changelog

## 0.9.1

- Reduce false findings in instruction analysis, wrapped YAML descriptions, indented Python examples, and shell command detection.
- Recognize shell path placeholders, documented project dependency commands, and explicit confirmation requirements.
- Expand the pinned real-skill benchmark and record the review of each new block.
- Report malformed URLs cleanly, enforce a total download deadline, and reject archive path collisions and Windows device names.
- Require an actual skill folder for installation and compare the full quarantine tree before reusing it.
- Pin skills by installation path so matching names stay independent. Existing lockfiles remain readable and migrate on the next pin.
- Pass GitHub Action inputs through quoted environment variables and treat deletion of core system folders as critical.
- Fingerprint full evidence before clipping report previews. Baselines from earlier versions may need new fingerprints for long evidence.
- Document the Codex user skill directory and invocation.
- Declare the MIT license using SPDX package metadata.
- Update GitHub workflows and the SARIF uploader to Node.js 24 action versions.

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
