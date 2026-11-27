<div align="center">

![skill-security-auditor banner](assets/banner.svg)

# 🛡️ skill-security-auditor

### Check an AI agent skill for malicious code and hidden instructions *before* you install it.

A fast, static security scanner for **Claude Code skills**, **Codex skills** and other `SKILL.md`-based agent skills.
Quarantine → analyze → verdict → install the exact files you checked → get warned when they change.

[![CI](https://github.com/saroo98/skill-security-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/saroo98/skill-security-auditor/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg?logo=python&logoColor=white)](pyproject.toml)
[![Dependencies: none](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey.svg)](.github/workflows/ci.yml)
[![SARIF](https://img.shields.io/badge/output-SARIF-orange.svg)](#ci-and-pre-commit)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Quick start](#-quick-start) •
[Verdicts](#-what-a-verdict-looks-like) •
[What it checks](#-what-it-checks) •
[Install and pin](#install-and-pin) •
[CI](#ci-and-pre-commit) •
[Benchmark](#-benchmark) •
[Limits](#%EF%B8%8F-limits)

</div>

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Highlights](#highlights)
- [Quick start](#-quick-start)
- [What a verdict looks like](#-what-a-verdict-looks-like)
- [What it checks](#-what-it-checks)
- [Install and pin](#install-and-pin)
- [Watching for changes](#watching-for-changes)
- [CI and pre-commit](#ci-and-pre-commit)
- [Optional: SkillSpector](#optional-skillspector)
- [Benchmark](#-benchmark)
- [Limits](#%EF%B8%8F-limits)
- [Contributing](#contributing)
- [License](#license)

---

## Why this exists

Agent skills are folders of instructions and scripts that an AI coding agent loads and follows. Installing one gives it the same reach as your agent: your files, your shell, your environment variables and your credentials. Some parts of a skill, such as hooks, MCP servers and pre-approved tools, can run **without any permission prompt**.

`skill-security-auditor` reads a skill **without ever running it** and tells you, in a few lines, what it can do, what it would run on its own, and whether anything looks malicious. It is built for the moment right before you install, and it finishes in seconds.

## Highlights

| Feature | What it means |
| --- | --- |
| 🔒 **Quarantined, never executed** | The skill is fetched into an isolated folder; symlinks are skipped and archives are extracted safely. |
| ⚡ **Fast and cheap** | Static analysis in well under a second for typical skills, with a hard 60-second budget. One small, capped model review at most. |
| 🎯 **Clear verdicts** | `PASS`, `REVIEW` or `BLOCK`, each with file, line and a one-line reason. |
| 🕵️ **Shows what runs without asking** | Hooks, monitors, MCP commands, npm lifecycle scripts and `allowed-tools` pre-approvals, all listed in one place. |
| 🔗 **Follows the data** | Tracks credentials and environment variables through pipelines, variables and files to the network. |
| 📌 **Install exactly what was checked** | Copies the checked files, records hashes in `skill.lock.json`, and reports drift later. |
| 🧩 **Works everywhere** | Claude Code and Codex skill, command line tool, GitHub Action, pre-commit hook, SARIF output. |
| 📦 **Zero dependencies** | Python 3.11+ standard library only. |

---

## 🚀 Quick start

**1. Add the skill to your agent.** Copy the [`skills/securityauditor`](skills/securityauditor) folder into your skills directory:

| Agent | Skills folder |
| --- | --- |
| Claude Code | `~/.claude/skills/securityauditor` |
| Codex | `~/.agents/skills/securityauditor` |

**2. Check a skill before installing it:**

```text
/securityauditor https://github.com/owner/repo/tree/main/skills/some-skill
```

**Or run it from a terminal**, no agent needed:

```powershell
python skills/securityauditor/scripts/scan_skill.py check owner/repo/skills/some-skill
```

---

## 🚦 What a verdict looks like

✅ **PASS**: nothing found.

```text
PASS  notes-helper  12 files  0.4s
can: read local files
```

⛔ **BLOCK**: at least one high or critical finding. Do not install.

```text
BLOCK  pdf-tools  31 files  0.9s
can: network (collect.example.test), download and run code, read credential files
runs without asking: SessionStart hook -> hooks/hooks.json
critical  secret-to-network  scripts/sync.py:4   Credential file contents are sent over the network
critical  remote-exec        scripts/setup.sh:1  Downloads code and runs it
+3 more  full report: <path>
```

⚠️ **REVIEW**: medium findings, or files that could not be checked. Read the lines and decide.

```text
REVIEW  api-helper  9 files  0.3s
can: network (api.vendor.example), use secret variables
medium  secret-to-unknown-host  scripts/call.py:7  A secret is sent to a host with no known vendor
not analyzed: assets/guide.pdf
```

| Line | Meaning |
| --- | --- |
| `can:` | What the skill is able to do. |
| `runs without asking:` | Everything the agent host would run without a prompt. This is the part the host's own permission prompts do not show you. |
| `not analyzed:` | Files that could not be checked. Never silently skipped. |

> [!NOTE]
> **Optional model review.** Unless the static checks already blocked the skill, the output also contains a capped, sanitized review packet. Your agent's model reads it against a fixed rubric and may **raise** the verdict, never lower it. `--static` turns it off.

> [!IMPORTANT]
> A PASS means nothing was found. It is not proof that a skill is safe.

---

## 🔍 What it checks

| Area | What is checked |
| --- | --- |
| **Runs without asking** | Hooks, monitors, MCP server commands, inline commands in `SKILL.md`, `allowed-tools` pre-approvals, npm lifecycle scripts. Each command is analyzed and marked as checked or not. |
| **Download and run** | Fetches that are piped, substituted, or saved and then executed, in shell, PowerShell, Python and JavaScript. |
| **Secrets leaving the machine** | Credential files or the whole environment read and sent out. A secret sent to its own vendor is fine; to a raw IP, a webhook service or another vendor it is not. |
| **Hidden instructions** | Unicode tag characters, zero-width runs, bidi overrides, HTML comments, image alt text, link titles, instructions split across lines, text addressed to a reviewer. |
| **Prompt injection** | Instructions to ignore rules, hide actions from the user, skip confirmation or bypass permissions. |
| **Odd files** | UTF-16 files and extensionless scripts are decoded and checked; anything that cannot be checked is listed. |
| **Installs something else** | Instructions to download and run an extra component as a "required" step. |
| **Lookalike source** | Repository names that imitate a well-known skill repository under another owner. |
| **Says one thing, does another** | Capabilities compared with what `SKILL.md` says the skill does. |
| **Meaning** | Paraphrased and non-English instructions, by the optional model review. |

Every one of the 40 checks has a page with a flagged and a not-flagged example in [`docs/checks`](docs/checks). Star, fork and download counts are never used. Architecture: [`docs/how-it-works.md`](docs/how-it-works.md).

---

## Install and pin

After a check, install the **exact files that were checked**:

```powershell
python skills/securityauditor/scripts/scan_skill.py install <check-id> --to <your skills folder>
```

- Refuses a BLOCK verdict.
- Refuses a quarantine that changed since the check.
- Copies files without downloading anything again.
- Records every file hash in `skill.lock.json`.

Already have a skill folder? Pin it with `pin <folder>`.

## Watching for changes

```powershell
python skills/securityauditor/scripts/scan_skill.py verify
```

`verify` reports any pinned skill whose files changed, in terms of **new capabilities, new hosts, new things that run without asking and new findings**.

- `verify --quiet` only compares hashes and prints nothing when nothing changed. Run it at session start with the [hook example](docs/hook-example.md).
- `diff <old> <new>` compares two versions of a skill directly.
- The tool never edits your agent settings itself.

---

## CI and pre-commit

**GitHub Action**: scans, writes SARIF and uploads it to code scanning.

```yaml
- uses: saroo98/skill-security-auditor@main
  with:
    path: skills
    fail-on: high
```

**pre-commit**: use the `skillaudit` hook from [`.pre-commit-hooks.yaml`](.pre-commit-hooks.yaml).

**Command line**:

```powershell
python skills/securityauditor/scripts/scan_skill.py scan <path> --format text|json|sarif|brief --fail-on LEVEL
```

> [!TIP]
> **Suppressions stay with you.** Findings can be suppressed only by the person running the scan: `--config` with `[[suppress]]` entries that each carry a reason, or `--baseline` with a reason for every fingerprint. A suppression file or ignore comment *inside* a scanned skill is itself reported and never honored.

## Optional: SkillSpector

If [NVIDIA SkillSpector](https://github.com/NVIDIA/skillspector) is installed (on `PATH`, or `SKILLSPECTOR_BIN`), `check` also runs it with its model stage off and takes the stricter of the two verdicts. The output says when it was used and which tool raised the verdict. SkillSpector looks up dependency names in a vulnerability database during a scan; `--no-external` turns it off.

---

## 📊 Benchmark

[`bench/`](bench) holds an inert corpus of skill attacks and harmless look-alikes, stored as data and written out as real folders only in a temporary directory. Cases that antivirus software flags are scored in memory unless `--include-av-sensitive` is given. `python -m bench.run` scores any scanner that has an adapter in [`bench/adapters/`](bench/adapters).

### Attack corpus

Results on 2026-11-27, model stages off for every scanner. Full table: [`bench/results/RESULTS.md`](bench/results/RESULTS.md).

| Scanner | Static-scope attacks caught | Benign cases blocked |
| --- | :---: | :---: |
| **skill-security-auditor 0.9.1** | **50/50** | **0/20** |
| Cisco skill-scanner 2.3.2 | 25/49 | 4/20 |
| SkillSpector 2.13.7 | 11/49 | 1/20 |

> The Cisco corpus run returned one adapter error. The reported denominator includes that case.

> [!NOTE]
> Most corpus cases were written by this project's authors while building its checks, so its own score on them is optimistic. The real-skill results below are the fairer measure.

### Real-world skills

**2,753 skills** from 26 public repositories pinned to exact commits in [`bench/sources.toml`](bench/sources.toml). Each skill directory was scanned independently. The two collections shared 490 skill directories from the same pinned repositories, counted once.

| Verdict | Skills | Share |
| --- | ---: | ---: |
| ✅ PASS | 2,204 | 80.06% |
| ⚠️ REVIEW | 453 | 16.45% |
| ⛔ BLOCK | 96 | 3.49% |

Manual triage recorded 42 blocks the user should check before installing and 54 false alarms (1.96% of all skills). See [`bench/triage.toml`](bench/triage.toml) and [the benchmark results](bench/results/RESULTS.md).

Reproduce:

```powershell
python -m bench.fetch_real <folder>
python -m bench.run --real <folder>
```

**Corpus rules:** every case cites a public source for its technique, and no case is removed to improve a number, this project's included.

---

## ⚠️ Limits

- Static checks plus one bounded model review. The skill is never run, so behavior that only appears at run time is not seen.
- Paraphrased and non-English instructions are left to the model review. A malicious package recognizable only by its name, and content fetched after review, are out of static scope.
- Instructions phrased as third-person description ("this skill tells an agent to ...") are treated as documentation by the static checks.
- Private repositories are not supported; no tokens are read or sent.
- A PASS means nothing was found, not that a skill is safe.

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for how to add a check, a benchmark case or a scanner adapter. Found a vulnerability? See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)

---

<div align="center">

**Keywords:** AI agent security · Claude Code skills · Codex skills · SKILL.md scanner · prompt injection detection · supply chain security · MCP server security · static analysis · malicious code detection · SARIF

If this tool helped you, consider starring the repository.

</div>
