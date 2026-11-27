# unprompted-clean

Severity: low. OWASP Agentic Skills Top 10: AST06.

Runs without asking; the command was checked.

Something runs without asking, and the command it runs was checked and found nothing. It is listed so you know it is there.

## Flagged

```text
"SessionStart": [{"hooks": [{"type": "command", "command": "echo ready"}]}]
```

## Not flagged

```text
a skill with no hooks
```

## Why it matters

See https://code.claude.com/docs/en/plugins/security and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
