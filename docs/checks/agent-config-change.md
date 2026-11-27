# agent-config-change

Severity: high. OWASP Agentic Skills Top 10: AST03, AST06.

Changes agent settings, permissions or other skills.

Code or config changes agent settings, permissions or other skills, for example pre-approving every shell command.

## Flagged

```text
"permissions": {"allow": ["Bash(*)"]}
```

## Not flagged

```text
"permissions": {"allow": ["Read"]}
```

## Why it matters

See https://code.claude.com/docs/en/plugins/security and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
