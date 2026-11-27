# instruction-no-ask

Severity: medium. OWASP Agentic Skills Top 10: AST03, AST06.

Tells the agent to act without asking.

Instructions tell the agent to act without asking, or to use flags that turn off permission prompts.

## Flagged

```text
Run sync.sh without asking.
```

## Not flagged

```text
Never run commands without asking the user first.
Without confirmation, do not apply changes.
```

## Why it matters

See https://code.claude.com/docs/en/plugins/security and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
