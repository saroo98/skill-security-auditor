# undeclared-persist

Severity: high. OWASP Agentic Skills Top 10: AST04.

Installs startup items without saying so.

Code installs startup items, and nothing in SKILL.md mentions hooks, schedules or startup.

## Flagged

```text
Register-ScheduledTask ...   # in a note formatter
```

## Not flagged

```text
the same line in a skill described as scheduling backups
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
