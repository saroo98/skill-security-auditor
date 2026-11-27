# shell-constant

Severity: low. OWASP Agentic Skills Top 10: none.

Runs a fixed shell command.

Code runs a fixed command.

## Flagged

```text
subprocess.run(['pandoc', 'notes.md', '-o', 'notes.pdf'])
```

## Not flagged

```text
a skill that runs no commands
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
