# project-delete

Severity: info. OWASP Agentic Skills Top 10: none.

Deletes files inside the project.

A recursive delete stays inside the project.

## Flagged

```text
rm -rf ./build
```

## Not flagged

```text
rm -rf ~ (reported as delete-root-or-home)
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
