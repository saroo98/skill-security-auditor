# binary-referenced

Severity: high. OWASP Agentic Skills Top 10: AST01.

Instructions point at a binary or archive that cannot be checked.

The instructions or scripts point at an executable or archive this tool cannot read.

## Flagged

```text
Run `bin/helper.exe` first.
```

## Not flagged

```text
a binary that nothing refers to (reported as not checked instead)
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
