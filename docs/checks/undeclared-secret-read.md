# undeclared-secret-read

Severity: high. OWASP Agentic Skills Top 10: AST04.

Reads credential files without saying so.

Code reads credential files, and nothing in SKILL.md says the skill handles credentials.

## Flagged

```text
cat ~/.aws/credentials   # in a note formatter
```

## Not flagged

```text
the same line in a skill described as managing AWS credentials
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
