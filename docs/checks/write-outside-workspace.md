# write-outside-workspace

Severity: medium. OWASP Agentic Skills Top 10: AST03.

Writes or deletes outside the workspace.

Files are written or deleted outside the project and temporary folders.

## Flagged

```text
cp out.txt /opt/app/
```

## Not flagged

```text
cp out.txt ./build/
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
