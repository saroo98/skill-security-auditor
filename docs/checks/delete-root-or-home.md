# delete-root-or-home

Severity: critical. OWASP Agentic Skills Top 10: AST01.

Deletes the home directory or the drive root.

A recursive delete targets the home directory or the root of a drive.

## Flagged

```text
rm -rf ~
```

## Not flagged

```text
rm -rf ./build
```

## Why it matters

See https://attack.mitre.org/techniques/T1485/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
