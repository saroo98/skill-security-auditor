# dynamic-exec

Severity: high. OWASP Agentic Skills Top 10: AST01.

Runs code generated or decoded at run time.

Code builds or decodes code at run time and executes it, so what runs is not what a reviewer reads.

## Flagged

```text
exec(base64.b64decode(blob))
```

## Not flagged

```text
eval('1 + 1')   # a constant
```

## Why it matters

See https://attack.mitre.org/techniques/T1027/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
