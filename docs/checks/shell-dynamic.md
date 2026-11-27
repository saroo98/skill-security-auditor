# shell-dynamic

Severity: medium. OWASP Agentic Skills Top 10: AST03.

Runs a shell command built at run time.

A shell command is built at run time (a string run through a shell), so its content depends on data.

## Flagged

```text
subprocess.run(cmd, shell=True)
```

## Not flagged

```text
subprocess.run(['git', 'status'])
```

## Why it matters

See https://attack.mitre.org/techniques/T1059/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
