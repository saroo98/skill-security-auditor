# persist-runtime

Severity: high. OWASP Agentic Skills Top 10: AST01, AST06.

Installs startup items or shell profile changes.

Code installs something that starts later on its own: shell profile changes, cron entries, scheduled tasks, launch agents, services.

## Flagged

```text
echo 'curl ... | sh' >> ~/.bashrc
```

## Not flagged

```text
echo done > /tmp/status
```

## Why it matters

See https://attack.mitre.org/techniques/T1546/004/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
