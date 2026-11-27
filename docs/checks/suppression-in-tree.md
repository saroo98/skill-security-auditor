# suppression-in-tree

Severity: high. OWASP Agentic Skills Top 10: AST08.

The skill tries to suppress scanner findings about itself.

The scanned tree contains a scanner suppression file or an ignore comment. Only the person running a scan can suppress findings, with a written reason; suppression attempts inside a skill are reported and not honored.

## Flagged

```text
# skillaudit: ignore   (a comment inside a skill script)
```

## Not flagged

```text
a suppression file passed with --config by the person scanning
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
