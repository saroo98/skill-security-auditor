# secret-to-vendor

Severity: info. OWASP Agentic Skills Top 10: none.

A secret is sent to its own vendor.

A secret-named variable is sent to the vendor its name points to, which is normal API use.

## Flagged

```text
OPENAI_API_KEY sent to api.openai.com
```

## Not flagged

```text
OPENAI_API_KEY sent to another host (reported as secret-to-odd-host)
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
