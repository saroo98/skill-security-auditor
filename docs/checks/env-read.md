# env-read

Severity: info. OWASP Agentic Skills Top 10: none.

Reads a named environment variable.

Code reads one named, non-secret environment variable.

## Flagged

```text
os.environ.get('AWS_REGION')
```

## Not flagged

```text
reading the whole environment (env-to-network when sent)
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
