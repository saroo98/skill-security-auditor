# secret-to-unknown-host

Severity: medium. OWASP Agentic Skills Top 10: AST01.

A secret is sent to a host with no known vendor.

A secret-named variable is sent to a fixed host with no known vendor. Normal API use and theft to a fixed host look the same, so this asks for review rather than blocking.

## Flagged

```text
requests.get('https://api.acme.example/v1', headers={'k': os.environ['ACME_TOKEN']})
```

## Not flagged

```text
the same call to the vendor named in the variable
```

## Why it matters

See https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
