# secret-near-network

Severity: medium. OWASP Agentic Skills Top 10: AST01.

Reads credential files and uses the network in the same file.

A file reads credential files and also uses the network, but the tool could not follow the data from one to the other.

## Flagged

```text
key = read_key(); upload(url, payload)   # key read and upload in one file
```

## Not flagged

```text
a file that only reads ~/.ssh/known_hosts
```

## Why it matters

See https://attack.mitre.org/techniques/T1552/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
