# obfuscation

Severity: high. OWASP Agentic Skills Top 10: AST01.

Behavior is encoded or disguised.

Behavior is disguised: encoded commands, command names assembled from variables, bidirectional control characters, hosts that mix alphabets, or encoded blobs that decode to commands.

## Flagged

```text
powershell -EncodedCommand SQBFAFgA...
```

## Not flagged

```text
a long base64 image inside a data: URI
```

## Why it matters

See https://attack.mitre.org/techniques/T1027/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
