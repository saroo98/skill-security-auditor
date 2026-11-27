# undeclared-capability

Severity: medium. OWASP Agentic Skills Top 10: AST04.

Does something the description does not mention.

The skill does something its description and instructions do not mention, such as network use in a note formatter.

## Flagged

```text
urlopen(...) in a skill described as 'Formats local notes'
```

## Not flagged

```text
the same call in a skill described as calling a web API
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
