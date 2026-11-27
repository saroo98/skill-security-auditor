# lookalike-source

Severity: high. OWASP Agentic Skills Top 10: AST02.

Source name imitates a well-known skill repository.

The repository name is the same as, or one character away from, a well-known skill repository, but the owner is different.

## Flagged

```text
someone-else/awesome-claude-skills
```

## Not flagged

```text
ComposioHQ/awesome-claude-skills
```

## Why it matters

See https://www.helpnetsecurity.com/2026/07/21/github-repos-malware-campaign-fakegit-ai-agents/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
