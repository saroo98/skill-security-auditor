# unprompted-unanalyzed

Severity: high. OWASP Agentic Skills Top 10: AST06.

Runs without asking, and the command could not be checked.

Something the host runs without asking (a hook, monitor, MCP server or lifecycle script) runs code this tool could not check: a script missing from the package, or a package fetched at run time.

## Flagged

```text
"command": "npx -y some-mcp-server@latest"
```

## Not flagged

```text
"command": "bash ${CLAUDE_PLUGIN_ROOT}/scripts/hello.sh"   # script is in the package
```

## Why it matters

See https://code.claude.com/docs/en/plugins/security and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
