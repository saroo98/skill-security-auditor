# Design

`skill-security-auditor` is a static scanner for Codex and agent skill repositories. It reviews files that can influence agent behavior without executing the target.

## Static-Only Scanning

The scanner reads text-like files and applies deterministic checks. It never imports, executes, installs, sources, or invokes scanned files. This keeps review safe for untrusted skills and makes the tool suitable for CI gates.

## Rule Organization

Rules are grouped by behavior:

- Prompt-injection and hidden instruction checks.
- Shell, hook, dependency-install, and network-call checks.
- Destructive file-operation and credential-access checks.
- Metadata consistency checks for skill descriptions that omit risky sibling scripts.

Each finding includes a rule ID, severity, category, file, optional line, evidence, and recommendation.

## False Positives

The scanner intentionally favors conservative review signals over silent misses. Documentation-safe hosts such as `example.com` and RFC 5737 IP ranges are suppressed where possible. New allowlist behavior is intentionally deferred until real-world rule noise is better understood.

## Plugin Packaging

Plugin packaging is deferred for v1. The repository distributes one standalone skill under `skills/skill-security-auditor`, which can be copied into a Codex skills directory. A plugin wrapper can be added later if distribution needs include multiple skills, tools, hooks, or app metadata.
