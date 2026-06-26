# Contributing

Thanks for improving `skill-security-auditor`.

## Development Setup

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

The scanner uses the Python standard library at runtime. Keep new runtime dependencies out unless they are necessary and clearly justified.

## Adding Detection Rules

- Add the rule to the relevant script under `skills/skill-security-auditor/scripts`.
- Give the rule a stable `rule_id`.
- Use an existing severity and category.
- Include a concise message and recommendation.
- Add tests that cover detection and at least one low-noise case when possible.

## Adding Examples

Examples must be inert fixtures. Do not include real credentials, realistic tokens, customer data, production hostnames, or commands that need to be executed.

## Reporting False Positives

Open an issue with the rule ID, a minimal sanitized sample, expected behavior, and actual behavior. Do not include credentials or sensitive repository content.

## Code Style

Prefer small functions, typed signatures where useful, deterministic output, and tests for every rule change.
