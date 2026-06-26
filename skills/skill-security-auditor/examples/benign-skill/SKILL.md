---
name: benign-skill
description: Safe example skill for formatting local Markdown notes with no network access, credential access, hooks, or file deletion.
---

# Benign Skill

Use this example to verify that routine skill instructions do not produce findings.

## Workflow

1. Read a local Markdown file supplied by the user.
2. Summarize visible headings.
3. Return a short report.

## Safety Boundaries

- Do not read credentials.
- Do not make network requests.
- Do not modify files.
