# runtime-pkg-install

Severity: medium. OWASP Agentic Skills Top 10: AST02.

Installs packages at run time.

Packages are installed while the skill runs, pulling code that was not part of the review.

## Flagged

```text
pip install some-package
```

## Not flagged

```text
a requirements file the user installs themselves
```

## Why it matters

See https://owasp.org/www-project-agentic-skills-top-10/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
