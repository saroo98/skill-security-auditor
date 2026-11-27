# dynamic-load

Severity: medium. OWASP Agentic Skills Top 10: AST01.

Loads code or serialized objects chosen at run time.

Code imports a module or loads a pickled object whose name or content is chosen at run time. Loading a pickle runs code.

## Flagged

```text
importlib.import_module(name); pickle.load(f)
```

## Not flagged

```text
import json; json.load(f)
```

## Why it matters

See https://attack.mitre.org/techniques/T1027/ and the OWASP Agentic Skills Top 10 (https://owasp.org/www-project-agentic-skills-top-10/).
