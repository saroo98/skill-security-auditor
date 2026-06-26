# Release Checklist

- Run `python -m pytest`.
- Run the benign example scan.
- Run the suspicious example scan and confirm it exits `1` at `--fail-on high`.
- Validate `skills/skill-security-auditor` with `quick_validate.py`.
- Review README and docs for public-facing language.
- Confirm examples use only documentation-safe placeholders.
- Confirm no credentials, local-only context, or non-public notes are present.
- Confirm repository description and topics match `docs/repository-metadata.md`.
- Confirm `LICENSE`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `CODE_OF_CONDUCT.md` are present.
- Confirm `assets/banner.svg`, `assets/card.svg`, `assets/icon.svg`, and `assets/preview.png` are present.
