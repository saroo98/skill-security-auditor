# How it works

`skill-security-auditor` checks an agent skill before it is installed. It never runs the skill.

## Pipeline

```text
fetch -> quarantine -> discover -> analyze -> link -> decide -> report -> (model review) -> install
```

1. **Fetch.** `check` accepts a local folder or archive, a GitHub address, `owner/repo[/path]`, or an https archive link. It downloads an archive over HTTPS with a size cap, refuses redirects to plain HTTP, and sends no tokens.
2. **Quarantine.** The archive is unpacked member by member into a per-user cache folder. Absolute and parent paths, links, devices, reserved Windows names, case collisions and expansion bombs are refused. The tree is hashed.
3. **Discover.** Every file is decoded (UTF-8, UTF-16 with or without BOM) and classified by extension, shebang and content. Anything that cannot be checked is listed with a reason; nothing is skipped silently.
4. **Analyze.** Each analyzer reports what a file can do, as capabilities with a file, line and snippet:
   - shell: download-and-run in all common forms, reverse shells, deletes by target, credential reads, environment dumps, persistence, and data flows through pipelines, variables and files;
   - Python: an `ast` pass with import aliases, constant and path folding, and taint from secrets to network calls;
   - JavaScript, PowerShell, and a low-confidence pass for other languages;
   - markdown and instructions: override, concealment, act-without-asking, fetch-and-follow, install-an-extra-component, and text addressed to a reviewer, with negation and descriptive framing handled;
   - hidden content in any file: Unicode tag characters, zero-width runs, bidi overrides, lookalike hosts, and encoded blobs that decode to commands;
   - config: hooks, monitors, MCP servers, lifecycle scripts and `allowed-tools`, each marked as checked or not.
5. **Link.** A reference graph decides what the instructions and code actually reach. Documentation and tests that nothing reaches are capped at low. A folder with `SKILL.md` is always a full skill, wherever it sits.
6. **Decide.** A fixed policy maps capabilities to findings (see `docs/checks/`) and compares them with what `SKILL.md` says the skill does. Any high or critical finding is BLOCK; medium findings or unchecked files are REVIEW; otherwise PASS.
7. **Report.** A short verdict for the agent to relay, plus full text, JSON and SARIF reports. Every string from a scanned file is sanitized.
8. **Model review.** Unless static analysis already blocked the skill, the agent's model reviews a capped, sanitized packet of the skill's instructions against a fixed rubric. It can raise the verdict and never lower it.
9. **Install.** After the user agrees, `install` copies the exact files that were checked and records them in a lockfile; `verify` reports later changes in terms of capabilities.

## What it does not do

It does not execute or sandbox the skill, does not prove a skill is safe, and does not read private repositories. Paraphrased or non-English instructions are left to the model review. Results on the benchmark corpus are in `bench/results/`.
