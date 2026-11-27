# Checking pinned skills at session start

`verify --quiet` compares each pinned skill with its lockfile entry by hash and prints nothing when nothing changed. To run it whenever a Claude Code session starts, add a hook to your own settings (for example `~/.claude/settings.json`). The tool never edits settings itself.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "python /path/to/skills/securityauditor/scripts/scan_skill.py verify --quiet --lock /path/to/skill.lock.json"
          }
        ]
      }
    ]
  }
}
```

When a pinned skill has changed, the hook prints one line per skill, for example:

```text
changed: notes: 2 files differ from the approved version
```

Run `verify` without `--quiet` to see what changed: new capabilities, new hosts, new things that run without asking, and new findings.
