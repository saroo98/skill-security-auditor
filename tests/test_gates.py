"""Repository-level gates: every check is documented and tested, the project passes its own scan,
and no analyzer raises on arbitrary input."""

import random
from pathlib import Path

from skillaudit.analyzers import configs, generic, hidden, javascript, markdown, powershell, python_ast, shell
from skillaudit.checks import CHECKS
from skillaudit.engine import scan_path
from skillaudit.model import FileEntry

ROOT = Path(__file__).resolve().parents[1]
TEST_TEXT = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "tests").glob("test_*.py"))


def test_every_check_has_a_page():
    missing = [cid for cid in CHECKS if not (ROOT / "docs" / "checks" / f"{cid}.md").is_file()]
    assert missing == []


def test_every_check_page_has_examples_and_a_source():
    for cid in CHECKS:
        page = (ROOT / "docs" / "checks" / f"{cid}.md").read_text(encoding="utf-8")
        for heading in ("## Flagged", "## Not flagged", "## Why it matters"):
            assert heading in page, (cid, heading)
        assert "https://" in page, cid


def test_every_check_is_named_in_a_test():
    assert [cid for cid in CHECKS if cid not in TEST_TEXT] == []


def test_legacy_rules_are_gone():
    assert not (ROOT / "skills" / "securityauditor" / "scripts" / "skillaudit" / "analyzers" / "legacy.py").exists()


def _blocking(result):
    return [(u.name, f.check_id, f.file, f.line) for u in result.units for f in u.findings
            if f.severity in ("medium", "high", "critical")] + [
        (u.name, "not-checked", n.rel, None) for u in result.units for n in u.not_checked if n.severity != "info"]


def test_repository_scans_clean():
    # the tracked tree, exactly as it is published; local scratch folders are not part of it
    import subprocess

    from skillaudit.engine import scan_files

    names = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout.split(bytes([0]))
    contents = {n.decode(): (ROOT / n.decode()).read_bytes() for n in names if n and (ROOT / n.decode()).is_file()}
    assert _blocking(scan_files(contents, root_name="repository")) == []


def test_shipped_skill_scans_clean():
    result = scan_path(ROOT / "skills" / "securityauditor")
    assert [u.verdict for u in result.units] == ["PASS"], _blocking(result)


ANALYZERS = {
    "python": python_ast.analyze, "shell": shell.analyze, "powershell": powershell.analyze,
    "javascript": javascript.analyze, "markdown": markdown.analyze, "json": configs.analyze,
    "yaml": configs.analyze, "toml": configs.analyze, "text": hidden.analyze, "other-source": generic.analyze,
}


def test_analyzers_never_raise_on_random_input():
    rng = random.Random(1234)
    alphabet = [chr(c) for c in range(32, 127)] + list("\n\t\"'`$(){}[]<>|&;#\\") + [chr(0x200B), chr(0x202E), chr(0xE0041), "é", "ک"]
    for _ in range(250):
        size = rng.randrange(1, 1500)
        if rng.random() < 0.5:
            text = "".join(rng.choice(alphabet) for _ in range(size))
        else:
            text = bytes(rng.randrange(256) for _ in range(size)).decode("utf-8", errors="replace")
        for kind, fn in ANALYZERS.items():
            rel = "SKILL.md" if kind == "markdown" else f"f.{kind}"
            fn(FileEntry(None, rel, kind, "executable", text, "utf-8", len(text)))
            hidden.analyze(FileEntry(None, rel, kind, "executable", text, "utf-8", len(text)))


def test_analyzers_survive_deep_nesting():
    deep = "(" * 3000 + ")" * 3000
    for kind, fn in ANALYZERS.items():
        fn(FileEntry(None, "x", kind, "executable", deep, "utf-8", len(deep)))
    shell.analyze_command("$(" * 200 + "x" + ")" * 200, "a", 1)
