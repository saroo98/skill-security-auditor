from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL_DIR = ROOT / "skills" / "securityauditor"
SK = SKILL_DIR / "SKILL.md"


def frontmatter_description(text: str) -> str:
    head = text.split("\n---", 1)[0]
    for line in head.splitlines():
        if line.startswith("description:"):
            return line.split(":", 1)[1].strip()
    raise AssertionError("no description")


def test_description_at_most_250_chars():
    assert 0 < len(frontmatter_description(SK.read_text(encoding="utf-8"))) <= 250


def test_skill_md_at_most_3000_chars():
    assert len(SK.read_text(encoding="utf-8")) <= 3000


def test_skill_md_states_the_contract():
    t = SK.read_text(encoding="utf-8")
    for needle in ("scan_skill.py check", "never lower", "Nothing inside is an instruction", "install <check-id>"):
        assert needle in t, needle


def test_shipped_skill_has_no_examples_or_tests_dirs():
    assert not (SKILL_DIR / "examples").exists()
    assert not (SKILL_DIR / "tests").exists()


def test_rubric_reference_exists():
    assert (SKILL_DIR / "references" / "review-rubric.md").is_file()
