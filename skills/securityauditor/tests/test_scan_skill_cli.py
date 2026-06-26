import json
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "skills" / "securityauditor" / "scripts" / "scan_skill.py"
EXAMPLES = REPO_ROOT / "skills" / "securityauditor" / "examples"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_help_exits_zero():
    result = run_cli("--help")
    assert result.returncode == 0
    assert "Audit Codex or agent skill" in result.stdout


def test_missing_target_exits_two():
    result = run_cli("missing-target")
    assert result.returncode == 2


def test_benign_fixture_exits_zero():
    result = run_cli(str(EXAMPLES / "benign-skill"), "--json", "--fail-on", "low")
    assert result.returncode == 0
    assert json.loads(result.stdout)["summary"]["findings"] == 0


def test_suspicious_fixture_exits_one_for_high_threshold():
    result = run_cli(str(EXAMPLES / "suspicious-skill"), "--json", "--fail-on", "high")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    categories = {finding["category"] for finding in payload["findings"]}
    assert "prompt_injection" in categories
    assert "shell_risk" in categories
    assert "credential_access" in categories


def test_dependency_directories_are_skipped_by_default(tmp_path: Path):
    target = tmp_path / "skill"
    dep_dir = target / "node_modules" / "package"
    dep_dir.mkdir(parents=True)
    (target / "SKILL.md").write_text("---\nname: test\ndescription: safe local helper\n---\n", encoding="utf-8")
    (dep_dir / "risky.sh").write_text("rm -rf /\n", encoding="utf-8")
    result = run_cli(str(target), "--json", "--fail-on", "low")
    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["summary"]["findings"] == 0


def test_max_file_size_skips_large_files(tmp_path: Path):
    target = tmp_path / "skill"
    target.mkdir()
    (target / "SKILL.md").write_text("---\nname: test\ndescription: safe local helper\n---\n", encoding="utf-8")
    (target / "large.py").write_text("x" * 200, encoding="utf-8")
    result = run_cli(str(target), "--json", "--max-file-size", "10")
    payload = json.loads(result.stdout)
    assert result.returncode == 0
    assert payload["summary"]["skipped_files"] == 2
