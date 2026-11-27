import json
import subprocess
import sys
from pathlib import Path

from helpers import FM, make

from skillaudit.cli import main

SCRIPT = Path(__file__).resolve().parents[1] / "skills" / "securityauditor" / "scripts" / "scan_skill.py"


def test_scan_exit_codes(tmp_path, capsys):
    clean = make(tmp_path / "clean", {"SKILL.md": FM})
    bad = make(tmp_path / "bad", {"SKILL.md": FM, "x.sh": "rm -rf /\n"})
    assert main(["scan", str(clean)]) == 0
    assert main(["scan", str(bad)]) == 1
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_fail_on_medium(tmp_path):
    t = make(tmp_path, {"SKILL.md": FM, "a.pdf": b"%PDF"})
    assert main(["scan", str(t)]) == 0
    assert main(["scan", str(t), "--fail-on", "medium"]) == 1


def test_json_alias_and_no_subcommand(tmp_path, capsys):
    make(tmp_path, {"SKILL.md": FM})
    main([str(tmp_path), "--json"])
    a = capsys.readouterr().out
    main(["scan", str(tmp_path), "--format", "json"])
    b = capsys.readouterr().out
    assert a == b and json.loads(a)["schema_version"] == 1


def test_brief_format(tmp_path, capsys):
    make(tmp_path, {"SKILL.md": FM})
    main(["scan", str(tmp_path), "--format", "brief"])
    assert capsys.readouterr().out.startswith("PASS  notes")


def test_script_entry_point_runs(tmp_path):
    make(tmp_path, {"SKILL.md": FM})
    p = subprocess.run([sys.executable, str(SCRIPT), str(tmp_path), "--json"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert json.loads(p.stdout)["units"][0]["name"] == "notes"


def test_help_exits_zero(capsys):
    try:
        main(["--help"])
    except SystemExit as exc:
        assert exc.code == 0
    assert "scan" in capsys.readouterr().out
