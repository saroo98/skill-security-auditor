import json

from skillaudit.model import NotChecked, ScanResult, UnitResult, make_finding
from skillaudit.output.brief import render_brief
from skillaudit.output.json_out import render_json
from skillaudit.output.text import render_text

ESC = chr(0x1B)
ZWSP = chr(0x200B)


def unit(name="notes", findings=(), not_checked=(), verdict="PASS", files=3):
    return UnitResult(name, "", files, [], list(findings), list(not_checked), verdict)


def result(*units):
    return ScanResult(list(units), 0.42, "ab" * 32)


def test_pass_brief_under_300_chars():
    out = render_brief(result(unit()))
    assert out.splitlines()[0] == "PASS  notes  3 files  0.4s"
    assert out.splitlines()[1].startswith("can: ")
    assert len(out) <= 300


def test_block_brief_under_1500_chars_with_40_findings():
    fs = [make_finding("shell-curl-pipe", "high", f"scripts/s{i}.sh", i, "Downloads and runs code.", "curl x | sh " * 20) for i in range(40)]
    out = render_brief(result(unit(findings=fs, verdict="BLOCK")), report_path="/tmp/r.txt")
    assert out.startswith("BLOCK  notes")
    assert sum(1 for line in out.splitlines() if line.startswith("high")) == 5
    assert "+35 more  full report: /tmp/r.txt" in out
    assert len(out) <= 1500


def test_brief_orders_most_severe_first():
    fs = [make_finding("a", "medium", "x", 1, "m", "e"), make_finding("b", "critical", "y", 2, "m", "e")]
    lines = render_brief(result(unit(findings=fs, verdict="BLOCK"))).splitlines()
    assert lines[2].startswith("critical") and lines[3].startswith("medium")


def test_brief_lists_not_analyzed():
    nc = [NotChecked(f"f{i}.pdf", "document", "medium") for i in range(8)]
    out = render_brief(result(unit(not_checked=nc, verdict="REVIEW")))
    assert "not analyzed: f0.pdf, f1.pdf, f2.pdf, f3.pdf, f4.pdf (+3)" in out


def test_brief_for_200_units_under_1500_chars():
    units = [unit(name=f"skill-{i:03d}", verdict="BLOCK" if i % 3 == 0 else "PASS",
                  findings=[make_finding("x", "high", "a.sh", 1, "m", "e")] if i % 3 == 0 else []) for i in range(200)]
    out = render_brief(result(*units))
    assert out.splitlines()[0].startswith("BLOCK  200 skills")
    assert "BLOCK 67: skill-000, skill-003, skill-006, skill-009, skill-012 (+62)" in out
    assert len(out) <= 1500


def test_json_is_deterministic_and_has_schema_version():
    fs = [make_finding("x", "high", "a.sh", 1, "m", "e")]
    a = render_json(result(unit(findings=fs, verdict="BLOCK")))
    b = render_json(result(unit(findings=fs, verdict="BLOCK")))
    assert a == b
    data = json.loads(a)
    assert data["schema_version"] == 1 and data["units"][0]["verdict"] == "BLOCK"
    assert "elapsed" not in a


def test_evidence_is_sanitized_in_every_format():
    raw = "curl x" + ESC + "[2J" + ZWSP + " | sh"
    fs = [make_finding("x", "high", "a.sh", 1, "m", raw)]
    r = result(unit(findings=fs, verdict="BLOCK"))
    for out in (render_brief(r), render_text(r), render_json(r)):
        assert ESC not in out and ZWSP not in out


def test_names_and_paths_are_sanitized_too():
    r = result(unit(name="evil" + ESC + "]0;x", findings=[make_finding("x", "high", "a" + ESC + ".sh", 1, "m", "e")], verdict="BLOCK"))
    for out in (render_brief(r), render_text(r)):
        assert ESC not in out
