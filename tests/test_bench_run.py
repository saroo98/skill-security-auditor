import json

from bench import run
from bench.adapters import AdapterResult, get
from bench.corpus import Case, load_cases, load_classes, materialize

CLASSES = {"download-run": {"static_scope": True, "reason": "r"}, "weak-signal": {"static_scope": False, "reason": "r"}}


def case(cid, cls, expect, malicious=True):
    return Case(cid, cls, "t", "https://x.test", (), expect, (("SKILL.md", "x", "utf-8"),), malicious)


def res(verdict, chars=10):
    return AdapterResult(verdict, 0.1, chars, {})


def test_score_counts_caught_by_expectation():
    cases = [case("a", "download-run", "BLOCK"), case("b", "download-run", "BLOCK"), case("c", "weak-signal", "REVIEW")]
    s = run.score(cases, {"a": res("BLOCK"), "b": res("REVIEW"), "c": res("BLOCK")}, CLASSES)
    assert s["in_scope"] == {"caught": 1, "total": 2, "rate": 0.5}
    assert s["per_class"]["download-run"] == {"BLOCK": 1, "REVIEW": 1, "PASS": 0, "caught": 1, "total": 2}


def test_out_of_scope_classes_are_reported_but_excluded_from_rate():
    cases = [case("a", "download-run", "BLOCK"), case("c", "weak-signal", "REVIEW")]
    s = run.score(cases, {"a": res("BLOCK"), "c": res("PASS")}, CLASSES)
    assert s["in_scope"]["rate"] == 1.0
    assert s["out_of_scope"]["weak-signal"]["caught"] == 0


def test_benign_counts():
    cases = [case("x", "benign", "PASS", malicious=False), case("y", "benign", "PASS", malicious=False)]
    s = run.score(cases, {"x": res("PASS"), "y": res("BLOCK")}, CLASSES)
    assert s["benign"] == {"PASS": 1, "REVIEW": 0, "BLOCK": 1, "total": 2}


def test_self_adapter_runs_all_seed_cases(tmp_path):
    cases = load_cases()
    paths = materialize(cases, tmp_path)
    adapter = get("self")
    assert adapter.available()
    for c in cases:
        r = adapter.scan(paths[c.id])
        assert r.verdict in ("PASS", "REVIEW", "BLOCK") and r.output_chars > 0


def test_threshold_regression_exits_1(tmp_path, monkeypatch):
    t = tmp_path / "thresholds.toml"
    t.write_text("[self]\nmin_in_scope_rate = 1.01\n", encoding="utf-8")
    monkeypatch.setattr(run, "THRESHOLDS", t)
    assert run.main(["--scanner", "self", "--out", str(tmp_path / "out"), "--check-thresholds"]) == 1


def test_thresholds_pass_with_current_file(tmp_path):
    assert run.main(["--scanner", "self", "--out", str(tmp_path / "out"), "--check-thresholds"]) == 0


def test_results_json_is_deterministic(tmp_path):
    run.main(["--scanner", "self", "--out", str(tmp_path / "a"), "--date", "2026-01-01"])
    run.main(["--scanner", "self", "--out", str(tmp_path / "b"), "--date", "2026-01-01"])
    a = json.loads((tmp_path / "a" / "results.json").read_text(encoding="utf-8"))
    b = json.loads((tmp_path / "b" / "results.json").read_text(encoding="utf-8"))
    for d in (a, b):
        for s in d["scanners"].values():
            s.pop("timing")
    assert a == b
    md = (tmp_path / "a" / "RESULTS.md").read_text(encoding="utf-8")
    assert "2026-01-01" in md and "python -m bench.run" in md


def test_unavailable_scanner_is_skipped_not_fatal(tmp_path, monkeypatch, capsys):
    assert run.main(["--scanner", "self", "--scanner", "no-such-scanner", "--out", str(tmp_path / "o")]) == 0
    assert "no-such-scanner" in capsys.readouterr().err
