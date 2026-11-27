import json
import subprocess

import pytest

from bench.adapters import skillspector


class Done:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


def fake(monkeypatch, stdout="", exc=None):
    calls = []

    def run(cmd, **kw):
        calls.append((cmd, kw))
        if exc:
            raise exc
        return Done(stdout)

    monkeypatch.setattr(skillspector.subprocess, "run", run)
    monkeypatch.setattr(skillspector, "_binary", lambda: "skillspector")
    return calls


def report(rec):
    return json.dumps({"risk_assessment": {"recommendation": rec, "score": 50}, "issues": []})


@pytest.mark.parametrize("rec,verdict", [("DO_NOT_INSTALL", "BLOCK"), ("CAUTION", "REVIEW"), ("SAFE", "PASS")])
def test_maps_recommendations(monkeypatch, tmp_path, rec, verdict):
    calls = fake(monkeypatch, report(rec))
    r = skillspector.ADAPTER.scan(tmp_path)
    assert r.verdict == verdict
    cmd, kw = calls[0]
    assert cmd[1:] == ["scan", str(tmp_path), "--no-llm", "--format", "json"]
    assert kw["env"]["PYTHONUTF8"] == "1"


def test_leading_noise_before_json_is_tolerated(monkeypatch, tmp_path):
    fake(monkeypatch, "Loading rules...\n" + report("SAFE"))
    assert skillspector.ADAPTER.scan(tmp_path).verdict == "PASS"


def test_crash_is_recorded_not_raised(monkeypatch, tmp_path):
    fake(monkeypatch, exc=subprocess.TimeoutExpired("skillspector", 180))
    r = skillspector.ADAPTER.scan(tmp_path)
    assert r.verdict == "PASS" and "error" in r.raw


def test_garbage_output_is_recorded(monkeypatch, tmp_path):
    fake(monkeypatch, "not json at all")
    assert "error" in skillspector.ADAPTER.scan(tmp_path).raw


def test_binary_from_environment(monkeypatch, tmp_path):
    exe = tmp_path / "skillspector.exe"
    exe.write_text("")
    monkeypatch.setenv("SKILLSPECTOR_BIN", str(exe))
    assert skillspector._binary() == str(exe)
