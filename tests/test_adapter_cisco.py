import json
import subprocess

import pytest

from bench.adapters import cisco


class Done:
    def __init__(self, stdout):
        self.stdout, self.returncode, self.stderr = stdout, 0, ""


def fake(monkeypatch, stdout="", exc=None):
    calls = []

    def run(cmd, **kw):
        calls.append(cmd)
        if exc:
            raise exc
        return Done(stdout)

    monkeypatch.setattr(cisco.subprocess, "run", run)
    monkeypatch.setattr(cisco, "_binary", lambda: "skill-scanner")
    return calls


def report(sev, n=1):
    return json.dumps({"is_safe": sev in ("INFO", "LOW", "NONE"), "max_severity": sev, "findings_count": n,
                       "findings": [{"rule_id": "R1", "severity": sev}]})


@pytest.mark.parametrize("sev,verdict", [("CRITICAL", "BLOCK"), ("HIGH", "BLOCK"), ("MEDIUM", "REVIEW"),
                                         ("LOW", "PASS"), ("INFO", "PASS"), ("NONE", "PASS")])
def test_maps_max_severity(monkeypatch, tmp_path, sev, verdict):
    calls = fake(monkeypatch, report(sev))
    assert cisco.ADAPTER.scan(tmp_path).verdict == verdict
    assert calls[0][1:] == ["scan", str(tmp_path), "--format", "json", "--compact"]


def test_leading_log_lines_are_tolerated(monkeypatch, tmp_path):
    fake(monkeypatch, "loading rules\n" + report("HIGH"))
    assert cisco.ADAPTER.scan(tmp_path).verdict == "BLOCK"


def test_crash_is_recorded_not_raised(monkeypatch, tmp_path):
    fake(monkeypatch, exc=subprocess.TimeoutExpired("skill-scanner", 180))
    r = cisco.ADAPTER.scan(tmp_path)
    assert r.verdict == "PASS" and "error" in r.raw


def test_registered():
    from bench.adapters import get

    assert get("cisco-skill-scanner") is cisco.ADAPTER
