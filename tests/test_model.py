from skillaudit.model import make_finding, stricter, verdict_for


def test_verdicts():
    assert verdict_for([]) == "PASS"
    assert verdict_for(["low", "info"]) == "PASS"
    assert verdict_for(["medium"]) == "REVIEW"
    assert verdict_for(["medium", "critical"]) == "BLOCK"
    assert verdict_for(["high"]) == "BLOCK"
    assert stricter("PASS", "REVIEW") == "REVIEW"
    assert stricter("BLOCK", "REVIEW") == "BLOCK"


def test_fingerprint_survives_line_shift():
    a = make_finding("remote-exec", "critical", "s.sh", 3, "m", "curl x | sh")
    b = make_finding("remote-exec", "critical", "s.sh", 9, "m", "curl  x | sh")
    assert a.fingerprint == b.fingerprint and len(a.fingerprint) == 16


def test_make_finding_sanitizes_evidence():
    f = make_finding("x", "low", "a", 1, "m", "a" + chr(0x200B) + "b")
    assert f.evidence == "a" + chr(92) + "u200bb"
