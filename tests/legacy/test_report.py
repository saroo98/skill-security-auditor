from report import (
    Finding,
    ScanResult,
    clip_evidence,
    exit_code_for_threshold,
    render_json,
    sort_findings,
)


def finding(rule_id: str, severity: str, file: str = "b.txt") -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category="shell_risk",
        file=file,
        line=1,
        message="message",
        evidence="evidence",
        recommendation="recommendation",
    )


def test_severity_sorting_highest_first():
    ordered = sort_findings(
        [
            finding("low-rule", "low"),
            finding("critical-rule", "critical"),
            finding("medium-rule", "medium"),
        ]
    )
    assert [item.severity for item in ordered] == ["critical", "medium", "low"]


def test_threshold_exit_logic():
    result = ScanResult(findings=[finding("medium-rule", "medium")], scanned_files=1, skipped_files=[], errors=[])
    assert exit_code_for_threshold(result, "high") == 0
    assert exit_code_for_threshold(result, "medium") == 1


def test_json_output_is_deterministic_and_counts_severities():
    result = ScanResult(
        findings=[finding("b", "low", "z.txt"), finding("a", "critical", "a.txt")],
        scanned_files=2,
        skipped_files=["skip.txt"],
        errors=[],
    )
    output = render_json(result)
    assert output == render_json(result)
    import json

    payload = json.loads(output)
    assert list(payload.keys()) == ["summary", "findings", "skipped_files", "errors"]
    assert '"critical": 1' in output
    assert '"low": 1' in output


def test_evidence_is_clipped():
    assert len(clip_evidence("x" * 250)) == 200
    assert clip_evidence("x" * 250).endswith("…")
