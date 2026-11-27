from skillaudit.checks import CHECKS
from skillaudit.model import Capability, NotChecked
from skillaudit.policy import can_summary, decide, unprompted_summary


def C(kind, file="f.py", **d):
    return Capability(kind, file, 1, "x", detail=tuple(sorted(d.items())))


def ids(caps, **kw):
    return {f.check_id for f in decide(caps, [], **kw)}


def sev(caps, **kw):
    return {f.check_id: f.severity for f in decide(caps, [], **kw)}


def test_flows():
    assert ids([C("flow", source="secret.read", sink="net.outbound", host="evil.test")]) == {"secret-to-network"}
    assert ids([C("flow", source="env.dump", sink="net.outbound")]) == {"env-to-network"}
    assert ids([C("flow", source="secret.use", sink="net.outbound", secret="OPENAI_API_KEY", host="api.openai.com")]) == {"secret-to-vendor"}
    assert ids([C("flow", source="secret.use", sink="net.outbound", secret="OPENAI_API_KEY", host="evil.test")]) == {"secret-to-odd-host"}
    assert ids([C("flow", source="secret.use", sink="net.outbound", secret="ACME_TOKEN", host="api.acme.test")]) == {"secret-to-unknown-host"}
    assert ids([C("flow", source="secret.use", sink="net.outbound", secret="ACME_TOKEN", host="webhook.site")]) == {"secret-to-odd-host"}
    assert ids([C("flow", source="secret.use", sink="net.outbound", secret="ACME_TOKEN", host="203.0.113.5")]) == {"secret-to-odd-host"}
    # a destination the code does not reveal is unknown, not proven odd (changed after the real-skill measurement)
    assert ids([C("flow", source="secret.use", sink="net.outbound", secret="ACME_TOKEN")]) == {"secret-to-unknown-host"}


def test_vendor_subdomains_match():
    assert ids([C("flow", source="secret.use", sink="net.outbound", secret="GITHUB_TOKEN", host="api.github.com")]) == {"secret-to-vendor"}
    assert ids([C("flow", source="secret.use", sink="net.outbound", secret="GITHUB_TOKEN", host="evilgithub.com")]) == {"secret-to-odd-host"}


def test_severities_follow_registry():
    s = sev([C("exec.remote"), C("net.listen"), C("exec.shell", constant="no"), C("exec.shell", file="g.sh", constant="yes"), C("pkg.install")])
    assert s == {"remote-exec": "critical", "reverse-shell": "critical", "shell-dynamic": "medium", "shell-constant": "low",
                 "runtime-pkg-install": "medium"}


def test_deletes():
    assert sev([C("fs.delete", target="home")]) == {"delete-root-or-home": "critical"}
    assert sev([C("fs.delete", target="root")]) == {"delete-root-or-home": "critical"}
    assert sev([C("fs.delete", target="system")]) == {"delete-root-or-home": "critical"}
    assert sev([C("fs.delete", target="project")]) == {"project-delete": "info"}
    assert sev([C("fs.delete", target="absolute")]) == {"write-outside-workspace": "medium"}


def test_unprompted():
    assert sev([C("unprompted", trigger="SessionStart hook", analyzed="no")]) == {"unprompted-unanalyzed": "high"}
    assert sev([C("unprompted", trigger="SessionStart hook", analyzed="yes")]) == {"unprompted-clean": "low"}


def test_instructions():
    got = sev([C("instruction.override"), C("instruction.conceal"), C("instruction.noask"), C("instruction.external"),
               C("instruction.install-extra"), C("instruction.hidden"), C("instruction.reviewer")])
    assert got == {"instruction-override": "high", "instruction-conceal": "high", "instruction-no-ask": "medium",
                   "instruction-external": "high", "install-extra-component": "high", "hidden-instruction": "critical",
                   "reviewer-directed": "critical"}


def test_secret_near_network_without_flow():
    assert ids([C("secret.read"), C("net.outbound", host="x.test")]) == {"secret-near-network"}
    assert ids([C("secret.read"), C("net.outbound", file="other.py", host="x.test")]) == set()


def test_cap_for_unreferenced_docs():
    got = decide([C("exec.remote", file="README.md")], [], unreferenced_low_roles={"README.md"})
    assert [(f.check_id, f.severity) for f in got] == [("remote-exec", "low")]


def test_no_undeclared_findings_without_declarations_enabled():
    assert ids([C("net.outbound", host="x.test"), C("secret.read")]) == {"secret-near-network"}


def test_every_check_in_registry_has_known_severity_and_title():
    expected = {
        "critical": {"secret-to-network", "env-to-network", "remote-exec", "reverse-shell", "delete-root-or-home",
                     "hidden-instruction", "reviewer-directed"},
        "high": {"unprompted-unanalyzed", "instruction-override", "instruction-conceal", "permission-bypass",
                 "instruction-external", "install-extra-component", "secret-to-odd-host",
                 "lookalike-source", "dynamic-exec", "obfuscation", "persist-runtime", "agent-config-change",
                 "undeclared-secret-read", "undeclared-persist", "binary-referenced"},
        "medium": {"instruction-no-ask", "secret-near-network", "dynamic-load", "secret-to-unknown-host", "shell-dynamic", "runtime-pkg-install", "write-outside-workspace",
                   "undeclared-capability", "not-checked"},
        "low": {"unprompted-clean", "declared-network", "shell-constant"},
        "info": {"secret-to-vendor", "env-read", "project-delete", "inert-media"},
    }
    for severity, names in expected.items():
        for name in names:
            assert CHECKS[name].severity == severity, name
            assert CHECKS[name].title
    assert set(CHECKS) >= set().union(*expected.values())


def test_can_summary_names_hosts():
    assert can_summary([C("net.outbound", host="evil.test")]) == ["network (evil.test)"]
    assert can_summary([C("net.outbound", host="b.test"), C("net.outbound", host="a.test"), C("exec.shell")]) == [
        "network (a.test, b.test)", "run shell commands"]


def test_can_summary_counts_flow_sinks_as_network():
    assert can_summary([C("flow", source="secret.read", sink="net.outbound", host="evil.test")]) == ["network (evil.test)", "read credential files"]


def test_unprompted_summary():
    assert unprompted_summary([C("unprompted", file=".claude/settings.json", trigger="SessionStart hook")]) == [
        "SessionStart hook -> .claude/settings.json"]


def test_not_checked_items_do_not_become_findings():
    assert decide([], [NotChecked("a.pdf", "doc", "medium")]) == []


def test_workflow_findings_are_capped_low(tmp_path):
    from helpers import FM, make
    from skillaudit.engine import scan_path

    make(tmp_path, {"SKILL.md": FM, ".github/workflows/ci.yml": "jobs:\n  t:\n    steps:\n      - run: python -m pip install -r requirements.txt\n"})
    found = {(f.check_id, f.severity) for f in scan_path(tmp_path).units[0].findings}
    assert ("runtime-pkg-install", "low") in found
