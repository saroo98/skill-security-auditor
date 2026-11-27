import re

import pytest

from bench.corpus import REPO_ROOT, load_cases, load_classes, materialize

SAFE_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
SAFE_HOSTS = {"docs.python.org"}


def test_seed_cases_load():
    cases = load_cases()
    ids = {c.id for c in cases}
    assert {f"e{i:02d}" for i in range(1, 17)} | {f"b{i:02d}" for i in range(1, 7)} <= ids


def test_every_case_has_source_class_and_inert_hosts():
    classes = load_classes()
    for c in load_cases():
        assert c.source.startswith("https://"), c.id
        assert c.cls in classes or (c.cls == "benign" and not c.malicious), c.id
        assert c.expect in ("PASS", "REVIEW", "BLOCK"), c.id
        assert c.files, c.id
        for _, content, _ in c.files:
            for host in re.findall(r"https?://([^/\s\"')]+)", content):
                host = host.split(":")[0]
                assert host.endswith((".test", ".example")) or host in SAFE_HOSTS or host.startswith(SAFE_PREFIXES), (c.id, host)


def test_classes_have_scope_and_reason():
    for name, info in load_classes().items():
        assert isinstance(info["static_scope"], bool) and info["reason"], name


def test_seed_class_mapping():
    by_id = {c.id: c for c in load_cases()}
    assert by_id["e08"].cls == "weak-signal" and by_id["e08"].expect == "REVIEW"
    assert by_id["e04"].cls == "paraphrased-injection"
    assert by_id["e15"].cls == "unprompted-exec"
    assert all(by_id[f"b{i:02d}"].expect == "PASS" for i in range(1, 7))


def test_case_files_are_ascii_on_disk():
    for path in (REPO_ROOT / "bench" / "corpus").rglob("*.toml"):
        path.read_bytes().decode("ascii")


def test_materialize_writes_exact_bytes(tmp_path):
    out = materialize(load_cases(), tmp_path / "m")
    e07 = (out["e07"] / "SKILL.md").read_bytes()
    assert e07.startswith(b"\xff\xfe")
    assert chr(0xE0049) in (out["e05"] / "SKILL.md").read_text(encoding="utf-8")
    assert (out["b04"] / "scripts" / "clean.sh").read_text() == "rm -rf ./build\n"
    assert out["e01"].parent.name == "malicious" and out["b01"].parent.name == "benign"


def test_materialize_refuses_repo_directory():
    with pytest.raises(ValueError, match="outside the repository"):
        materialize(load_cases(), REPO_ROOT / "bench" / "tmp-out")
