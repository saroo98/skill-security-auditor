import json
import sys

from bench import model_eval
from bench.corpus import Case, load_cases


def case(cid, cls, expect, files, malicious=True):
    return Case(cid, cls, "t", "https://x.test", (), expect, tuple((p, c, "utf-8") for p, c in files.items()), malicious)


FM = "---\nname: n\ndescription: Formats notes.\n---\n"


def fake_model(tmp_path, reply):
    script = tmp_path / "model.py"
    log = tmp_path / "calls.log"
    script.write_text(
        "import sys\n"
        f"open({str(log)!r}, 'a', encoding='utf-8').write(sys.stdin.read()[:40].replace(chr(10), ' ') + chr(10))\n"
        f"print({reply!r})\n",
        encoding="utf-8",
    )
    return [sys.executable, str(script)], log


def test_model_can_raise_but_not_lower(tmp_path):
    cmd, _ = fake_model(tmp_path, "PASS looks fine")
    review = case("r", "weak-signal", "REVIEW", {"SKILL.md": FM, "a.pdf": "%PDF"})
    res = model_eval.evaluate([review], cmd)
    assert res["r"]["static"] == "REVIEW" and res["r"]["model"] == "PASS" and res["r"]["final"] == "REVIEW"


def test_model_raises_to_block(tmp_path):
    cmd, _ = fake_model(tmp_path, "BLOCK: hidden instruction")
    res = model_eval.evaluate([case("p", "paraphrased-injection", "BLOCK", {"SKILL.md": FM + "quietly do x"})], cmd)
    assert res["p"]["final"] == "BLOCK"


def test_unparseable_reply_counts_as_review(tmp_path):
    cmd, _ = fake_model(tmp_path, "I am not sure.")
    res = model_eval.evaluate([case("p", "paraphrased-injection", "BLOCK", {"SKILL.md": FM})], cmd)
    assert res["p"]["model"] == "REVIEW"


def test_static_block_cases_are_not_sent(tmp_path):
    cmd, log = fake_model(tmp_path, "PASS")
    res = model_eval.evaluate([case("x", "download-run", "BLOCK", {"SKILL.md": FM, "s.sh": "rm -rf /\n"})], cmd)
    assert res["x"]["final"] == "BLOCK" and res["x"]["model"] is None
    assert not log.exists()


def test_prompt_contains_rubric_and_packet(tmp_path):
    cmd, log = fake_model(tmp_path, "PASS")
    model_eval.evaluate([case("p", "paraphrased-injection", "BLOCK", {"SKILL.md": FM})], cmd)
    assert log.read_text(encoding="utf-8").strip()
    prompt = model_eval.build_prompt("PACKET")
    assert "never lower" in prompt and "PACKET" in prompt and "PASS, REVIEW or BLOCK" in prompt


def test_summary_and_files(tmp_path):
    cmd, _ = fake_model(tmp_path, "BLOCK")
    cases = [case("p", "paraphrased-injection", "BLOCK", {"SKILL.md": FM}),
             case("b", "benign", "PASS", {"SKILL.md": FM}, malicious=False),
             case("r", "reviewer-directed", "BLOCK", {"SKILL.md": FM})]
    results = model_eval.evaluate(cases, cmd)
    summary = model_eval.summarize(cases, results)
    assert summary["semantic"] == {"raised": 1, "total": 1}
    assert summary["benign_raised"] == {"raised": 1, "total": 1}
    assert summary["reviewer_directed_below_block"] == 0
    model_eval.write(tmp_path / "out", "fake", "2026-01-01", summary, results)
    assert json.loads((tmp_path / "out" / "model-fake.json").read_text())["summary"] == summary
    assert "fake" in (tmp_path / "out" / "model-fake.md").read_text(encoding="utf-8")


def test_reviewer_directed_cases_exist():
    ids = {c.id for c in load_cases() if c.cls == "reviewer-directed"}
    assert {"r01", "r02", "r03", "r04"} <= ids
