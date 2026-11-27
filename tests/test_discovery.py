import os
import time

import pytest

from skillaudit.discovery import MAX_LINE, discover


def by_rel(files):
    return {f.rel: f for f in files}


def test_extensionless_shebang_script_is_shell(tmp_path):
    (tmp_path / "install").write_text("#!/bin/sh\necho hi\n")
    files, _ = discover(tmp_path)
    assert files[0].kind == "shell" and files[0].role == "executable"


def test_shebang_python_and_node(tmp_path):
    (tmp_path / "a").write_text("#!/usr/bin/env python3\nprint(1)\n")
    (tmp_path / "b").write_text("#!/usr/bin/env node\nconsole.log(1)\n")
    files = by_rel(discover(tmp_path)[0])
    assert files["a"].kind == "python" and files["b"].kind == "javascript"


def test_utf16_skill_md_is_decoded(tmp_path):
    (tmp_path / "SKILL.md").write_bytes(("﻿# Hello").encode("utf-16-le"))
    files, nc = discover(tmp_path)
    assert files[0].text.endswith("# Hello")
    assert files[0].encoding.startswith("utf-16")
    assert files[0].role == "instruction"
    assert nc == []


def test_utf16_without_bom_is_decoded(tmp_path):
    (tmp_path / "notes.txt").write_bytes("plain words here".encode("utf-16-le"))
    files, _ = discover(tmp_path)
    assert files[0].text == "plain words here"


def test_unknown_things_are_listed_not_dropped(tmp_path):
    (tmp_path / "tool.rb").write_text("puts 1")
    (tmp_path / "a.pdf").write_bytes(b"%PDF-1.4")
    (tmp_path / "x.exe").write_bytes(b"MZ\x00\x00")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG")
    _, nc = discover(tmp_path)
    assert {(n.rel, n.severity) for n in nc} == {
        ("tool.rb", "medium"),
        ("a.pdf", "medium"),
        ("x.exe", "medium"),
        ("logo.png", "info"),
    }


def test_binary_magic_wins_over_extension(tmp_path):
    (tmp_path / "helper.py").write_bytes(b"\x7fELF\x02\x01")
    files, nc = discover(tmp_path)
    assert files == [] and nc[0].rel == "helper.py" and nc[0].severity == "medium"


def test_oversize_file_reported(tmp_path):
    (tmp_path / "big.txt").write_text("x" * 100)
    files, nc = discover(tmp_path, max_file_size=10)
    assert files == [] and "larger than" in nc[0].reason and nc[0].severity == "medium"


def test_file_count_cap_reported_once(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text("x")
    files, nc = discover(tmp_path, max_files=3)
    assert len(files) == 3
    assert [n for n in nc if "file limit" in n.reason] and len([n for n in nc if "file limit" in n.reason]) == 1


def test_dependency_dirs_skipped_and_reported(tmp_path):
    (tmp_path / "node_modules" / "p").mkdir(parents=True)
    (tmp_path / "node_modules" / "p" / "x.js").write_text("evil()")
    files, nc = discover(tmp_path)
    assert files == []
    assert [(n.rel, n.severity) for n in nc] == [("node_modules", "info")]


def test_symlink_reported_not_followed(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("x")
    link = tmp_path / "link.txt"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted here")
    files, nc = discover(tmp_path)
    assert [f.rel for f in files] == ["real.txt"]
    assert [(n.rel, n.severity) for n in nc] == [("link.txt", "medium")]


def test_long_line_truncated_and_reported(tmp_path):
    (tmp_path / "min.js").write_text("a" * 200_000)
    files, nc = discover(tmp_path)
    assert len(files[0].text) == MAX_LINE == 10_000
    assert "truncated" in nc[0].reason and nc[0].severity == "medium"


def test_five_megabyte_single_line_finishes_fast(tmp_path):
    (tmp_path / "big.js").write_text("x" * 5_000_000)
    start = time.perf_counter()
    discover(tmp_path, max_file_size=10_000_000)
    assert time.perf_counter() - start < 2


def test_roles(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text("x=1")
    (tmp_path / "SKILL.md").write_text("# s")
    (tmp_path / "README.md").write_text("# r")
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / ".github" / "workflows" / "ci.yml").write_text("on: push")
    (tmp_path / "run.py").write_text("x=1")
    roles = {f.rel: f.role for f in discover(tmp_path)[0]}
    assert roles == {
        "tests/t.py": "test",
        "SKILL.md": "instruction",
        "README.md": "docs",
        "package.json": "config",
        ".github/workflows/ci.yml": "config",
        "run.py": "executable",
    }


def test_svg_is_text(tmp_path):
    (tmp_path / "i.svg").write_text("<svg></svg>")
    files, nc = discover(tmp_path)
    assert files[0].kind == "text" and nc == []


def test_results_are_sorted(tmp_path):
    for name in ("b.txt", "a.txt", "c.txt"):
        (tmp_path / name).write_text("x")
    assert [f.rel for f in discover(tmp_path)[0]] == ["a.txt", "b.txt", "c.txt"]
