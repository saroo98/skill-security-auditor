import io
import tarfile
import zipfile

import pytest

from skillaudit import quarantine
from skillaudit.fetch import Source
from skillaudit.quarantine import UnsafeArchive, cache_get, cache_put, extract, home, place, tree_hash


def make_tar(path, members, top="repo-abc"):
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(f"{top}/{name}" if top else name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def make_zip(path, members):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return path


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLAUDIT_HOME", str(tmp_path / "home"))


def test_strips_single_top_directory(tmp_path):
    arc = make_tar(tmp_path / "a.tar.gz", {"SKILL.md": b"# s", "scripts/x.sh": b"echo"})
    out = extract(arc, tmp_path / "out")
    assert (out / "SKILL.md").read_bytes() == b"# s" and (out / "scripts" / "x.sh").exists()


def test_zip_without_top_directory(tmp_path):
    arc = make_zip(tmp_path / "a.zip", {"SKILL.md": b"# s", "b/c.txt": b"c"})
    out = extract(arc, tmp_path / "out")
    assert (out / "SKILL.md").exists() and (out / "b" / "c.txt").exists()


@pytest.mark.parametrize("name", ["../evil", "/abs", "CON", "aux.txt", "dir/NUL.md", "trail.", "space ", "C:/x"])
def test_rejects_unsafe_member_names(tmp_path, name):
    arc = make_zip(tmp_path / "a.zip", {"ok.md": b"1", name: b"x"})
    with pytest.raises(UnsafeArchive):
        extract(arc, tmp_path / "out")


def test_rejects_backslash_in_tar_member(tmp_path):
    # zipfile on Windows already turns backslashes into "/", so tar is the real case
    arc = make_tar(tmp_path / "a.tar.gz", {"ok.md": b"1", "a" + chr(92) + "b": b"x"}, top="")
    with pytest.raises(UnsafeArchive, match="backslash"):
        extract(arc, tmp_path / "out")


def test_rejects_case_collision(tmp_path):
    arc = make_zip(tmp_path / "a.zip", {"A.md": b"1", "a.md": b"2"})
    with pytest.raises(UnsafeArchive, match="case"):
        extract(arc, tmp_path / "out")


def test_rejects_links_and_devices(tmp_path):
    for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE):
        path = tmp_path / f"l{kind!r}.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            info = tarfile.TarInfo("top/link")
            info.type = kind
            info.linkname = "/etc/passwd"
            tar.addfile(info)
        with pytest.raises(UnsafeArchive):
            extract(path, tmp_path / f"out{kind!r}")


def test_rejects_too_many_files(tmp_path):
    arc = make_zip(tmp_path / "a.zip", {f"f{i}.txt": b"x" for i in range(11)})
    with pytest.raises(UnsafeArchive, match="files"):
        extract(arc, tmp_path / "out", max_files=10)


def test_rejects_expansion_bomb(tmp_path):
    arc = make_zip(tmp_path / "a.zip", {"big.txt": b"0" * 5000})
    with pytest.raises(UnsafeArchive, match="size"):
        extract(arc, tmp_path / "out", max_total_bytes=1000)
    assert not (tmp_path / "out").exists()


def test_rejected_archive_leaves_nothing_behind(tmp_path):
    arc = make_zip(tmp_path / "a.zip", {"ok.md": b"1", "../evil": b"x"})
    with pytest.raises(UnsafeArchive):
        extract(arc, tmp_path / "out")
    assert not (tmp_path / "out").exists() and not (tmp_path / "evil").exists()


def test_extracted_files_are_not_executable(tmp_path):
    path = tmp_path / "a.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("top/run.sh")
        info.size = 2
        info.mode = 0o755
        tar.addfile(info, io.BytesIO(b"hi"))
    out = extract(path, tmp_path / "out")
    assert (out / "run.sh").stat().st_mode & 0o111 == 0 or quarantine.os.name == "nt"


def test_tree_hash_changes_with_content_not_mtime(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "a.txt").write_text("1")
    h1 = tree_hash(d)
    quarantine.os.utime(d / "a.txt", (1, 1))
    assert tree_hash(d) == h1
    (d / "a.txt").write_text("2")
    assert tree_hash(d) != h1
    assert len(h1) == 64


def test_home_respects_env(tmp_path):
    assert home() == tmp_path / "home"


def test_place_archive_goes_under_home(tmp_path):
    arc = make_tar(tmp_path / "a.tar.gz", {"SKILL.md": b"# s"})
    check_id, qdir = place(Source("url", "https://x", "", "x", None), arc)
    assert qdir.is_relative_to(home() / "quarantine") and (qdir / "SKILL.md").exists()
    assert check_id == tree_hash(qdir)[:12]


def test_place_local_dir_copies_and_skips_links(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "SKILL.md").write_text("# s")
    check_id, qdir = place(Source("dir", str(src), "", str(src), None), None)
    assert (qdir / "SKILL.md").read_text() == "# s" and qdir != src


def test_place_is_idempotent(tmp_path):
    arc = make_tar(tmp_path / "a.tar.gz", {"SKILL.md": b"# s"})
    a = place(Source("url", "u", "", "u", None), arc)
    b = place(Source("url", "u", "", "u", None), arc)
    assert a == b


def test_cache_roundtrip(tmp_path):
    assert cache_get("t" * 64, "0") is None
    cache_put("t" * 64, "0", {"verdict": "PASS"})
    assert cache_get("t" * 64, "0") == {"verdict": "PASS"}
    assert cache_get("t" * 64, "1") is None


def test_tree_hash_survives_unreadable_file(tmp_path, monkeypatch):
    # antivirus software can refuse to open a file; the hash must still be computed
    d = tmp_path / "d"
    d.mkdir()
    (d / "ok.txt").write_text("1")
    (d / "blocked.json").write_text("{}")
    real = quarantine.Path.read_bytes

    def fake(self):
        if self.name == "blocked.json":
            raise OSError(22, "Invalid argument")
        return real(self)

    monkeypatch.setattr(quarantine.Path, "read_bytes", fake)
    assert len(tree_hash(d)) == 64


def _tar_with_link(path):
    with tarfile.open(path, "w:gz") as tar:
        info = tarfile.TarInfo("top/SKILL.md")
        info.size = 3
        tar.addfile(info, io.BytesIO(b"# s"))
        link = tarfile.TarInfo("top/shims/pip3")
        link.type = tarfile.SYMTYPE
        link.linkname = "/usr/bin/pip3"
        tar.addfile(link)
    return path


def test_extract_can_skip_links_and_report_them(tmp_path):
    out, skipped = quarantine.extract_skipping_links(_tar_with_link(tmp_path / "a.tar.gz"), tmp_path / "out")
    assert (out / "SKILL.md").exists() and not (out / "shims" / "pip3").exists()
    assert skipped == ["shims/pip3"]


def test_place_records_skipped_links(tmp_path):
    check_id, qdir = place(Source("url", "u", "", "u", None), _tar_with_link(tmp_path / "a.tar.gz"))
    assert quarantine.skipped_links(qdir) == ["shims/pip3"]
