import io
import tarfile

import pytest
from helpers import FM

from skillaudit import cli
from skillaudit.lookalike import known_sources, lookalike


def test_lookalike():
    known = ["ComposioHQ/awesome-claude-skills", "anthropics/skills"]
    assert lookalike("Mann1988/awesome-claude-skills", known) == "ComposioHQ/awesome-claude-skills"
    assert lookalike("ComposioHQ/awesome-claude-skills", known) is None
    assert lookalike("someone/awesome-claude-skilIs", known) == "ComposioHQ/awesome-claude-skills"
    assert lookalike("someone/notes", known) is None
    assert lookalike("someone/skills", known) is None  # short names are too common to compare
    assert lookalike(None, known) is None


def test_known_sources_list_ships_with_the_skill():
    known = known_sources()
    assert "anthropics/skills" in known and "NVIDIA/skillspector" in known


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("SKILLAUDIT_HOME", str(tmp_path / "home"))


def test_check_blocks_lookalike_source(tmp_path, capsys, monkeypatch):
    archive = tmp_path / "a.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        info = tarfile.TarInfo("repo-x/SKILL.md")
        info.size = len(FM)
        tar.addfile(info, io.BytesIO(FM.encode()))
    monkeypatch.setattr(cli, "download", lambda url, dest, **kw: archive)
    code = cli.main(["check", "Mann1988/awesome-claude-skills", "--static"])
    out = capsys.readouterr().out
    assert code == 1 and "lookalike-source" in out
