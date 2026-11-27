import io
import urllib.error

import pytest

from skillaudit.fetch import FetchError, Source, download, resolve

U = "https://codeload.github.com/o/r/tar.gz/HEAD"


@pytest.mark.parametrize("addr,url,sub,owner_repo", [
    ("anthropics/skills", "https://codeload.github.com/anthropics/skills/tar.gz/HEAD", "", "anthropics/skills"),
    ("o/r/skills/pdf", "https://codeload.github.com/o/r/tar.gz/HEAD", "skills/pdf", "o/r"),
    ("https://github.com/o/r", U, "", "o/r"),
    ("https://github.com/o/r.git/", U, "", "o/r"),
    ("https://github.com/o/r/", U, "", "o/r"),
    ("https://github.com/o/r/tree/dev/skills/pdf", "https://codeload.github.com/o/r/tar.gz/dev", "skills/pdf", "o/r"),
    ("https://github.com/o/r/tree/dev", "https://codeload.github.com/o/r/tar.gz/dev", "", "o/r"),
    ("https://github.com/o/r/blob/main/skills/pdf/SKILL.md", "https://codeload.github.com/o/r/tar.gz/main", "skills/pdf", "o/r"),
    ("https://github.com/o/r/blob/main/SKILL.md", "https://codeload.github.com/o/r/tar.gz/main", "", "o/r"),
])
def test_github_variants(addr, url, sub, owner_repo):
    s = resolve(addr)
    assert (s.kind, s.location, s.subpath, s.owner_repo) == ("url", url, sub, owner_repo)


def test_plain_archive_url():
    s = resolve("https://files.example.test/skill.zip")
    assert s.kind == "url" and s.location.endswith("skill.zip") and s.owner_repo is None


def test_local_dir_and_archive(tmp_path):
    (tmp_path / "a.tar.gz").write_bytes(b"")
    assert resolve(str(tmp_path)).kind == "dir"
    assert resolve(str(tmp_path / "a.tar.gz")).kind == "archive"


def test_http_is_refused():
    with pytest.raises(FetchError, match="only https"):
        resolve("http://github.com/o/r")


def test_unknown_address_is_refused():
    with pytest.raises(FetchError, match="cannot tell"):
        resolve("https://example.test/page.html")


class FakeResponse(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self._url = url

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeOpener:
    def __init__(self, data=b"", url=U, exc=None):
        self.data, self.url, self.exc, self.requests = data, url, exc, []

    def open(self, request, timeout=None):
        self.requests.append(request)
        if self.exc:
            raise self.exc
        return FakeResponse(self.data, self.url)


def test_download_writes_file_and_sends_only_user_agent(tmp_path):
    opener = FakeOpener(b"abc")
    out = download(U, tmp_path / "a.tar.gz", opener=opener)
    assert out.read_bytes() == b"abc"
    headers = {k.lower(): v for k, v in opener.requests[0].header_items()}
    assert headers == {"user-agent": "skillaudit"}


def test_download_stops_at_cap(tmp_path):
    with pytest.raises(FetchError, match="20 MB"):
        download(U, tmp_path / "a", opener=FakeOpener(b"x" * (21 * 1024 * 1024)))
    assert not (tmp_path / "a").exists()


def test_redirect_to_http_is_refused(tmp_path):
    with pytest.raises(FetchError, match="https"):
        download(U, tmp_path / "a", opener=FakeOpener(b"x", url="http://evil.test/a"))


@pytest.mark.parametrize("exc", [
    urllib.error.HTTPError(U, 404, "Not Found", {}, None),
    urllib.error.URLError("offline"),
    TimeoutError(),
])
def test_failures_are_one_line(tmp_path, exc):
    with pytest.raises(FetchError) as e:
        download(U, tmp_path / "a", opener=FakeOpener(exc=exc))
    assert "\n" not in str(e.value) and U in str(e.value)


def test_404_on_tree_ref_explains_slash_branches(tmp_path):
    src = resolve("https://github.com/o/r/tree/feature/x/skills/pdf")
    with pytest.raises(FetchError, match="branch name contains"):
        download(src.location, tmp_path / "a", opener=FakeOpener(exc=urllib.error.HTTPError(src.location, 404, "nf", {}, None)), source=src)
