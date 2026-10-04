"""Offline security tests for automatic updater transport and ZIP handling."""

import io
import json
import stat
import zipfile

import pytest
import requests

import downpour_updater as updater_module
from downpour_updater import DownpourUpdater


class _Raw:
    def __init__(self, body):
        self.body = body
        self.closed = False

    def stream(self, _chunk_size, decode_content=False):
        assert decode_content is False
        for offset in range(0, len(self.body), 7):
            yield self.body[offset:offset + 7]

    def close(self):
        self.closed = True


def _response(body=b"", *, status=200, headers=None, url="https://api.github.com/data"):
    response = requests.Response()
    response.status_code = status
    response.url = url
    response.headers.update(headers or {})
    response.raw = _Raw(body)
    return response


def _zip_bytes(entries):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    return output.getvalue()


def test_github_url_validator_allows_only_expected_https_hosts():
    assert DownpourUpdater._validate_github_url("https://api.github.com/repos/example")
    assert DownpourUpdater._validate_github_url("https://codeload.github.com/user/repo/zip/abc")
    for url in (
        "http://api.github.com/repos/example",
        "https://github.com.evil.test/repos/example",
        "https://evil.test/github.zip",
        "https://user:pass@api.github.com/repos/example",
        "https://api.github.com:444/repos/example",
    ):
        with pytest.raises(ValueError):
            DownpourUpdater._validate_github_url(url)


def test_github_stream_rejects_http_downgrade_before_following(monkeypatch):
    redirect = _response(status=302, headers={"Location": "http://evil.test/archive"})
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return redirect

    monkeypatch.setattr(updater_module.requests, "get", fake_get)
    updater = DownpourUpdater(".")

    with pytest.raises(ValueError, match="HTTPS GitHub"):
        updater._open_github_stream("https://api.github.com/archive", timeout=5)

    assert len(calls) == 1
    assert redirect.raw.closed


def test_github_stream_rejects_unapproved_https_redirect_host(monkeypatch):
    redirect = _response(status=302, headers={"Location": "https://evil.test/archive"})
    calls = []
    monkeypatch.setattr(updater_module.requests, "get", lambda url, **_kw: calls.append(url) or redirect)
    updater = DownpourUpdater(".")

    with pytest.raises(ValueError, match="approved HTTPS GitHub host"):
        updater._open_github_stream("https://api.github.com/archive", timeout=5)

    assert len(calls) == 1
    assert redirect.raw.closed


def test_github_stream_follows_only_approved_https_redirects(monkeypatch):
    redirect = _response(status=302, headers={"Location": "https://codeload.github.com/user/repo/zip/tag"})
    final = _response(b"archive", url="https://codeload.github.com/user/repo/zip/tag")
    responses = iter((redirect, final))
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return next(responses)

    monkeypatch.setattr(updater_module.requests, "get", fake_get)
    updater = DownpourUpdater(".")

    assert updater._open_github_stream("https://api.github.com/archive", timeout=5) is final
    assert len(calls) == 2
    assert calls[0][1]["allow_redirects"] is False
    assert redirect.raw.closed


def test_cached_api_response_enforces_body_limit_and_preserves_json():
    body = json.dumps({"tag_name": "v29.125"}).encode()
    response = _response(body, headers={"Content-Length": str(len(body))})

    result = DownpourUpdater._cache_bounded_response(response, 128)

    assert result.json() == {"tag_name": "v29.125"}
    assert response.raw.closed


def test_cached_api_response_rejects_oversized_length_before_read():
    response = _response(b"ignored", headers={"Content-Length": "9"})

    with pytest.raises(ValueError, match="exceeds"):
        DownpourUpdater._cache_bounded_response(response, 8)

    assert response.raw.closed


def test_cached_api_response_rejects_truncated_body():
    response = _response(b"short", headers={"Content-Length": "8"})

    with pytest.raises(ValueError, match="truncated"):
        DownpourUpdater._cache_bounded_response(response, 16)

    assert response.raw.closed


def test_safe_extract_copies_only_update_allowlist(tmp_path, monkeypatch):
    monkeypatch.setattr(
        updater_module,
        "UPDATE_FILES",
        ["downpour_v29_titanium.py", "module.py"],
    )
    archive_path = tmp_path / "safe.zip"
    archive_path.write_bytes(_zip_bytes([
        ("repo-tag/", b""),
        ("repo-tag/downpour_v29_titanium.py", b"app source"),
        ("repo-tag/module.py", b"module source"),
        ("repo-tag/unlisted.txt", b"not staged"),
    ]))
    destination = tmp_path / "stage"

    root = DownpourUpdater._safe_extract_update(str(archive_path), destination)

    assert (root / "downpour_v29_titanium.py").read_bytes() == b"app source"
    assert (root / "module.py").read_bytes() == b"module source"
    assert not (root / "unlisted.txt").exists()


@pytest.mark.parametrize(
    "member",
    ["../outside.txt", "/absolute.txt", "C:/outside.txt", "repo\\..\\outside.txt"],
)
def test_safe_extract_rejects_traversal_and_absolute_paths(tmp_path, monkeypatch, member):
    monkeypatch.setattr(updater_module, "UPDATE_FILES", ["downpour_v29_titanium.py"])
    archive_path = tmp_path / "bad.zip"
    archive_path.write_bytes(_zip_bytes([
        ("repo/downpour_v29_titanium.py", b"app"),
        (member, b"escape"),
    ]))

    with pytest.raises(ValueError, match="unsafe|drive-qualified|missing"):
        DownpourUpdater._safe_extract_update(str(archive_path), tmp_path / "stage")

    assert not (tmp_path / "outside.txt").exists()


def test_safe_extract_rejects_symlink_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(updater_module, "UPDATE_FILES", ["downpour_v29_titanium.py"])
    archive_path = tmp_path / "symlink.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("repo/downpour_v29_titanium.py", b"app")
        link = zipfile.ZipInfo("repo/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "../../outside.txt")

    with pytest.raises(ValueError, match="non-regular"):
        DownpourUpdater._safe_extract_update(str(archive_path), tmp_path / "stage")


def test_safe_extract_enforces_archive_metadata_limits(tmp_path, monkeypatch):
    monkeypatch.setattr(updater_module, "UPDATE_FILES", ["downpour_v29_titanium.py"])
    archive_path = tmp_path / "large.zip"
    archive_path.write_bytes(_zip_bytes([
        ("repo/downpour_v29_titanium.py", b"app"),
        ("repo/extra", b"0123456789"),
    ]))
    monkeypatch.setattr(updater_module, "MAX_UPDATE_EXPANDED_BYTES", 8)

    with pytest.raises(ValueError, match="expanded size"):
        DownpourUpdater._safe_extract_update(str(archive_path), tmp_path / "stage")


def test_download_installs_valid_archive_and_never_extracts_unlisted_files(tmp_path, monkeypatch):
    monkeypatch.setattr(
        updater_module,
        "UPDATE_FILES",
        ["downpour_v29_titanium.py", "module.py"],
    )
    monkeypatch.setattr(updater_module, "UPDATE_DIRS", [])
    archive = _zip_bytes([
        ("repo-v29.125/", b""),
        ("repo-v29.125/downpour_v29_titanium.py", b"new app"),
        ("repo-v29.125/module.py", b"new module"),
        ("repo-v29.125/evil.txt", b"ignored"),
    ])
    response = _response(
        archive,
        headers={"Content-Length": str(len(archive))},
        url="https://codeload.github.com/user/repo/zip/v29.125",
    )
    monkeypatch.setattr(updater_module.requests, "get", lambda *_a, **_kw: response)
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "downpour_v29_titanium.py").write_text("old app")
    (app_dir / "module.py").write_text("old module")
    updater = DownpourUpdater(str(app_dir))
    updater.latest_version = "29.125"
    updater._update_dependencies = lambda: None

    assert updater.download_and_install()
    assert (app_dir / "downpour_v29_titanium.py").read_text() == "new app"
    assert (app_dir / "module.py").read_text() == "new module"
    assert (app_dir / "VERSION").read_text().splitlines()[0] == "29.125"
    assert not (app_dir / "evil.txt").exists()
    assert response.raw.closed


def test_download_rejects_oversized_declared_archive_before_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(updater_module, "MAX_UPDATE_ARCHIVE_BYTES", 8)
    response = _response(
        b"ignored",
        headers={"Content-Length": "9"},
        url="https://codeload.github.com/user/repo/zip/v29.125",
    )
    monkeypatch.setattr(updater_module.requests, "get", lambda *_a, **_kw: response)
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    target = app_dir / "downpour_v29_titanium.py"
    target.write_text("keep current version")
    updater = DownpourUpdater(str(app_dir))
    updater.latest_version = "29.125"

    assert updater.download_and_install() is False
    assert target.read_text() == "keep current version"
    assert response.raw.closed


def test_download_rejects_chunked_archive_that_exceeds_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(updater_module, "MAX_UPDATE_ARCHIVE_BYTES", 8)
    response = _response(
        b"x" * 9,
        url="https://codeload.github.com/user/repo/zip/v29.125",
    )
    monkeypatch.setattr(updater_module.requests, "get", lambda *_a, **_kw: response)
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    target = app_dir / "downpour_v29_titanium.py"
    target.write_text("keep current version")
    updater = DownpourUpdater(str(app_dir))
    updater.latest_version = "29.125"

    assert updater.download_and_install() is False
    assert target.read_text() == "keep current version"
    assert response.raw.closed
