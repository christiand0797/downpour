"""Security tests for user-defined threat-feed preview requests."""

import gzip
from io import BytesIO
from urllib.error import URLError
from urllib.request import HTTPSHandler, Request

import pytest

from feed_transport import (
    MAX_CUSTOM_FEED_BYTES,
    _HTTPSOnlyRedirectHandler,
    count_https_feed_records,
    open_https_feed,
    validate_https_feed_url,
)
from downpour_v29_titanium import downpour


class _FakeResponse:
    def __init__(self, body, url="https://feeds.example/list.txt", headers=None):
        self._body = BytesIO(body)
        self._url = url
        self.headers = headers or {}
        self.read_sizes = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.closed = True

    def close(self):
        self.closed = True

    def geturl(self):
        return self._url

    def read(self, size):
        self.read_sizes.append(size)
        return self._body.read(size)


class _FakeOpener:
    def __init__(self, response):
        self.response = response
        self.request = None
        self.timeout = None

    def open(self, request, timeout):
        self.request = request
        self.timeout = timeout
        return self.response


class _Value:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class _Config:
    def __init__(self):
        self.values = {("feeds", "custom"): []}

    def get(self, section, key, default=None):
        return self.values.get((section, key), default)

    def set(self, section, key, value):
        self.values[(section, key)] = value


class _Intel:
    def __init__(self):
        self.FEEDS = {}


def _custom_feed_app(url):
    app = object.__new__(downpour)
    app._custom_db_name = _Value("test-feed")
    app._custom_db_url = _Value(url)
    app._custom_db_type = _Value("ip")
    app._custom_feed_tree = None
    app.cfg = _Config()
    app.intel = _Intel()
    return app


@pytest.mark.parametrize(
    "url",
    [
        "http://feeds.example/list.txt",
        "file:///C:/Windows/win.ini",
        "ftp://feeds.example/list.txt",
        "https://user:secret@feeds.example/list.txt",
        "https://feeds.example/list.txt#fragment",
        "https://feeds.example:bad/list.txt",
        " https://feeds.example/list.txt",
        "https://feeds.example/" + "x" * 2049,
    ],
)
def test_validate_https_feed_url_rejects_unsafe_or_malformed_urls(url):
    with pytest.raises(ValueError):
        validate_https_feed_url(url)


def test_count_streams_and_counts_only_nonblank_noncomment_lines():
    response = _FakeResponse(b"# comment\r\n1.2.3.4\n \nexample.test")
    opener = _FakeOpener(response)

    assert count_https_feed_records(
        "https://feeds.example/list.txt", opener=opener
    ) == 2
    assert opener.request.full_url == "https://feeds.example/list.txt"
    assert opener.timeout == 15
    assert max(response.read_sizes) <= 64 * 1024
    assert response.closed


def test_count_supports_standalone_carriage_return_line_endings():
    response = _FakeResponse(b"# comment\r1.2.3.4\rexample.test")

    assert count_https_feed_records(
        "https://feeds.example/list.txt", opener=_FakeOpener(response)
    ) == 2


def test_count_rejects_downgraded_final_url():
    response = _FakeResponse(b"item", url="http://feeds.example/list.txt")

    with pytest.raises(ValueError):
        count_https_feed_records(
            "https://feeds.example/list.txt", opener=_FakeOpener(response)
        )
    assert response.closed


def test_count_rejects_oversized_content_length_without_reading():
    response = _FakeResponse(b"item", headers={"Content-Length": str(MAX_CUSTOM_FEED_BYTES + 1)})

    with pytest.raises(ValueError, match="preview limit"):
        count_https_feed_records(
            "https://feeds.example/list.txt", opener=_FakeOpener(response)
        )
    assert response.read_sizes == []
    assert response.closed


def test_count_safely_decodes_gzip_content_encoding():
    response = _FakeResponse(
        gzip.compress(b"# comment\n1.2.3.4\nexample.test\n"),
        headers={"Content-Encoding": "gzip"},
    )

    assert count_https_feed_records(
        "https://feeds.example/list.txt", opener=_FakeOpener(response)
    ) == 2
    assert response.closed


def test_count_rejects_unsupported_content_encoding():
    response = _FakeResponse(b"item", headers={"Content-Encoding": "br"})

    with pytest.raises(ValueError, match="unsupported content encoding"):
        count_https_feed_records(
            "https://feeds.example/list.txt", opener=_FakeOpener(response)
        )
    assert response.read_sizes == []
    assert response.closed


def test_count_caps_wire_bytes_for_concatenated_empty_gzip_members():
    response = _FakeResponse(
        gzip.compress(b"") * 3,
        headers={"Content-Encoding": "gzip"},
    )

    with pytest.raises(ValueError, match="preview limit"):
        count_https_feed_records(
            "https://feeds.example/list.txt",
            max_bytes=32,
            opener=_FakeOpener(response),
        )
    assert response.closed


def test_count_stops_when_chunked_body_exceeds_limit():
    response = _FakeResponse(b"x" * 33)

    with pytest.raises(ValueError, match="preview limit"):
        count_https_feed_records(
            "https://feeds.example/list.txt",
            max_bytes=32,
            opener=_FakeOpener(response),
        )
    assert response.read_sizes[-1] <= 33
    assert response.closed


def test_redirect_handler_rejects_http_downgrade():
    handler = _HTTPSOnlyRedirectHandler()
    request = Request("https://feeds.example/start")

    with pytest.raises(URLError, match="unsafe custom-feed redirect"):
        handler.redirect_request(
            request, None, 302, "Found", {}, "http://feeds.example/list.txt"
        )


def test_redirect_handler_accepts_https_destination():
    handler = _HTTPSOnlyRedirectHandler()
    request = Request("https://feeds.example/start")

    redirected = handler.redirect_request(
        request, None, 302, "Found", {}, "https://cdn.example/list.txt"
    )

    assert redirected.full_url == "https://cdn.example/list.txt"


def test_open_https_feed_builds_verified_https_only_opener(monkeypatch):
    response = _FakeResponse(b"item")
    opener = _FakeOpener(response)
    handlers = []
    context = object()

    def fake_build_opener(*items):
        handlers.extend(items)
        return opener

    monkeypatch.setattr("feed_transport.build_opener", fake_build_opener)
    with open_https_feed("https://feeds.example/list.txt", ssl_context=context) as result:
        assert result is response

    assert any(isinstance(handler, _HTTPSOnlyRedirectHandler) for handler in handlers)
    assert any(
        isinstance(handler, HTTPSHandler) and handler._context is context
        for handler in handlers
    )
    assert opener.timeout == 15


def test_open_https_feed_closes_response_with_insecure_final_url():
    response = _FakeResponse(b"item", url="http://feeds.example/list.txt")

    with pytest.raises(ValueError, match="HTTPS URL"):
        open_https_feed(
            "https://feeds.example/start", opener=_FakeOpener(response)
        )
    assert response.closed


def test_custom_feed_form_rejects_http_before_saving(monkeypatch):
    import tkinter.messagebox as messagebox

    warnings = []
    monkeypatch.setattr(messagebox, "showwarning", lambda *args: warnings.append(args))
    app = _custom_feed_app("http://feeds.example/list.txt")

    app._add_custom_feed()

    assert warnings
    assert app.cfg.values[("feeds", "custom")] == []
    assert app.intel.FEEDS == {}


def test_custom_feed_form_saves_valid_https_feed():
    app = _custom_feed_app("https://feeds.example/list.txt")

    app._add_custom_feed()

    assert app.cfg.values[("feeds", "custom")][0]["url"] == "https://feeds.example/list.txt"
    assert app.intel.FEEDS["test-feed"] == (
        "https://feeds.example/list.txt", "ip", 3600
    )
    assert app._custom_db_name.get() == ""
    assert app._custom_db_url.get() == ""
