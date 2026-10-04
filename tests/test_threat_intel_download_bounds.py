"""Bounds and truncation checks for the live ThreatIntelEngine feed path."""

import gzip
import time

from downpour_v29_titanium import ThreatIntelEngine


class _FakeResponse:
    def __init__(self, body, headers=None):
        self.body = body
        self.headers = headers or {}
        self.read_limit = None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.closed = True

    def read(self, size=-1):
        self.read_limit = size
        return self.body if size < 0 else self.body[:size]


def _engine(monkeypatch, response, max_bytes=32):
    engine = object.__new__(ThreatIntelEngine)
    engine._feed_errors = {}
    engine._verify_download = lambda _raw, _name: True
    monkeypatch.setattr(ThreatIntelEngine, "MAX_FEED_BYTES", max_bytes)
    monkeypatch.setattr(time, "sleep", lambda *_args: None)
    calls = []

    def fake_open(request, **kwargs):
        calls.append((request, kwargs))
        return response

    monkeypatch.setattr("feed_transport.open_https_feed", fake_open)
    return engine, calls


def test_active_fetch_returns_complete_plain_feed_and_requests_identity(monkeypatch):
    response = _FakeResponse(b"1.2.3.4\n")
    engine, calls = _engine(monkeypatch, response)

    assert engine._fetch_feed("sample", "https://feeds.example/list.txt") == b"1.2.3.4\n"
    request, _kwargs = calls[0]
    assert request.get_header("Accept-encoding") == "identity"
    assert response.read_limit == engine.MAX_FEED_BYTES + 1
    assert response.closed


def test_active_fetch_rejects_oversized_wire_body_without_validation(monkeypatch):
    response = _FakeResponse(b"x" * 33)
    engine, calls = _engine(monkeypatch, response, max_bytes=32)
    validated = []
    engine._verify_download = lambda raw, _name: validated.append(raw) or True

    assert engine._fetch_feed("large", "https://feeds.example/list.txt") is None
    assert calls
    assert not validated
    assert "download limit" in engine._feed_errors["large"]


def test_active_fetch_caps_gzip_expansion_before_validation(monkeypatch):
    response = _FakeResponse(
        gzip.compress(b"x" * 64), {"Content-Encoding": "gzip"}
    )
    engine, _calls = _engine(monkeypatch, response, max_bytes=32)
    validated = []
    engine._verify_download = lambda raw, _name: validated.append(raw) or True

    assert engine._fetch_feed("bomb", "https://feeds.example/list.txt") is None
    assert not validated
    assert "Expanded feed" in engine._feed_errors["bomb"]


def test_active_fetch_rejects_truncated_content_length(monkeypatch):
    response = _FakeResponse(b"item", {"Content-Length": "5"})
    engine, _calls = _engine(monkeypatch, response, max_bytes=32)

    assert engine._fetch_feed("truncated", "https://feeds.example/list.txt") is None
    assert "does not match Content-Length" in engine._feed_errors["truncated"]


def test_active_fetch_decodes_small_gzip_feed_within_bound(monkeypatch):
    body = gzip.compress(b"1.2.3.4\n")
    response = _FakeResponse(body)
    engine, _calls = _engine(monkeypatch, response, max_bytes=32)

    assert engine._fetch_feed("compressed", "https://feeds.example/list.gz") == b"1.2.3.4\n"


def test_active_fetch_rejects_unsupported_content_encoding(monkeypatch):
    response = _FakeResponse(b"raw", {"Content-Encoding": "deflate"})
    engine, _calls = _engine(monkeypatch, response, max_bytes=32)

    assert engine._fetch_feed("encoded", "https://feeds.example/list.txt") is None
    assert "Unsupported feed content encoding" in engine._feed_errors["encoded"]
