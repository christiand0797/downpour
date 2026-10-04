"""Offline security tests for the scheduled threat-intelligence updater."""

import gzip
import json

import pytest
import requests

import threat_intelligence_updater as updater_module
from threat_intelligence_updater import ThreatIntelligenceUpdater


class _Raw:
    def __init__(self, body):
        self.body = body
        self.closed = False

    def stream(self, _size, decode_content=False):
        assert decode_content is False
        for offset in range(0, len(self.body), 5):
            yield self.body[offset:offset + 5]

    def close(self):
        self.closed = True


def _response(body=b'{"ok": true}', *, status=200, headers=None,
              url="https://feeds.example.test/data"):
    response = requests.Response()
    response.status_code = status
    response.url = url
    response.headers.update(headers or {})
    response.raw = _Raw(body)
    return response


def _updater(monkeypatch, limit=64):
    updater = object.__new__(ThreatIntelligenceUpdater)
    updater._last_request_time = {}
    updater._backoff_state = {}
    monkeypatch.setattr(ThreatIntelligenceUpdater, "RATE_LIMIT_S", 0)
    monkeypatch.setattr(ThreatIntelligenceUpdater, "MAX_RESPONSE_BYTES", limit)
    monkeypatch.setattr(ThreatIntelligenceUpdater, "RESPONSE_CHUNK_BYTES", 8)
    monkeypatch.setattr(updater_module.time, "sleep", lambda *_args: None)
    return updater


def test_fetch_with_backoff_preserves_response_json_and_identity_headers(monkeypatch):
    body = json.dumps({"items": ["ioc"]}).encode()
    response = _response(body, headers={"Content-Length": str(len(body))})
    calls = []
    monkeypatch.setattr(
        updater_module.requests,
        "get",
        lambda url, **kwargs: calls.append((url, kwargs)) or response,
    )

    result = _updater(monkeypatch)._fetch_with_backoff(
        "sample", "https://feeds.example.test/data"
    )

    assert result.json() == {"items": ["ioc"]}
    assert result.content == body
    assert calls[0][1]["stream"] is True
    assert calls[0][1]["allow_redirects"] is False
    assert calls[0][1]["headers"]["Accept-Encoding"] == "identity"
    assert response.raw.closed


def test_fetch_with_backoff_rejects_http_url_without_request(monkeypatch):
    calls = []
    monkeypatch.setattr(updater_module.requests, "get", lambda *a, **k: calls.append((a, k)))

    result = _updater(monkeypatch)._fetch_with_backoff(
        "insecure", "http://feeds.example.test/data"
    )

    assert result is None
    assert calls == []


def test_bounded_response_rejects_oversized_content_length(monkeypatch):
    response = _response(b"ignored", headers={"Content-Length": "65"})

    with pytest.raises(ValueError, match="64-byte limit"):
        _updater(monkeypatch)._cache_bounded_response(response)

    assert response.raw.closed


def test_bounded_response_caps_chunked_body(monkeypatch):
    response = _response(b"x" * 65)

    with pytest.raises(ValueError, match="64-byte limit"):
        _updater(monkeypatch)._cache_bounded_response(response)

    assert response.raw.closed


def test_bounded_response_caps_gzip_expansion(monkeypatch):
    response = _response(gzip.compress(b"x" * 65), headers={"Content-Encoding": "gzip"})

    with pytest.raises(ValueError, match="Expanded threat feed"):
        _updater(monkeypatch)._cache_bounded_response(response)

    assert response.raw.closed


def test_bounded_response_rejects_truncated_content_length(monkeypatch):
    response = _response(b"short", headers={"Content-Length": "10"})

    with pytest.raises(ValueError, match="truncated"):
        _updater(monkeypatch)._cache_bounded_response(response)

    assert response.raw.closed


def test_fetch_with_backoff_rejects_http_redirect(monkeypatch):
    redirect = _response(b"", status=302, headers={"Location": "http://evil.test/feed"})
    calls = []
    monkeypatch.setattr(
        updater_module.requests,
        "get",
        lambda url, **kwargs: calls.append((url, kwargs)) or redirect,
    )

    assert _updater(monkeypatch)._fetch_with_backoff(
        "downgrade", "https://feeds.example.test/data"
    ) is None
    assert len(calls) == 1
    assert redirect.raw.closed


def test_fetch_with_backoff_strips_credentials_on_cross_origin_redirect(monkeypatch):
    redirect = _response(b"", status=302, headers={"Location": "https://cdn.example.test/feed"})
    final = _response(b"ok", url="https://cdn.example.test/feed")
    responses = iter((redirect, final))
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return next(responses)

    monkeypatch.setattr(updater_module.requests, "get", fake_get)
    result = _updater(monkeypatch)._fetch_with_backoff(
        "redirect",
        "https://feeds.example.test/data",
        headers={"Authorization": "Bearer secret", "X-Feed": "ok"},
        params={"token": "secret"},
        cookies={"session": "secret"},
        auth=("user", "secret"),
        cert="client.pem",
    )

    assert result.content == b"ok"
    assert len(calls) == 2
    assert calls[1][1]["headers"] == {"X-Feed": "ok", "Accept-Encoding": "identity"}
    assert calls[1][1]["params"] is None
    assert "cookies" not in calls[1][1]
    assert "auth" not in calls[1][1]
    assert "cert" not in calls[1][1]
    assert redirect.raw.closed
    assert final.raw.closed


def test_backoff_retry_closes_rate_limited_response(monkeypatch):
    limited = _response(b"too many", status=429)
    valid = _response(b"ok")
    responses = iter((limited, valid))
    monkeypatch.setattr(updater_module.requests, "get", lambda *_a, **_k: next(responses))

    result = _updater(monkeypatch)._fetch_with_backoff(
        "retry", "https://feeds.example.test/data"
    )

    assert result.content == b"ok"
    assert limited.raw.closed
    assert valid.raw.closed
