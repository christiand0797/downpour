"""Offline coverage for bounded legacy threat-intelligence HTTP requests."""

import gzip
import json

import pytest
import requests

import threat_intelligence
from threat_intelligence import ThreatIntelligenceManager


class _RawStream:
    def __init__(self, body, chunk_size=None):
        self.body = body
        self.chunk_size = chunk_size
        self.closed = False

    def stream(self, amt, decode_content=False):
        assert decode_content is False
        size = self.chunk_size or amt
        for offset in range(0, len(self.body), size):
            yield self.body[offset:offset + size]

    def close(self):
        self.closed = True


class _Client:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if not self.responses:
            raise AssertionError("unexpected HTTP request")
        return self.responses.pop(0)


def _response(body=b'{"ok": true}', *, headers=None, status=200,
              url="https://feeds.example.test/feed"):
    response = requests.Response()
    response.status_code = status
    response.url = url
    response.headers.update(headers or {})
    response.raw = _RawStream(body)
    return response


def _manager(monkeypatch, client, max_bytes=64):
    manager = object.__new__(ThreatIntelligenceManager)
    manager._session = client
    monkeypatch.setattr(ThreatIntelligenceManager, "MAX_FEED_RESPONSE_BYTES", max_bytes)
    monkeypatch.setattr(ThreatIntelligenceManager, "FEED_RESPONSE_CHUNK_BYTES", 8)
    return manager


def test_bounded_get_preserves_requests_response_parsing_after_close(monkeypatch):
    body = json.dumps({"iocs": ["1.2.3.4"]}).encode()
    response = _response(body, headers={"Content-Length": str(len(body))})
    client = _Client(response)
    manager = _manager(monkeypatch, client)

    result = manager._bounded_get("https://feeds.example.test/feed")

    assert result.content == body
    assert result.json() == {"iocs": ["1.2.3.4"]}
    assert result.text == body.decode()
    assert response.raw.closed
    assert client.calls[0][1]["stream"] is True
    assert client.calls[0][1]["allow_redirects"] is False
    assert client.calls[0][1]["headers"]["Accept-Encoding"] == "identity"


def test_bounded_get_rejects_oversized_declared_length_before_reading(monkeypatch):
    response = _response(b"ignored", headers={"Content-Length": "65"})
    manager = _manager(monkeypatch, _Client(response), max_bytes=64)

    with pytest.raises(ValueError, match="download limit"):
        manager._bounded_get("https://feeds.example.test/feed")

    assert response.raw.closed


def test_bounded_get_caps_chunked_wire_body(monkeypatch):
    response = _response(b"x" * 65)
    manager = _manager(monkeypatch, _Client(response), max_bytes=64)

    with pytest.raises(ValueError, match="download limit"):
        manager._bounded_get("https://feeds.example.test/feed")

    assert response.raw.closed


def test_bounded_get_caps_gzip_expansion(monkeypatch):
    compressed = gzip.compress(b"x" * 65)
    response = _response(compressed, headers={"Content-Encoding": "gzip"})
    manager = _manager(monkeypatch, _Client(response), max_bytes=64)

    with pytest.raises(ValueError, match="Expanded feed"):
        manager._bounded_get("https://feeds.example.test/feed")

    assert response.raw.closed


def test_bounded_get_decodes_small_gzip_payload(monkeypatch):
    expected = b'{"ioc":"1.2.3.4"}'
    response = _response(gzip.compress(expected), headers={"Content-Encoding": "gzip"})
    manager = _manager(monkeypatch, _Client(response), max_bytes=64)

    assert manager._bounded_get("https://feeds.example.test/feed").json() == {
        "ioc": "1.2.3.4"
    }


def test_bounded_get_rejects_truncated_content_length(monkeypatch):
    response = _response(b"short", headers={"Content-Length": "10"})
    manager = _manager(monkeypatch, _Client(response))

    with pytest.raises(ValueError, match="does not match Content-Length"):
        manager._bounded_get("https://feeds.example.test/feed")

    assert response.raw.closed


def test_bounded_get_refuses_https_to_http_redirect(monkeypatch):
    response = _response(
        b"", status=302,
        headers={"Location": "http://insecure.example.test/feed"},
    )
    client = _Client(response)
    manager = _manager(monkeypatch, client)

    with pytest.raises(ValueError, match="HTTPS"):
        manager._bounded_get("https://feeds.example.test/feed")

    assert len(client.calls) == 1
    assert response.raw.closed


def test_bounded_get_drops_credentials_on_cross_origin_redirect(monkeypatch):
    redirect = _response(
        b"", status=302,
        headers={"Location": "https://cdn.example.test/feed"},
    )
    final = _response(b"ok", url="https://cdn.example.test/feed")
    session = _Client(redirect)
    manager = _manager(monkeypatch, session)
    stateless = _Client(final)
    monkeypatch.setattr(threat_intelligence.requests, "get", stateless.get)

    result = manager._bounded_get(
        "https://feeds.example.test/feed",
        headers={"Authorization": "Bearer secret", "X-Feed": "public"},
        cookies={"session": "secret"},
        auth=("user", "secret"),
        params={"token": "secret"},
    )

    assert result.content == b"ok"
    assert len(session.calls) == 1
    assert len(stateless.calls) == 1
    destination_kwargs = stateless.calls[0][1]
    assert destination_kwargs["headers"] == {"X-Feed": "public", "Accept-Encoding": "identity"}
    assert destination_kwargs["params"] is None
    assert "cookies" not in destination_kwargs
    assert "auth" not in destination_kwargs


def test_bounded_get_rejects_http_initial_url(monkeypatch):
    client = _Client()
    manager = _manager(monkeypatch, client)

    with pytest.raises(ValueError, match="HTTPS"):
        manager._bounded_get("http://feeds.example.test/feed")

    assert client.calls == []
