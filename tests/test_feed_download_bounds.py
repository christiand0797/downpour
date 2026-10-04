"""Threat-feed downloads remain bounded before any parser processes input."""

import gzip

from threat_feed_aggregator import ThreatFeedAggregator


class _FakeResponse:
    def __init__(self, chunks, headers=None):
        self._chunks = chunks
        self.headers = headers or {}
        self.chunk_sizes = []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.closed = True

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size):
        self.chunk_sizes.append(chunk_size)
        yield from self._chunks

    @property
    def content(self):
        raise AssertionError("fetch_feed must stream instead of buffering response.content")


class _FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.response


class _ValidManifest:
    @staticmethod
    def verify_feed(_feed_id, _content):
        return True

    @staticmethod
    def _manifest_path(_feed_id):
        class _Existing:
            @staticmethod
            def exists():
                return True
        return _Existing()


def _aggregator(response):
    aggregator = object.__new__(ThreatFeedAggregator)
    aggregator.session = _FakeSession(response)
    aggregator._manifest_verifier = _ValidManifest()
    return aggregator


def test_fetch_feed_streams_https_body_and_returns_text():
    response = _FakeResponse([b"first ", b"second"], {"Content-Length": "12"})
    aggregator = _aggregator(response)

    assert aggregator.fetch_feed("sample", {"url": "https://feeds.example/sample.txt"}) == "first second"
    assert aggregator.session.calls[0][1]["stream"] is True
    assert response.chunk_sizes == [aggregator.DOWNLOAD_CHUNK_BYTES]
    assert response.closed


def test_fetch_feed_rejects_declared_oversize_before_reading(monkeypatch):
    monkeypatch.setattr(ThreatFeedAggregator, "MAX_DOWNLOAD_BYTES", 4)
    response = _FakeResponse([b"skip"], {"Content-Length": "5"})
    aggregator = _aggregator(response)

    assert aggregator.fetch_feed("large", {"url": "https://feeds.example/large.txt"}) is None
    assert response.chunk_sizes == []
    assert response.closed


def test_fetch_feed_rejects_oversize_chunked_body(monkeypatch):
    monkeypatch.setattr(ThreatFeedAggregator, "MAX_DOWNLOAD_BYTES", 4)
    response = _FakeResponse([b"1234", b"5"])
    aggregator = _aggregator(response)

    assert aggregator.fetch_feed("large", {"url": "https://feeds.example/large.txt"}) is None
    assert response.closed


def test_fetch_feed_caps_gzip_expansion(monkeypatch):
    monkeypatch.setattr(ThreatFeedAggregator, "MAX_DOWNLOAD_BYTES", 128)
    monkeypatch.setattr(ThreatFeedAggregator, "MAX_DECOMPRESSED_BYTES", 8)
    compressed = gzip.compress(b"x" * 64)
    response = _FakeResponse([compressed], {"Content-Type": "application/gzip"})
    aggregator = _aggregator(response)

    assert aggregator.fetch_feed("bomb", {"url": "https://feeds.example/data.gz"}) is None
    assert response.closed
