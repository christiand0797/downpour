"""Safe transport helpers for user-configured threat-feed previews."""

from __future__ import annotations

import gzip
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


MAX_CUSTOM_FEED_BYTES = 64 * 1024 * 1024
_READ_CHUNK_BYTES = 64 * 1024
_ASCII_WHITESPACE = {9, 10, 11, 12, 13, 32}


class _BoundedResponseReader:
    """Enforce a wire-byte ceiling while a gzip decoder pulls input."""

    def __init__(self, response, max_bytes: int):
        self._response = response
        self._max_bytes = max_bytes
        self._bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        remaining_plus_probe = self._max_bytes - self._bytes_read + 1
        requested = remaining_plus_probe if size is None or size < 0 else min(size, remaining_plus_probe)
        chunk = self._response.read(requested)
        self._bytes_read += len(chunk)
        if self._bytes_read > self._max_bytes:
            raise ValueError(f"Feed exceeds the {self._max_bytes}-byte preview limit")
        return chunk


def validate_https_feed_url(url: str) -> str:
    """Return a normalized URL or reject unsafe/malformed feed endpoints."""
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise ValueError("Feed URL must be between 1 and 2048 characters")
    if url != url.strip() or any(ord(character) < 33 for character in url):
        raise ValueError("Feed URL contains whitespace or control characters")

    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        _ = parsed.port  # Force validation of malformed ports.
    except ValueError as exc:
        raise ValueError("Feed URL is malformed") from exc

    if parsed.scheme.lower() != "https" or not hostname:
        raise ValueError("Custom threat feeds must use an HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials are not allowed in feed URLs")
    if parsed.fragment:
        raise ValueError("Feed URLs must not contain fragments")
    return url


class _HTTPSOnlyRedirectHandler(HTTPRedirectHandler):
    """Prevent a secure feed request from redirecting to a non-HTTPS URL."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            destination = urlsplit(newurl)
            if (
                destination.scheme.lower() != "https"
                or not destination.hostname
                or destination.username is not None
                or destination.password is not None
            ):
                raise ValueError
        except ValueError as exc:
            raise URLError("refusing unsafe custom-feed redirect") from exc
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def open_https_feed(request, *, timeout: float = 15, ssl_context=None, opener=None):
    """Open a feed request with TLS verification and HTTPS-only redirects."""
    if isinstance(request, str):
        request = Request(validate_https_feed_url(request))
    elif isinstance(request, Request):
        validate_https_feed_url(request.full_url)
    else:
        raise TypeError("request must be a URL string or urllib Request")

    if opener is None:
        opener = build_opener(
            _HTTPSOnlyRedirectHandler(),
            HTTPSHandler(context=ssl_context) if ssl_context is not None else HTTPSHandler(),
        )
    response = opener.open(request, timeout=timeout)
    try:
        validate_https_feed_url(response.geturl())
    except Exception:
        response.close()
        raise
    return response


def count_https_feed_records(
    url: str,
    *,
    timeout: float = 15,
    max_bytes: int = MAX_CUSTOM_FEED_BYTES,
    opener=None,
) -> int:
    """Count nonblank, non-comment lines without retaining the feed in memory."""
    url = validate_https_feed_url(url)
    if not isinstance(max_bytes, int) or not 1 <= max_bytes <= MAX_CUSTOM_FEED_BYTES:
        raise ValueError(f"max_bytes must be between 1 and {MAX_CUSTOM_FEED_BYTES}")

    request = Request(url, headers={"User-Agent": "Downpour/29 ThreatFeedPreview"})
    opener = opener or build_opener(_HTTPSOnlyRedirectHandler())
    with opener.open(request, timeout=timeout) as response:
        validate_https_feed_url(response.geturl())
        declared_length = response.headers.get("Content-Length")
        if declared_length is not None:
            try:
                declared_length = int(declared_length)
            except (TypeError, ValueError) as exc:
                raise ValueError("Feed has an invalid Content-Length") from exc
            if declared_length < 0 or declared_length > max_bytes:
                raise ValueError(f"Feed exceeds the {max_bytes}-byte preview limit")

        content_encodings = [
            encoding.strip().lower()
            for encoding in response.headers.get("Content-Encoding", "").split(",")
            if encoding.strip() and encoding.strip().lower() != "identity"
        ]
        if content_encodings not in ([], ["gzip"]):
            raise ValueError("Feed uses an unsupported content encoding")
        total_bytes = 0
        record_count = 0
        line_started = False
        line_has_content = False
        line_first_byte = None
        compressed_stream = bool(content_encodings)
        source = _BoundedResponseReader(response, max_bytes) if compressed_stream else response
        stream = gzip.GzipFile(fileobj=source, mode="rb") if compressed_stream else source
        try:
            while True:
                chunk = stream.read(min(_READ_CHUNK_BYTES, max_bytes - total_bytes + 1))
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    raise ValueError(f"Feed exceeds the {max_bytes}-byte preview limit")

                for value in chunk:
                    if not line_started:
                        line_started = True
                        line_first_byte = value
                    if value not in _ASCII_WHITESPACE:
                        line_has_content = True
                    if value in (10, 13):
                        if line_has_content and line_first_byte != ord("#"):
                            record_count += 1
                        line_started = False
                        line_has_content = False
                        line_first_byte = None
        finally:
            if compressed_stream:
                stream.close()

        if line_started and line_has_content and line_first_byte != ord("#"):
            record_count += 1
        return record_count
