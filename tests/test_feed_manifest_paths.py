"""Feed identifiers are constrained before they become manifest filenames."""

import pytest

from threat_feed_aggregator import FeedManifestVerifier


@pytest.fixture
def verifier(tmp_path, monkeypatch):
    manifest_dir = tmp_path / "manifests"
    monkeypatch.setattr(FeedManifestVerifier, "MANIFEST_DIR", manifest_dir)
    instance = object.__new__(FeedManifestVerifier)
    return instance


@pytest.mark.parametrize(
    "feed_id",
    [
        "",
        ".",
        "..",
        "../outside",
        r"..\outside",
        "nested/feed",
        r"nested\feed",
        r"C:\outside",
        "NUL",
        "CON",
        "x" * 129,
    ],
)
def test_manifest_path_rejects_unsafe_feed_ids(verifier, feed_id):
    with pytest.raises(ValueError):
        verifier._manifest_path(feed_id)


@pytest.mark.parametrize("feed_id", ["openphish", "cisa_kev", "vendor-feed-2"])
def test_manifest_path_accepts_known_slug_shapes(verifier, feed_id):
    path = verifier._manifest_path(feed_id)

    assert path.parent == verifier.MANIFEST_DIR.resolve()
    assert path.name == f"{feed_id}.json"


def test_create_manifest_rejects_traversal_without_writing_outside(verifier, tmp_path):
    outside = tmp_path / "outside.json"

    assert verifier.create_manifest("../outside", "a" * 64) is False
    assert not outside.exists()
