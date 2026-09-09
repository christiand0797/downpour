"""Unit tests for quarantine_core — unified quarantine service (v29.43b).

agent-audit-001's v2 rewrite: QuarantineService with its own SQLite DB,
write-ahead manifests, AES-GCM content encryption, and per-file security-
descriptor preservation. Tests point the module's storage constants at tmp
dirs and reset the service singleton so nothing touches the real
downpour_data quarantine.
"""

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import quarantine_core as qc


@pytest.fixture()
def qservice(tmp_path, monkeypatch):
    """Isolated quarantine service: storage constants -> tmp_path."""
    qdir = tmp_path / 'quarantine'
    monkeypatch.setattr(qc, 'QUARANTINE_DIR', qdir)
    monkeypatch.setattr(qc, 'LOCKED_DIR', qdir / 'locked')
    monkeypatch.setattr(qc, 'MANIFEST_DIR', qdir / 'manifests')
    monkeypatch.setattr(qc, 'KEY_FILE', qdir / '.quarantine_key')
    monkeypatch.setattr(qc, 'DB_FILE', qdir / 'quarantine.db')
    monkeypatch.setattr(qc, '_service', None)
    for d in (qdir, qdir / 'locked', qdir / 'manifests'):
        d.mkdir(parents=True, exist_ok=True)
    yield qc.get_service()
    qc._service = None


def _sha(p) -> str:
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(65536), b''):
            h.update(c)
    return h.hexdigest()


def test_roundtrip_quarantine_restore(qservice, tmp_path):
    """Quarantine -> original removed; restore(entry_id) -> identical bytes."""
    src = tmp_path / 'evil.exe'
    src.write_bytes(bytes(range(256)) * 64)
    expected = _sha(src)  # hash BEFORE quarantine removes the file

    entry = qc.quarantine_file(src, threat_type='test')
    assert not src.exists(), "original must be removed after quarantine"
    assert Path(entry.quarantine_path).exists(), "content file must exist"
    assert entry.file_hash == expected

    assert qc.restore_file(entry.id) is True
    assert src.exists(), "restore must recreate the original"
    assert _sha(src) == entry.file_hash, "restored bytes must match"


def test_restore_by_original_path(qservice, tmp_path):
    src = tmp_path / 'deep' / 'evil.bin'
    src.parent.mkdir(parents=True)
    src.write_bytes(b'payload' * 10)

    entry = qc.quarantine_file(src, threat_type='test')
    assert qc.restore_by_original_path(str(src)) is True
    assert src.exists()
    assert _sha(src) == entry.file_hash


def test_tamper_refused_on_restore(qservice, tmp_path):
    """Corrupted quarantine content must fail the restore and must NOT
    recreate the original."""
    src = tmp_path / 'evil.exe'
    src.write_bytes(b'malware-bytes' * 100)
    entry = qc.quarantine_file(src, threat_type='test')

    blob = bytearray(Path(entry.quarantine_path).read_bytes())
    blob[5] ^= 0xFF
    Path(entry.quarantine_path).write_bytes(bytes(blob))

    assert qc.restore_file(entry.id) is False
    assert not src.exists(), "tampered content must NOT be restored"


def test_list_and_reconcile(qservice, tmp_path):
    src = tmp_path / 'x.bin'
    src.write_bytes(b'zzz')
    entry = qc.quarantine_file(src, threat_type='test')

    entries = qc.list_quarantined()
    assert any(e.id == entry.id for e in entries)

    stats = qc.reconcile_quarantine()
    assert isinstance(stats, dict), "reconcile must return a stats dict"


def test_missing_source_raises(qservice, tmp_path):
    with pytest.raises(Exception):
        qc.quarantine_file(tmp_path / 'does_not_exist.exe')


def test_entry_metadata_preserved(qservice, tmp_path):
    """The entry must carry the threat metadata callers pass in."""
    src = tmp_path / 'sample.exe'
    src.write_bytes(b'A' * 32)
    entry = qc.quarantine_file(src, threat_type='rat',
                               threat_name='TestRAT', severity='CRITICAL')
    assert entry.threat_type == 'rat'
    assert entry.threat_name == 'TestRAT'
    assert entry.severity == 'CRITICAL'
    assert entry.file_size == 32


def test_collision_disambiguation(qservice, tmp_path):
    """v29.43c: quarantining the same name+hash twice must NOT overwrite
    the first copy (the timestamp suffix disambiguates)."""
    src = tmp_path / 'dup.exe'
    src.write_bytes(b'same-content' * 10)
    e1 = qc.quarantine_file(src, threat_type='t')
    src.write_bytes(b'same-content' * 10)  # recreate identical file
    e2 = qc.quarantine_file(src, threat_type='t')
    assert e1.quarantine_path != e2.quarantine_path
    assert Path(e1.quarantine_path).exists()
    assert Path(e2.quarantine_path).exists()
    assert e1.id != e2.id


def test_migrate_legacy_xor_sidecar(qservice, tmp_path):
    """v1 XOR sidecar entries are ingested into the v2 service and remain
    restorable to their original path."""
    from quarantine_core import migrate_legacy_entries
    legacy_root = tmp_path / 'legacy'
    locked = legacy_root / 'locked'
    locked.mkdir(parents=True)
    src = tmp_path / 'old.exe'
    src.write_bytes(b'legacy-content' * 40)
    digest = hashlib.sha256(src.read_bytes()).hexdigest()
    dest = locked / f"old.exe.{digest[:8]}.quarantined"
    dest.write_bytes(bytes(b ^ 0x5A for b in src.read_bytes()))
    meta = {'original_path': str(src), 'hash_sha256': digest,
            'method': 'xor-0x5a', 'quarantined_at': '2026-01-01T00:00:00'}
    Path(str(dest) + '.meta.json').write_text(json.dumps(meta), encoding='utf-8')
    src.unlink()

    stats = migrate_legacy_entries([legacy_root])
    assert stats['migrated'] == 1
    assert dest.with_name(dest.name + '.migrated').exists(), \
        "consumed legacy artifact must be renamed, not deleted"

    # the migrated entry is restorable via the service
    assert qc.restore_by_original_path(str(src)) is True
    assert src.exists() and _sha(src) == digest


def test_migrate_legacy_plain_quar_no_metadata(qservice, tmp_path):
    """GUI .quar plain moves (no metadata) are ingested and flagged."""
    from quarantine_core import migrate_legacy_entries
    legacy_root = tmp_path / 'legacy'
    legacy_root.mkdir(parents=True)
    quar = legacy_root / 'suspicious.exe.quar'
    quar.write_bytes(b'quarantine-gui-content' * 10)

    stats = migrate_legacy_entries([legacy_root])
    assert stats['migrated'] == 1
    assert stats['no_metadata'] == 1
    assert quar.with_name(quar.name + '.migrated').exists()


def test_migrate_skips_v2_owned_files(qservice, tmp_path):
    """v2-owned content files must be skipped, not double-registered."""
    src = tmp_path / 'mine.exe'
    src.write_bytes(b'v2-content' * 10)
    entry = qc.quarantine_file(src, threat_type='t')
    from quarantine_core import migrate_legacy_entries
    stats = migrate_legacy_entries([tmp_path / 'quarantine'])  # same root
    assert stats['skipped_v2'] >= 1
    assert stats['migrated'] == 0
    assert not src.exists()  # untouched


def test_stream_format_roundtrip_for_large_files(qservice, tmp_path, monkeypatch):
    """v29.43e: files above _STREAM_THRESHOLD use the DQS2 streamed format
    (constant memory). Force the threshold down to exercise the path."""
    monkeypatch.setattr(qc, '_STREAM_THRESHOLD', 1024)
    src = tmp_path / 'big.bin'
    src.write_bytes(os.urandom(5000))
    expected = _sha(src)  # hash BEFORE quarantine removes the file

    entry = qc.quarantine_file(src, threat_type='big')
    assert not src.exists()
    with open(entry.quarantine_path, 'rb') as f:
        assert f.read(4) == qc._STREAM_MAGIC, "expected streamed format"

    assert qc.restore_file(entry.id) is True
    assert src.exists()
    assert _sha(src) == expected


def test_stream_format_tamper_refused(qservice, tmp_path, monkeypatch):
    """A corrupted streamed file must fail restore, never recreate the
    original (GCM auth fails on the tampered chunk)."""
    monkeypatch.setattr(qc, '_STREAM_THRESHOLD', 1024)
    src = tmp_path / 'evil.bin'
    src.write_bytes(os.urandom(3000))
    entry = qc.quarantine_file(src, threat_type='evil')

    blob = bytearray(Path(entry.quarantine_path).read_bytes())
    blob[20] ^= 0xFF  # corrupt a GCM chunk
    Path(entry.quarantine_path).write_bytes(bytes(blob))

    assert qc.restore_file(entry.id) is False
    assert not src.exists(), "tampered content must NOT be restored"


# ---------------------------------------------------------------------------
# Sensor liveness registry (v29.43f, audit §8.5)
# ---------------------------------------------------------------------------

def test_sensor_hub_liveness_roundtrip():
    """mark_alive + liveness_report: fresh marks are not stale."""
    from sensor_hub import SensorHub
    hub = SensorHub()
    hub.mark_alive('proc_loop')
    hub.mark_alive('net_loop')
    rep = hub.liveness_report(stale_after=180.0)
    assert 'proc_loop' in rep and 'net_loop' in rep
    assert rep['proc_loop']['stale'] is False
    assert rep['proc_loop']['age_seconds'] < 5


def test_sensor_hub_liveness_stale_detection():
    """A sensor that stopped marking goes stale past the threshold."""
    import time as _t
    from sensor_hub import SensorHub
    hub = SensorHub()
    hub.mark_alive('dead_sensor')
    # backdate the mark past the stale threshold
    hub._liveness['dead_sensor'] -= 999
    rep = hub.liveness_report(stale_after=180.0)
    assert rep['dead_sensor']['stale'] is True


def test_sensor_hub_marks_itself_alive():
    """The hub's own loop marks 'sensor_hub' alive on start."""
    import time
    from sensor_hub import SensorHub
    hub = SensorHub()
    hub.start()
    try:
        deadline = time.time() + 10
        while time.time() < deadline and 'sensor_hub' not in hub._liveness:
            time.sleep(0.1)
        assert 'sensor_hub' in hub._liveness
    finally:
        hub.stop()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])