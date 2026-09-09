"""Unit tests for code_integrity — signed self-integrity (v29.43f, audit §8.4)."""

import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import code_integrity as ci


@pytest.fixture()
def app_dir(tmp_path):
    """Fake app tree: a few .py files + downpour_data dir."""
    app = tmp_path / 'app'
    (app / 'tests').mkdir(parents=True)
    (app / 'downpour_data').mkdir()
    (app / 'main.py').write_text('print("main")', encoding='utf-8')
    (app / 'helper.py').write_text('x = 1\n', encoding='utf-8')
    (app / 'tests' / 'test_x.py').write_text('def test_x(): pass\n',
                                             encoding='utf-8')
    return app


def test_baseline_roundtrip_ok(app_dir):
    ci.save_baseline(app_dir)
    rep = ci.verify_baseline(app_dir)
    assert rep['ok'] is True
    assert rep['baseline_tampered'] is False
    assert rep['file_count'] == 3  # main.py, helper.py, tests/test_x.py


def test_modified_file_detected(app_dir):
    ci.save_baseline(app_dir)
    (app_dir / 'helper.py').write_text('x = 999\n', encoding='utf-8')
    rep = ci.verify_baseline(app_dir)
    assert rep['ok'] is False
    assert 'helper.py' in rep['modified']


def test_missing_file_detected(app_dir):
    ci.save_baseline(app_dir)
    os.remove(app_dir / 'helper.py')
    rep = ci.verify_baseline(app_dir)
    assert rep['ok'] is False
    assert 'helper.py' in rep['missing']


def test_extra_file_reported_but_ok(app_dir):
    ci.save_baseline(app_dir)
    (app_dir / 'newmodule.py').write_text('y = 2\n', encoding='utf-8')
    rep = ci.verify_baseline(app_dir)
    assert rep['ok'] is True  # extra files are informational
    assert 'newmodule.py' in rep['extra']


def test_skips_data_and_cache_dirs(app_dir):
    (app_dir / 'downpour_data' / 'junk.py').write_text('z = 3\n',
                                                       encoding='utf-8')
    cache = app_dir / '__pycache__'
    cache.mkdir()
    (cache / 'junk2.py').write_text('z = 4\n', encoding='utf-8')
    manifest = ci.build_manifest(app_dir)
    assert all(not k.startswith('downpour_data') for k in manifest)
    assert all('__pycache__' not in k for k in manifest)


def test_tampered_baseline_detected(app_dir):
    ci.save_baseline(app_dir)
    bp = app_dir / 'downpour_data' / 'code_integrity.json'
    data = json.loads(bp.read_text(encoding='utf-8'))
    # attacker modifies a recorded hash WITHOUT the signing key -> the
    # stale signature no longer matches
    data['helper.py'] = '0' * 64
    bp.write_text(json.dumps(data, indent=2), encoding='utf-8')
    rep = ci.verify_baseline(app_dir)
    assert rep['baseline_tampered'] is True
    assert rep['ok'] is False


def test_no_baseline_flag(app_dir, tmp_path):
    rep = ci.verify_baseline(app_dir, data_dir=tmp_path)
    assert rep['no_baseline'] is True


def test_key_file_created(app_dir):
    data_dir = app_dir / 'downpour_data'
    ci._load_or_create_key(data_dir)
    blob = (data_dir / 'code_integrity.key').read_bytes()
    assert blob.startswith(b'DPAPI:') or blob.startswith(b'RAW:')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])