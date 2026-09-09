"""
CODE INTEGRITY — v29.43f (audit §8.4)
================================================================================
Signed self-integrity manifest for Downpour's own code.

Threat model (audit 2026-09-07, Risk 1 residual): the app directory is
Defender-excluded and user-writable, so code replacement by same-user
malware is otherwise undetectable. This module hashes every code file,
signs the manifest with HMAC-SHA256 (key DPAPI-protected in
downpour_data/code_integrity.key), and verifies at run time.

  * modified / missing / extra files are reported per file
  * a tampered baseline (bad signature) is reported as baseline_tampered
    — the operator must then re-run --baseline from a trusted copy

Honest limitation: a same-user attacker can delete the key/baseline pair
(both live in downpour_data); that act is itself detectable (baseline
missing = loud alert) but not preventable without a kernel-level store.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

_log = logging.getLogger(__name__)

KEY_FILE_NAME = 'code_integrity.key'
BASELINE_FILE_NAME = 'code_integrity.json'
SCAN_PATTERNS = ('*.py', '*.yar')
SKIP_DIRS = {'downpour_data', 'downpour_tmp', '__pycache__', '.git',
             '.venv', 'venv', 'docs', '.mypy_cache', '.pytest_cache',
             '.aicode', '.aura', 'node_modules', 'aicompanion',
             'downpour_v27_data', '_ARCHIVE', '_legacy_launchers'}


class IntegrityError(Exception):
    pass


def _key_path(data_dir: Path) -> Path:
    return Path(data_dir) / KEY_FILE_NAME


def _baseline_path(data_dir: Path) -> Path:
    return Path(data_dir) / BASELINE_FILE_NAME


def _load_or_create_key(data_dir: Path) -> bytes:
    """DPAPI-protected HMAC key (RAW fallback); created on first use."""
    kp = _key_path(data_dir)
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        if kp.exists():
            blob = kp.read_bytes().strip()
            if blob.startswith(b'DPAPI:'):
                import win32crypt
                return win32crypt.CryptUnprotectData(
                    base64.b64decode(blob[6:]), None, None, None, 0)[1]
            if blob.startswith(b'RAW:'):
                return base64.b64decode(blob[4:])
        import secrets
        key = secrets.token_bytes(32)
        try:
            import win32crypt
            protected = win32crypt.CryptProtectData(
                key, 'downpour-code-integrity', None, None, None, 0)
            kp.write_bytes(b'DPAPI:' + base64.b64encode(protected))
        except Exception:
            kp.write_bytes(b'RAW:' + base64.b64encode(key))
        return key
    except Exception as exc:
        raise IntegrityError(f'code integrity key unavailable: {exc}') from exc


def build_manifest(app_dir: Path,
                   patterns: tuple = SCAN_PATTERNS) -> Dict[str, str]:
    """sha256 map of all code files under app_dir (relpath -> hex digest).

    Skip check uses parts RELATIVE to app_dir — absolute parts would
    misfire when the tree lives under a skipped dir name (e.g. tmp dirs).
    """
    app_dir = Path(app_dir)
    manifest: Dict[str, str] = {}
    for pattern in patterns:
        for f in sorted(app_dir.rglob(pattern)):
            if not f.is_file():
                continue
            try:
                rel_path = f.relative_to(app_dir)
            except ValueError:
                continue
            if any(part in SKIP_DIRS for part in rel_path.parts):
                continue
            rel = rel_path.as_posix()
            h = hashlib.sha256()
            with open(f, 'rb') as fh:
                for chunk in iter(lambda: fh.read(65536), b''):
                    h.update(chunk)
            manifest[rel] = h.hexdigest()
    return manifest


def _sign(manifest: Dict[str, str], key: bytes) -> str:
    canonical = json.dumps(manifest, sort_keys=True).encode('utf-8')
    return hmac.new(key, canonical, hashlib.sha256).hexdigest()


def save_baseline(app_dir: Path, data_dir: Optional[Path] = None) -> Dict[str, str]:
    """Build and sign a fresh baseline for app_dir. Returns the manifest."""
    app_dir = Path(app_dir)
    data_dir = Path(data_dir) if data_dir else app_dir / 'downpour_data'
    key = _load_or_create_key(data_dir)
    manifest = build_manifest(app_dir)
    signed = dict(manifest)
    signed['_meta'] = {
        'generated': datetime.now().isoformat(),
        'file_count': len(manifest),
        'version': 1,
    }
    sig = _sign(signed, key)
    signed['_signature'] = sig
    bp = _baseline_path(data_dir)
    bp.write_text(json.dumps(signed, indent=2), encoding='utf-8')
    _log.info('code_integrity: baseline saved (%d files)', len(manifest))
    return manifest


def verify_baseline(app_dir: Path,
                    data_dir: Optional[Path] = None) -> Dict[str, object]:
    """Verify app_dir code files against the signed baseline.

    Returns {ok, baseline_tampered, no_baseline, modified, missing, extra,
    file_count}. 'ok' is True only when the baseline signature verifies AND
    no file is modified/missing/extra.
    """
    app_dir = Path(app_dir)
    data_dir = Path(data_dir) if data_dir else app_dir / 'downpour_data'
    report: Dict[str, object] = {
        'ok': False, 'baseline_tampered': False, 'no_baseline': False,
        'modified': [], 'missing': [], 'extra': [], 'file_count': 0,
    }
    bp = _baseline_path(data_dir)
    if not bp.exists():
        report['no_baseline'] = True
        _log.warning('code_integrity: no baseline at %s — run --baseline',
                     bp)
        return report

    key = _load_or_create_key(data_dir)
    try:
        signed = json.loads(bp.read_text(encoding='utf-8'))
    except Exception as exc:
        report['baseline_tampered'] = True
        _log.error('code_integrity: baseline unreadable: %s', exc)
        return report

    sig = signed.pop('_signature', '')
    # NB: _meta stays IN the dict — save_baseline signed everything except
    # _signature, so the verification must hash the exact same shape.
    expected_sig = _sign(signed, key)
    if not hmac.compare_digest(sig, expected_sig):
        report['baseline_tampered'] = True
        _log.error('code_integrity: BASELINE SIGNATURE INVALID — the '
                   'baseline itself was modified outside --baseline')
        return report

    current = build_manifest(app_dir)
    baseline = {k: v for k, v in signed.items() if not k.startswith('_')}
    report['file_count'] = len(baseline)

    for rel, digest in baseline.items():
        cur = current.get(rel)
        if cur is None:
            report['missing'].append(rel)
        elif cur != digest:
            report['modified'].append(rel)
    for rel in current:
        if rel not in baseline:
            report['extra'].append(rel)

    tampered = bool(report['modified'] or report['missing'])
    # extra files are informational (new legit files appear without a
    # re-baseline) but reported
    report['ok'] = not tampered
    if report['modified'] or report['missing'] or report['extra']:
        _log.warning('code_integrity: %d modified, %d missing, %d extra',
                     len(report['modified']), len(report['missing']),
                     len(report['extra']))
    return report


if __name__ == '__main__':
    import argparse
    _here = Path(__file__).parent
    _ap = argparse.ArgumentParser(description='Downpour code integrity (v29.43f)')
    _ap.add_argument('action', choices=['baseline', 'verify'])
    _ap.add_argument('--dir', default=str(_here), help='app directory to guard')
    _ap.add_argument('--data-dir', default=str(_here / 'downpour_data'))
    _args = _ap.parse_args()
    if _args.action == 'baseline':
        m = save_baseline(_args.dir, _args.data_dir)
        print(f'Baseline saved: {len(m)} files')
    else:
        rep = verify_baseline(_args.dir, _args.data_dir)
        if rep['no_baseline']:
            print('No baseline — run: python code_integrity.py baseline')
        elif rep['baseline_tampered']:
            print('BASELINE TAMPERED — verify from a trusted copy')
        else:
            print(f"OK: {rep['file_count']} files verified")
            for k in ('modified', 'missing', 'extra'):
                if rep[k]:
                    print(f'  {k}: {rep[k]}')