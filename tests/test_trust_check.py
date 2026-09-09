"""Unit tests for trust_check — signature-bound allowlists (v29.42y, TASK-015)."""

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trust_check import (is_system_image, trusted_system_process,
                         verify_signature)


SAFE_NAMES = {'svchost.exe', 'lsass.exe', 'services.exe'}


def test_is_system_image_paths():
    assert is_system_image(r'C:\Windows\System32\svchost.exe') is True
    assert is_system_image(r'C:\Windows\SysWOW64\foo.dll') is True
    # v29.43a: bare Windows root and look-alike dirs are NOT system images
    # (stricter System32/SysWOW64-only policy from the merged trust_check)
    assert is_system_image(r'C:\Windows\explorer.exe') is False
    assert is_system_image(r'C:\Windows\System32evil\payload.dll') is False
    assert is_system_image(r'C:\Temp\svchost.exe') is False
    assert is_system_image(r'C:\Users\evil\svchost.exe') is False
    assert is_system_image('') is False
    assert is_system_image(None) is False


def test_is_system_image_case_insensitive():
    assert is_system_image(r'c:\windows\system32\svchost.EXE') is True


def test_trusted_system_process_rejects_wrong_path(tmp_path):
    """A spoofed name outside the Windows directory is never trusted."""
    fake = tmp_path / 'svchost.exe'
    fake.write_bytes(b'not really svchost')
    assert trusted_system_process('svchost.exe', str(fake),
                                  system_names=SAFE_NAMES) is False


def test_trusted_system_process_rejects_unknown_name(tmp_path):
    real = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'cmd.exe'
    assert trusted_system_process('evilware.exe', str(real),
                                  system_names=SAFE_NAMES) is False


def test_trusted_system_process_missing_file():
    real = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32'
    missing = real / 'definitely_not_a_real_file_xyz.exe'
    assert trusted_system_process('svchost.exe', str(missing),
                                  system_names=SAFE_NAMES) is False


@pytest.mark.skipif(os.name != 'nt', reason='WinVerifyTrust is Windows-only')
def test_verify_signature_windows_binary():
    """A real Windows system binary must verify; a temp file must not."""
    real = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'cmd.exe'
    if not real.is_file():
        pytest.skip('cmd.exe not found')
    assert verify_signature(str(real)) is True

    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        f.write(b'MZ unsigned test payload')
        unsigned = f.name
    try:
        assert verify_signature(unsigned) is False
    finally:
        os.remove(unsigned)


def test_verify_signature_missing_file_returns_none():
    assert verify_signature(r'C:\Windows\System32\nope_missing.exe') is None


def test_signature_cache_hit():
    """Second call must hit the cache (same result, no crash)."""
    real = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'cmd.exe'
    if not real.is_file():
        pytest.skip('cmd.exe not found')
    a = verify_signature(str(real))
    b = verify_signature(str(real))
    assert a == b


if __name__ == '__main__':
    pytest.main([__file__, '-v'])