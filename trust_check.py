r"""
trust_check.py - Signature-bound trust validation (TASK-015)
==============================================================
Provides WinVerifyTrust-based validation for system processes.
Replaces name-only allowlists with (name, signed-path, signature) validation.

A process is trusted iff:
  1. Name matches a known system process name
  2. Image path is under %SystemRoot%\System32 or SysWOW64
  3. Digital signature validates via WinVerifyTrust (Microsoft/WHQL)
"""

from __future__ import annotations
import os
import sys
import logging
from pathlib import Path
from typing import Optional, Dict, Set
from functools import lru_cache

_log = logging.getLogger(__name__)

# Known system process names that MAY be trusted (if also path + signature valid)
SYSTEM_PROCESS_NAMES: Set[str] = {
    'svchost.exe', 'system', 'registry', 'smss.exe', 'csrss.exe',
    'wininit.exe', 'services.exe', 'lsass.exe', 'fontdrvhost.exe',
    'dwm.exe', 'explorer.exe', 'taskhostw.exe', 'dllhost.exe',
    'winlogon.exe', 'taskhost.exe', 'conhost.exe', 'sihost.exe',
    'runtimebroker.exe', 'searchhost.exe', 'sihost.exe', 'ctfmon.exe',
    'msdtc.exe', 'spoolsv.exe', 'wmiprvse.exe', 'audiodg.exe',
    'securityhealthservice.exe', 'msmpeng.exe', 'mrt.exe',
}

# Trusted Microsoft signer subjects (common patterns)
TRUSTED_SIGNER_PATTERNS = (
    'microsoft corporation',
    'microsoft windows',
    'microsoft windows publisher',
    'windows publisher',
    'windows',
)

def _get_system_root() -> str:
    return os.environ.get('SystemRoot', r'C:\Windows').rstrip('\\').lower()

def _is_system_path(path: str) -> bool:
    """Check if path is under System32 or SysWOW64.

    v29.43a merge fix: the trailing-backslash-less prefixes matched
    look-alike directories (e.g. C:\\Windows\\System32evil\\) — removed.
    """
    if not path:
        return False
    p = str(path).lower()
    sysroot = _get_system_root()
    return (
        p.startswith(sysroot + '\\system32\\') or
        p.startswith(sysroot + '\\syswow64\\')
    )


def is_system_image(path: str) -> bool:
    """Public alias for _is_system_path.

    Used by threat_response_center.py's process-info display and
    tests/test_trust_check.py — keep the public name stable.
    """
    return _is_system_path(path)

@lru_cache(maxsize=256)
def _verify_signature_wintrust(filepath: str, mtime: int = 0, size: int = 0) -> Dict:
    """
    Verify file signature using PowerShell Get-AuthenticodeSignature
    (WinVerifyTrust under the hood). Cached per (path, mtime, size) so a
    replaced binary at the same path is NOT served a stale verdict.

    Returns dict with 'valid' (bool), 'signer' (str), 'status' (str),
    'error' (str|None).

    v29.43a merge fixes: PSModulePath is stripped from the child env (an
    inherited venv/shell PSModulePath breaks Microsoft.PowerShell.Security
    module loading), and single quotes in the path are escaped for the PS
    literal.
    """
    if not filepath or not os.path.exists(filepath):
        return {'valid': False, 'signer': '', 'status': 'NOT_FOUND', 'error': 'File not found'}

    try:
        # Use PowerShell Get-AuthenticodeSignature for proper WinVerifyTrust validation
        # -LiteralPath prevents injection; single quotes doubled for PS literals
        esc = filepath.replace("'", "''")
        ps_cmd = (
            f'$sig = Get-AuthenticodeSignature -LiteralPath \'{esc}\'; '
            f'@($sig.Status, $sig.SignerCertificate.Subject, $sig.StatusMessage) -join \'|\''
        )
        import subprocess
        env = {k: v for k, v in os.environ.items() if k.upper() != 'PSMODULEPATH'}
        result = subprocess.run(
            ['powershell', '-NoProfile', '-NonInteractive', '-Command', ps_cmd],
            capture_output=True, text=True, timeout=10, creationflags=0x08000000,
            env=env
        )
        if result.returncode != 0:
            return {'valid': False, 'signer': '', 'status': 'PS_ERROR', 'error': result.stderr[:200]}

        parts = result.stdout.strip().split('|', 2)
        if len(parts) < 3:
            return {'valid': False, 'signer': '', 'status': 'PARSE_ERROR', 'error': 'Unexpected output'}

        status, subject, message = parts[0].strip(), parts[1].strip(), parts[2].strip()
        is_valid = status == 'Valid'
        signer_lower = subject.lower()
        trusted_signer = any(pattern in signer_lower for pattern in TRUSTED_SIGNER_PATTERNS)

        return {
            'valid': is_valid and trusted_signer,
            'signer': subject,
            'status': status,
            'message': message,
            'trusted_signer': trusted_signer
        }

    except subprocess.TimeoutExpired:
        return {'valid': False, 'signer': '', 'status': 'TIMEOUT', 'error': 'Get-AuthenticodeSignature timeout'}
    except Exception as e:
        return {'valid': False, 'signer': '', 'status': 'EXCEPTION', 'error': str(e)[:200]}

def trusted_system_process(process_name: str, image_path: str, system_names: Optional[Set[str]] = None) -> bool:
    """
    Main trust check: name in allowlist + path under System32/SysWOW64 + valid Microsoft signature.
    Returns True only if ALL three checks pass.
    Kernel pseudo-processes ('system', 'registry') are exempt from path/signature checks.
    """
    if not process_name:
        return False

    name_lower = process_name.lower()

    # Kernel pseudo-processes: no image path, trusted by name
    if name_lower in ('system', 'registry'):
        return True

    # Must be in known system process names
    allowed_names = system_names if system_names is not None else SYSTEM_PROCESS_NAMES
    if name_lower not in allowed_names:
        return False

    # Must be running from System32 or SysWOW64
    if not _is_system_path(image_path):
        _log.debug(f"Trust check FAILED path: {process_name} at {image_path}")
        return False

    # Verify digital signature (cache key includes mtime/size — see fn)
    try:
        _st = os.stat(image_path)
        sig = _verify_signature_wintrust(image_path,
                                         int(_st.st_mtime), int(_st.st_size))
    except OSError:
        sig = {'valid': False, 'signer': '', 'status': 'NOT_FOUND',
               'error': 'stat failed'}
    if not sig['valid']:
        _log.warning(f"Trust check FAILED signature: {process_name} at {image_path} — {sig}")
        return False

    _log.debug(f"Trust check PASSED: {process_name} at {image_path} — signer: {sig['signer']}")
    return True

# Backward-compat alias for downpour_v29_titanium.py
def is_trusted_system_process(name: str, path: str) -> bool:
    return trusted_system_process(name, path)

# Path-only check (for display/UI masquerading warning)
def is_system_image(path: str) -> bool:
    """Check if path is under Windows System32 or SysWOW64 directory."""
    return _is_system_path(path)


def verify_signature(exe_path: str) -> Optional[bool]:
    """Public boolean wrapper over the signature check.

    True = valid Microsoft-signed Authenticode; False = unsigned/invalid/
    untrusted; None = verification impossible (non-Windows, missing file,
    or the checker itself failed). Used by tests and any caller that wants
    a tri-state answer instead of the full allowlist decision.
    """
    if os.name != 'nt':
        return None
    try:
        if not exe_path or not os.path.exists(str(exe_path)):
            return None
        st = os.stat(exe_path)
        info = _verify_signature_wintrust(str(exe_path),
                                          int(st.st_mtime), int(st.st_size))
    except Exception:
        return None
    if info.get('status') in ('NOT_FOUND', 'PS_ERROR', 'PARSE_ERROR',
                              'TIMEOUT', 'EXCEPTION'):
        return None
    return bool(info.get('valid'))

if __name__ == '__main__':
    import logging
    logging.basicConfig(level=logging.DEBUG)
    # Quick test
    for name, path in [
        ('svchost.exe', r'C:\Windows\System32\svchost.exe'),
        ('svchost.exe', r'C:\Temp\svchost.exe'),
        ('notepad.exe', r'C:\Windows\System32\notepad.exe'),
        ('system', ''),
    ]:
        print(f"{name} @ {path}: {trusted_system_process(name, path)}")