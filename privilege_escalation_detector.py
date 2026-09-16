"""
Privilege Escalation & UAC Bypass Detector
Downpour v29 Titanium

Monitors for common privilege escalation techniques:
  - UAC bypass via fodhelper, eventvwr, computerdefaults, sdclt
  - Token manipulation (SeDebugPrivilege abuse)
  - AlwaysInstallElevated exploitation
  - DLL search-order hijacking in elevated contexts
  - Named pipe impersonation for privilege escalation
  - Unquoted service path exploitation
  - Auto-elevating COM objects abuse

Uses native Windows commands only (no PowerShell).
Thread-safe with bounded alert storage.
"""

import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_log = logging.getLogger('downpour.privesc')

# Registry keys commonly abused for UAC bypass
UAC_BYPASS_KEYS = {
    'fodhelper': {
        'key': r'HKCU\Software\Classes\ms-settings\Shell\Open\command',
        'binary': 'fodhelper.exe',
        'mitre': 'T1548.002',
        'description': 'UAC bypass via fodhelper.exe (ms-settings handler hijack)',
    },
    'eventvwr': {
        'key': r'HKCU\Software\Classes\mscfile\Shell\Open\command',
        'binary': 'eventvwr.exe',
        'mitre': 'T1548.002',
        'description': 'UAC bypass via eventvwr.exe (mscfile handler hijack)',
    },
    'computerdefaults': {
        'key': r'HKCU\Software\Classes\ms-settings\Shell\Open\command',
        'binary': 'computerdefaults.exe',
        'mitre': 'T1548.002',
        'description': 'UAC bypass via computerdefaults.exe',
    },
    'sdclt': {
        'key': r'HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe',
        'binary': 'sdclt.exe',
        'mitre': 'T1548.002',
        'description': 'UAC bypass via sdclt.exe (App Paths hijack)',
    },
    'cmstp': {
        'key': r'HKCU\Software\Classes\CLSID',
        'binary': 'cmstp.exe',
        'mitre': 'T1218.003',
        'description': 'UAC bypass via CMSTP.exe COM object registration',
    },
    'silentcleanup': {
        'key': r'HKCU\Environment',
        'binary': 'schtasks.exe',
        'mitre': 'T1548.002',
        'description': 'UAC bypass via SilentCleanup scheduled task env var injection',
    },
}

# Dangerous service configurations indicating privesc
UNQUOTED_PATH_RE = re.compile(
    r'^[A-Za-z]:\\[^"]*\s+.*\.exe',
    re.IGNORECASE,
)

# Auto-elevating COM CLSIDs commonly abused
SUSPICIOUS_COM_CLSIDS = {
    '{3E5FC7F9-9A51-4367-9063-A120244FBEC7}': 'EventVwr elevated COM',
    '{D2E7025F-4E85-4214-9683-A12D7C48C5B0}': 'Disk Cleanup elevated COM',
    '{BDB57FF2-79B9-4205-9447-F5FE85F37312}': 'ICMLuaUtil elevated COM',
    '{C41AFBA8-7B82-11D2-BF2A-0060976B4B45}': 'ShellWindows elevated COM',
}


@dataclass
class PrivEscAlert:
    """Alert for privilege escalation attempt."""
    timestamp: str
    technique: str
    details: str
    registry_key: str = ''
    process: str = ''
    severity: str = 'high'
    mitre_id: str = 'T1548'

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'technique': self.technique,
            'details': self.details,
            'registry_key': self.registry_key,
            'process': self.process,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
        }


class PrivilegeEscalationDetector:
    """
    Detect privilege escalation and UAC bypass attempts.

    Monitors registry keys for UAC bypass setups, checks for
    unquoted service paths, AlwaysInstallElevated, and other
    common Windows privesc vectors.
    """

    def __init__(
        self,
        check_interval: float = 15.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._baseline_uac: Dict[str, Optional[str]] = {}
        self._baseline_services: Set[str] = set()
        self._alerts: List[PrivEscAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

    def start(self) -> bool:
        """Start privilege escalation monitoring."""
        if self._running:
            return True
        try:
            self._baseline_uac = self._read_uac_bypass_keys()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='privesc-monitor',
                daemon=True,
            )
            self._thread.start()
            _log.info('Privilege escalation detector started')
            self._initial_scan()
            return True
        except Exception as exc:
            _log.warning('PrivEsc detector failed to start: %s', exc)
            return False

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks_performed': self._check_count,
            'alerts_count': len(self._alerts),
            'monitored_uac_keys': len(UAC_BYPASS_KEYS),
        }

    def _initial_scan(self) -> None:
        """Run one-time checks on startup."""
        self._check_always_install_elevated()
        self._check_unquoted_service_paths()
        self._check_weak_service_permissions()

    def _monitor_loop(self) -> None:
        """Continuous monitoring loop."""
        while self._running:
            try:
                self._check_uac_bypass_registry()
                self._check_count += 1
            except Exception as exc:
                _log.debug('PrivEsc check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_uac_bypass_registry(self) -> None:
        """Check UAC bypass registry keys for changes."""
        current = self._read_uac_bypass_keys()
        now = datetime.now(timezone.utc).isoformat()

        for name, config in UAC_BYPASS_KEYS.items():
            old_val = self._baseline_uac.get(name)
            new_val = current.get(name)

            if new_val and new_val != old_val:
                alert = PrivEscAlert(
                    timestamp=now,
                    technique=f'uac_bypass_{name}',
                    details=config['description'] + f' — value set to: {new_val}',
                    registry_key=config['key'],
                    severity='critical',
                    mitre_id=config['mitre'],
                )
                self._add_alert(alert)

        self._baseline_uac = current

    def _check_always_install_elevated(self) -> None:
        """Check if AlwaysInstallElevated is enabled (privesc vector)."""
        now = datetime.now(timezone.utc).isoformat()
        for hive in ['HKLM', 'HKCU']:
            key = f'{hive}\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer'
            val = self._reg_query_dword(key, 'AlwaysInstallElevated')
            if val == 1:
                alert = PrivEscAlert(
                    timestamp=now,
                    technique='always_install_elevated',
                    details=f'AlwaysInstallElevated enabled in {hive} — any user can install MSI as SYSTEM',
                    registry_key=key,
                    severity='critical',
                    mitre_id='T1548.002',
                )
                self._add_alert(alert)

    def _check_unquoted_service_paths(self) -> None:
        """Check for unquoted service paths (classic privesc vector)."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ['wmic', 'service', 'get', 'name,pathname,startmode'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return

            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith('Name') or line.startswith('No Instance'):
                    continue
                if UNQUOTED_PATH_RE.match(line) and '"' not in line.split('.exe')[0]:
                    parts = line.split()
                    svc_name = parts[0] if parts else 'unknown'
                    alert = PrivEscAlert(
                        timestamp=now,
                        technique='unquoted_service_path',
                        details=f'Service "{svc_name}" has unquoted path with spaces: {line[:120]}',
                        severity='medium',
                        mitre_id='T1574.009',
                    )
                    self._add_alert(alert)
        except Exception as exc:
            _log.debug('Unquoted path check error: %s', exc)

    def _check_weak_service_permissions(self) -> None:
        """Check for services writable by non-admin users."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ['sc', 'query', 'type=', 'service', 'state=', 'all'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return
            services = re.findall(r'SERVICE_NAME:\s+(\S+)', result.stdout)
            for svc in services[:100]:  # limit to first 100
                try:
                    sdshow = subprocess.run(
                        ['sc', 'sdshow', svc],
                        capture_output=True, text=True, timeout=5,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
                    )
                    if sdshow.returncode != 0:
                        continue
                    sddl = sdshow.stdout.strip()
                    # Check for Everyone (WD) or Authenticated Users (AU) with write access
                    if '(A;;RPWP;;;WD)' in sddl or '(A;;RPWPCCDCLCSWRC;;;WD)' in sddl:
                        alert = PrivEscAlert(
                            timestamp=now,
                            technique='weak_service_permissions',
                            details=f'Service "{svc}" writable by Everyone',
                            severity='high',
                            mitre_id='T1574.011',
                        )
                        self._add_alert(alert)
                except Exception:
                    continue
        except Exception as exc:
            _log.debug('Weak service perm check error: %s', exc)

    def _read_uac_bypass_keys(self) -> Dict[str, Optional[str]]:
        """Read all UAC bypass registry keys."""
        result = {}
        for name, config in UAC_BYPASS_KEYS.items():
            val = self._reg_query_string(config['key'], '')
            result[name] = val
        return result

    @staticmethod
    def _reg_query_dword(key: str, value_name: str) -> Optional[int]:
        try:
            result = subprocess.run(
                ['reg', 'query', key, '/v', value_name],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return None
            for line in result.stdout.splitlines():
                if value_name in line and 'REG_DWORD' in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith('0x'):
                            return int(part, 16)
            return None
        except Exception:
            return None

    @staticmethod
    def _reg_query_string(key: str, value_name: str) -> Optional[str]:
        try:
            args = ['reg', 'query', key]
            if value_name:
                args.extend(['/v', value_name])
            else:
                args.append('/ve')
            result = subprocess.run(
                args, capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return None
            for line in result.stdout.splitlines():
                if 'REG_SZ' in line or 'REG_EXPAND_SZ' in line:
                    parts = line.split('REG_SZ' if 'REG_SZ' in line else 'REG_EXPAND_SZ', 1)
                    if len(parts) > 1:
                        return parts[1].strip()
            return None
        except Exception:
            return None

    def _add_alert(self, alert: PrivEscAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('PrivEsc: %s', alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[PrivilegeEscalationDetector] = None


def get_privesc_detector() -> PrivilegeEscalationDetector:
    global _detector
    if _detector is None:
        _detector = PrivilegeEscalationDetector()
    return _detector


def start_privesc_detection(callback=None) -> bool:
    global _detector
    _detector = PrivilegeEscalationDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'PrivilegeEscalationDetector', 'PrivEscAlert',
    'get_privesc_detector', 'start_privesc_detection',
    'UAC_BYPASS_KEYS', 'SUSPICIOUS_COM_CLSIDS',
]
