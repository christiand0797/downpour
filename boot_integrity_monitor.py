"""
Boot & MBR Integrity Monitor
Downpour v29 Titanium

Monitors boot configuration and critical system files for tampering:
  - BCD (Boot Configuration Data) integrity
  - Boot manager hash verification
  - Secure Boot status
  - Driver signing enforcement
  - Early Launch Anti-Malware (ELAM) status
  - Test-signing mode detection
  - Kernel debugging detection
  - BitLocker protection status

Uses bcdedit.exe, reg.exe, manage-bde.exe — no PowerShell.
"""

import hashlib
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_log = logging.getLogger('downpour.bootintegrity')

CRITICAL_BOOT_FILES = [
    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'winload.exe'),
    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'winload.efi'),
    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'ntoskrnl.exe'),
    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'ci.dll'),
    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'hal.dll'),
    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'drivers', 'disk.sys'),
    os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'bootmgr'),
]


@dataclass
class BootAlert:
    """Alert for boot integrity violation."""
    timestamp: str
    category: str
    details: str
    severity: str
    mitre_id: str
    file_path: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'file_path': self.file_path,
        }


class BootIntegrityMonitor:
    """
    Monitor boot configuration and critical system files for tampering.
    Detects bootkits, test-signing abuse, and boot config weakening.
    """

    def __init__(
        self,
        check_interval: float = 60.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._baseline_hashes: Dict[str, str] = {}
        self._baseline_bcd: Dict[str, str] = {}
        self._alerts: List[BootAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

    def start(self) -> bool:
        """Start boot integrity monitoring."""
        if self._running:
            return True
        try:
            self._baseline_hashes = self._hash_boot_files()
            self._baseline_bcd = self._read_bcd_config()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='boot-integrity',
                daemon=True,
            )
            self._thread.start()
            _log.info('Boot integrity monitor started (%d files, %d BCD entries)',
                     len(self._baseline_hashes), len(self._baseline_bcd))
            self._initial_checks()
            return True
        except Exception as exc:
            _log.warning('Boot integrity monitor failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks_performed': self._check_count,
            'monitored_files': len(self._baseline_hashes),
            'bcd_entries': len(self._baseline_bcd),
            'alerts_count': len(self._alerts),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _initial_checks(self) -> None:
        """One-time checks on startup."""
        now = datetime.now(timezone.utc).isoformat()

        # Check test-signing mode
        bcd = self._baseline_bcd
        if bcd.get('testsigning', '').lower() == 'yes':
            self._add_alert(BootAlert(
                timestamp=now,
                category='test_signing',
                details='Test-signing mode is ENABLED — unsigned drivers can load',
                severity='critical',
                mitre_id='T1553.006',
            ))

        # Check kernel debugging
        if bcd.get('debug', '').lower() == 'yes':
            self._add_alert(BootAlert(
                timestamp=now,
                category='kernel_debug',
                details='Kernel debugging is ENABLED — system may be under analysis',
                severity='high',
                mitre_id='T1562',
            ))

        # Check boot log
        if bcd.get('bootlog', '').lower() == 'yes':
            _log.info('Boot logging is enabled (informational)')

        # Check Secure Boot
        self._check_secure_boot(now)

        # Check BitLocker
        self._check_bitlocker(now)

        # Check ELAM
        self._check_elam(now)

    def _monitor_loop(self) -> None:
        """Continuous monitoring."""
        while self._running:
            try:
                self._check_boot_file_integrity()
                self._check_bcd_changes()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Boot check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_boot_file_integrity(self) -> None:
        """Verify boot file hashes haven't changed."""
        now = datetime.now(timezone.utc).isoformat()
        current = self._hash_boot_files()

        for filepath, old_hash in self._baseline_hashes.items():
            new_hash = current.get(filepath)
            if new_hash is None:
                self._add_alert(BootAlert(
                    timestamp=now,
                    category='boot_file_missing',
                    details=f'Critical boot file missing: {filepath}',
                    severity='critical',
                    mitre_id='T1542',
                    file_path=filepath,
                ))
            elif new_hash != old_hash:
                self._add_alert(BootAlert(
                    timestamp=now,
                    category='boot_file_modified',
                    details=f'Boot file hash changed: {filepath} ({old_hash[:16]}→{new_hash[:16]})',
                    severity='critical',
                    mitre_id='T1542',
                    file_path=filepath,
                ))

        self._baseline_hashes = current

    def _check_bcd_changes(self) -> None:
        """Detect BCD configuration changes."""
        now = datetime.now(timezone.utc).isoformat()
        current = self._read_bcd_config()

        dangerous_changes = {
            'testsigning': ('Test-signing mode changed', 'T1553.006', 'critical'),
            'debug': ('Kernel debugging mode changed', 'T1562', 'high'),
            'nointegritychecks': ('Integrity checks setting changed', 'T1553', 'critical'),
            'loadoptions': ('Boot load options changed', 'T1542', 'high'),
        }

        for key, (desc, mitre, severity) in dangerous_changes.items():
            old_val = self._baseline_bcd.get(key)
            new_val = current.get(key)
            if new_val != old_val and new_val is not None:
                self._add_alert(BootAlert(
                    timestamp=now,
                    category=f'bcd_{key}',
                    details=f'{desc}: {old_val} → {new_val}',
                    severity=severity,
                    mitre_id=mitre,
                ))

        self._baseline_bcd = current

    def _check_secure_boot(self, now: str) -> None:
        """Check Secure Boot status."""
        try:
            result = subprocess.run(
                ['reg', 'query',
                 r'HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State',
                 '/v', 'UEFISecureBootEnabled'],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'UEFISecureBootEnabled' in line and '0x0' in line:
                        self._add_alert(BootAlert(
                            timestamp=now,
                            category='secure_boot_disabled',
                            details='UEFI Secure Boot is DISABLED — unsigned bootloaders can execute',
                            severity='high',
                            mitre_id='T1542.003',
                        ))
        except Exception:
            pass

    def _check_bitlocker(self, now: str) -> None:
        """Check BitLocker protection status on system drive."""
        try:
            result = subprocess.run(
                ['manage-bde', '-status', os.environ.get('SystemDrive', 'C:')],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                if 'protection off' in output:
                    self._add_alert(BootAlert(
                        timestamp=now,
                        category='bitlocker_off',
                        details='BitLocker protection is OFF on system drive',
                        severity='medium',
                        mitre_id='T1486',
                    ))
        except Exception:
            pass

    def _check_elam(self, now: str) -> None:
        """Check Early Launch Anti-Malware driver status."""
        try:
            result = subprocess.run(
                ['reg', 'query',
                 r'HKLM\SYSTEM\CurrentControlSet\Control\EarlyLaunch',
                 '/v', 'DriverLoadPolicy'],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'DriverLoadPolicy' in line:
                        if '0x7' in line or '0x3' in line:
                            self._add_alert(BootAlert(
                                timestamp=now,
                                category='elam_weakened',
                                details='ELAM driver load policy allows bad/unknown drivers',
                                severity='high',
                                mitre_id='T1562.001',
                            ))
        except Exception:
            pass

    @staticmethod
    def _hash_boot_files() -> Dict[str, str]:
        """Hash critical boot files."""
        hashes = {}
        for filepath in CRITICAL_BOOT_FILES:
            try:
                if os.path.exists(filepath):
                    h = hashlib.sha256()
                    with open(filepath, 'rb') as f:
                        for chunk in iter(lambda: f.read(65536), b''):
                            h.update(chunk)
                    hashes[filepath] = h.hexdigest()
            except PermissionError:
                hashes[filepath] = 'permission_denied'
            except Exception:
                pass
        return hashes

    @staticmethod
    def _read_bcd_config() -> Dict[str, str]:
        """Read BCD configuration via bcdedit."""
        config: Dict[str, str] = {}
        try:
            result = subprocess.run(
                ['bcdedit', '/enum', '{current}'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        config[parts[0].lower()] = parts[1]
        except Exception:
            pass
        return config

    def _add_alert(self, alert: BootAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('Boot integrity: %s', alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[BootIntegrityMonitor] = None


def get_boot_monitor() -> BootIntegrityMonitor:
    global _monitor
    if _monitor is None:
        _monitor = BootIntegrityMonitor()
    return _monitor


def start_boot_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = BootIntegrityMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'BootIntegrityMonitor', 'BootAlert',
    'get_boot_monitor', 'start_boot_monitoring',
    'CRITICAL_BOOT_FILES',
]
