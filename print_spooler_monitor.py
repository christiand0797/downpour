"""
Print Spooler Attack Monitor
Downpour v29 Titanium

Monitors for Print Spooler exploitation:
  - PrintNightmare (CVE-2021-34527, CVE-2021-1675)
  - SpoolFool (CVE-2022-21999)
  - Print spooler service state changes
  - Suspicious DLL loading into spoolsv.exe
  - Remote print driver installation attempts
  - Spooler configuration tampering

Uses reg.exe, sc.exe, wmic — no PowerShell.
"""

import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.spooler')

SPOOLER_REGISTRY = {
    'NoRemotePrinterDrivers': (
        r'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',
        'NoWarningNoElevationOnInstall',
        'Point and Print restriction',
    ),
    'RestrictDriverInstall': (
        r'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint',
        'RestrictDriverInstallationToAdministrators',
        'Driver installation restriction',
    ),
    'SpoolerRpcAuth': (
        r'HKLM\SYSTEM\CurrentControlSet\Control\Print',
        'RpcAuthnLevelPrivacyEnabled',
        'Spooler RPC authentication level',
    ),
}

SUSPICIOUS_SPOOLER_DLLS = [
    'mimilib.dll',
    'mimispool.dll',
    'evil.dll',
    'payload.dll',
    'shell.dll',
    'beacon.dll',
    'reverse.dll',
]

PRINT_NIGHTMARE_PATTERNS = [
    (re.compile(r'Add-PrinterDriver', re.I), 'PrintNightmare PS driver add', 'T1068', 'critical'),
    (re.compile(r'AddPrinterDriverEx', re.I), 'PrintNightmare API call', 'T1068', 'critical'),
    (re.compile(r'pcAddPrinterDriverEx', re.I), 'PrintNightmare RPC', 'T1068', 'critical'),
    (re.compile(r'\\\\.*\\pipe\\spoolss', re.I), 'Remote spooler pipe access', 'T1068', 'high'),
    (re.compile(r'mimikatz.*misc::printnightmare', re.I), 'Mimikatz PrintNightmare', 'T1068', 'critical'),
    (re.compile(r'SharpPrintNightmare|CVE-2021-1675', re.I), 'PrintNightmare exploit tool', 'T1068', 'critical'),
    (re.compile(r'SpoolFool|CVE-2022-21999', re.I), 'SpoolFool exploit', 'T1068', 'critical'),
    (re.compile(r'printerbug|dementor', re.I), 'Print spooler coercion tool', 'T1187', 'high'),
]


@dataclass
class SpoolerAlert:
    """Print spooler alert."""
    timestamp: str
    category: str
    details: str
    severity: str
    mitre_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
        }


class PrintSpoolerMonitor:
    """
    Monitor Print Spooler service for exploitation attempts.
    Checks service state, registry hardening, and driver loading.
    """

    def __init__(
        self,
        check_interval: float = 30.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._alerts: List[SpoolerAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0
        self._baseline_drivers: Set[str] = set()
        self._spooler_was_running = False

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._spooler_was_running = self._is_spooler_running()
            self._baseline_drivers = self._enumerate_print_drivers()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='spooler-monitor',
                daemon=True,
            )
            self._thread.start()
            _log.info('Print Spooler monitor started (spooler %s, %d drivers)',
                       'running' if self._spooler_was_running else 'stopped',
                       len(self._baseline_drivers))
            self._initial_hardening_check()
            return True
        except Exception as exc:
            _log.warning('Spooler monitor failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'alerts': len(self._alerts),
            'spooler_running': self._spooler_was_running,
            'driver_count': len(self._baseline_drivers),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def scan_command_line(self, process_name: str, command_line: str) -> Optional[SpoolerAlert]:
        """Check command line for PrintNightmare exploit patterns."""
        now = datetime.now(timezone.utc).isoformat()
        for pattern, desc, mitre, severity in PRINT_NIGHTMARE_PATTERNS:
            if pattern.search(command_line):
                alert = SpoolerAlert(
                    timestamp=now,
                    category='exploit_attempt',
                    details=f'{desc} detected in {process_name}',
                    severity=severity,
                    mitre_id=mitre,
                )
                self._add_alert(alert)
                return alert
        return None

    def _initial_hardening_check(self) -> None:
        """Check if spooler is properly hardened against PrintNightmare."""
        now = datetime.now(timezone.utc).isoformat()

        if self._spooler_was_running:
            self._add_alert(SpoolerAlert(
                timestamp=now,
                category='hardening',
                details='Print Spooler service is running — disable if not needed (PrintNightmare attack surface)',
                severity='medium',
                mitre_id='T1068',
            ))

        for key_name, (reg_path, value_name, desc) in SPOOLER_REGISTRY.items():
            try:
                result = subprocess.run(
                    ['reg', 'query', reg_path, '/v', value_name],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
                )
                if result.returncode != 0:
                    self._add_alert(SpoolerAlert(
                        timestamp=now,
                        category='hardening_missing',
                        details=f'{desc} not configured: {key_name}',
                        severity='medium',
                        mitre_id='T1068',
                    ))
            except Exception:
                pass

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_spooler_state()
                self._check_new_drivers()
                self._check_suspicious_dlls()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Spooler check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_spooler_state(self) -> None:
        """Detect spooler service state changes."""
        now = datetime.now(timezone.utc).isoformat()
        running = self._is_spooler_running()

        if running and not self._spooler_was_running:
            self._add_alert(SpoolerAlert(
                timestamp=now,
                category='service_started',
                details='Print Spooler service was started — potential attack preparation',
                severity='high',
                mitre_id='T1068',
            ))
        elif not running and self._spooler_was_running:
            self._add_alert(SpoolerAlert(
                timestamp=now,
                category='service_stopped',
                details='Print Spooler service was stopped',
                severity='low',
                mitre_id='T1068',
            ))
        self._spooler_was_running = running

    def _check_new_drivers(self) -> None:
        """Detect newly added print drivers."""
        now = datetime.now(timezone.utc).isoformat()
        current = self._enumerate_print_drivers()
        new_drivers = current - self._baseline_drivers

        for driver in new_drivers:
            self._add_alert(SpoolerAlert(
                timestamp=now,
                category='new_driver',
                details=f'New print driver installed: {driver}',
                severity='high',
                mitre_id='T1068',
            ))
        self._baseline_drivers = current

    def _check_suspicious_dlls(self) -> None:
        """Check for suspicious DLLs in spooler directories."""
        now = datetime.now(timezone.utc).isoformat()
        spool_dirs = [
            r'C:\Windows\System32\spool\drivers\x64\3',
            r'C:\Windows\System32\spool\drivers\W32X86\3',
            r'C:\Windows\System32\spool\drivers\x64\4',
        ]
        for spool_dir in spool_dirs:
            if not os.path.exists(spool_dir):
                continue
            try:
                for entry in os.scandir(spool_dir):
                    if entry.is_file() and entry.name.lower() in [d.lower() for d in SUSPICIOUS_SPOOLER_DLLS]:
                        self._add_alert(SpoolerAlert(
                            timestamp=now,
                            category='suspicious_dll',
                            details=f'Suspicious DLL in spool directory: {entry.name}',
                            severity='critical',
                            mitre_id='T1068',
                        ))
            except OSError:
                pass

    @staticmethod
    def _is_spooler_running() -> bool:
        try:
            result = subprocess.run(
                ['sc', 'query', 'Spooler'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            return 'RUNNING' in result.stdout
        except Exception:
            return False

    @staticmethod
    def _enumerate_print_drivers() -> Set[str]:
        drivers: Set[str] = set()
        try:
            result = subprocess.run(
                ['reg', 'query',
                 r'HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Drivers\Version-3'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and '\\' in line:
                        driver_name = line.rsplit('\\', 1)[-1]
                        if driver_name:
                            drivers.add(driver_name)
        except Exception:
            pass
        return drivers

    def _add_alert(self, alert: SpoolerAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('Spooler: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[PrintSpoolerMonitor] = None


def get_spooler_monitor() -> PrintSpoolerMonitor:
    global _monitor
    if _monitor is None:
        _monitor = PrintSpoolerMonitor()
    return _monitor


def start_spooler_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = PrintSpoolerMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'PrintSpoolerMonitor', 'SpoolerAlert',
    'get_spooler_monitor', 'start_spooler_monitoring',
]
