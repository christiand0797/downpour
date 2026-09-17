"""
DPAPI Credential Theft Monitor
Downpour v29 Titanium

Monitors for Data Protection API (DPAPI) abuse:
  - Master key file access and extraction
  - Browser credential store targeting (Chrome, Edge, Firefox)
  - WiFi password extraction
  - Credential Manager vault theft
  - DPAPI blob decryption attempts
  - Domain backup key extraction

Uses native commands only — no PowerShell.
"""

import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.dpapi')

DPAPI_MASTER_KEY_PATHS = [
    os.path.expandvars(r'%APPDATA%\Microsoft\Protect'),
    os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Protect'),
    r'C:\Windows\System32\Microsoft\Protect',
]

BROWSER_CREDENTIAL_PATHS = {
    'chrome_login': os.path.expandvars(
        r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data'),
    'chrome_cookies': os.path.expandvars(
        r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies'),
    'chrome_local_state': os.path.expandvars(
        r'%LOCALAPPDATA%\Google\Chrome\User Data\Local State'),
    'edge_login': os.path.expandvars(
        r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data'),
    'edge_cookies': os.path.expandvars(
        r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies'),
    'edge_local_state': os.path.expandvars(
        r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Local State'),
    'firefox_profiles': os.path.expandvars(
        r'%APPDATA%\Mozilla\Firefox\Profiles'),
}

WIFI_CREDENTIAL_PATH = r'C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces'

CREDENTIAL_VAULT_PATHS = [
    os.path.expandvars(r'%APPDATA%\Microsoft\Credentials'),
    os.path.expandvars(r'%LOCALAPPDATA%\Microsoft\Credentials'),
    r'C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials',
]

DPAPI_ATTACK_PATTERNS = [
    (re.compile(r'dpapi::masterkey', re.I), 'Mimikatz DPAPI master key', 'T1555.004', 'critical'),
    (re.compile(r'dpapi::cred', re.I), 'Mimikatz DPAPI credential', 'T1555.004', 'critical'),
    (re.compile(r'dpapi::vault', re.I), 'Mimikatz DPAPI vault', 'T1555.004', 'critical'),
    (re.compile(r'dpapi::chrome', re.I), 'Mimikatz Chrome DPAPI', 'T1555.003', 'critical'),
    (re.compile(r'dpapi::blob', re.I), 'Mimikatz DPAPI blob decrypt', 'T1555.004', 'critical'),
    (re.compile(r'dpapi::backupkey', re.I), 'Mimikatz domain backup key', 'T1555.004', 'critical'),
    (re.compile(r'lsadump::backupkeys', re.I), 'Mimikatz backup key extraction', 'T1555.004', 'critical'),
    (re.compile(r'SharpDPAPI|SharpChrome', re.I), 'SharpDPAPI tool', 'T1555.004', 'critical'),
    (re.compile(r'DonPAPI', re.I), 'DonPAPI credential tool', 'T1555', 'critical'),
    (re.compile(r'LaZagne', re.I), 'LaZagne password recovery', 'T1555', 'critical'),
    (re.compile(r'vaultcmd\s+/list', re.I), 'Vault credential listing', 'T1555.004', 'medium'),
    (re.compile(r'netsh\s+wlan\s+show\s+profiles?.*key=clear', re.I),
     'WiFi password extraction', 'T1555.005', 'high'),
]


@dataclass
class DPAPIAlert:
    """DPAPI theft alert."""
    timestamp: str
    category: str
    target: str
    details: str
    severity: str
    mitre_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'target': self.target,
            'details': self.details,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
        }


class DPAPIMonitor:
    """
    Monitor for DPAPI credential theft attempts.
    Watches master key directories, browser credential stores,
    and process command lines for DPAPI abuse tools.
    """

    def __init__(
        self,
        check_interval: float = 30.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._file_baselines: Dict[str, float] = {}
        self._alerts: List[DPAPIAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_files()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='dpapi-monitor',
                daemon=True,
            )
            self._thread.start()
            _log.info('DPAPI monitor started (%d files baselined)',
                       len(self._file_baselines))
            return True
        except Exception as exc:
            _log.warning('DPAPI monitor failed: %s', exc)
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
            'monitored_files': len(self._file_baselines),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def scan_command_line(self, process_name: str, command_line: str) -> Optional[DPAPIAlert]:
        """Scan for DPAPI attack command patterns."""
        now = datetime.now(timezone.utc).isoformat()
        for pattern, desc, mitre, severity in DPAPI_ATTACK_PATTERNS:
            if pattern.search(command_line):
                alert = DPAPIAlert(
                    timestamp=now,
                    category='dpapi_attack',
                    target=desc,
                    details=f'DPAPI attack: {desc} via {process_name}',
                    severity=severity,
                    mitre_id=mitre,
                )
                self._add_alert(alert)
                return alert
        return None

    def _baseline_files(self) -> None:
        """Record modification times for monitored credential files."""
        for name, path in BROWSER_CREDENTIAL_PATHS.items():
            if os.path.exists(path) and os.path.isfile(path):
                try:
                    self._file_baselines[path] = os.path.getmtime(path)
                except OSError:
                    pass

        for vault_dir in CREDENTIAL_VAULT_PATHS:
            if os.path.exists(vault_dir):
                try:
                    for entry in os.scandir(vault_dir):
                        if entry.is_file():
                            self._file_baselines[entry.path] = entry.stat().st_mtime
                except OSError:
                    pass

        for mk_dir in DPAPI_MASTER_KEY_PATHS:
            if os.path.exists(mk_dir):
                try:
                    for root, dirs, files in os.walk(mk_dir):
                        for f in files:
                            fp = os.path.join(root, f)
                            try:
                                self._file_baselines[fp] = os.path.getmtime(fp)
                            except OSError:
                                pass
                except OSError:
                    pass

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_file_access()
                self._scan_processes()
                self._check_count += 1
            except Exception as exc:
                _log.debug('DPAPI check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_file_access(self) -> None:
        """Detect unexpected access to credential files."""
        now = datetime.now(timezone.utc).isoformat()

        for name, path in BROWSER_CREDENTIAL_PATHS.items():
            if not os.path.exists(path) or not os.path.isfile(path):
                continue
            try:
                mtime = os.path.getmtime(path)
                baseline = self._file_baselines.get(path)
                if baseline and mtime > baseline + 1.0:
                    self._add_alert(DPAPIAlert(
                        timestamp=now,
                        category='credential_access',
                        target=name,
                        details=f'Browser credential file accessed: {name}',
                        severity='high',
                        mitre_id='T1555.003',
                    ))
                    self._file_baselines[path] = mtime
            except OSError:
                pass

        for mk_dir in DPAPI_MASTER_KEY_PATHS:
            if not os.path.exists(mk_dir):
                continue
            try:
                for root, dirs, files in os.walk(mk_dir):
                    for f in files:
                        fp = os.path.join(root, f)
                        try:
                            mtime = os.path.getmtime(fp)
                            baseline = self._file_baselines.get(fp)
                            if baseline and mtime > baseline + 1.0:
                                self._add_alert(DPAPIAlert(
                                    timestamp=now,
                                    category='master_key_access',
                                    target=fp,
                                    details=f'DPAPI master key file accessed: {f}',
                                    severity='critical',
                                    mitre_id='T1555.004',
                                ))
                                self._file_baselines[fp] = mtime
                        except OSError:
                            pass
            except OSError:
                pass

    def _scan_processes(self) -> None:
        """Scan running processes for DPAPI attack tools."""
        try:
            result = subprocess.run(
                ['wmic', 'process', 'get', 'name,commandline', '/format:csv'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith('Node,'):
                    continue
                parts = line.split(',', 2)
                if len(parts) >= 3:
                    self.scan_command_line(parts[2], parts[1])
        except Exception:
            pass

    def _add_alert(self, alert: DPAPIAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('DPAPI: %s — %s', alert.target, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[DPAPIMonitor] = None


def get_dpapi_monitor() -> DPAPIMonitor:
    global _monitor
    if _monitor is None:
        _monitor = DPAPIMonitor()
    return _monitor


def start_dpapi_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = DPAPIMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'DPAPIMonitor', 'DPAPIAlert',
    'get_dpapi_monitor', 'start_dpapi_monitoring',
    'DPAPI_ATTACK_PATTERNS', 'BROWSER_CREDENTIAL_PATHS',
]
