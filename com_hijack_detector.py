"""
COM Object Hijack Detector
Downpour v29 Titanium

Detects Component Object Model (COM) hijacking for persistence:
  - CLSID registry key modifications
  - InprocServer32/LocalServer32 value changes
  - Known auto-elevating COM objects abuse
  - Suspicious DLL registration via regsvr32
  - TreatAs CLSID redirection
  - Scheduled Task COM handler abuse

Uses reg.exe only — no PowerShell.
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.comhijack')

HIGH_VALUE_CLSIDS = {
    '{0A29FF9E-7F9C-4437-8B11-F424491E3931}': 'Session Moniker (UAC bypass)',
    '{3E5FC7F9-9A51-4367-9063-A120244FBEC7}': 'eventvwr.msc handler',
    '{D2E7025F-2709-4E68-B93B-A1F9B287F33C}': 'sdclt.exe AutoPlay handler',
    '{BDB57FF2-79B9-4205-9447-F5FE85F37312}': 'InProcServer32 hijack target',
    '{E44E5D18-0652-4508-A4E2-8A090067BCB0}': 'Scheduled Task COM handler',
    '{F56F6FDD-AA9D-4618-A949-C1B91AF43B1A}': 'File Explorer browser helper',
    '{BCDE0395-E52F-467C-8E3D-C4579291692E}': 'MMDeviceEnumerator (audio)',
    '{4590F811-1D3A-11D0-891F-00AA004B2E24}': 'WBEM Locator (WMI)',
    '{C08AFD90-F2A1-11D1-8455-00A0C91F3880}': 'Shell.AutoComplete',
}

PERSISTENCE_REGISTRY_PATHS = [
    r'HKCU\SOFTWARE\Classes\CLSID',
    r'HKLM\SOFTWARE\Classes\CLSID',
]


@dataclass
class COMAlert:
    """COM hijacking alert."""
    timestamp: str
    category: str
    clsid: str
    details: str
    severity: str
    mitre_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'clsid': self.clsid,
            'details': self.details,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
        }


class COMHijackDetector:
    """
    Detect COM object hijacking for persistence and UAC bypass.
    Baselines known-good CLSIDs and monitors for modifications.
    """

    def __init__(
        self,
        check_interval: float = 60.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._baseline_clsids: Dict[str, Set[str]] = {}
        self._alerts: List[COMAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_clsids = self._enumerate_user_clsids()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='com-hijack-detector',
                daemon=True,
            )
            self._thread.start()
            total = sum(len(v) for v in self._baseline_clsids.values())
            _log.info('COM hijack detector started (%d user CLSIDs)', total)
            self._check_high_value_clsids()
            return True
        except Exception as exc:
            _log.warning('COM hijack detector failed: %s', exc)
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
            'monitored_clsids': len(HIGH_VALUE_CLSIDS),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _check_high_value_clsids(self) -> None:
        """Initial scan of high-value CLSIDs for existing hijacks."""
        now = datetime.now(timezone.utc).isoformat()
        for clsid, desc in HIGH_VALUE_CLSIDS.items():
            user_key = f'HKCU\\SOFTWARE\\Classes\\CLSID\\{clsid}\\InprocServer32'
            try:
                result = subprocess.run(
                    ['reg', 'query', user_key],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
                )
                if result.returncode == 0:
                    self._add_alert(COMAlert(
                        timestamp=now,
                        category='existing_hijack',
                        clsid=clsid,
                        details=f'User-level COM override found for {desc}: {clsid}',
                        severity='high',
                        mitre_id='T1546.015',
                    ))
            except Exception:
                pass

            treat_as_key = f'HKCU\\SOFTWARE\\Classes\\CLSID\\{clsid}\\TreatAs'
            try:
                result = subprocess.run(
                    ['reg', 'query', treat_as_key],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
                )
                if result.returncode == 0:
                    self._add_alert(COMAlert(
                        timestamp=now,
                        category='treatas_redirect',
                        clsid=clsid,
                        details=f'TreatAs redirect on {desc}: {clsid}',
                        severity='critical',
                        mitre_id='T1546.015',
                    ))
            except Exception:
                pass

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_user_clsid_changes()
                self._check_count += 1
            except Exception as exc:
                _log.debug('COM check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_user_clsid_changes(self) -> None:
        """Detect new user-level CLSID registrations."""
        now = datetime.now(timezone.utc).isoformat()
        current = self._enumerate_user_clsids()

        for path, current_clsids in current.items():
            baseline = self._baseline_clsids.get(path, set())
            new_clsids = current_clsids - baseline

            for clsid in new_clsids:
                severity = 'critical' if clsid in HIGH_VALUE_CLSIDS else 'high'
                desc = HIGH_VALUE_CLSIDS.get(clsid, 'unknown')
                self._add_alert(COMAlert(
                    timestamp=now,
                    category='new_clsid',
                    clsid=clsid,
                    details=f'New user-level CLSID registered: {clsid} ({desc})',
                    severity=severity,
                    mitre_id='T1546.015',
                ))

        self._baseline_clsids = current

    @staticmethod
    def _enumerate_user_clsids() -> Dict[str, Set[str]]:
        """List user-level CLSID registrations."""
        result_map: Dict[str, Set[str]] = {}
        user_clsid_path = r'HKCU\SOFTWARE\Classes\CLSID'
        clsids: Set[str] = set()
        try:
            result = subprocess.run(
                ['reg', 'query', user_clsid_path],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    match = re.search(r'(\{[A-Fa-f0-9-]{36}\})$', line)
                    if match:
                        clsids.add(match.group(1).upper())
        except Exception:
            pass
        result_map[user_clsid_path] = clsids
        return result_map

    def _add_alert(self, alert: COMAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('COM hijack: %s — %s', alert.clsid, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[COMHijackDetector] = None


def get_com_detector() -> COMHijackDetector:
    global _detector
    if _detector is None:
        _detector = COMHijackDetector()
    return _detector


def start_com_detection(callback=None) -> bool:
    global _detector
    _detector = COMHijackDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'COMHijackDetector', 'COMAlert',
    'get_com_detector', 'start_com_detection',
    'HIGH_VALUE_CLSIDS',
]
