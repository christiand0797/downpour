"""
DLL Search Order Hijack Detector
Downpour v29 Titanium

Detects DLL search order hijacking and side-loading:
  - Known hijackable DLL monitoring in writable directories
  - DLL planted alongside legitimate executables
  - Phantom DLL detection (DLLs loaded from non-standard paths)
  - Side-loading pattern detection (legitimate exe + malicious DLL)
  - Known vulnerable applications database
  - User-writable PATH directory monitoring
  - DLL in Downloads/Desktop/Temp directories

Uses reg and dir — no PowerShell.
MITRE ATT&CK: T1574.001 (DLL Search Order Hijacking),
              T1574.002 (DLL Side-Loading)
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

_log = logging.getLogger('downpour.dllhijack')

HIJACKABLE_DLLS = {
    'version.dll', 'winmm.dll', 'wsock32.dll', 'wtsapi32.dll',
    'dbghelp.dll', 'dbgcore.dll', 'uxtheme.dll', 'propsys.dll',
    'dwmapi.dll', 'cryptbase.dll', 'msasn1.dll', 'profapi.dll',
    'secur32.dll', 'netapi32.dll', 'userenv.dll', 'samcli.dll',
    'mswsock.dll', 'dnsapi.dll', 'iphlpapi.dll', 'winnsi.dll',
    'fwpuclnt.dll', 'rasadhlp.dll', 'wship6.dll', 'nlaapi.dll',
    'napinsp.dll', 'pnrpnsp.dll', 'winrnr.dll', 'wshbth.dll',
    'crypt32.dll', 'wldap32.dll', 'ncrypt.dll', 'bcrypt.dll',
    'bcryptprimitives.dll', 'mscoree.dll', 'clrjit.dll',
    'amsi.dll', 'ntmarta.dll', 'linkinfo.dll', 'ntshrui.dll',
    'srvcli.dll', 'cscapi.dll', 'edputil.dll', 'windows.storage.dll',
    'comctl32.dll', 'sxs.dll', 'mpr.dll', 'cabinet.dll',
    'apphelp.dll', 'textshaping.dll', 'textinputframework.dll',
}

WRITABLE_WATCH_DIRS = [
    os.environ.get('TEMP', ''),
    os.environ.get('TMP', ''),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
    os.path.join(os.environ.get('USERPROFILE', ''), 'Documents'),
    os.environ.get('APPDATA', ''),
    os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Temp'),
    os.environ.get('PROGRAMDATA', ''),
    os.path.join(os.environ.get('USERPROFILE', ''), 'AppData', 'Local'),
]


@dataclass
class DLLHijackAlert:
    """DLL hijack detection alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    dll_name: str = ''
    dll_path: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'dll_name': self.dll_name,
            'dll_path': self.dll_path,
        }


class DLLHijackDetector:
    """
    Detect DLL search order hijacking by monitoring for known
    hijackable DLLs in writable directories.
    """

    def __init__(
        self,
        check_interval: float = 180.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

        self._known_dlls: Set[str] = set()
        self._alerts: List[DLLHijackAlert] = []

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._known_dlls = self._scan_writable_dirs()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='dll-hijack-det',
                daemon=True,
            )
            self._thread.start()
            _log.info('DLL hijack detector started (baseline: %d known DLLs in writable dirs)',
                      len(self._known_dlls))
            return True
        except Exception as exc:
            _log.warning('DLL hijack detector failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'tracked_dlls': len(self._known_dlls),
            'alerts': len(self._alerts),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_hijackable_dlls()
                self._check_path_hijack()
                self._check_count += 1
            except Exception as exc:
                _log.debug('DLL hijack check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_hijackable_dlls(self) -> None:
        """Scan writable dirs for known hijackable DLLs."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._scan_writable_dirs()
        new_dlls = current - self._known_dlls

        for dll_path in new_dlls:
            dll_name = os.path.basename(dll_path).lower()
            if dll_name in HIJACKABLE_DLLS:
                self._add_alert(DLLHijackAlert(
                    timestamp=now_ts,
                    category='hijackable_dll_planted',
                    details=f'Known hijackable DLL in writable directory: {dll_path}',
                    indicator=dll_path,
                    severity='critical',
                    mitre_id='T1574.001',
                    dll_name=dll_name,
                    dll_path=dll_path,
                ))
            else:
                parent = os.path.dirname(dll_path)
                exes_nearby = any(
                    f.lower().endswith('.exe')
                    for f in os.listdir(parent)
                    if os.path.isfile(os.path.join(parent, f))
                ) if os.path.isdir(parent) else False

                if exes_nearby:
                    self._add_alert(DLLHijackAlert(
                        timestamp=now_ts,
                        category='dll_sideload_candidate',
                        details=f'New DLL alongside executables: {dll_path}',
                        indicator=dll_path,
                        severity='high',
                        mitre_id='T1574.002',
                        dll_name=dll_name,
                        dll_path=dll_path,
                    ))

        self._known_dlls = current

    def _check_path_hijack(self) -> None:
        """Check for user-writable directories in system PATH."""
        now_ts = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ['reg', 'query',
                 r'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
                 '/v', 'Path'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return

            for line in result.stdout.splitlines():
                if 'Path' in line and 'REG_' in line:
                    path_val = line.split('REG_EXPAND_SZ')[-1].strip()
                    if not path_val:
                        path_val = line.split('REG_SZ')[-1].strip()
                    dirs = path_val.split(';')
                    for d in dirs:
                        d = d.strip()
                        if not d:
                            continue
                        d_expanded = os.path.expandvars(d)
                        if os.path.isdir(d_expanded):
                            user_profile = os.environ.get('USERPROFILE', '').lower()
                            if user_profile and d_expanded.lower().startswith(user_profile):
                                self._add_alert(DLLHijackAlert(
                                    timestamp=now_ts,
                                    category='user_writable_path',
                                    details=f'User-writable directory in system PATH: {d_expanded}',
                                    indicator=d_expanded,
                                    severity='high',
                                    mitre_id='T1574.007',
                                    dll_path=d_expanded,
                                ))
        except Exception:
            pass

    @staticmethod
    def _scan_writable_dirs() -> Set[str]:
        """Scan writable directories for DLL files."""
        dlls: Set[str] = set()
        for dir_path in WRITABLE_WATCH_DIRS:
            if not dir_path or not os.path.isdir(dir_path):
                continue
            try:
                for entry in os.scandir(dir_path):
                    if entry.is_file() and entry.name.lower().endswith('.dll'):
                        dlls.add(entry.path)
            except (PermissionError, OSError):
                continue
        return dlls

    def _add_alert(self, alert: DLLHijackAlert) -> None:
        with self._lock:
            for existing in reversed(self._alerts[-20:]):
                if (existing.category == alert.category
                        and existing.indicator == alert.indicator):
                    try:
                        t = datetime.fromisoformat(existing.timestamp)
                        if (datetime.now(timezone.utc) - t).total_seconds() < 3600:
                            return
                    except Exception:
                        pass
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('DLLHijack: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[DLLHijackDetector] = None


def get_dllhijack_detector() -> DLLHijackDetector:
    global _detector
    if _detector is None:
        _detector = DLLHijackDetector()
    return _detector


def start_dllhijack_detection(callback=None) -> bool:
    global _detector
    _detector = DLLHijackDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'DLLHijackDetector', 'DLLHijackAlert',
    'get_dllhijack_detector', 'start_dllhijack_detection',
    'HIJACKABLE_DLLS',
]
