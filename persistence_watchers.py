"""
PERSISTENCE WATCHERS — v29.44d (closes audit blind spots #4, #6, #9)
================================================================================
  1. RegistryPersistenceWatcher — Run/RunOnce/Winlogon auto-start keys,
     baseline + diff (T1060/T1547.001). Baselines persist to
     downpour_data, so a Run key written while Downpour is OFF is
     flagged on the next start.
  2. DLLHijackDetector — writable PATH-order dirs + cwd scanned for
     planted DLLs shadowing known system DLL names (T1574.001/002).
  3. DriverMonitor — baseline + diff over System32\\drivers\\*.sys plus
     a notorious BYOVD name list (T1068).

Stdlib-only (winreg polling), TOFU-baselined, gracefully degrades when
keys/dirs are unreadable.
"""
from __future__ import annotations

import json
import logging
import os
import winreg
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
BASELINE_PATH = SCRIPT_DIR / 'downpour_data' / 'persistence_baseline.json'

# (hive_constant, hive_name, subkey) — auto-start locations attackers use
REGISTRY_KEYS_TO_WATCH: List[Tuple[int, str, str]] = [
    (winreg.HKEY_CURRENT_USER, 'HKCU',
     r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_CURRENT_USER, 'HKCU',
     r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_LOCAL_MACHINE, 'HKLM',
     r'Software\Microsoft\Windows\CurrentVersion\Run'),
    (winreg.HKEY_LOCAL_MACHINE, 'HKLM',
     r'Software\Microsoft\Windows\CurrentVersion\RunOnce'),
    (winreg.HKEY_LOCAL_MACHINE, 'HKLM',
     r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'),
]

# DLL names attackers plant to hijack app-dir / PATH loads (T1574)
HIJACKABLE_SYSTEM_DLLS = {
    'version.dll', 'winmm.dll', 'dbghelp.dll', 'shcore.dll', 'uxtheme.dll',
    'dwmapi.dll', 'propsys.dll', 'linkinfo.dll', 'ntlanman.dll',
    'msvcp140.dll', 'vcruntime140.dll', 'vcruntime140_1.dll',
    'iphlpapi.dll', 'winhttp.dll', 'secur32.dll', 'shell32.dll',
    'wlanapi.dll', 'cryptbase.dll', 'sfc_os.dll', 'profapi.dll',
}

# Notorious vulnerable drivers abused via BYOVD (T1068)
BYOVD_BLOCKLIST = {
    'gdrv.sys': 'Gigabyte GDRV (CVE-2018-19320)',
    'dbutil_2_3.sys': 'Dell DBUtil (CVE-2021-21551)',
    'rtcore64.sys': 'MSI Afterburner RTCore64',
    'iqvw64e.sys': 'Intel IQVW64E (CVE-2015-2291)',
    'kprocesshacker.sys': 'KProcessHacker',
    'ntiolib.sys': 'MSI NTIOLib',
    'msio64.sys': 'MSI MSIO64',
    'asrdrv.sys': 'ASRock ASRDRV (CVE-2019-16902)',
    'glckio2.sys': 'GIGABYTE GLCKIO2',
    'winio64.sys': 'WinIo64',
}


@dataclass
class PersistenceAlert:
    """One persistence-watch finding (mirrors event_log_monitor.EventAlert)."""
    source: str          # 'registry' | 'dll_hijack' | 'driver'
    technique: str       # MITRE ATT&CK id
    severity: str        # LOW/MEDIUM/HIGH/CRITICAL
    description: str
    detail: str


def _load_baseline() -> dict:
    try:
        with open(BASELINE_PATH, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def _save_baseline(baseline: dict) -> None:
    try:
        path = Path(BASELINE_PATH)  # tolerate str or Path overrides
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(baseline, f, indent=1)
    except Exception as exc:
        _log.debug('baseline save failed: %s', exc)


class RegistryPersistenceWatcher:
    """Baseline + diff over the classic auto-start registry keys."""

    def __init__(self) -> None:
        self._snapshot: Dict[str, Dict[str, str]] = {}

    def _read_key(self, hive: int, subkey: str) -> Dict[str, str]:
        values: Dict[str, str] = {}
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                idx = 0
                while True:
                    try:
                        name, data, _ = winreg.EnumValue(key, idx)
                    except OSError:
                        break
                    values[name] = str(data)[:300]
                    idx += 1
        except FileNotFoundError:
            pass
        except OSError as exc:
            _log.debug('reg read %s: %s', subkey, exc)
        return values

    def check(self) -> Tuple[List[PersistenceAlert], bool]:
        """One pass. Returns (alerts, first_run). First run = TOFU."""
        alerts: List[PersistenceAlert] = []
        current: Dict[str, Dict[str, str]] = {}
        for hive, hive_name, subkey in REGISTRY_KEYS_TO_WATCH:
            current[f'{hive_name}\\{subkey}'] = self._read_key(hive, subkey)
        first_run = not self._snapshot and not _load_baseline().get('registry')
        if not first_run:
            known = (self._snapshot
                     or _load_baseline().get('registry', {}))
            for key_path, values in current.items():
                old = known.get(key_path, {})
                for name, data in values.items():
                    if name not in old:
                        alerts.append(PersistenceAlert(
                            source='registry', technique='T1060',
                            severity='HIGH',
                            description='New auto-start registry value',
                            detail=f'{key_path}\\{name} = {data}'))
                    elif old[name] != data:
                        alerts.append(PersistenceAlert(
                            source='registry', technique='T1574.011',
                            severity='HIGH',
                            description='Auto-start registry value modified',
                            detail=f'{key_path}\\{name}: '
                                   f'{old[name][:100]} -> {data}'))
        baseline = _load_baseline()
        baseline['registry'] = current
        _save_baseline(baseline)
        self._snapshot = current
        return alerts, first_run


class DLLHijackDetector:
    """Finds planted DLLs shadowing system names in writable load paths."""

    def check(self) -> List[PersistenceAlert]:
        alerts: List[PersistenceAlert] = []
        seen_dirs: set = set()
        candidates: List[str] = [os.getcwd()]
        path_env = os.environ.get('PATH', '')
        candidates.extend(p for p in path_env.split(';') if p)
        sysroot = os.environ.get('SystemRoot', r'C:\Windows').lower()
        for directory in candidates:
            directory = os.path.expandvars(directory).strip('"')
            if (not directory or not os.path.isdir(directory)
                    or directory.lower() in seen_dirs):
                continue
            seen_dirs.add(directory.lower())
            if directory.lower().startswith(sysroot):
                continue  # legitimate Windows dirs
            try:
                if not os.access(directory, os.W_OK):
                    continue  # not plantable
                for entry in os.listdir(directory):
                    if entry.lower() in HIJACKABLE_SYSTEM_DLLS:
                        full = os.path.join(directory, entry)
                        alerts.append(PersistenceAlert(
                            source='dll_hijack', technique='T1574.001',
                            severity='HIGH',
                            description='DLL planting / hijack shadow',
                            detail=f'{full} shadows a known system DLL '
                                   f'in a writable PATH directory'))
            except OSError as exc:
                _log.debug('dll scan %s: %s', directory, exc)
        return alerts


class DriverMonitor:
    """Baseline + diff over System32\\drivers + BYOVD name blocklist."""

    def __init__(self) -> None:
        self._known: Optional[set] = None

    def _drivers_dir(self) -> str:
        return os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                            'System32', 'drivers')

    def check(self) -> List[PersistenceAlert]:
        alerts: List[PersistenceAlert] = []
        ddir = self._drivers_dir()
        try:
            current = {e.lower() for e in os.listdir(ddir)
                       if e.lower().endswith('.sys')}
        except OSError as exc:
            _log.debug('driver dir read: %s', exc)
            return alerts
        # BYOVD check runs every pass (cheap set lookup)
        for name in current:
            if name in BYOVD_BLOCKLIST:
                alerts.append(PersistenceAlert(
                    source='driver', technique='T1068', severity='CRITICAL',
                    description='Known-vulnerable driver present (BYOVD)',
                    detail=f'{name}: {BYOVD_BLOCKLIST[name]}'))
        if self._known is None:
            persisted = _load_baseline().get('drivers', [])
            self._known = set(current) | set(persisted)
            baseline = _load_baseline()
            baseline['drivers'] = sorted(self._known)
            _save_baseline(baseline)
            return alerts
        new_drivers = current - self._known
        if new_drivers:
            for name in sorted(new_drivers):
                if name in BYOVD_BLOCKLIST:
                    continue  # already CRITICAL above
                alerts.append(PersistenceAlert(
                    source='driver', technique='T1068', severity='MEDIUM',
                    description='New kernel driver file appeared',
                    detail=f'{ddir}\\{name}'))
            self._known |= new_drivers
            baseline = _load_baseline()
            baseline['drivers'] = sorted(self._known)
            _save_baseline(baseline)
        return alerts


_registry_watcher: Optional[RegistryPersistenceWatcher] = None
_driver_monitor: Optional[DriverMonitor] = None
_dll_detector: Optional[DLLHijackDetector] = None


def run_all_persistence_checks() -> List[PersistenceAlert]:
    """One combined pass; registry TOFU on first run (no alert spam)."""
    global _registry_watcher, _driver_monitor, _dll_detector
    alerts: List[PersistenceAlert] = []
    if _registry_watcher is None:
        _registry_watcher = RegistryPersistenceWatcher()
    if _driver_monitor is None:
        _driver_monitor = DriverMonitor()
    if _dll_detector is None:
        _dll_detector = DLLHijackDetector()
    reg_alerts, first_run = _registry_watcher.check()
    if not first_run:
        alerts.extend(reg_alerts)
    alerts.extend(_driver_monitor.check())
    alerts.extend(_dll_detector.check())
    return alerts


__all__ = ['PersistenceAlert', 'RegistryPersistenceWatcher',
           'DLLHijackDetector', 'DriverMonitor',
           'run_all_persistence_checks', 'REGISTRY_KEYS_TO_WATCH',
           'HIJACKABLE_SYSTEM_DLLS', 'BYOVD_BLOCKLIST', 'BASELINE_PATH']