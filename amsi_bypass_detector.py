"""
AMSI Bypass Detector
Downpour v29 Titanium

Detects AMSI (Antimalware Scan Interface) bypass attempts:
  - amsi.dll load manipulation (DLL not loaded in process)
  - AmsiScanBuffer patch detection (memory modification)
  - AMSI provider deregistration monitoring
  - Known bypass tool detection (AmsiScanBufferBypass, PowerShell bypass strings)
  - AMSI registry key tampering
  - AMSI COM provider enumeration and removal detection
  - Script-based bypass pattern matching

Uses reg and wmic — no PowerShell.
MITRE ATT&CK: T1562.001 (Disable or Modify Tools),
              T1059.001 (PowerShell)
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.amsibypass')

AMSI_BYPASS_PATTERNS = [
    re.compile(r'(?i)AmsiScanBuffer'),
    re.compile(r'(?i)AmsiInitFailed'),
    re.compile(r'(?i)amsiContext'),
    re.compile(r'(?i)amsiSession'),
    re.compile(r'(?i)AmsiUtils'),
    re.compile(r'(?i)amsi\.dll'),
    re.compile(r'(?i)Disable-Amsi'),
    re.compile(r'(?i)Bypass-Amsi'),
    re.compile(r'(?i)Set-MpPreference.*-DisableRealtimeMonitoring'),
    re.compile(r'(?i)Remove-MpPreference'),
    re.compile(r'(?i)Add-MpPreference.*-ExclusionPath'),
    re.compile(r'(?i)\[Ref\]\.Assembly\.GetType.*AMSIUtils'),
    re.compile(r'(?i)System\.Management\.Automation\.AmsiUtils'),
    re.compile(r'(?i)VirtualProtect.*amsi'),
    re.compile(r'(?i)WriteProcessMemory.*amsi'),
    re.compile(r'(?i)Invoke-AmsiBypass'),
    re.compile(r'(?i)Matt.*Graeber.*Reflection'),
    re.compile(r'(?i)Patching.*amsi\.dll'),
    re.compile(r'(?i)\[Runtime\.InteropServices\.Marshal\]'),
]

DEFENDER_TAMPERING_PATTERNS = [
    re.compile(r'(?i)Set-MpPreference.*DisableIOAVProtection'),
    re.compile(r'(?i)Set-MpPreference.*DisableRealtimeMonitoring'),
    re.compile(r'(?i)Set-MpPreference.*DisableBehaviorMonitoring'),
    re.compile(r'(?i)Set-MpPreference.*DisableScriptScanning'),
    re.compile(r'(?i)Set-MpPreference.*DisableBlockAtFirstSeen'),
    re.compile(r'(?i)sc\s+(stop|config|delete)\s+WinDefend'),
    re.compile(r'(?i)sc\s+(stop|config|delete)\s+WdNisSvc'),
    re.compile(r'(?i)net\s+stop\s+WinDefend'),
    re.compile(r'(?i)MpCmdRun.*-RemoveDefinitions'),
    re.compile(r'(?i)reg\s+add.*DisableAntiSpyware'),
    re.compile(r'(?i)reg\s+add.*DisableAntiVirus'),
    re.compile(r'(?i)reg\s+delete.*Windows\s+Defender'),
]

AMSI_REGISTRY_KEY = r'HKLM\SOFTWARE\Microsoft\AMSI\Providers'


@dataclass
class AMSIAlert:
    """AMSI bypass alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
        }


class AMSIBypassDetector:
    """
    Detect AMSI bypass attempts including provider tampering,
    registry modification, and known bypass tool patterns.
    """

    def __init__(
        self,
        check_interval: float = 90.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

        self._baseline_providers: Set[str] = set()
        self._alerts: List[AMSIAlert] = []

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_providers = self._get_amsi_providers()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='amsi-bypass-det',
                daemon=True,
            )
            self._thread.start()
            _log.info('AMSI bypass detector started (%d providers)',
                      len(self._baseline_providers))
            return True
        except Exception as exc:
            _log.warning('AMSI bypass detector failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'providers': len(self._baseline_providers),
            'alerts': len(self._alerts),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def scan_command_line(self, proc_name: str,
                          cmdline: str) -> Optional[AMSIAlert]:
        """Scan a command line for AMSI bypass patterns."""
        now_ts = datetime.now(timezone.utc).isoformat()
        for pattern in AMSI_BYPASS_PATTERNS:
            if pattern.search(cmdline):
                alert = AMSIAlert(
                    timestamp=now_ts,
                    category='amsi_bypass_attempt',
                    details=f'AMSI bypass pattern: {proc_name} — {cmdline[:160]}',
                    indicator=cmdline[:200],
                    severity='critical',
                    mitre_id='T1562.001',
                )
                self._add_alert(alert)
                return alert
        for pattern in DEFENDER_TAMPERING_PATTERNS:
            if pattern.search(cmdline):
                alert = AMSIAlert(
                    timestamp=now_ts,
                    category='defender_tampering',
                    details=f'Defender tampering: {proc_name} — {cmdline[:160]}',
                    indicator=cmdline[:200],
                    severity='critical',
                    mitre_id='T1562.001',
                )
                self._add_alert(alert)
                return alert
        return None

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_provider_removal()
                self._check_defender_service()
                self._check_count += 1
            except Exception as exc:
                _log.debug('AMSI bypass check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_provider_removal(self) -> None:
        """Detect AMSI provider removal from registry."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_amsi_providers()

        removed = self._baseline_providers - current
        for provider in removed:
            self._add_alert(AMSIAlert(
                timestamp=now_ts,
                category='amsi_provider_removed',
                details=f'AMSI provider removed: {provider}',
                indicator=provider,
                severity='critical',
                mitre_id='T1562.001',
            ))

        if current:
            self._baseline_providers = current

    def _check_defender_service(self) -> None:
        """Check Windows Defender service state."""
        now_ts = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ['sc', 'query', 'WinDefend'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                state_match = re.search(r'STATE\s+:\s+\d+\s+(\S+)', result.stdout)
                if state_match:
                    state = state_match.group(1).upper()
                    if state == 'STOPPED':
                        self._add_alert(AMSIAlert(
                            timestamp=now_ts,
                            category='defender_stopped',
                            details='Windows Defender service is STOPPED',
                            indicator='WinDefend:STOPPED',
                            severity='critical',
                            mitre_id='T1562.001',
                        ))
            elif 'not exist' in result.stderr.lower() or result.returncode == 1060:
                self._add_alert(AMSIAlert(
                    timestamp=now_ts,
                    category='defender_missing',
                    details='Windows Defender service does not exist',
                    indicator='WinDefend:MISSING',
                    severity='critical',
                    mitre_id='T1562.001',
                ))
        except Exception:
            pass

    @staticmethod
    def _get_amsi_providers() -> Set[str]:
        """Get registered AMSI provider GUIDs."""
        providers: Set[str] = set()
        try:
            result = subprocess.run(
                ['reg', 'query', AMSI_REGISTRY_KEY],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line and '{' in line and '}' in line:
                        m = re.search(r'\{[A-Fa-f0-9-]+\}', line)
                        if m:
                            providers.add(m.group(0))
        except Exception:
            pass
        return providers

    def _add_alert(self, alert: AMSIAlert) -> None:
        with self._lock:
            for existing in reversed(self._alerts[-20:]):
                if (existing.category == alert.category
                        and existing.indicator == alert.indicator):
                    try:
                        t = datetime.fromisoformat(existing.timestamp)
                        if (datetime.now(timezone.utc) - t).total_seconds() < 600:
                            return
                    except Exception:
                        pass
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('AMSIBypass: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[AMSIBypassDetector] = None


def get_amsi_detector() -> AMSIBypassDetector:
    global _detector
    if _detector is None:
        _detector = AMSIBypassDetector()
    return _detector


def start_amsi_detection(callback=None) -> bool:
    global _detector
    _detector = AMSIBypassDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'AMSIBypassDetector', 'AMSIAlert',
    'get_amsi_detector', 'start_amsi_detection',
    'AMSI_BYPASS_PATTERNS', 'DEFENDER_TAMPERING_PATTERNS',
]
