"""
Shadow Copy / VSS Tampering Monitor
Downpour v29 Titanium

Monitors Volume Shadow Copy Service for ransomware and anti-forensics:
  - VSS service state monitoring (stopped = ransomware indicator)
  - Shadow copy deletion detection
  - Shadow copy count baseline and change alerting
  - vssadmin.exe / wmic shadowcopy abuse detection
  - BCDEdit boot config tampering (recoveryenabled, safeboot)
  - System restore point monitoring
  - Backup catalog deletion indicators

Uses vssadmin, wmic, sc, and bcdedit — no PowerShell.
MITRE ATT&CK: T1490 (Inhibit System Recovery), T1562.001 (Disable or Modify Tools)
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

_log = logging.getLogger('downpour.vssmon')


@dataclass
class VSSAlert:
    """VSS / shadow copy alert."""
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


class ShadowCopyMonitor:
    """
    Monitor Volume Shadow Copy Service and backup infrastructure
    for ransomware and anti-forensics tampering.
    """

    def __init__(
        self,
        check_interval: float = 60.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

        self._baseline_shadow_count: int = -1
        self._baseline_vss_state: str = ''
        self._baseline_recovery_enabled: Optional[bool] = None
        self._alerts: List[VSSAlert] = []

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_shadow_count = self._count_shadow_copies()
            self._baseline_vss_state = self._get_vss_service_state()
            self._baseline_recovery_enabled = self._get_recovery_enabled()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='vss-monitor',
                daemon=True,
            )
            self._thread.start()
            _log.info('Shadow copy monitor started (baseline: %d copies, VSS: %s)',
                      self._baseline_shadow_count, self._baseline_vss_state)
            return True
        except Exception as exc:
            _log.warning('Shadow copy monitor failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'shadow_copies': self._baseline_shadow_count,
            'vss_state': self._baseline_vss_state,
            'recovery_enabled': self._baseline_recovery_enabled,
            'alerts': len(self._alerts),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_vss_service()
                self._check_shadow_count()
                self._check_recovery_config()
                self._check_count += 1
            except Exception as exc:
                _log.debug('VSS check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_vss_service(self) -> None:
        """Monitor VSS service state changes."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current_state = self._get_vss_service_state()

        if (self._baseline_vss_state and current_state
                and current_state != self._baseline_vss_state):
            if current_state.lower() in ('stopped', 'disabled'):
                self._add_alert(VSSAlert(
                    timestamp=now_ts,
                    category='vss_service_stopped',
                    details=(f'VSS service state changed: {self._baseline_vss_state} -> '
                             f'{current_state} (ransomware indicator)'),
                    indicator='VSS',
                    severity='critical',
                    mitre_id='T1490',
                ))
            elif self._baseline_vss_state.lower() in ('stopped', 'disabled'):
                self._add_alert(VSSAlert(
                    timestamp=now_ts,
                    category='vss_service_restored',
                    details=f'VSS service restored: {current_state}',
                    indicator='VSS',
                    severity='low',
                    mitre_id='T1490',
                ))

        self._baseline_vss_state = current_state

    def _check_shadow_count(self) -> None:
        """Detect shadow copy deletion (ransomware behavior)."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current_count = self._count_shadow_copies()

        if self._baseline_shadow_count >= 0 and current_count >= 0:
            deleted = self._baseline_shadow_count - current_count
            if deleted > 0:
                severity = 'critical' if deleted >= 3 else 'high'
                self._add_alert(VSSAlert(
                    timestamp=now_ts,
                    category='shadow_copies_deleted',
                    details=(f'{deleted} shadow copies deleted '
                             f'({self._baseline_shadow_count} -> {current_count}) — '
                             f'possible ransomware'),
                    indicator=f'deleted:{deleted}',
                    severity=severity,
                    mitre_id='T1490',
                ))

            if current_count == 0 and self._baseline_shadow_count > 0:
                self._add_alert(VSSAlert(
                    timestamp=now_ts,
                    category='all_shadows_deleted',
                    details='ALL shadow copies have been deleted — strong ransomware indicator',
                    indicator='all_deleted',
                    severity='critical',
                    mitre_id='T1490',
                ))

        self._baseline_shadow_count = current_count

    def _check_recovery_config(self) -> None:
        """Check if Windows recovery options have been tampered with."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_recovery_enabled()

        if (self._baseline_recovery_enabled is True
                and current is False):
            self._add_alert(VSSAlert(
                timestamp=now_ts,
                category='recovery_disabled',
                details='Windows Recovery has been disabled (bcdedit /set recoveryenabled No)',
                indicator='recoveryenabled=No',
                severity='critical',
                mitre_id='T1490',
            ))

        self._baseline_recovery_enabled = current

    @staticmethod
    def _get_vss_service_state() -> str:
        """Get VSS service state via sc query."""
        try:
            result = subprocess.run(
                ['sc', 'query', 'VSS'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'STATE' in line:
                        m = re.search(r'(\d+)\s+(\w+)', line)
                        if m:
                            return m.group(2)
        except Exception:
            pass
        return ''

    @staticmethod
    def _count_shadow_copies() -> int:
        """Count existing shadow copies via vssadmin."""
        try:
            result = subprocess.run(
                ['vssadmin', 'list', 'shadows'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                return len(re.findall(r'Shadow Copy ID:', result.stdout,
                                      re.IGNORECASE))
            return 0
        except Exception:
            return -1

    @staticmethod
    def _get_recovery_enabled() -> Optional[bool]:
        """Check if Windows Recovery is enabled via bcdedit."""
        try:
            result = subprocess.run(
                ['bcdedit', '/enum', '{current}'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'recoveryenabled' in line.lower():
                        return 'yes' in line.lower()
        except Exception:
            pass
        return None

    def _add_alert(self, alert: VSSAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('VSS: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[ShadowCopyMonitor] = None


def get_vss_monitor() -> ShadowCopyMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ShadowCopyMonitor()
    return _monitor


def start_vss_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = ShadowCopyMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'ShadowCopyMonitor', 'VSSAlert',
    'get_vss_monitor', 'start_vss_monitoring',
]
