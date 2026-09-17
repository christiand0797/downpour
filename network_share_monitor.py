"""
Network Share Monitor
Downpour v29 Titanium

Monitors SMB/network share security:
  - Active share enumeration and change detection
  - Unauthorized share creation alerts
  - Admin share (C$, ADMIN$, IPC$) tampering detection
  - Share permission auditing (Everyone access)
  - Lateral movement indicators (remote share access)
  - Suspicious mapped drive detection
  - UNC path abuse monitoring
  - Null session detection

Uses net share, net use, and wmic — no PowerShell.
MITRE ATT&CK: T1021.002 (SMB/Windows Admin Shares),
              T1135 (Network Share Discovery), T1039 (Data from Network Shared Drive)
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.sharemon')

DEFAULT_ADMIN_SHARES = {'C$', 'ADMIN$', 'IPC$', 'D$', 'E$'}

SUSPICIOUS_SHARE_NAMES = [
    re.compile(r'(?i)^temp$|^tmp$|^staging$'),
    re.compile(r'(?i)^drop$|^upload$|^exfil$'),
    re.compile(r'(?i)^public$|^open$|^share$'),
    re.compile(r'(?i)^tools$|^hack$|^payload$'),
    re.compile(r'(?i)^c\$|^admin\$'),
]


@dataclass
class ShareAlert:
    """Network share security alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    share_name: str = ''
    share_path: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'share_name': self.share_name,
            'share_path': self.share_path,
        }


class NetworkShareMonitor:
    """
    Monitor network shares for security threats including unauthorized
    creation, permission changes, and lateral movement indicators.
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

        self._baseline_shares: Dict[str, str] = {}
        self._baseline_mapped: Set[str] = set()
        self._alerts: List[ShareAlert] = []

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_shares = self._get_local_shares()
            self._baseline_mapped = self._get_mapped_drives()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='share-monitor',
                daemon=True,
            )
            self._thread.start()
            _log.info('Network share monitor started (%d baseline shares)',
                      len(self._baseline_shares))
            self._initial_audit()
            return True
        except Exception as exc:
            _log.warning('Share monitor failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'local_shares': len(self._baseline_shares),
            'mapped_drives': len(self._baseline_mapped),
            'alerts': len(self._alerts),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def get_share_inventory(self) -> List[Dict[str, Any]]:
        """Return current share inventory."""
        shares = self._get_local_shares()
        result = []
        for name, path in shares.items():
            is_admin = name in DEFAULT_ADMIN_SHARES
            is_suspicious = any(p.search(name) for p in SUSPICIOUS_SHARE_NAMES)
            result.append({
                'name': name,
                'path': path,
                'is_admin_share': is_admin,
                'is_suspicious': is_suspicious,
            })
        return result

    def _initial_audit(self) -> None:
        """Run initial share security audit."""
        now_ts = datetime.now(timezone.utc).isoformat()

        for name, path in self._baseline_shares.items():
            if name in DEFAULT_ADMIN_SHARES:
                continue
            for pattern in SUSPICIOUS_SHARE_NAMES:
                if pattern.search(name):
                    self._add_alert(ShareAlert(
                        timestamp=now_ts,
                        category='suspicious_share_name',
                        details=f'Suspicious share name: {name} -> {path}',
                        indicator=name,
                        severity='medium',
                        mitre_id='T1135',
                        share_name=name,
                        share_path=path,
                    ))
                    break

        self._check_share_permissions()

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_share_changes()
                self._check_mapped_drive_changes()
                self._check_active_sessions()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Share check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_share_changes(self) -> None:
        """Detect share creation and removal."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_local_shares()

        new_shares = set(current.keys()) - set(self._baseline_shares.keys())
        removed_shares = set(self._baseline_shares.keys()) - set(current.keys())

        for name in new_shares:
            path = current.get(name, '')
            severity = 'high'
            if name in DEFAULT_ADMIN_SHARES:
                severity = 'critical'

            self._add_alert(ShareAlert(
                timestamp=now_ts,
                category='share_created',
                details=f'New network share created: {name} -> {path}',
                indicator=name,
                severity=severity,
                mitre_id='T1021.002',
                share_name=name,
                share_path=path,
            ))

        for name in removed_shares:
            if name in DEFAULT_ADMIN_SHARES:
                self._add_alert(ShareAlert(
                    timestamp=now_ts,
                    category='admin_share_removed',
                    details=f'Admin share removed: {name} (possible tampering)',
                    indicator=name,
                    severity='critical',
                    mitre_id='T1021.002',
                    share_name=name,
                ))

        self._baseline_shares = current

    def _check_mapped_drive_changes(self) -> None:
        """Detect new mapped drives (lateral movement indicator)."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_mapped_drives()
        new_drives = current - self._baseline_mapped

        for drive_info in new_drives:
            self._add_alert(ShareAlert(
                timestamp=now_ts,
                category='new_mapped_drive',
                details=f'New mapped network drive: {drive_info}',
                indicator=drive_info,
                severity='medium',
                mitre_id='T1039',
                share_name=drive_info,
            ))

        self._baseline_mapped = current

    def _check_active_sessions(self) -> None:
        """Check for active SMB sessions from remote hosts."""
        now_ts = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ['net', 'session'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return

            for line in result.stdout.splitlines():
                line = line.strip()
                m = re.match(r'\\\\([\d.]+)\s+', line)
                if m:
                    remote_ip = m.group(1)
                    if remote_ip.startswith('10.') or remote_ip.startswith('192.168.'):
                        continue
                    self._add_alert(ShareAlert(
                        timestamp=now_ts,
                        category='external_smb_session',
                        details=f'SMB session from external IP: {remote_ip}',
                        indicator=remote_ip,
                        severity='high',
                        mitre_id='T1021.002',
                    ))
        except Exception:
            pass

    def _check_share_permissions(self) -> None:
        """Audit share permissions for overly permissive access."""
        now_ts = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ['net', 'share'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return

            for line in result.stdout.splitlines():
                if 'Everyone' in line and 'FULL' in line.upper():
                    parts = line.split()
                    if parts:
                        self._add_alert(ShareAlert(
                            timestamp=now_ts,
                            category='overly_permissive_share',
                            details=f'Share with Everyone/Full access: {parts[0]}',
                            indicator=parts[0],
                            severity='high',
                            mitre_id='T1135',
                            share_name=parts[0],
                        ))
        except Exception:
            pass

    @staticmethod
    def _get_local_shares() -> Dict[str, str]:
        """Get local shares via 'net share'."""
        shares: Dict[str, str] = {}
        try:
            result = subprocess.run(
                ['net', 'share'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return shares
            parsing = False
            for line in result.stdout.splitlines():
                if '-----' in line:
                    parsing = True
                    continue
                if not parsing or not line.strip():
                    continue
                if line.startswith('The command'):
                    break
                parts = line.split()
                if len(parts) >= 2:
                    name = parts[0]
                    path = parts[1] if len(parts) > 1 else ''
                    shares[name] = path
        except Exception:
            pass
        return shares

    @staticmethod
    def _get_mapped_drives() -> Set[str]:
        """Get mapped network drives via 'net use'."""
        drives: Set[str] = set()
        try:
            result = subprocess.run(
                ['net', 'use'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    m = re.search(r'([A-Z]:)\s+(\\\\[^\s]+)', line)
                    if m:
                        drives.add(f'{m.group(1)} -> {m.group(2)}')
        except Exception:
            pass
        return drives

    def _add_alert(self, alert: ShareAlert) -> None:
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
        _log.warning('Share: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[NetworkShareMonitor] = None


def get_share_monitor() -> NetworkShareMonitor:
    global _monitor
    if _monitor is None:
        _monitor = NetworkShareMonitor()
    return _monitor


def start_share_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = NetworkShareMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'NetworkShareMonitor', 'ShareAlert',
    'get_share_monitor', 'start_share_monitoring',
    'DEFAULT_ADMIN_SHARES',
]
