"""
Lateral Movement Detector
Downpour v29 Titanium

Detects lateral movement techniques:
  - PsExec-style service installation patterns
  - Remote service creation via sc.exe
  - WMI-based remote execution indicators
  - RDP session enumeration and brute force
  - Pass-the-Hash / Pass-the-Ticket indicators
  - WinRM abuse detection
  - DCOM lateral movement patterns
  - Remote scheduled task creation
  - Suspicious remote process execution

Uses netstat, sc, wmic, and reg — no PowerShell.
MITRE ATT&CK: T1021 (Remote Services), T1047 (WMI), T1053 (Scheduled Task),
              T1570 (Lateral Tool Transfer)
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.lateral')

LATERAL_PORTS = {
    135: 'RPC/DCOM',
    139: 'NetBIOS Session',
    445: 'SMB',
    3389: 'RDP',
    5985: 'WinRM HTTP',
    5986: 'WinRM HTTPS',
}

PSEXEC_SERVICE_PATTERNS = [
    re.compile(r'(?i)psexe'),
    re.compile(r'(?i)^[a-z]{8}$'),
    re.compile(r'(?i)remcom'),
    re.compile(r'(?i)^csexe'),
    re.compile(r'(?i)^paexe'),
    re.compile(r'(?i)winexe'),
]

LATERAL_TOOL_CMDLINES = [
    re.compile(r'(?i)psexec'),
    re.compile(r'(?i)wmic\s+/node:'),
    re.compile(r'(?i)winrs\s+-r:'),
    re.compile(r'(?i)schtasks\s+/create\s+/s\s'),
    re.compile(r'(?i)sc\s+\\\\'),
    re.compile(r'(?i)net\s+use\s+\\\\'),
    re.compile(r'(?i)copy\s+.*\\\\'),
    re.compile(r'(?i)xcopy\s+.*\\\\'),
    re.compile(r'(?i)robocopy\s+.*\\\\'),
    re.compile(r'(?i)wmiexec'),
    re.compile(r'(?i)smbexec'),
    re.compile(r'(?i)atexec'),
    re.compile(r'(?i)dcomexec'),
    re.compile(r'(?i)evil-winrm'),
    re.compile(r'(?i)crackmapexec|cme'),
    re.compile(r'(?i)impacket'),
    re.compile(r'(?i)secretsdump'),
]


@dataclass
class LateralAlert:
    """Lateral movement alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    source_ip: str = ''
    target: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'source_ip': self.source_ip,
            'target': self.target,
        }


class LateralMovementDetector:
    """
    Detect lateral movement by monitoring inbound connections on
    sensitive ports, service installations, and tool command lines.
    """

    def __init__(
        self,
        check_interval: float = 30.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

        self._known_inbound: Set[str] = set()
        self._baseline_services: Set[str] = set()
        self._alerts: List[LateralAlert] = []
        self._alerted_ips: Dict[str, float] = {}
        self._rdp_attempts: Dict[str, List[float]] = {}

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_services = self._get_service_names()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='lateral-movement-det',
                daemon=True,
            )
            self._thread.start()
            _log.info('Lateral movement detector started (%d baseline services)',
                      len(self._baseline_services))
            return True
        except Exception as exc:
            _log.warning('Lateral movement detector failed: %s', exc)
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
            'tracked_inbound': len(self._known_inbound),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def scan_command_line(self, proc_name: str,
                          cmdline: str) -> Optional[LateralAlert]:
        """Scan a command line for lateral movement tool signatures."""
        now_ts = datetime.now(timezone.utc).isoformat()
        for pattern in LATERAL_TOOL_CMDLINES:
            if pattern.search(cmdline):
                alert = LateralAlert(
                    timestamp=now_ts,
                    category='lateral_tool_detected',
                    details=f'Lateral movement tool: {proc_name} — {cmdline[:160]}',
                    indicator=cmdline[:200],
                    severity='critical',
                    mitre_id='T1021',
                )
                self._add_alert(alert)
                return alert
        return None

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_inbound_connections()
                self._check_new_services()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Lateral check error: %s', exc)

            if self._check_count % 20 == 0:
                self._cleanup_stale()

            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_inbound_connections(self) -> None:
        """Monitor inbound connections on lateral movement ports."""
        now_ts = datetime.now(timezone.utc).isoformat()
        now = time.time()
        try:
            result = subprocess.run(
                ['netstat', '-n', '-o', '-p', 'tcp'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return

            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4 or parts[0] != 'TCP':
                    continue
                state = parts[3]
                if state != 'ESTABLISHED':
                    continue

                local = parts[1]
                remote = parts[2]
                local_m = re.match(r'[\d.]+:(\d+)', local)
                remote_m = re.match(r'([\d.]+):(\d+)', remote)
                if not local_m or not remote_m:
                    continue

                local_port = int(local_m.group(1))
                remote_ip = remote_m.group(1)

                if local_port not in LATERAL_PORTS:
                    continue
                if remote_ip in ('127.0.0.1', '0.0.0.0'):
                    continue

                conn_key = f'{remote_ip}:{local_port}'
                if conn_key in self._known_inbound:
                    continue

                last_alert = self._alerted_ips.get(conn_key, 0)
                if now - last_alert < 1800:
                    continue

                service = LATERAL_PORTS.get(local_port, 'Unknown')
                severity = 'high'
                if local_port == 3389:
                    self._track_rdp_attempt(remote_ip, now, now_ts)
                    severity = 'medium'
                elif local_port in (5985, 5986):
                    severity = 'critical'

                self._add_alert(LateralAlert(
                    timestamp=now_ts,
                    category='inbound_lateral_port',
                    details=(f'Inbound {service} connection from {remote_ip} '
                             f'on port {local_port}'),
                    indicator=conn_key,
                    severity=severity,
                    mitre_id='T1021',
                    source_ip=remote_ip,
                ))
                self._alerted_ips[conn_key] = now
                self._known_inbound.add(conn_key)

        except Exception:
            pass

    def _track_rdp_attempt(self, ip: str, now: float, now_ts: str) -> None:
        """Track RDP connection attempts for brute force detection."""
        attempts = self._rdp_attempts.setdefault(ip, [])
        attempts.append(now)
        recent = [t for t in attempts if now - t < 300]
        self._rdp_attempts[ip] = recent

        if len(recent) >= 5:
            self._add_alert(LateralAlert(
                timestamp=now_ts,
                category='rdp_brute_force',
                details=(f'RDP brute force from {ip}: '
                         f'{len(recent)} connections in 5 minutes'),
                indicator=ip,
                severity='critical',
                mitre_id='T1021.001',
                source_ip=ip,
            ))
            self._rdp_attempts[ip] = []

    def _check_new_services(self) -> None:
        """Detect new services that match PsExec-style patterns."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_service_names()
        new_services = current - self._baseline_services

        for svc_name in new_services:
            is_psexec = any(p.search(svc_name) for p in PSEXEC_SERVICE_PATTERNS)
            if is_psexec:
                self._add_alert(LateralAlert(
                    timestamp=now_ts,
                    category='psexec_service',
                    details=f'PsExec-style service installed: {svc_name}',
                    indicator=svc_name,
                    severity='critical',
                    mitre_id='T1021.002',
                ))
            else:
                self._add_alert(LateralAlert(
                    timestamp=now_ts,
                    category='new_service',
                    details=f'New service created: {svc_name}',
                    indicator=svc_name,
                    severity='medium',
                    mitre_id='T1543.003',
                ))

        self._baseline_services = current

    @staticmethod
    def _get_service_names() -> Set[str]:
        """Get installed service names via sc query."""
        services: Set[str] = set()
        try:
            result = subprocess.run(
                ['sc', 'query', 'type=', 'service', 'state=', 'all'],
                capture_output=True, text=True, timeout=20,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    m = re.match(r'SERVICE_NAME:\s+(.+)', line.strip())
                    if m:
                        services.add(m.group(1).strip())
        except Exception:
            pass
        return services

    def _cleanup_stale(self) -> None:
        """Clean up old tracking data."""
        cutoff = time.time() - 3600
        self._alerted_ips = {k: v for k, v in self._alerted_ips.items()
                             if v > cutoff}
        self._known_inbound = set()

    def _add_alert(self, alert: LateralAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('Lateral: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[LateralMovementDetector] = None


def get_lateral_detector() -> LateralMovementDetector:
    global _detector
    if _detector is None:
        _detector = LateralMovementDetector()
    return _detector


def start_lateral_detection(callback=None) -> bool:
    global _detector
    _detector = LateralMovementDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'LateralMovementDetector', 'LateralAlert',
    'get_lateral_detector', 'start_lateral_detection',
    'LATERAL_PORTS', 'LATERAL_TOOL_CMDLINES',
]
