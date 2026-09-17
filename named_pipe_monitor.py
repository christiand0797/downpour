"""
Named Pipe Security Monitor
Downpour v29 Titanium

Monitors Windows named pipes for:
  - C2 framework communication pipes (Cobalt Strike, PsExec, Meterpreter)
  - Lateral movement pipe indicators
  - Unusual pipe creation patterns
  - Token impersonation via pipe (potato attacks)
  - Suspicious pipe naming patterns

Uses native Windows commands only — no PowerShell.
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.pipemon')

MALICIOUS_PIPES = {
    'msagent_': ('Cobalt Strike default', 'T1071.001', 'critical'),
    'MSSE-': ('Cobalt Strike SSH', 'T1071.001', 'critical'),
    'postex_': ('Cobalt Strike post-exploitation', 'T1071.001', 'critical'),
    'postex_ssh_': ('Cobalt Strike SSH tunnel', 'T1071.001', 'critical'),
    'status_': ('Cobalt Strike status pipe', 'T1071.001', 'critical'),
    'mojo.': ('Cobalt Strike (Chrome-styled)', 'T1071.001', 'high'),
    'psexecsvc': ('PsExec service pipe', 'T1569.002', 'high'),
    'PSEXESVC': ('PsExec service pipe', 'T1569.002', 'high'),
    'RemCom_communicaton': ('RemCom (PsExec alternative)', 'T1569.002', 'high'),
    'csexecsvc': ('CsExec variant pipe', 'T1569.002', 'high'),
    'PAExec': ('PAExec variant pipe', 'T1569.002', 'high'),
    'svcctl': ('Service Control Manager RPC', 'T1021.002', 'medium'),
    'ntsvcs': ('NT Services RPC', 'T1021.002', 'medium'),
    'samr': ('SAM Remote Protocol', 'T1003.002', 'high'),
    'lsarpc': ('LSA Remote Protocol', 'T1003.001', 'high'),
    'epmapper': ('Endpoint Mapper', 'T1021.003', 'low'),
    'atsvc': ('AT Scheduler RPC', 'T1053', 'medium'),
    'meterpreter': ('Meterpreter pipe', 'T1071.001', 'critical'),
    'msf_': ('Metasploit Framework pipe', 'T1071.001', 'critical'),
    'gecko_': ('Cobalt Strike Firefox-styled', 'T1071.001', 'critical'),
    'win_svc_': ('Generic malware pipe', 'T1071.001', 'high'),
    'DserNamePipe': ('DarkSide ransomware', 'T1486', 'critical'),
    'crashpad_': ('Cobalt Strike crashpad-styled', 'T1071.001', 'high'),
    'MicrosoftDiag': ('Cobalt Strike diagnostic-styled', 'T1071.001', 'high'),
}

SUSPICIOUS_PATTERNS = [
    (re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', re.I),
     'GUID-named pipe (common C2 pattern)', 'T1071.001', 'high'),
    (re.compile(r'^[A-Z]{3,5}_[0-9]{4,8}$'),
     'Uppercase prefix with numeric suffix', 'T1071.001', 'medium'),
    (re.compile(r'\\\\\.\\pipe\\[0-9]{6,}$'),
     'Numeric-only pipe name', 'T1071.001', 'medium'),
]


@dataclass
class PipeAlert:
    """Named pipe security alert."""
    timestamp: str
    pipe_name: str
    category: str
    description: str
    severity: str
    mitre_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'pipe_name': self.pipe_name,
            'category': self.category,
            'description': self.description,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
        }


class NamedPipeMonitor:
    """
    Monitor Windows named pipes for malicious activity.
    Baselines normal system pipes and alerts on suspicious additions.
    """

    def __init__(
        self,
        check_interval: float = 15.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._baseline_pipes: Set[str] = set()
        self._alerted_pipes: Set[str] = set()
        self._alerts: List[PipeAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_pipes = self._enumerate_pipes()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='named-pipe-monitor',
                daemon=True,
            )
            self._thread.start()
            _log.info('Named pipe monitor started (%d baseline pipes)', len(self._baseline_pipes))
            return True
        except Exception as exc:
            _log.warning('Named pipe monitor failed: %s', exc)
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
            'baseline_count': len(self._baseline_pipes),
            'alerted_count': len(self._alerted_pipes),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_pipes()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Pipe check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_pipes(self) -> None:
        """Check for new suspicious pipes."""
        now = datetime.now(timezone.utc).isoformat()
        current = self._enumerate_pipes()
        new_pipes = current - self._baseline_pipes - self._alerted_pipes

        for pipe_name in new_pipes:
            for prefix, (desc, mitre, severity) in MALICIOUS_PIPES.items():
                if prefix.lower() in pipe_name.lower():
                    self._add_alert(PipeAlert(
                        timestamp=now,
                        pipe_name=pipe_name,
                        category='known_malicious',
                        description=f'Known malicious pipe: {desc}',
                        severity=severity,
                        mitre_id=mitre,
                    ))
                    self._alerted_pipes.add(pipe_name)
                    break
            else:
                for pattern, desc, mitre, severity in SUSPICIOUS_PATTERNS:
                    basename = pipe_name.split('\\')[-1] if '\\' in pipe_name else pipe_name
                    if pattern.search(basename):
                        self._add_alert(PipeAlert(
                            timestamp=now,
                            pipe_name=pipe_name,
                            category='suspicious_pattern',
                            description=desc,
                            severity=severity,
                            mitre_id=mitre,
                        ))
                        self._alerted_pipes.add(pipe_name)
                        break

    @staticmethod
    def _enumerate_pipes() -> Set[str]:
        """List currently open named pipes."""
        pipes: Set[str] = set()
        try:
            import os
            pipe_dir = r'\\.\pipe'
            try:
                for entry in os.listdir(pipe_dir):
                    pipes.add(entry)
            except PermissionError:
                pass
        except Exception:
            pass
        return pipes

    def _add_alert(self, alert: PipeAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('Pipe alert: %s — %s', alert.pipe_name, alert.description)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[NamedPipeMonitor] = None


def get_pipe_monitor() -> NamedPipeMonitor:
    global _monitor
    if _monitor is None:
        _monitor = NamedPipeMonitor()
    return _monitor


def start_pipe_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = NamedPipeMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'NamedPipeMonitor', 'PipeAlert',
    'get_pipe_monitor', 'start_pipe_monitoring',
    'MALICIOUS_PIPES',
]
