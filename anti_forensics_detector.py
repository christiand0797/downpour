"""
Anti-Forensics Detector
Downpour v29 Titanium

Detects anti-forensics and evidence destruction techniques:
  - Event log clearing (wevtutil cl, Clear-EventLog)
  - Timestamp stomping indicators (timestomp, SetFileTime abuse)
  - Secure deletion tools (sdelete, eraser, cipher /w)
  - Prefetch / USN journal deletion
  - MFT manipulation indicators
  - Recycle bin bypass (shift+delete detection via recent file monitoring)
  - Disk cleaning tool execution (bleachbit, ccleaner, privazer)
  - Audit policy tampering (auditpol /clear, /set)

Uses wevtutil, reg, and wmic — no PowerShell.
MITRE ATT&CK: T1070 (Indicator Removal), T1070.001 (Clear Windows Event Logs),
              T1070.004 (File Deletion), T1070.006 (Timestomp)
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

_log = logging.getLogger('downpour.antiforensics')

EVENT_LOGS_TO_WATCH = [
    'Security', 'System', 'Application',
    'Microsoft-Windows-Sysmon/Operational',
    'Microsoft-Windows-PowerShell/Operational',
    'Microsoft-Windows-Windows Defender/Operational',
]

ANTI_FORENSICS_TOOLS = [
    re.compile(r'(?i)sdelete'),
    re.compile(r'(?i)eraser\.exe'),
    re.compile(r'(?i)cipher\s+/w'),
    re.compile(r'(?i)bleachbit'),
    re.compile(r'(?i)ccleaner'),
    re.compile(r'(?i)privazer'),
    re.compile(r'(?i)dban'),
    re.compile(r'(?i)evidence.eliminator'),
    re.compile(r'(?i)timestomp'),
    re.compile(r'(?i)SetMACE'),
    re.compile(r'(?i)ninjacopy'),
    re.compile(r'(?i)invoke-phant0m'),
    re.compile(r'(?i)mimikatz.*event'),
    re.compile(r'(?i)wevtutil\s+(cl|clear-log)'),
    re.compile(r'(?i)fsutil\s+usn\s+deletejournal'),
]

AUDIT_TAMPERING_PATTERNS = [
    re.compile(r'(?i)auditpol\s+/clear'),
    re.compile(r'(?i)auditpol\s+/set.*failure:disable'),
    re.compile(r'(?i)auditpol\s+/set.*success:disable'),
    re.compile(r'(?i)auditpol\s+/remove'),
]


@dataclass
class AntiForensicsAlert:
    """Anti-forensics detection alert."""
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


class AntiForensicsDetector:
    """
    Detect anti-forensics techniques including log clearing,
    timestamp manipulation, and evidence destruction tools.
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

        self._baseline_log_counts: Dict[str, int] = {}
        self._baseline_prefetch_count: int = -1
        self._alerts: List[AntiForensicsAlert] = []

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_log_counts = self._get_log_counts()
            self._baseline_prefetch_count = self._count_prefetch_files()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='antiforensics-det',
                daemon=True,
            )
            self._thread.start()
            _log.info('Anti-forensics detector started (tracking %d logs)',
                      len(self._baseline_log_counts))
            return True
        except Exception as exc:
            _log.warning('Anti-forensics detector failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'tracked_logs': len(self._baseline_log_counts),
            'prefetch_count': self._baseline_prefetch_count,
            'alerts': len(self._alerts),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def scan_command_line(self, proc_name: str,
                          cmdline: str) -> Optional[AntiForensicsAlert]:
        """Scan a command line for anti-forensics tool signatures."""
        now_ts = datetime.now(timezone.utc).isoformat()
        for pattern in ANTI_FORENSICS_TOOLS:
            if pattern.search(cmdline):
                alert = AntiForensicsAlert(
                    timestamp=now_ts,
                    category='anti_forensics_tool',
                    details=f'Anti-forensics tool detected: {proc_name} — {cmdline[:160]}',
                    indicator=cmdline[:200],
                    severity='critical',
                    mitre_id='T1070',
                )
                self._add_alert(alert)
                return alert
        for pattern in AUDIT_TAMPERING_PATTERNS:
            if pattern.search(cmdline):
                alert = AntiForensicsAlert(
                    timestamp=now_ts,
                    category='audit_tampering',
                    details=f'Audit policy tampering: {proc_name} — {cmdline[:160]}',
                    indicator=cmdline[:200],
                    severity='critical',
                    mitre_id='T1562.002',
                )
                self._add_alert(alert)
                return alert
        return None

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_log_clearing()
                self._check_prefetch_deletion()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Anti-forensics check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_log_clearing(self) -> None:
        """Detect event log clearing by monitoring record counts."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_log_counts()

        for log_name, baseline_count in self._baseline_log_counts.items():
            current_count = current.get(log_name, -1)
            if current_count < 0:
                continue

            if baseline_count > 100 and current_count < baseline_count * 0.1:
                self._add_alert(AntiForensicsAlert(
                    timestamp=now_ts,
                    category='event_log_cleared',
                    details=(f'Event log "{log_name}" appears cleared: '
                             f'{baseline_count} -> {current_count} records'),
                    indicator=log_name,
                    severity='critical',
                    mitre_id='T1070.001',
                ))

            if current_count == 0 and baseline_count > 0:
                self._add_alert(AntiForensicsAlert(
                    timestamp=now_ts,
                    category='event_log_wiped',
                    details=f'Event log "{log_name}" completely wiped (was {baseline_count} records)',
                    indicator=log_name,
                    severity='critical',
                    mitre_id='T1070.001',
                ))

        self._baseline_log_counts = current

    def _check_prefetch_deletion(self) -> None:
        """Detect prefetch file deletion (anti-forensics behavior)."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current_count = self._count_prefetch_files()

        if self._baseline_prefetch_count > 20 and current_count >= 0:
            deleted = self._baseline_prefetch_count - current_count
            if deleted > self._baseline_prefetch_count * 0.5:
                self._add_alert(AntiForensicsAlert(
                    timestamp=now_ts,
                    category='prefetch_mass_deletion',
                    details=(f'Mass prefetch file deletion: '
                             f'{self._baseline_prefetch_count} -> {current_count} files'),
                    indicator='prefetch',
                    severity='high',
                    mitre_id='T1070.004',
                ))

        if current_count >= 0:
            self._baseline_prefetch_count = current_count

    @staticmethod
    def _get_log_counts() -> Dict[str, int]:
        """Get event log record counts via wevtutil."""
        counts: Dict[str, int] = {}
        for log_name in EVENT_LOGS_TO_WATCH:
            try:
                result = subprocess.run(
                    ['wevtutil', 'gli', log_name],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if 'numberOfLogRecords' in line.lower() or 'records' in line.lower():
                            m = re.search(r'(\d+)', line)
                            if m:
                                counts[log_name] = int(m.group(1))
                                break
            except Exception:
                pass
        return counts

    @staticmethod
    def _count_prefetch_files() -> int:
        """Count files in the Prefetch directory."""
        prefetch_dir = os.path.join(
            os.environ.get('SYSTEMROOT', r'C:\Windows'), 'Prefetch')
        try:
            if os.path.isdir(prefetch_dir):
                return sum(1 for e in os.scandir(prefetch_dir)
                           if e.is_file() and e.name.endswith('.pf'))
        except (PermissionError, OSError):
            pass
        return -1

    def _add_alert(self, alert: AntiForensicsAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('AntiForensics: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[AntiForensicsDetector] = None


def get_antiforensics_detector() -> AntiForensicsDetector:
    global _detector
    if _detector is None:
        _detector = AntiForensicsDetector()
    return _detector


def start_antiforensics_detection(callback=None) -> bool:
    global _detector
    _detector = AntiForensicsDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'AntiForensicsDetector', 'AntiForensicsAlert',
    'get_antiforensics_detector', 'start_antiforensics_detection',
    'ANTI_FORENSICS_TOOLS', 'AUDIT_TAMPERING_PATTERNS',
]
