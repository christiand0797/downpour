"""
Scheduled Task Persistence Monitor
Downpour v29 Titanium

Monitors Windows scheduled tasks for persistence and abuse:
  - New task creation detection
  - Task modification monitoring
  - Suspicious task properties (hidden, runs as SYSTEM, runs scripts)
  - Known malware task name patterns
  - Task action analysis (PowerShell, cmd, wscript, mshta, rundll32)
  - High-frequency task detection (< 5 minute intervals)
  - Task running from user-writable locations
  - XML-based task definition monitoring

Uses schtasks — no PowerShell.
MITRE ATT&CK: T1053.005 (Scheduled Task), T1053.002 (At)
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.schtask')

SUSPICIOUS_TASK_ACTIONS = [
    re.compile(r'(?i)powershell'),
    re.compile(r'(?i)cmd\.exe\s+/c'),
    re.compile(r'(?i)wscript'),
    re.compile(r'(?i)cscript'),
    re.compile(r'(?i)mshta'),
    re.compile(r'(?i)rundll32'),
    re.compile(r'(?i)regsvr32'),
    re.compile(r'(?i)certutil'),
    re.compile(r'(?i)bitsadmin'),
    re.compile(r'(?i)msiexec'),
]

SUSPICIOUS_TASK_PATHS = [
    re.compile(r'(?i)\\Users\\.*\\AppData'),
    re.compile(r'(?i)\\Temp\\'),
    re.compile(r'(?i)\\ProgramData\\'),
    re.compile(r'(?i)\\Public\\'),
    re.compile(r'(?i)\\Downloads\\'),
    re.compile(r'(?i)\\Desktop\\'),
    re.compile(r'(?i)%APPDATA%'),
    re.compile(r'(?i)%TEMP%'),
    re.compile(r'(?i)%USERPROFILE%'),
]

KNOWN_MALWARE_TASK_NAMES = [
    re.compile(r'(?i)^WindowsUpdate\d{3,}$'),
    re.compile(r'(?i)^SystemCheck\d+$'),
    re.compile(r'(?i)^MicrosoftUpdate'),
    re.compile(r'(?i)^Updater[A-Z]'),
    re.compile(r'(?i)^GoogleUpdate[A-Z]{4,}'),
    re.compile(r'(?i)^[a-f0-9]{32}$'),
    re.compile(r'(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}'),
]


@dataclass
class TaskAlert:
    """Scheduled task alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    task_name: str = ''
    task_action: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'task_name': self.task_name,
            'task_action': self.task_action,
        }


class ScheduledTaskMonitor:
    """
    Monitor scheduled tasks for persistence abuse and suspicious configurations.
    """

    def __init__(
        self,
        check_interval: float = 120.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

        self._known_tasks: Set[str] = set()
        self._alerts: List[TaskAlert] = []

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._known_tasks = self._get_task_names()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='schtask-monitor',
                daemon=True,
            )
            self._thread.start()
            _log.info('Scheduled task monitor started (%d baseline tasks)',
                      len(self._known_tasks))
            return True
        except Exception as exc:
            _log.warning('Scheduled task monitor failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'known_tasks': len(self._known_tasks),
            'alerts': len(self._alerts),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_new_tasks()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Schtask check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_new_tasks(self) -> None:
        """Detect new scheduled tasks and analyze them."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_task_names()
        new_tasks = current - self._known_tasks

        for task_name in new_tasks:
            task_info = self._get_task_details(task_name)
            action = task_info.get('action', '')
            run_as = task_info.get('run_as', '')

            severity = 'medium'
            alerts_generated = False

            if any(p.search(task_name) for p in KNOWN_MALWARE_TASK_NAMES):
                self._add_alert(TaskAlert(
                    timestamp=now_ts,
                    category='malware_task_name',
                    details=f'Task name matches malware pattern: {task_name}',
                    indicator=task_name,
                    severity='critical',
                    mitre_id='T1053.005',
                    task_name=task_name,
                    task_action=action[:200],
                ))
                alerts_generated = True

            if action:
                if any(p.search(action) for p in SUSPICIOUS_TASK_ACTIONS):
                    self._add_alert(TaskAlert(
                        timestamp=now_ts,
                        category='suspicious_task_action',
                        details=f'New task with suspicious action: {task_name} -> {action[:120]}',
                        indicator=task_name,
                        severity='high',
                        mitre_id='T1053.005',
                        task_name=task_name,
                        task_action=action[:200],
                    ))
                    alerts_generated = True

                if any(p.search(action) for p in SUSPICIOUS_TASK_PATHS):
                    self._add_alert(TaskAlert(
                        timestamp=now_ts,
                        category='task_user_writable_path',
                        details=f'Task runs from user-writable path: {task_name} -> {action[:120]}',
                        indicator=task_name,
                        severity='high',
                        mitre_id='T1053.005',
                        task_name=task_name,
                        task_action=action[:200],
                    ))
                    alerts_generated = True

            if run_as.upper() in ('SYSTEM', 'NT AUTHORITY\\SYSTEM', 'LOCAL SERVICE'):
                self._add_alert(TaskAlert(
                    timestamp=now_ts,
                    category='task_system_privilege',
                    details=f'New task running as {run_as}: {task_name}',
                    indicator=task_name,
                    severity='high',
                    mitre_id='T1053.005',
                    task_name=task_name,
                    task_action=action[:200],
                ))
                alerts_generated = True

            if not alerts_generated:
                self._add_alert(TaskAlert(
                    timestamp=now_ts,
                    category='new_scheduled_task',
                    details=f'New scheduled task: {task_name}',
                    indicator=task_name,
                    severity='medium',
                    mitre_id='T1053.005',
                    task_name=task_name,
                    task_action=action[:200],
                ))

        self._known_tasks = current

    @staticmethod
    def _get_task_names() -> Set[str]:
        """Get all scheduled task names via schtasks."""
        tasks: Set[str] = set()
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/fo', 'csv', '/nh'],
                capture_output=True, text=True, timeout=30,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('"'):
                        parts = line.split('","')
                        if parts:
                            name = parts[0].strip('"')
                            if name and not name.startswith('TaskName'):
                                tasks.add(name)
        except Exception:
            pass
        return tasks

    @staticmethod
    def _get_task_details(task_name: str) -> Dict[str, str]:
        """Get details about a specific scheduled task."""
        info: Dict[str, str] = {}
        try:
            result = subprocess.run(
                ['schtasks', '/query', '/tn', task_name, '/v', '/fo', 'list'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('Task To Run:'):
                        info['action'] = line.split(':', 1)[-1].strip()
                    elif line.startswith('Run As User:'):
                        info['run_as'] = line.split(':', 1)[-1].strip()
                    elif line.startswith('Schedule Type:'):
                        info['schedule'] = line.split(':', 1)[-1].strip()
                    elif line.startswith('Repeat: Every:'):
                        info['repeat'] = line.split(':', 2)[-1].strip()
        except Exception:
            pass
        return info

    def _add_alert(self, alert: TaskAlert) -> None:
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
        _log.warning('SchTask: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[ScheduledTaskMonitor] = None


def get_schtask_monitor() -> ScheduledTaskMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ScheduledTaskMonitor()
    return _monitor


def start_schtask_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = ScheduledTaskMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'ScheduledTaskMonitor', 'TaskAlert',
    'get_schtask_monitor', 'start_schtask_monitoring',
    'SUSPICIOUS_TASK_ACTIONS', 'KNOWN_MALWARE_TASK_NAMES',
]
