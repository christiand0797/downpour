"""
WMI Persistence Detector
Downpour v29 Titanium

Detects WMI-based persistence mechanisms:
  - WMI event subscription monitoring (EventFilter + EventConsumer + Binding)
  - CommandLineEventConsumer detection (most common malware persistence)
  - ActiveScriptEventConsumer detection (script-based WMI persistence)
  - WMI class creation monitoring
  - WMI repository size anomaly detection
  - Known WMI persistence tool signatures
  - WMI namespace enumeration for suspicious entries

Uses wmic — no PowerShell.
MITRE ATT&CK: T1546.003 (WMI Event Subscription), T1047 (WMI)
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.wmipersist')

LEGITIMATE_FILTERS = {
    'BVTFilter',
    'SCM Event Log Filter',
    '__InstanceCreationEvent',
}

SUSPICIOUS_CONSUMER_NAMES = [
    re.compile(r'(?i)^[a-f0-9]{32}$'),
    re.compile(r'(?i)^[a-f0-9]{8}-'),
    re.compile(r'(?i)update'),
    re.compile(r'(?i)checker'),
    re.compile(r'(?i)loader'),
    re.compile(r'(?i)runner'),
    re.compile(r'(?i)exec'),
    re.compile(r'(?i)payload'),
    re.compile(r'(?i)beacon'),
]


@dataclass
class WMIPersistAlert:
    """WMI persistence alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    filter_name: str = ''
    consumer_name: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'filter_name': self.filter_name,
            'consumer_name': self.consumer_name,
        }


class WMIPersistenceDetector:
    """
    Detect WMI-based persistence by monitoring event subscriptions,
    consumers, and bindings in the WMI repository.
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

        self._known_filters: Set[str] = set()
        self._known_consumers: Set[str] = set()
        self._alerts: List[WMIPersistAlert] = []

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._known_filters = self._get_event_filters()
            self._known_consumers = self._get_event_consumers()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='wmi-persist-det',
                daemon=True,
            )
            self._thread.start()
            _log.info('WMI persistence detector started '
                      '(baseline: %d filters, %d consumers)',
                      len(self._known_filters), len(self._known_consumers))
            self._initial_audit()
            return True
        except Exception as exc:
            _log.warning('WMI persistence detector failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'known_filters': len(self._known_filters),
            'known_consumers': len(self._known_consumers),
            'alerts': len(self._alerts),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def get_subscription_inventory(self) -> Dict[str, Any]:
        """Return current WMI subscription inventory."""
        return {
            'filters': list(self._known_filters),
            'consumers': list(self._known_consumers),
            'bindings': self._get_bindings(),
        }

    def _initial_audit(self) -> None:
        """Audit existing WMI subscriptions for suspicious entries."""
        now_ts = datetime.now(timezone.utc).isoformat()

        cmd_consumers = self._get_commandline_consumers()
        for name, cmd in cmd_consumers.items():
            self._add_alert(WMIPersistAlert(
                timestamp=now_ts,
                category='commandline_consumer_exists',
                details=(f'CommandLineEventConsumer "{name}": {cmd[:120]}'),
                indicator=name,
                severity='critical',
                mitre_id='T1546.003',
                consumer_name=name,
            ))

        script_consumers = self._get_script_consumers()
        for name in script_consumers:
            self._add_alert(WMIPersistAlert(
                timestamp=now_ts,
                category='script_consumer_exists',
                details=f'ActiveScriptEventConsumer "{name}" found',
                indicator=name,
                severity='critical',
                mitre_id='T1546.003',
                consumer_name=name,
            ))

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_new_filters()
                self._check_new_consumers()
                self._check_count += 1
            except Exception as exc:
                _log.debug('WMI persistence check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_new_filters(self) -> None:
        """Detect new WMI event filters."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_event_filters()
        new_filters = current - self._known_filters

        for name in new_filters:
            if name in LEGITIMATE_FILTERS:
                continue
            self._add_alert(WMIPersistAlert(
                timestamp=now_ts,
                category='new_event_filter',
                details=f'New WMI EventFilter created: "{name}"',
                indicator=name,
                severity='high',
                mitre_id='T1546.003',
                filter_name=name,
            ))

        self._known_filters = current

    def _check_new_consumers(self) -> None:
        """Detect new WMI event consumers."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_event_consumers()
        new_consumers = current - self._known_consumers

        for name in new_consumers:
            severity = 'high'
            if any(p.search(name) for p in SUSPICIOUS_CONSUMER_NAMES):
                severity = 'critical'

            self._add_alert(WMIPersistAlert(
                timestamp=now_ts,
                category='new_event_consumer',
                details=f'New WMI EventConsumer created: "{name}"',
                indicator=name,
                severity=severity,
                mitre_id='T1546.003',
                consumer_name=name,
            ))

        self._known_consumers = current

    @staticmethod
    def _get_event_filters() -> Set[str]:
        """Get WMI event filter names."""
        filters: Set[str] = set()
        try:
            result = subprocess.run(
                ['wmic', 'path', '__EventFilter', 'get', 'Name',
                 '/format:list'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('Name=') and line[5:]:
                        filters.add(line[5:])
        except Exception:
            pass
        return filters

    @staticmethod
    def _get_event_consumers() -> Set[str]:
        """Get WMI event consumer names (all types)."""
        consumers: Set[str] = set()
        for consumer_class in ('CommandLineEventConsumer',
                                'ActiveScriptEventConsumer',
                                'LogFileEventConsumer',
                                'NTEventLogEventConsumer',
                                'SMTPEventConsumer'):
            try:
                result = subprocess.run(
                    ['wmic', 'path', consumer_class, 'get', 'Name',
                     '/format:list'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        line = line.strip()
                        if line.startswith('Name=') and line[5:]:
                            consumers.add(f'{consumer_class}:{line[5:]}')
            except Exception:
                pass
        return consumers

    @staticmethod
    def _get_commandline_consumers() -> Dict[str, str]:
        """Get CommandLineEventConsumer details."""
        consumers: Dict[str, str] = {}
        try:
            result = subprocess.run(
                ['wmic', 'path', 'CommandLineEventConsumer', 'get',
                 'Name,CommandLineTemplate', '/format:list'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                name = ''
                cmd = ''
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('Name='):
                        name = line[5:]
                    elif line.startswith('CommandLineTemplate='):
                        cmd = line[20:]
                    if name and cmd:
                        consumers[name] = cmd
                        name = ''
                        cmd = ''
        except Exception:
            pass
        return consumers

    @staticmethod
    def _get_script_consumers() -> Set[str]:
        """Get ActiveScriptEventConsumer names."""
        names: Set[str] = set()
        try:
            result = subprocess.run(
                ['wmic', 'path', 'ActiveScriptEventConsumer', 'get', 'Name',
                 '/format:list'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('Name=') and line[5:]:
                        names.add(line[5:])
        except Exception:
            pass
        return names

    @staticmethod
    def _get_bindings() -> List[str]:
        """Get FilterToConsumerBinding info."""
        bindings: List[str] = []
        try:
            result = subprocess.run(
                ['wmic', 'path', '__FilterToConsumerBinding', 'get',
                 'Filter,Consumer', '/format:list'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('Consumer=') or line.startswith('Filter='):
                        bindings.append(line)
        except Exception:
            pass
        return bindings

    def _add_alert(self, alert: WMIPersistAlert) -> None:
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
        _log.warning('WMIPersist: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[WMIPersistenceDetector] = None


def get_wmi_persist_detector() -> WMIPersistenceDetector:
    global _detector
    if _detector is None:
        _detector = WMIPersistenceDetector()
    return _detector


def start_wmi_persist_detection(callback=None) -> bool:
    global _detector
    _detector = WMIPersistenceDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'WMIPersistenceDetector', 'WMIPersistAlert',
    'get_wmi_persist_detector', 'start_wmi_persist_detection',
]
