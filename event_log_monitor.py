"""
WINDOWS EVENT LOG MONITOR — v29.44b (closes audit blind spots #2/#3)
================================================================================
Near-real-time monitoring of the Windows Event Log for persistence and
tamper indicators. Complements the polling sensors with OS-level events:
  * 7045  — service installed (System log) — T1543.003
  * 4698  — scheduled task created — T1053.005
  * 4699  — scheduled task deleted
  * 4720  — user account created — T1136.001
  * 4732  — member added to privileged group — T1078
  * 1102  — audit log cleared (Security) — T1070.001 (TAMPER)
  * 104   — log cleared (System) — T1070.001 (TAMPER)
  * 4104  — PowerShell script block — T1059.001
  * 4625  — failed logon bursts — T1110 brute force
  * 4688  — process creation (if audit policy enabled)
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional

_log = logging.getLogger(__name__)

try:
    import win32evtlog
    _EVT_AVAILABLE = True
except ImportError:
    _EVT_AVAILABLE = False

# Event ID -> (mitre_technique, severity, description)
EVENT_MAP: Dict[int, tuple] = {
    7045: ('T1543.003', 'HIGH', 'Service installed'),
    4698: ('T1053.005', 'HIGH', 'Scheduled task created'),
    4699: ('T1053.005', 'LOW', 'Scheduled task deleted'),
    4720: ('T1136.001', 'MEDIUM', 'User account created'),
    4732: ('T1078', 'MEDIUM', 'Member added to security-enabled local group'),
    1102: ('T1070.001', 'CRITICAL', 'Security audit log cleared (TAMPER)'),
    104: ('T1070.001', 'CRITICAL', 'System log cleared (TAMPER)'),
    4104: ('T1059.001', 'LOW', 'PowerShell script block executed'),
    4625: ('T1110', 'LOW', 'Logon failure'),
    4688: ('T1059', 'LOW', 'New process created'),
}
BRUTE_FORCE_THRESHOLD = 10  # 4625 events within window
BRUTE_FORCE_WINDOW = 300  # seconds


@dataclass
class EventAlert:
    """One notable Windows event."""
    event_id: int
    log_name: str
    technique: str
    severity: str
    description: str
    detail: str
    timestamp: str


class EventLogMonitor:
    """Polls Windows event logs for persistence/tamper indicators."""

    def __init__(self, callback: Optional[Callable[[EventAlert], None]] = None):
        self.callback = callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._bookmarks: Dict[str, Optional[int]] = {
            'Security': None, 'System': None,
            'Microsoft-Windows-PowerShell/Operational': None}
        self._failed_logons: List[float] = []
        self.alerts_emitted = 0
        self.last_error: Optional[str] = None

    # -- public API ---------------------------------------------------------
    def start(self, interval: float = 15.0) -> None:
        if not _EVT_AVAILABLE:
            _log.warning('win32evtlog unavailable - event monitor disabled')
            return
        with self._lock:
            if self._running:
                return
            self._running = True
        self._thread = threading.Thread(
            target=self._loop, args=(interval,),
            name='EventLogMonitor', daemon=True)
        self._thread.start()

    def stop(self) -> None:
        with self._lock:
            self._running = False

    def is_running(self) -> bool:
        return self._running

    def check_once(self) -> List[EventAlert]:
        """One polling pass across all watched logs (also used by tests)."""
        alerts: List[EventAlert] = []
        if not _EVT_AVAILABLE:
            return alerts
        for log_name in list(self._bookmarks):
            try:
                alerts.extend(self._read_new_events(log_name))
            except Exception as exc:
                self.last_error = f'{log_name}: {exc}'
                _log.debug('event log read %s: %s', log_name, exc)
        alerts.extend(self._check_brute_force())
        for a in alerts:
            self._emit(a)
        return alerts

    # -- internals ------------------------------------------------------
    def _emit(self, alert: EventAlert) -> None:
        self.alerts_emitted += 1
        if self.callback:
            try:
                self.callback(alert)
            except Exception:
                _log.exception('event alert callback failed')

    def _loop(self, interval: float) -> None:
        while self._running:
            try:
                self.check_once()
                self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)
            time.sleep(interval)

    def _read_new_events(self, log_name: str) -> List[EventAlert]:
        alerts: List[EventAlert] = []
        flags = (win32evtlog.EVENTLOG_BACKWARDS_READ
                 | win32evtlog.EVENTLOG_SEQUENTIAL_READ)
        handle = win32evtlog.OpenEventLog(None, log_name)
        try:
            events = win32evtlog.ReadEventLog(handle, flags, 0)
        finally:
            win32evtlog.CloseEventLog(handle)
        # events come newest-first; process oldest-last
        for ev in reversed(events):
            eid = ev.EventID & 0xFFFF
            record = ev.RecordNumber
            bm = self._bookmarks.get(log_name)
            if bm is not None and record <= bm:
                continue
            self._bookmarks[log_name] = record
            info = EVENT_MAP.get(eid)
            if not info:
                continue
            technique, severity, desc = info
            detail = self._extract_detail(ev)
            # Brute-force raw failures tracked separately, not alerted singly
            if eid == 4625:
                self._failed_logons.append(
                    ev.TimeGenerated.timestamp() if ev.TimeGenerated
                    else time.time())
                continue
            # PowerShell script blocks: only flag suspicious content
            if eid == 4104 and not self._ps_block_suspicious(detail):
                continue
            ts = ''
            if ev.TimeGenerated:
                ts = ev.TimeGenerated.isoformat()
            alerts.append(EventAlert(
                event_id=eid, log_name=log_name, technique=technique,
                severity=severity, description=desc, detail=detail,
                timestamp=ts))
        return alerts

    @staticmethod
    def _extract_detail(ev) -> str:
        try:
            parts = [str(s) for s in (ev.StringInserts or [])]
            return ' | '.join(p for p in parts if p)[:500]
        except Exception:
            return ''

    @staticmethod
    def _ps_block_suspicious(detail: str) -> bool:
        """Filter 4104 noise: only flag clearly hostile script content."""
        lowered = (detail or '').lower()
        markers = (
            'downloadstring', 'frombase64string', 'encodedcommand',
            'invoke-expression', 'iex ', 'bypass', '-nop -w hidden',
            'hidden', 'virtualalloc', 'createthread', 'sleep;',
            'reflection.assembly', 'win32_', 'shellexecute')
        return any(m in lowered for m in markers)

    def _check_brute_force(self) -> List[EventAlert]:
        now = time.time()
        with self._lock:
            self._failed_logons = [
                t for t in self._failed_logons
                if now - t <= BRUTE_FORCE_WINDOW]
            count = len(self._failed_logons)
        if count >= BRUTE_FORCE_THRESHOLD:
            self._failed_logons.clear()
            return [EventAlert(
                event_id=4625, log_name='Security', technique='T1110',
                severity='HIGH', description='Brute-force logon burst',
                detail=f'{count} failed logons in '
                       f'{BRUTE_FORCE_WINDOW}s window',
                timestamp=datetime.now(timezone.utc).isoformat())]
        return []


_default_monitor: Optional[EventLogMonitor] = None
_default_lock = threading.Lock()


def get_event_log_monitor(
        callback: Optional[Callable[[EventAlert], None]] = None
) -> EventLogMonitor:
    """Process-wide singleton."""
    global _default_monitor
    with _default_lock:
        if _default_monitor is None:
            _default_monitor = EventLogMonitor(callback=callback)
        elif callback and _default_monitor.callback is None:
            _default_monitor.callback = callback
        return _default_monitor


__all__ = ['EventAlert', 'EventLogMonitor', 'get_event_log_monitor',
           'EVENT_MAP']
