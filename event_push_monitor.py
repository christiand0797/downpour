"""
EVENT PUSH MONITOR — v29.48 (improvement catalog item 1c — push telemetry)
================================================================================
Closes the 15-second polling gap of event_log_monitor: instead of asking
"anything new?" on a timer, EvtSubscribe makes Windows PUSH each event to
a callback the instant it is written. Service installs, task creation,
log-clearing, brute-force bursts and hostile PowerShell script blocks are
visible with zero detection latency (poll-based evasion defeated).

  * Same hostile-event set as event_log_monitor (7045/4698/4699/4720/
    4732/1102/104/4625-burst/4104) and the same alert shape, so both
    bridges feed the pipeline uniformly.
  * 4104 script blocks are additionally evaluated through sigma_engine
    (optional import) — push-delivered script blocks get the full Sigma
    rule treatment, not just the LOW informational alert.
  * 4625 brute-force burst detection (10 failures / 300 s) is shared
    across channels.
  * start_push() returns {covered: [...], failed: [...]} so the caller
    can drop the poll monitor's bookmarks for covered channels — no
    duplicate alerts, poll stays as the fallback for channels push could
    not subscribe (missing channel, non-admin Security log).

Threading: callbacks arrive on a native Windows thread; emit is a plain
callback (the app bridge is thread-safe via the alert queue). Every
failure is tolerated — a channel that cannot subscribe is reported in
'failed' and never breaks the others. Never raises into the caller.
"""
from __future__ import annotations

import logging
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

_log = logging.getLogger(__name__)

try:
    import win32evtlog
    _EVT_AVAILABLE = True
except ImportError:
    win32evtlog = None
    _EVT_AVAILABLE = False

try:
    import sigma_engine
    _SIGMA_AVAILABLE = True
except ImportError:
    sigma_engine = None
    _SIGMA_AVAILABLE = False

try:
    import amsi_integration
    _AMSI_AVAILABLE = True
except ImportError:
    amsi_integration = None
    _AMSI_AVAILABLE = False

_AMSI_MALICIOUS_RESULT = 32768          # AMSI_RESULT_DETECTED (0x8000)

# Event ID -> (mitre_technique, severity, description)
# Mirrors event_log_monitor.EVENT_MAP — keep both in sync.
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
}
BRUTE_FORCE_THRESHOLD = 10          # 4625 events within window
BRUTE_FORCE_WINDOW = 300.0          # seconds

# Channels watched, in coverage priority order
CHANNELS = (
    'Security',
    'System',
    'Microsoft-Windows-PowerShell/Operational',
)

_EVTID_RE = re.compile(r'<EventID[^>]*>(\d+)</EventID>')
_SBT_RE = re.compile(r"<Data Name='ScriptBlockText'>(.*?)</Data>",
                     re.DOTALL)
_SUBJ_RE = re.compile(r"<Data Name='SubjectUserName'>(.*?)</Data>")


@dataclass
class EventPushAlert:
    """One push-delivered notable event (EventAlert-compatible fields)."""
    event_id: int
    log_name: str
    technique: str
    severity: str
    description: str
    detail: str
    timestamp: str


def parse_event_id(xml: str) -> Optional[int]:
    """Extract the EventID from rendered event XML (None if absent)."""
    m = _EVTID_RE.search(xml or '')
    return int(m.group(1)) if m else None


def extract_script_block(xml: str) -> str:
    """Extract ScriptBlockText from a 4104 event XML ('' if absent)."""
    m = _SBT_RE.search(xml or '')
    return m.group(1)[:8000] if m else ''


class EventPushMonitor:
    """Subscribes to Windows event channels via EvtSubscribe (push).

    One instance per process. Callback signature: callable(EventPushAlert)
    invoked from a native Windows thread — keep it fast and thread-safe.
    """

    def __init__(self, callback: Optional[
            Callable[[EventPushAlert], None]] = None):
        self.callback = callback
        self._lock = threading.Lock()
        self._handles: Dict[str, Any] = {}
        self._covered: List[str] = []
        self._failed: Dict[str, str] = {}
        self._failed_logons: deque = deque(maxlen=200)
        self._started = False
        self.alerts_emitted = 0

    # -- public API ---------------------------------------------------------
    def start_push(self) -> Dict[str, List[str]]:
        """Subscribe every channel with EvtSubscribeToFutureEvents.
        Returns {'covered': [...], 'failed': [...]}. Never raises."""
        if not _EVT_AVAILABLE:
            return {'covered': [],
                    'failed': [f'{c}: win32evtlog unavailable'
                               for c in CHANNELS]}
        with self._lock:
            if self._started:
                return {'covered': list(self._covered),
                        'failed': list(self._failed)}
        for channel in CHANNELS:
            try:
                handle = win32evtlog.EvtSubscribe(
                    channel,
                    win32evtlog.EvtSubscribeToFutureEvents,
                    None, self._on_event, None, None, None)
                if handle:
                    with self._lock:
                        self._handles[channel] = handle
                        self._covered.append(channel)
                else:
                    with self._lock:
                        self._failed[channel] = 'subscribe returned None'
            except Exception as exc:
                msg = str(exc)[:120]
                with self._lock:
                    self._failed[channel] = msg
                _log.debug('event push subscribe %s: %s', channel, msg)
        with self._lock:
            self._started = True
            result = {'covered': list(self._covered),
                      'failed': list(self._failed)}
        _log.info('event push monitor: covered=%s failed=%s',
                  result['covered'], result['failed'])
        return result

    def stop(self) -> None:
        """Close every subscription handle (thread-safe)."""
        with self._lock:
            handles = list(self._handles.items())
            self._handles.clear()
            self._started = False
        for _channel, handle in handles:
            try:
                win32evtlog.EvtClose(handle)
            except Exception as exc:
                _log.debug('event push close: %s', exc)

    def is_running(self) -> bool:
        with self._lock:
            return bool(self._started and self._handles)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {'started': self._started,
                    'covered': list(self._covered),
                    'failed': dict(self._failed),
                    'alerts_emitted': self.alerts_emitted}

    # -- event handling (native thread) ---------------------------------
    def _emit(self, alert: EventPushAlert) -> None:
        self.alerts_emitted += 1
        if self.callback:
            try:
                self.callback(alert)
            except Exception:
                _log.exception('event push callback failed')

    def _amsi_evaluate(self, script: str, now: str) -> None:
        """v29.49: run a pushed 4104 script block through the AMSI
        integration (catalog 5b) — the real AV-engine verdict via
        AmsiScanString plus the obfuscation/pattern analyzer. Note: we use
        the integration's context WITHOUT .start() — its own wevtutil poll
        loop is redundant with push delivery; we only want the AMSI scan
        and the pattern engine. Never raises."""
        try:
            integration = amsi_integration.get_amsi_integration()
            event = amsi_integration.PowerShellEvent(
                timestamp=time.time(), event_id=4104, sequence_number=0,
                script_block_text=script[:32000], script_block_id='')
            integration._analyze_script(event)
            if event.is_suspicious:
                self._emit(EventPushAlert(
                    event_id=4104, log_name='PowerShell',
                    technique=','.join(event.mitre_techniques[:3])
                    or 'T1059.001',
                    severity=event.severity,
                    description='[AMSI-PS] Suspicious PowerShell content',
                    detail='; '.join(event.suspicious_patterns[:4])[:160],
                    timestamp=now))
            if integration.amsi_initialized:
                scan = integration.scan_string(script[:32000],
                                               'downpour-4104')
                if scan is not None and scan.result >= _AMSI_MALICIOUS_RESULT:
                    self._emit(EventPushAlert(
                        event_id=4104, log_name='PowerShell',
                        technique='T1059.001', severity='CRITICAL',
                        description='[AMSI] AV engine flagged script content',
                        detail=f'AMSI result {scan.result} '
                               f'(name: {scan.content_name})', timestamp=now))
        except Exception as exc:              # defensive — never raise
            _log.debug('push amsi bridge: %s', exc)

    def _on_event(self, action, context, event_handle) -> None:
        """EvtSubscribe callback — runs on a native Windows thread."""
        try:
            if action != win32evtlog.EvtSubscribeActionDeliver:
                return
            xml = win32evtlog.EvtRender(event_handle,
                                        win32evtlog.EvtRenderEventXml)
            event_id = parse_event_id(xml)
            if event_id is None or event_id not in EVENT_MAP:
                return
            self._handle_event(event_id, xml)
        except Exception as exc:          # defensive — never raise
            _log.debug('event push _on_event: %s', exc)

    def _handle_event(self, event_id: int, xml: str) -> None:
        mapped = EVENT_MAP.get(event_id)
        if mapped is None:
            return                          # unwatched event id
        technique, severity, description = mapped
        detail = ''
        now = time.strftime('%Y-%m-%d %H:%M:%S')
        if event_id == 4625:
            # brute-force burst detection across channels
            subject = ''
            m = _SUBJ_RE.search(xml)
            if m:
                subject = m.group(1)
            self._failed_logons.append(time.time())
            recent = [t for t in self._failed_logons
                      if time.time() - t <= BRUTE_FORCE_WINDOW]
            self._failed_logons.clear()
            self._failed_logons.extend(recent)
            if len(recent) < BRUTE_FORCE_THRESHOLD:
                return                    # single failure — too noisy
            severity = 'HIGH'
            description = 'Logon failure burst (brute force?)'
            detail = (f'{len(recent)} failed logons in '
                      f'{BRUTE_FORCE_WINDOW:.0f}s window'
                      + (f' (last subject: {subject})' if subject else ''))
        elif event_id == 4104:
            script = extract_script_block(xml)
            detail = script[:160]
            if sigma_engine is not None and script:
                try:
                    for f in sigma_engine.match_script_block(script):
                        self._emit(EventPushAlert(
                            event_id=4104, log_name='PowerShell',
                            technique=f.technique or 'T1059.001',
                            severity=f.level,
                            description=f'[SIGMA] {f.title}',
                            detail=f.detail, timestamp=now))
                except Exception as exc:  # defensive
                    _log.debug('push sigma bridge: %s', exc)
            if _AMSI_AVAILABLE and script:
                self._amsi_evaluate(script, now)
        self._emit(EventPushAlert(
            event_id=event_id,
            log_name='windows-event',
            technique=technique,
            severity=severity,
            description=description,
            detail=detail,
            timestamp=now))


_module_monitor: Optional[EventPushMonitor] = None


def start_push(callback: Callable[[EventPushAlert], None]
               ) -> Dict[str, List[str]]:
    """Install the process-wide push monitor (idempotent). Returns
    {'covered': [...], 'failed': [...]}."""
    global _module_monitor
    if _module_monitor is None:
        _module_monitor = EventPushMonitor(callback)
    return _module_monitor.start_push()


def get_push_monitor() -> Optional[EventPushMonitor]:
    return _module_monitor


__all__ = ['EventPushAlert', 'EventPushMonitor', 'start_push',
           'get_push_monitor', 'parse_event_id', 'extract_script_block',
           'EVENT_MAP', 'CHANNELS', 'BRUTE_FORCE_THRESHOLD',
           'BRUTE_FORCE_WINDOW', '_EVT_AVAILABLE', '_SIGMA_AVAILABLE',
           '_AMSI_AVAILABLE', '_AMSI_MALICIOUS_RESULT']
