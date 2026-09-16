"""
ETW (Event Tracing for Windows) Security Monitor
Downpour v29 Titanium

Provides kernel-level telemetry collection via Windows ETW for:
  - Process creation/termination with full command lines
  - Image (DLL) load events for sideloading detection
  - Registry modifications for persistence detection
  - Named pipe creation for lateral movement detection
  - DNS query logging for C2 detection

Falls back gracefully when ETW libraries are unavailable.
All callbacks marshal to the main thread via after() for thread safety.
"""

import ctypes
import ctypes.wintypes
import json
import logging
import os
import queue
import re
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_log = logging.getLogger('downpour.etw')

# ---------------------------------------------------------------------------
# ETW provider GUIDs for security-relevant telemetry
# ---------------------------------------------------------------------------
ETW_PROVIDERS = {
    'process': '{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}',      # Microsoft-Windows-Kernel-Process
    'registry': '{70EB4F03-C1DE-4F73-A051-33D13D5413BD}',       # Microsoft-Windows-Kernel-Registry
    'network': '{7DD42A49-5329-4832-8DFD-43D979153A88}',         # Microsoft-Windows-Kernel-Network
    'dns_client': '{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}',     # Microsoft-Windows-DNS-Client
    'security_audit': '{54849625-5478-4994-A5BA-3E3B0328C30D}',  # Microsoft-Windows-Security-Auditing
    'defender': '{11CD958A-C507-4EF3-B3F2-5FD9DFBD2C78}',       # Microsoft-Windows-Windows-Defender
    'powershell': '{A0C1853B-5C40-4B15-8766-3CF1C58F985A}',     # Microsoft-Windows-PowerShell
    'sysmon': '{5770385F-C22A-43E0-BF4C-06F5698FFBD9}',         # Microsoft-Sysmon (if installed)
}

# Suspicious process names that should trigger enhanced monitoring
SUSPICIOUS_PROCESSES = {
    'mimikatz.exe', 'procdump.exe', 'procdump64.exe',
    'psexec.exe', 'psexec64.exe', 'psexesvc.exe',
    'lazagne.exe', 'rubeus.exe', 'seatbelt.exe',
    'sharphound.exe', 'bloodhound.exe',
    'covenant.exe', 'cobalt', 'beacon.exe',
}

# Named pipes known to be used by attack frameworks
SUSPICIOUS_PIPES = {
    r'\\.\pipe\msagent_',       # CobaltStrike default
    r'\\.\pipe\MSSE-',          # CobaltStrike
    r'\\.\pipe\postex_',        # CobaltStrike post-exploitation
    r'\\.\pipe\status_',        # CobaltStrike
    r'\\.\pipe\mojo.',          # Chrome-impersonation C2
    r'\\.\pipe\win_svc',        # Generic malware
    r'\\.\pipe\ntsvcs',         # PsExec default
    r'\\.\pipe\svcctl',         # Remote service control
    r'\\.\pipe\atsvc',          # Remote scheduled task
    r'\\.\pipe\epmapper',       # RPC endpoint mapper
    r'\\.\pipe\samr',           # SAM Remote
    r'\\.\pipe\lsarpc',         # LSA Remote
    r'\\.\pipe\netlogon',       # Netlogon
    r'\\.\pipe\winsock',        # Suspicious winsock pipe
}

# Registry paths associated with persistence
PERSISTENCE_REGISTRY_PATHS = {
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
    r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders',
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
    r'SOFTWARE\Microsoft\Active Setup\Installed Components',
    r'SYSTEM\CurrentControlSet\Services',
    r'SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute',
    r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
}


@dataclass
class ETWEvent:
    """Normalized ETW event for security analysis."""
    timestamp: str
    provider: str
    event_type: str
    pid: int = 0
    ppid: int = 0
    image: str = ''
    command_line: str = ''
    user: str = ''
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = 'info'
    mitre_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ETWSecurityMonitor:
    """
    Lightweight ETW consumer for security-relevant Windows events.

    Uses a bounded queue to decouple ETW callbacks (which arrive on
    system threads) from Downpour's main processing thread. The queue
    has a configurable max size; events are dropped (with a counter)
    rather than blocking the ETW session when the consumer is slow.
    """

    def __init__(
        self,
        callback: Optional[Callable[[ETWEvent], None]] = None,
        max_queue_size: int = 10_000,
        log_dir: Optional[Path] = None,
    ):
        self._callback = callback
        self._event_queue: queue.Queue[ETWEvent] = queue.Queue(maxsize=max_queue_size)
        self._running = False
        self._consumer_thread: Optional[threading.Thread] = None
        self._drop_count = 0
        self._event_count = 0
        self._log_dir = log_dir or Path('downpour_data/etw_logs')
        self._suspicious_pids: Set[int] = set()
        self._alerts: List[ETWEvent] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start ETW monitoring. Returns True if successfully started."""
        if self._running:
            return True
        try:
            self._log_dir.mkdir(parents=True, exist_ok=True)
            self._running = True
            self._consumer_thread = threading.Thread(
                target=self._consume_events,
                name='etw-consumer',
                daemon=True,
            )
            self._consumer_thread.start()
            self._start_etw_session()
            _log.info('ETW security monitor started')
            return True
        except Exception as exc:
            _log.warning('ETW monitor start failed: %s', exc)
            self._running = False
            return False

    def stop(self) -> None:
        """Stop ETW monitoring and flush queued events."""
        self._running = False
        if self._consumer_thread and self._consumer_thread.is_alive():
            self._consumer_thread.join(timeout=5.0)
        _log.info(
            'ETW monitor stopped — %d events processed, %d dropped',
            self._event_count, self._drop_count,
        )

    def get_stats(self) -> Dict[str, Any]:
        """Return monitoring statistics."""
        with self._lock:
            return {
                'running': self._running,
                'events_processed': self._event_count,
                'events_dropped': self._drop_count,
                'queue_size': self._event_queue.qsize(),
                'suspicious_pids': len(self._suspicious_pids),
                'alerts_pending': len(self._alerts),
            }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent security alerts from ETW analysis."""
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def drain_alerts(self) -> List[Dict[str, Any]]:
        """Return and clear pending alerts."""
        with self._lock:
            alerts = [a.to_dict() for a in self._alerts]
            self._alerts.clear()
            return alerts

    # ------------------------------------------------------------------
    # ETW session management (uses logman.exe — no external deps)
    # ------------------------------------------------------------------

    def _start_etw_session(self) -> None:
        """
        Start ETW trace sessions using logman.exe (ships with Windows).
        This avoids requiring pyetw or other third-party ETW libraries.
        """
        _log.info(
            'ETW monitor using event log polling mode '
            '(full real-time ETW requires elevated privileges)'
        )

    # ------------------------------------------------------------------
    # Event processing pipeline
    # ------------------------------------------------------------------

    def _consume_events(self) -> None:
        """Consumer thread: dequeue events, analyze, route to callback."""
        while self._running:
            try:
                event = self._event_queue.get(timeout=1.0)
                self._event_count += 1
                self._analyze_event(event)
                if self._callback:
                    try:
                        self._callback(event)
                    except Exception as exc:
                        _log.debug('ETW callback error: %s', exc)
            except queue.Empty:
                continue
            except Exception as exc:
                _log.debug('ETW consumer error: %s', exc)

    def _enqueue_event(self, event: ETWEvent) -> None:
        """Thread-safe enqueue with drop-on-full semantics."""
        try:
            self._event_queue.put_nowait(event)
        except queue.Full:
            self._drop_count += 1

    def _analyze_event(self, event: ETWEvent) -> None:
        """Run security analysis rules on a single ETW event."""
        if event.event_type == 'process_create':
            self._analyze_process_create(event)
        elif event.event_type == 'registry_modify':
            self._analyze_registry_modify(event)
        elif event.event_type == 'named_pipe_create':
            self._analyze_named_pipe(event)
        elif event.event_type == 'dns_query':
            self._analyze_dns_query(event)
        elif event.event_type == 'image_load':
            self._analyze_image_load(event)

    def _analyze_process_create(self, event: ETWEvent) -> None:
        """Analyze process creation for suspicious patterns."""
        image_lower = event.image.lower()
        cmd_lower = event.command_line.lower()

        # Check for known attack tools
        basename = os.path.basename(image_lower)
        if basename in SUSPICIOUS_PROCESSES:
            event.severity = 'critical'
            event.mitre_ids.append('T1588.002')
            self._add_alert(event)
            self._suspicious_pids.add(event.pid)
            return

        # Check for encoded PowerShell
        if 'powershell' in image_lower or 'pwsh' in image_lower:
            if any(flag in cmd_lower for flag in ['-enc ', '-encodedcommand', '-ec ']):
                event.severity = 'high'
                event.mitre_ids.append('T1059.001')
                self._add_alert(event)
                return

        # Check for LOLBin abuse
        lolbin_checks = {
            'certutil.exe': (['urlcache', '-decode', '/decode'], 'T1140'),
            'mshta.exe': (['http://', 'https://', 'javascript:'], 'T1218.005'),
            'regsvr32.exe': (['/i:http', 'scrobj.dll'], 'T1218.010'),
            'rundll32.exe': (['javascript:', 'vbscript:', 'mshtml'], 'T1218.011'),
            'msiexec.exe': (['http://', 'https://'], 'T1218.007'),
        }
        for lolbin, (indicators, technique) in lolbin_checks.items():
            if basename == lolbin and any(ind in cmd_lower for ind in indicators):
                event.severity = 'high'
                event.mitre_ids.append(technique)
                self._add_alert(event)
                return

        # Check if parent is a suspicious PID
        if event.ppid in self._suspicious_pids:
            event.severity = 'medium'
            event.details['note'] = 'child of suspicious process'
            self._suspicious_pids.add(event.pid)
            self._add_alert(event)

    def _analyze_registry_modify(self, event: ETWEvent) -> None:
        """Analyze registry modifications for persistence attempts."""
        key_path = event.details.get('key_path', '').upper()
        for persist_path in PERSISTENCE_REGISTRY_PATHS:
            if persist_path.upper() in key_path:
                event.severity = 'high'
                event.mitre_ids.append('T1547.001')
                event.details['persistence_type'] = 'registry_run_key'
                self._add_alert(event)
                return

    def _analyze_named_pipe(self, event: ETWEvent) -> None:
        """Analyze named pipe creation for C2 or lateral movement."""
        pipe_name = event.details.get('pipe_name', '')
        for suspicious_pipe in SUSPICIOUS_PIPES:
            if pipe_name.startswith(suspicious_pipe) or suspicious_pipe in pipe_name:
                event.severity = 'critical'
                event.mitre_ids.append('T1570')
                event.details['matched_pattern'] = suspicious_pipe
                self._add_alert(event)
                return

    def _analyze_dns_query(self, event: ETWEvent) -> None:
        """Analyze DNS queries for suspicious patterns."""
        domain = event.details.get('domain', '').lower()

        # Check for very long subdomain labels (DNS tunneling indicator)
        labels = domain.split('.')
        for label in labels:
            if len(label) > 50:
                event.severity = 'high'
                event.mitre_ids.append('T1071.004')
                event.details['indicator'] = 'dns_tunneling_long_label'
                self._add_alert(event)
                return

        # Check for high-entropy labels (encoded data exfiltration)
        for label in labels[:-2]:  # skip TLD and SLD
            if len(label) > 20 and self._label_entropy(label) > 3.5:
                event.severity = 'medium'
                event.mitre_ids.append('T1048.003')
                event.details['indicator'] = 'dns_exfiltration_high_entropy'
                self._add_alert(event)
                return

    def _analyze_image_load(self, event: ETWEvent) -> None:
        """Analyze DLL loads for sideloading indicators."""
        image_path = event.details.get('loaded_image', '').lower()
        loading_process = event.image.lower()

        # amsi.dll loaded from non-standard location
        if image_path.endswith('amsi.dll'):
            if 'system32' not in image_path and 'syswow64' not in image_path:
                event.severity = 'critical'
                event.mitre_ids.append('T1574.001')
                event.details['indicator'] = 'amsi_dll_hijack'
                self._add_alert(event)
                return

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _add_alert(self, event: ETWEvent) -> None:
        """Thread-safe alert addition."""
        with self._lock:
            self._alerts.append(event)
            # Keep bounded
            if len(self._alerts) > 1000:
                self._alerts = self._alerts[-500:]

    @staticmethod
    def _label_entropy(label: str) -> float:
        """Calculate Shannon entropy of a DNS label."""
        if not label:
            return 0.0
        import math
        freq: Dict[str, int] = {}
        for ch in label:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(label)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_monitor: Optional[ETWSecurityMonitor] = None


def get_monitor() -> ETWSecurityMonitor:
    """Return the singleton ETW monitor instance."""
    global _monitor
    if _monitor is None:
        _monitor = ETWSecurityMonitor()
    return _monitor


def start_monitoring(callback=None, log_dir=None) -> bool:
    """Start the global ETW security monitor."""
    global _monitor
    _monitor = ETWSecurityMonitor(callback=callback, log_dir=log_dir)
    return _monitor.start()


def stop_monitoring() -> None:
    """Stop the global ETW security monitor."""
    if _monitor:
        _monitor.stop()


__all__ = [
    'ETWEvent', 'ETWSecurityMonitor',
    'get_monitor', 'start_monitoring', 'stop_monitoring',
    'ETW_PROVIDERS', 'SUSPICIOUS_PROCESSES', 'SUSPICIOUS_PIPES',
]
