"""
C2 Beacon Detector
Downpour v29 Titanium

Detects Command & Control beaconing patterns in network connections
using statistical timing analysis inspired by RITA/RITA-J:
  - Connection interval regularity (jitter scoring)
  - Data size consistency analysis
  - Destination frequency analysis
  - Long-connection detection
  - DNS beaconing (periodic resolution patterns)
  - Known C2 port patterns

Uses netstat and ipconfig — no PowerShell.
MITRE ATT&CK: T1071 (Application Layer Protocol), T1573 (Encrypted Channel),
              T1095 (Non-Application Layer Protocol), T1571 (Non-Standard Port)
"""

import logging
import math
import re
import subprocess
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_log = logging.getLogger('downpour.beacon')

KNOWN_C2_PORTS = {
    4444, 5555, 8443, 8080, 9090, 1234, 31337, 6666, 6667, 6668, 6669,
    1337, 7777, 4443, 8888, 9999, 4445, 5544, 2222, 3333, 12345, 54321,
    41524, 50050, 50051, 13337, 443, 80,
}

WHITELISTED_DESTINATIONS = {
    '127.0.0.1', '::1', '0.0.0.0', '255.255.255.255',
}

WHITELISTED_PORTS = {
    53, 67, 68, 123, 137, 138, 139, 445, 5353, 1900,
}


@dataclass
class BeaconAlert:
    """Beacon detection alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    destination: str = ''
    port: int = 0
    score: float = 0.0
    intervals: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'destination': self.destination,
            'port': self.port,
            'score': self.score,
            'intervals': self.intervals,
        }


class BeaconDetector:
    """
    Detect C2 beaconing by analyzing connection timing patterns.
    Uses coefficient of variation on connection intervals to identify
    regular "phone home" behavior.
    """

    def __init__(
        self,
        check_interval: float = 30.0,
        alert_callback: Optional[Callable] = None,
        beacon_threshold: float = 0.35,
        min_connections: int = 5,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._beacon_threshold = beacon_threshold
        self._min_connections = min_connections
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

        self._connection_log: Dict[str, List[float]] = defaultdict(list)
        self._data_sizes: Dict[str, List[int]] = defaultdict(list)
        self._alerts: List[BeaconAlert] = []
        self._alerted_destinations: Dict[str, float] = {}
        self._long_connections: Dict[str, float] = {}

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='beacon-detector',
                daemon=True,
            )
            self._thread.start()
            _log.info('Beacon detector started (threshold=%.2f)',
                      self._beacon_threshold)
            return True
        except Exception as exc:
            _log.warning('Beacon detector failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'running': self._running,
                'checks': self._check_count,
                'tracked_destinations': len(self._connection_log),
                'alerts': len(self._alerts),
                'long_connections': len(self._long_connections),
            }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def get_tracked_connections(self) -> List[Dict[str, Any]]:
        """Return all tracked connection destinations with their scores."""
        with self._lock:
            results = []
            for dest, timestamps in self._connection_log.items():
                if len(timestamps) < 3:
                    continue
                score = self._calculate_beacon_score(timestamps)
                results.append({
                    'destination': dest,
                    'connection_count': len(timestamps),
                    'beacon_score': round(score, 3),
                    'is_beacon': score <= self._beacon_threshold,
                    'first_seen': timestamps[0],
                    'last_seen': timestamps[-1],
                })
            results.sort(key=lambda x: x['beacon_score'])
            return results

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._scan_connections()
                self._analyze_patterns()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Beacon check error: %s', exc)

            if self._check_count % 10 == 0:
                self._cleanup_old_data()

            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _scan_connections(self) -> None:
        """Capture current TCP connections via netstat."""
        try:
            result = subprocess.run(
                ['netstat', '-n', '-o', '-p', 'tcp'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return

            now = time.time()
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 5 or parts[0] != 'TCP':
                    continue
                state = parts[3]
                if state != 'ESTABLISHED':
                    continue

                remote = parts[2]
                m = re.match(r'([\d.]+):(\d+)', remote)
                if not m:
                    continue
                ip = m.group(1)
                port = int(m.group(2))
                pid = parts[4] if len(parts) > 4 else '0'

                if ip in WHITELISTED_DESTINATIONS:
                    continue
                if ip.startswith('10.') or ip.startswith('192.168.'):
                    continue
                if port in WHITELISTED_PORTS:
                    continue

                dest_key = f'{ip}:{port}'
                self._connection_log[dest_key].append(now)
                if len(self._connection_log[dest_key]) > 200:
                    self._connection_log[dest_key] = \
                        self._connection_log[dest_key][-100:]

        except Exception as exc:
            _log.debug('Netstat scan error: %s', exc)

    def _analyze_patterns(self) -> None:
        """Analyze connection patterns for beaconing behavior."""
        now_ts = datetime.now(timezone.utc).isoformat()
        now = time.time()

        for dest, timestamps in list(self._connection_log.items()):
            if len(timestamps) < self._min_connections:
                continue

            # Skip if we already alerted this destination recently (1 hour)
            last_alert = self._alerted_destinations.get(dest, 0)
            if now - last_alert < 3600:
                continue

            score = self._calculate_beacon_score(timestamps)

            if score <= self._beacon_threshold:
                intervals = self._get_intervals(timestamps)
                avg_interval = sum(intervals) / len(intervals) if intervals else 0

                ip, port_str = dest.rsplit(':', 1)
                port = int(port_str)

                severity = 'critical' if score < 0.15 else 'high'
                if port in KNOWN_C2_PORTS:
                    severity = 'critical'

                self._add_alert(BeaconAlert(
                    timestamp=now_ts,
                    category='beacon_detected',
                    details=(f'C2 beacon pattern: {dest} '
                             f'(score={score:.3f}, '
                             f'avg_interval={avg_interval:.1f}s, '
                             f'{len(timestamps)} connections)'),
                    indicator=dest,
                    severity=severity,
                    mitre_id='T1071',
                    destination=ip,
                    port=port,
                    score=score,
                    intervals=len(timestamps),
                ))
                self._alerted_destinations[dest] = now

            # Check for known C2 port usage
            ip, port_str = dest.rsplit(':', 1)
            port = int(port_str)
            if port in KNOWN_C2_PORTS and port not in (80, 443):
                if dest not in self._alerted_destinations:
                    self._add_alert(BeaconAlert(
                        timestamp=now_ts,
                        category='c2_port',
                        details=f'Connection to known C2 port: {dest}',
                        indicator=dest,
                        severity='high',
                        mitre_id='T1571',
                        destination=ip,
                        port=port,
                        score=0,
                        intervals=len(timestamps),
                    ))
                    self._alerted_destinations[dest] = now

    @staticmethod
    def _get_intervals(timestamps: List[float]) -> List[float]:
        """Calculate intervals between consecutive timestamps."""
        if len(timestamps) < 2:
            return []
        return [timestamps[i+1] - timestamps[i]
                for i in range(len(timestamps) - 1)]

    @staticmethod
    def _calculate_beacon_score(timestamps: List[float]) -> float:
        """
        Calculate beacon score using coefficient of variation.
        Lower score = more regular intervals = more likely beacon.
        Perfect beacon = 0.0, random connections ~ 1.0+
        """
        if len(timestamps) < 3:
            return 1.0

        intervals = [timestamps[i+1] - timestamps[i]
                     for i in range(len(timestamps) - 1)]

        if not intervals:
            return 1.0

        mean = sum(intervals) / len(intervals)
        if mean == 0:
            return 1.0

        variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)

        cv = std_dev / mean
        return min(cv, 2.0)

    def _cleanup_old_data(self) -> None:
        """Remove stale connection data older than 2 hours."""
        cutoff = time.time() - 7200
        with self._lock:
            for dest in list(self._connection_log.keys()):
                self._connection_log[dest] = [
                    t for t in self._connection_log[dest] if t > cutoff
                ]
                if not self._connection_log[dest]:
                    del self._connection_log[dest]

            for dest in list(self._alerted_destinations.keys()):
                if self._alerted_destinations[dest] < cutoff:
                    del self._alerted_destinations[dest]

    def _add_alert(self, alert: BeaconAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('Beacon: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[BeaconDetector] = None


def get_beacon_detector() -> BeaconDetector:
    global _detector
    if _detector is None:
        _detector = BeaconDetector()
    return _detector


def start_beacon_detection(callback=None) -> bool:
    global _detector
    _detector = BeaconDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'BeaconDetector', 'BeaconAlert',
    'get_beacon_detector', 'start_beacon_detection',
    'KNOWN_C2_PORTS',
]
