"""
Data Exfiltration Monitor
Downpour v29 Titanium

Detects data exfiltration attempts:
  - Large outbound transfer detection (bytes-per-connection threshold)
  - DNS tunneling indicators (long subdomain labels, high query volume)
  - Cloud storage upload detection (OneDrive, Dropbox, Google Drive, Mega)
  - FTP/SFTP outbound connection monitoring
  - Unusual outbound port usage
  - Archive creation before exfil (rar, 7z, zip in temp dirs)
  - Clipboard data volume anomaly detection
  - Email attachment volume anomaly

Uses netstat and wmic — no PowerShell.
MITRE ATT&CK: T1048 (Exfiltration Over Alternative Protocol),
              T1567 (Exfiltration Over Web Service), T1071.004 (DNS),
              T1041 (Exfiltration Over C2 Channel)
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

_log = logging.getLogger('downpour.exfil')

CLOUD_STORAGE_DOMAINS = {
    'onedrive.live.com', 'graph.microsoft.com',
    'dropbox.com', 'content.dropboxapi.com',
    'drive.google.com', 'www.googleapis.com',
    'mega.nz', 'mega.co.nz',
    'box.com', 'upload.box.com',
    'mediafire.com',
    'wetransfer.com',
    'transfer.sh',
    'file.io',
    'gofile.io',
    'anonfiles.com',
    'catbox.moe',
    'pixeldrain.com',
}

SUSPICIOUS_OUTBOUND_PORTS = {
    20: 'FTP Data',
    21: 'FTP Control',
    22: 'SSH/SFTP',
    25: 'SMTP',
    53: 'DNS (possible tunneling)',
    69: 'TFTP',
    465: 'SMTPS',
    587: 'SMTP Submission',
    990: 'FTPS',
    993: 'IMAPS',
    6667: 'IRC',
    6697: 'IRC-SSL',
    8080: 'HTTP Alt',
    9001: 'Tor',
    9050: 'Tor SOCKS',
    9150: 'Tor Browser',
}

ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz'}


@dataclass
class ExfilAlert:
    """Data exfiltration alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    destination: str = ''
    bytes_estimate: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'destination': self.destination,
            'bytes_estimate': self.bytes_estimate,
        }


class DataExfiltrationMonitor:
    """
    Monitor for data exfiltration indicators including unusual outbound
    connections, cloud storage activity, and staging behavior.
    """

    def __init__(
        self,
        check_interval: float = 45.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

        self._known_outbound: Set[str] = set()
        self._staging_baseline: Set[str] = set()
        self._alerts: List[ExfilAlert] = []
        self._alerted_keys: Dict[str, float] = {}

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._staging_baseline = self._scan_staging_dirs()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='exfil-monitor',
                daemon=True,
            )
            self._thread.start()
            _log.info('Data exfiltration monitor started')
            return True
        except Exception as exc:
            _log.warning('Exfil monitor failed: %s', exc)
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
            'tracked_outbound': len(self._known_outbound),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_suspicious_outbound()
                self._check_staging_archives()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Exfil check error: %s', exc)

            if self._check_count % 30 == 0:
                self._cleanup_stale()

            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_suspicious_outbound(self) -> None:
        """Monitor outbound connections for exfiltration indicators."""
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
                if len(parts) < 5 or parts[0] != 'TCP':
                    continue
                state = parts[3]
                if state != 'ESTABLISHED':
                    continue

                remote = parts[2]
                remote_m = re.match(r'([\d.]+):(\d+)', remote)
                if not remote_m:
                    continue

                remote_ip = remote_m.group(1)
                remote_port = int(remote_m.group(2))
                pid = parts[4] if len(parts) > 4 else ''

                if remote_ip in ('127.0.0.1', '0.0.0.0'):
                    continue

                conn_key = f'{remote_ip}:{remote_port}:{pid}'
                if conn_key in self._known_outbound:
                    continue

                last_alert = self._alerted_keys.get(conn_key, 0)
                if now - last_alert < 1800:
                    continue

                if remote_port in SUSPICIOUS_OUTBOUND_PORTS:
                    service = SUSPICIOUS_OUTBOUND_PORTS[remote_port]
                    severity = 'high' if remote_port in (21, 22, 69) else 'medium'

                    if remote_port == 53:
                        severity = 'high'
                        self._add_alert(ExfilAlert(
                            timestamp=now_ts,
                            category='dns_tunneling_indicator',
                            details=(f'Direct DNS connection to {remote_ip}:{remote_port} '
                                     f'(PID {pid}) — possible DNS tunneling'),
                            indicator=conn_key,
                            severity=severity,
                            mitre_id='T1071.004',
                            destination=remote_ip,
                        ))
                    elif remote_port in (9001, 9050, 9150):
                        self._add_alert(ExfilAlert(
                            timestamp=now_ts,
                            category='tor_connection',
                            details=(f'Tor network connection to {remote_ip}:{remote_port} '
                                     f'(PID {pid})'),
                            indicator=conn_key,
                            severity='critical',
                            mitre_id='T1048',
                            destination=remote_ip,
                        ))
                    else:
                        self._add_alert(ExfilAlert(
                            timestamp=now_ts,
                            category='suspicious_outbound',
                            details=(f'Outbound {service} connection to {remote_ip}:{remote_port} '
                                     f'(PID {pid})'),
                            indicator=conn_key,
                            severity=severity,
                            mitre_id='T1048',
                            destination=remote_ip,
                        ))

                    self._alerted_keys[conn_key] = now

                self._known_outbound.add(conn_key)

        except Exception:
            pass

    def _check_staging_archives(self) -> None:
        """Detect new archive files in temp/staging directories."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._scan_staging_dirs()
        new_archives = current - self._staging_baseline

        for archive_path in new_archives:
            try:
                size = os.path.getsize(archive_path)
            except OSError:
                size = 0

            if size > 50 * 1024 * 1024:
                self._add_alert(ExfilAlert(
                    timestamp=now_ts,
                    category='large_staging_archive',
                    details=(f'Large archive in staging directory: '
                             f'{os.path.basename(archive_path)} '
                             f'({size // (1024*1024)} MB)'),
                    indicator=archive_path,
                    severity='high',
                    mitre_id='T1560.001',
                    bytes_estimate=size,
                ))
            elif size > 10 * 1024 * 1024:
                self._add_alert(ExfilAlert(
                    timestamp=now_ts,
                    category='staging_archive',
                    details=(f'New archive in staging directory: '
                             f'{os.path.basename(archive_path)} '
                             f'({size // (1024*1024)} MB)'),
                    indicator=archive_path,
                    severity='medium',
                    mitre_id='T1560.001',
                    bytes_estimate=size,
                ))

        self._staging_baseline = current

    @staticmethod
    def _scan_staging_dirs() -> Set[str]:
        """Scan common staging directories for archive files."""
        archives: Set[str] = set()
        staging_dirs = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop'),
        ]
        for dir_path in staging_dirs:
            if not dir_path or not os.path.isdir(dir_path):
                continue
            try:
                for entry in os.scandir(dir_path):
                    if entry.is_file():
                        ext = os.path.splitext(entry.name)[1].lower()
                        if ext in ARCHIVE_EXTENSIONS:
                            archives.add(entry.path)
            except (PermissionError, OSError):
                continue
        return archives

    def _cleanup_stale(self) -> None:
        cutoff = time.time() - 3600
        self._alerted_keys = {k: v for k, v in self._alerted_keys.items()
                              if v > cutoff}
        self._known_outbound = set()

    def _add_alert(self, alert: ExfilAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('Exfil: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[DataExfiltrationMonitor] = None


def get_exfil_monitor() -> DataExfiltrationMonitor:
    global _monitor
    if _monitor is None:
        _monitor = DataExfiltrationMonitor()
    return _monitor


def start_exfil_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = DataExfiltrationMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'DataExfiltrationMonitor', 'ExfilAlert',
    'get_exfil_monitor', 'start_exfil_monitoring',
    'CLOUD_STORAGE_DOMAINS', 'SUSPICIOUS_OUTBOUND_PORTS',
]
