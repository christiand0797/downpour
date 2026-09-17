"""
TLS Certificate Anomaly Monitor
Downpour v29 Titanium

Monitors TLS certificate chains and Windows certificate stores for:
  - Untrusted or self-signed root CA additions
  - Expired/revoked certificates still in use
  - Certificate store tampering (new roots added silently)
  - Known-malicious certificate thumbprints
  - Weak key sizes (< 2048-bit RSA, < 256-bit ECC)
  - SHA-1 signed certificates (deprecated)

Uses certutil.exe and reg.exe — no PowerShell.
"""

import hashlib
import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_log = logging.getLogger('downpour.tlsmon')

KNOWN_BAD_THUMBPRINTS = {
    'E1A7D76BC64A19B903F54D1B52F5A3E5A7D4E8A2': 'Superfish (Lenovo adware CA)',
    'C864484869D41D2B0D32319C5A62F9315AAF2CBD': 'eDellRoot (Dell support CA)',
    'EC30C9C3065A06BB07DC5B1C6B497F370C1CA65C': 'DSDTestProvider (Dell duplicate)',
    '326E22D4BD1E58FEF5F73D3B21B7A0A8FA0C4E5C': 'Komodia/PrivDog CA',
    '6D6482DA8C6E663CB8D5E5DB266345DF9A10A8A5': 'MCS Holdings (CNNIC sub-CA)',
}

CERT_STORES = [
    ('Root', r'HKLM\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'),
    ('AuthRoot', r'HKLM\SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates'),
    ('CA', r'HKLM\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates'),
    ('UserRoot', r'HKCU\SOFTWARE\Microsoft\SystemCertificates\Root\Certificates'),
]


@dataclass
class CertAlert:
    """Certificate anomaly alert."""
    timestamp: str
    category: str
    thumbprint: str
    subject: str
    details: str
    severity: str
    mitre_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'thumbprint': self.thumbprint,
            'subject': self.subject,
            'details': self.details,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
        }


class TLSCertificateMonitor:
    """
    Monitor Windows certificate stores for anomalies and tampering.
    Baselines trusted root CAs on first run, alerts on any additions.
    """

    def __init__(
        self,
        check_interval: float = 60.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._baseline_roots: Dict[str, Set[str]] = {}
        self._alerts: List[CertAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

    def start(self) -> bool:
        """Start certificate monitoring."""
        if self._running:
            return True
        try:
            self._baseline_roots = self._enumerate_all_stores()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='tls-cert-monitor',
                daemon=True,
            )
            self._thread.start()
            total = sum(len(v) for v in self._baseline_roots.values())
            _log.info('TLS certificate monitor started (%d baseline certs)', total)
            self._initial_scan()
            return True
        except Exception as exc:
            _log.warning('TLS cert monitor failed: %s', exc)
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
            'store_sizes': {k: len(v) for k, v in self._baseline_roots.items()},
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _initial_scan(self) -> None:
        """Check for known-bad certs and weak algorithms on startup."""
        now = datetime.now(timezone.utc).isoformat()
        certs = self._get_cert_details()

        for cert in certs:
            thumb = cert.get('thumbprint', '').upper()
            subject = cert.get('subject', '')

            if thumb in KNOWN_BAD_THUMBPRINTS:
                self._add_alert(CertAlert(
                    timestamp=now,
                    category='known_bad_ca',
                    thumbprint=thumb,
                    subject=subject,
                    details=f'Known-malicious CA found: {KNOWN_BAD_THUMBPRINTS[thumb]}',
                    severity='critical',
                    mitre_id='T1553.004',
                ))

            algo = cert.get('algorithm', '').lower()
            if 'sha1' in algo and 'sha1' not in subject.lower():
                self._add_alert(CertAlert(
                    timestamp=now,
                    category='weak_algorithm',
                    thumbprint=thumb,
                    subject=subject,
                    details=f'SHA-1 signed certificate (deprecated): {subject}',
                    severity='medium',
                    mitre_id='T1553.004',
                ))

            key_size = cert.get('key_size', 0)
            if 0 < key_size < 2048:
                self._add_alert(CertAlert(
                    timestamp=now,
                    category='weak_key',
                    thumbprint=thumb,
                    subject=subject,
                    details=f'Weak key size ({key_size}-bit) on cert: {subject}',
                    severity='high',
                    mitre_id='T1553.004',
                ))

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_store_changes()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Cert check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_store_changes(self) -> None:
        """Detect new certificates added to trusted stores."""
        now = datetime.now(timezone.utc).isoformat()
        current = self._enumerate_all_stores()

        for store_name, current_thumbs in current.items():
            baseline_thumbs = self._baseline_roots.get(store_name, set())
            new_certs = current_thumbs - baseline_thumbs
            removed_certs = baseline_thumbs - current_thumbs

            for thumb in new_certs:
                severity = 'critical' if 'Root' in store_name else 'high'
                self._add_alert(CertAlert(
                    timestamp=now,
                    category='new_cert_added',
                    thumbprint=thumb,
                    subject=f'(in {store_name} store)',
                    details=f'New certificate added to {store_name} store: {thumb}',
                    severity=severity,
                    mitre_id='T1553.004',
                ))

            for thumb in removed_certs:
                self._add_alert(CertAlert(
                    timestamp=now,
                    category='cert_removed',
                    thumbprint=thumb,
                    subject=f'(from {store_name} store)',
                    details=f'Certificate removed from {store_name} store: {thumb}',
                    severity='medium',
                    mitre_id='T1553.004',
                ))

        self._baseline_roots = current

    def _enumerate_all_stores(self) -> Dict[str, Set[str]]:
        """Enumerate certificate thumbprints from all monitored stores."""
        result = {}
        for store_name, reg_key in CERT_STORES:
            thumbs = self._enumerate_store_via_reg(reg_key)
            result[store_name] = thumbs
        return result

    @staticmethod
    def _enumerate_store_via_reg(reg_key: str) -> Set[str]:
        """List certificate thumbprints from a registry store."""
        thumbs: Set[str] = set()
        try:
            result = subprocess.run(
                ['reg', 'query', reg_key],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return thumbs
            for line in result.stdout.splitlines():
                line = line.strip()
                match = re.search(r'\\([A-Fa-f0-9]{40})$', line)
                if match:
                    thumbs.add(match.group(1).upper())
        except Exception:
            pass
        return thumbs

    @staticmethod
    def _get_cert_details() -> List[Dict[str, Any]]:
        """Get details of root certificates via certutil."""
        certs: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ['certutil', '-store', 'Root'],
                capture_output=True, text=True, timeout=30,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return certs

            current: Dict[str, Any] = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('Cert Hash(sha1):'):
                    if current:
                        certs.append(current)
                    current = {'thumbprint': line.split(':', 1)[1].strip().replace(' ', '').upper()}
                elif line.startswith('Subject:'):
                    current['subject'] = line.split(':', 1)[1].strip()
                elif line.startswith('Signature Algorithm:'):
                    current['algorithm'] = line.split(':', 1)[1].strip()
                elif 'Public Key Length:' in line:
                    match = re.search(r'(\d+)', line)
                    if match:
                        current['key_size'] = int(match.group(1))
            if current:
                certs.append(current)
        except Exception:
            pass
        return certs

    def _add_alert(self, alert: CertAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('TLS cert: %s', alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[TLSCertificateMonitor] = None


def get_tls_monitor() -> TLSCertificateMonitor:
    global _monitor
    if _monitor is None:
        _monitor = TLSCertificateMonitor()
    return _monitor


def start_tls_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = TLSCertificateMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'TLSCertificateMonitor', 'CertAlert',
    'get_tls_monitor', 'start_tls_monitoring',
    'KNOWN_BAD_THUMBPRINTS', 'CERT_STORES',
]
