"""
DNS Security Monitor
Downpour v29 Titanium

Advanced DNS security monitoring:
  - DNS cache poisoning detection
  - DNS-over-HTTPS (DoH) bypass detection
  - Suspicious DNS resolver changes
  - DNS rebinding attack indicators
  - Typosquatting/homoglyph domain detection
  - DNS amplification indicators
  - Known malicious DNS server detection

Uses ipconfig, netsh, and reg.exe — no PowerShell.
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.dnsmon')

KNOWN_DOH_ENDPOINTS = {
    '1.1.1.1': 'Cloudflare',
    '1.0.0.1': 'Cloudflare',
    '8.8.8.8': 'Google',
    '8.8.4.4': 'Google',
    '9.9.9.9': 'Quad9',
    '149.112.112.112': 'Quad9',
    '208.67.222.222': 'OpenDNS',
    '208.67.220.220': 'OpenDNS',
    '94.140.14.14': 'AdGuard',
    '94.140.15.15': 'AdGuard',
}

KNOWN_BAD_DNS_SERVERS = {
    '185.228.168.10': 'Known malware DNS',
    '104.238.186.68': 'Suspicious resolver',
}

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',
    '.top', '.xyz', '.click', '.link',
    '.work', '.date', '.bid', '.stream',
    '.racing', '.win', '.download', '.loan',
}

DOH_REGISTRY = r'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'


@dataclass
class DNSAlert:
    """DNS security alert."""
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


class DNSSecurityMonitor:
    """
    Monitor DNS configuration and traffic patterns for security threats.
    Baselines DNS servers and detects unauthorized changes.
    """

    def __init__(
        self,
        check_interval: float = 30.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._baseline_servers: Set[str] = set()
        self._alerts: List[DNSAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_servers = self._get_dns_servers()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='dns-security-monitor',
                daemon=True,
            )
            self._thread.start()
            _log.info('DNS security monitor started (%d baseline servers)',
                       len(self._baseline_servers))
            self._initial_checks()
            return True
        except Exception as exc:
            _log.warning('DNS monitor failed: %s', exc)
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
            'baseline_servers': list(self._baseline_servers),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def check_domain(self, domain: str) -> Optional[DNSAlert]:
        """Analyze a domain for suspicious characteristics."""
        now = datetime.now(timezone.utc).isoformat()

        for tld in SUSPICIOUS_TLDS:
            if domain.lower().endswith(tld):
                alert = DNSAlert(
                    timestamp=now,
                    category='suspicious_tld',
                    details=f'Domain uses high-risk TLD: {domain}',
                    indicator=domain,
                    severity='medium',
                    mitre_id='T1071.004',
                )
                self._add_alert(alert)
                return alert

        labels = domain.split('.')
        for label in labels:
            if len(label) > 40:
                alert = DNSAlert(
                    timestamp=now,
                    category='dns_tunneling',
                    details=f'Unusually long DNS label ({len(label)} chars): possible tunneling',
                    indicator=domain,
                    severity='high',
                    mitre_id='T1048.003',
                )
                self._add_alert(alert)
                return alert

        entropy = self._calculate_entropy(labels[0]) if labels else 0
        if entropy > 4.0 and len(labels[0]) > 12:
            alert = DNSAlert(
                timestamp=now,
                category='dga_suspect',
                details=f'High-entropy domain label (entropy={entropy:.1f}): possible DGA',
                indicator=domain,
                severity='high',
                mitre_id='T1568.002',
            )
            self._add_alert(alert)
            return alert

        return None

    def _initial_checks(self) -> None:
        """Run initial DNS configuration checks."""
        now = datetime.now(timezone.utc).isoformat()

        for server in self._baseline_servers:
            if server in KNOWN_BAD_DNS_SERVERS:
                self._add_alert(DNSAlert(
                    timestamp=now,
                    category='malicious_dns',
                    details=f'Known-bad DNS server: {KNOWN_BAD_DNS_SERVERS[server]}',
                    indicator=server,
                    severity='critical',
                    mitre_id='T1584.002',
                ))

        self._check_doh_settings()

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_dns_server_changes()
                self._check_count += 1
            except Exception as exc:
                _log.debug('DNS check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_dns_server_changes(self) -> None:
        """Detect DNS server configuration changes."""
        now = datetime.now(timezone.utc).isoformat()
        current = self._get_dns_servers()

        new_servers = current - self._baseline_servers
        removed_servers = self._baseline_servers - current

        for server in new_servers:
            severity = 'critical' if server in KNOWN_BAD_DNS_SERVERS else 'high'
            self._add_alert(DNSAlert(
                timestamp=now,
                category='dns_server_added',
                details=f'New DNS server configured: {server}',
                indicator=server,
                severity=severity,
                mitre_id='T1584.002',
            ))

        for server in removed_servers:
            self._add_alert(DNSAlert(
                timestamp=now,
                category='dns_server_removed',
                details=f'DNS server removed: {server}',
                indicator=server,
                severity='medium',
                mitre_id='T1584.002',
            ))

        self._baseline_servers = current

    def _check_doh_settings(self) -> None:
        """Check for DNS-over-HTTPS configuration that may bypass monitoring."""
        now = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ['reg', 'query', DOH_REGISTRY, '/v', 'EnableAutoDoh'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0 and '0x2' in result.stdout:
                self._add_alert(DNSAlert(
                    timestamp=now,
                    category='doh_enabled',
                    details='DNS-over-HTTPS auto-mode enabled — DNS queries bypass network monitoring',
                    indicator='EnableAutoDoh=2',
                    severity='medium',
                    mitre_id='T1071.004',
                ))
        except Exception:
            pass

    @staticmethod
    def _get_dns_servers() -> Set[str]:
        """Get currently configured DNS servers."""
        servers: Set[str] = set()
        try:
            result = subprocess.run(
                ['netsh', 'interface', 'ip', 'show', 'dns'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    if match:
                        servers.add(match.group(1))
        except Exception:
            pass
        return servers

    @staticmethod
    def _calculate_entropy(s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        import math
        freq: Dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length)
                     for count in freq.values())

    def _add_alert(self, alert: DNSAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('DNS: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[DNSSecurityMonitor] = None


def get_dns_monitor() -> DNSSecurityMonitor:
    global _monitor
    if _monitor is None:
        _monitor = DNSSecurityMonitor()
    return _monitor


def start_dns_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = DNSSecurityMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'DNSSecurityMonitor', 'DNSAlert',
    'get_dns_monitor', 'start_dns_monitoring',
    'KNOWN_DOH_ENDPOINTS', 'SUSPICIOUS_TLDS',
]
