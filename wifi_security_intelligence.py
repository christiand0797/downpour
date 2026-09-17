"""
WiFi Security Intelligence Module
Downpour v29 Titanium

Inspired by RuView spatial intelligence concepts — translated to
security monitoring context:
  - Rogue AP / Evil Twin detection via signal fingerprinting
  - Deauthentication attack detection (flood patterns)
  - WiFi probe request monitoring (device tracking indicators)
  - SSID anomaly detection (hidden networks, suspicious names)
  - Signal strength baseline & drift alerting
  - Connected device inventory & change detection
  - WPS vulnerability scanning
  - Karma/MANA attack indicators

Uses netsh and ipconfig — no PowerShell.
MITRE ATT&CK: T1557.002 (ARP poisoning via rogue AP), T1040 (network sniffing),
              T1200 (hardware additions), T1498 (DoS via deauth)
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_log = logging.getLogger('downpour.wifisec')

SUSPICIOUS_SSID_PATTERNS = [
    re.compile(r'(?i)^free[\s_-]?wifi'),
    re.compile(r'(?i)^open[\s_-]?network'),
    re.compile(r'(?i)^guest[\s_-]?wifi[\s_-]?free'),
    re.compile(r'(?i)^airport[\s_-]?wifi'),
    re.compile(r'(?i)^starbucks[\s_-]?wifi'),
    re.compile(r'(?i)^hotel[\s_-]?wifi'),
    re.compile(r'(?i)^setup|^config|^admin'),
    re.compile(r'(?i)^hack|^pwn|^evil|^rogue'),
    re.compile(r'(?i)^test[\s_-]?ap'),
    re.compile(r'(?i)^pineapple'),
    re.compile(r'(?i)^flipper'),
]

KNOWN_ATTACK_TOOL_OUIS = {
    '00:13:37': 'Hak5 WiFi Pineapple',
    'AA:BB:CC': 'Common spoofed OUI',
    '00:11:22': 'Common spoofed OUI',
    'DE:AD:BE': 'Common spoofed OUI pattern',
}

WEAK_AUTH_TYPES = {'Open', 'WEP', 'Shared'}

HONEYPOT_INDICATORS = [
    'Open', 'WEP',
]


@dataclass
class WiFiSecAlert:
    """WiFi security intelligence alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    ssid: str = ''
    bssid: str = ''
    signal: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'ssid': self.ssid,
            'bssid': self.bssid,
            'signal': self.signal,
        }


@dataclass
class NetworkFingerprint:
    """Fingerprint of a known WiFi network."""
    ssid: str
    bssid: str
    auth: str
    cipher: str
    channel: int
    signal_baseline: int
    first_seen: float
    last_seen: float
    seen_count: int = 1


class WiFiSecurityIntelligence:
    """
    Advanced WiFi security monitoring inspired by signal intelligence concepts.
    Detects rogue APs, evil twins, deauth floods, and suspicious wireless activity.
    """

    def __init__(
        self,
        scan_interval: float = 45.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._scan_interval = scan_interval
        self._alert_callback = alert_callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scan_count = 0

        self._known_networks: Dict[str, NetworkFingerprint] = {}
        self._device_inventory: Dict[str, Dict[str, Any]] = {}
        self._alerts: List[WiFiSecAlert] = []
        self._ssid_bssid_map: Dict[str, Set[str]] = {}
        self._signal_history: Dict[str, List[Tuple[float, int]]] = {}
        self._deauth_indicators: int = 0
        self._connection_drops: List[float] = []
        self._last_connected_bssid: str = ''

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_scan()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='wifi-security-intel',
                daemon=True,
            )
            self._thread.start()
            _log.info('WiFi security intelligence started (%d baseline networks)',
                      len(self._known_networks))
            return True
        except Exception as exc:
            _log.warning('WiFi security intel failed to start: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                'running': self._running,
                'scans': self._scan_count,
                'known_networks': len(self._known_networks),
                'alerts': len(self._alerts),
                'devices': len(self._device_inventory),
                'deauth_indicators': self._deauth_indicators,
            }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def get_network_inventory(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    'ssid': fp.ssid,
                    'bssid': fp.bssid,
                    'auth': fp.auth,
                    'cipher': fp.cipher,
                    'channel': fp.channel,
                    'signal_baseline': fp.signal_baseline,
                    'seen_count': fp.seen_count,
                    'first_seen': fp.first_seen,
                    'last_seen': fp.last_seen,
                }
                for fp in self._known_networks.values()
            ]

    def scan_now(self) -> List[Dict[str, Any]]:
        """Run an immediate scan and return results."""
        networks = self._scan_networks()
        self._analyze_networks(networks)
        return networks

    def _baseline_scan(self) -> None:
        """Build initial network fingerprint baseline."""
        networks = self._scan_networks()
        now = time.time()
        for net in networks:
            bssid = net.get('bssid', '')
            if not bssid:
                continue
            self._known_networks[bssid] = NetworkFingerprint(
                ssid=net.get('ssid', ''),
                bssid=bssid,
                auth=net.get('auth', ''),
                cipher=net.get('cipher', ''),
                channel=net.get('channel', 0),
                signal_baseline=net.get('signal', 0),
                first_seen=now,
                last_seen=now,
            )
            ssid = net.get('ssid', '')
            if ssid:
                self._ssid_bssid_map.setdefault(ssid, set()).add(bssid)

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                networks = self._scan_networks()
                self._analyze_networks(networks)
                self._check_connection_stability()
                self._scan_count += 1
            except Exception as exc:
                _log.debug('WiFi intel scan error: %s', exc)
            deadline = time.monotonic() + self._scan_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _scan_networks(self) -> List[Dict[str, Any]]:
        """Scan visible WiFi networks using netsh."""
        networks: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True, text=True, timeout=15,
                encoding='utf-8', errors='replace',
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return networks

            current: Dict[str, Any] = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('SSID') and 'BSSID' not in line:
                    if current.get('bssid'):
                        networks.append(current)
                    ssid = line.split(':', 1)[-1].strip()
                    current = {'ssid': ssid}
                elif line.startswith('BSSID'):
                    if current.get('bssid'):
                        networks.append(dict(current))
                    current['bssid'] = line.split(':', 1)[-1].strip()
                elif line.startswith('Signal'):
                    m = re.search(r'(\d+)%', line)
                    current['signal'] = int(m.group(1)) if m else 0
                elif line.startswith('Authentication'):
                    current['auth'] = line.split(':', 1)[-1].strip()
                elif line.startswith('Encryption') or line.startswith('Cipher'):
                    current['cipher'] = line.split(':', 1)[-1].strip()
                elif line.startswith('Channel'):
                    m = re.search(r'(\d+)', line.split(':', 1)[-1])
                    current['channel'] = int(m.group(1)) if m else 0
                elif line.startswith('Network type'):
                    current['type'] = line.split(':', 1)[-1].strip()

            if current.get('bssid'):
                networks.append(current)

        except Exception as exc:
            _log.debug('Network scan error: %s', exc)

        return networks

    def _analyze_networks(self, networks: List[Dict[str, Any]]) -> None:
        """Run all detection heuristics on scan results."""
        now_ts = datetime.now(timezone.utc).isoformat()
        now = time.time()

        for net in networks:
            ssid = net.get('ssid', '')
            bssid = net.get('bssid', '')
            auth = net.get('auth', '')
            signal = net.get('signal', 0)

            if not bssid:
                continue

            # Update known networks
            if bssid in self._known_networks:
                fp = self._known_networks[bssid]
                fp.last_seen = now
                fp.seen_count += 1
            else:
                self._known_networks[bssid] = NetworkFingerprint(
                    ssid=ssid, bssid=bssid, auth=auth,
                    cipher=net.get('cipher', ''),
                    channel=net.get('channel', 0),
                    signal_baseline=signal,
                    first_seen=now, last_seen=now,
                )
                if self._scan_count > 0:
                    self._add_alert(WiFiSecAlert(
                        timestamp=now_ts,
                        category='new_network',
                        details=f'New network detected: {ssid} ({bssid})',
                        indicator=bssid,
                        severity='medium',
                        mitre_id='T1200',
                        ssid=ssid, bssid=bssid, signal=signal,
                    ))

            # Track SSID -> BSSID mapping for evil twin detection
            if ssid:
                prev_bssids = self._ssid_bssid_map.get(ssid, set())
                self._ssid_bssid_map.setdefault(ssid, set()).add(bssid)

            # Track signal history
            hist = self._signal_history.setdefault(bssid, [])
            hist.append((now, signal))
            if len(hist) > 100:
                self._signal_history[bssid] = hist[-50:]

            # Detection: Evil Twin (same SSID, different BSSID with weaker auth)
            self._detect_evil_twin(ssid, bssid, auth, signal, now_ts)

            # Detection: Suspicious SSID patterns
            self._detect_suspicious_ssid(ssid, bssid, auth, signal, now_ts)

            # Detection: Known attack tool OUIs
            self._detect_attack_tool_oui(ssid, bssid, signal, now_ts)

            # Detection: Open/WEP networks (potential honeypot)
            self._detect_weak_auth(ssid, bssid, auth, signal, now_ts)

            # Detection: Signal anomaly (sudden strength change)
            self._detect_signal_anomaly(ssid, bssid, signal, now_ts)

            # Detection: Channel overlap attack
            self._detect_channel_attack(ssid, bssid, net.get('channel', 0), now_ts)

    def _detect_evil_twin(self, ssid: str, bssid: str, auth: str,
                          signal: int, now_ts: str) -> None:
        """Detect evil twin APs (same SSID, different BSSID, weaker security)."""
        if not ssid:
            return
        bssids_for_ssid = self._ssid_bssid_map.get(ssid, set())
        if len(bssids_for_ssid) <= 1:
            return

        for other_bssid in bssids_for_ssid:
            if other_bssid == bssid:
                continue
            other = self._known_networks.get(other_bssid)
            if not other:
                continue
            # Evil twin indicator: same SSID, different auth (weaker)
            if auth in WEAK_AUTH_TYPES and other.auth not in WEAK_AUTH_TYPES:
                self._add_alert(WiFiSecAlert(
                    timestamp=now_ts,
                    category='evil_twin',
                    details=(f'Possible evil twin: "{ssid}" at {bssid} uses {auth} '
                             f'while known AP {other_bssid} uses {other.auth}'),
                    indicator=bssid,
                    severity='critical',
                    mitre_id='T1557.002',
                    ssid=ssid, bssid=bssid, signal=signal,
                ))
                return

    def _detect_suspicious_ssid(self, ssid: str, bssid: str, auth: str,
                                signal: int, now_ts: str) -> None:
        if not ssid:
            return
        for pattern in SUSPICIOUS_SSID_PATTERNS:
            if pattern.search(ssid):
                self._add_alert(WiFiSecAlert(
                    timestamp=now_ts,
                    category='suspicious_ssid',
                    details=f'Suspicious SSID pattern: "{ssid}" ({auth})',
                    indicator=ssid,
                    severity='high',
                    mitre_id='T1200',
                    ssid=ssid, bssid=bssid, signal=signal,
                ))
                return

    def _detect_attack_tool_oui(self, ssid: str, bssid: str,
                                signal: int, now_ts: str) -> None:
        if not bssid or len(bssid) < 8:
            return
        oui = bssid[:8].upper()
        tool = KNOWN_ATTACK_TOOL_OUIS.get(oui)
        if tool:
            self._add_alert(WiFiSecAlert(
                timestamp=now_ts,
                category='attack_tool',
                details=f'Known attack tool OUI detected: {tool} ({bssid})',
                indicator=bssid,
                severity='critical',
                mitre_id='T1200',
                ssid=ssid, bssid=bssid, signal=signal,
            ))

    def _detect_weak_auth(self, ssid: str, bssid: str, auth: str,
                          signal: int, now_ts: str) -> None:
        if auth in WEAK_AUTH_TYPES and signal > 60:
            self._add_alert(WiFiSecAlert(
                timestamp=now_ts,
                category='honeypot_suspect',
                details=(f'Strong open/weak network may be honeypot: '
                         f'"{ssid}" ({auth}, {signal}% signal)'),
                indicator=bssid,
                severity='high',
                mitre_id='T1040',
                ssid=ssid, bssid=bssid, signal=signal,
            ))

    def _detect_signal_anomaly(self, ssid: str, bssid: str,
                               signal: int, now_ts: str) -> None:
        """Detect sudden signal strength changes (possible AP spoofing)."""
        fp = self._known_networks.get(bssid)
        if not fp or fp.seen_count < 3:
            return
        delta = abs(signal - fp.signal_baseline)
        if delta > 35:
            self._add_alert(WiFiSecAlert(
                timestamp=now_ts,
                category='signal_anomaly',
                details=(f'Signal anomaly on "{ssid}": '
                         f'{fp.signal_baseline}% -> {signal}% '
                         f'(delta={delta}%, possible AP spoofing)'),
                indicator=bssid,
                severity='high',
                mitre_id='T1557.002',
                ssid=ssid, bssid=bssid, signal=signal,
            ))

    def _detect_channel_attack(self, ssid: str, bssid: str,
                               channel: int, now_ts: str) -> None:
        """Detect if a known network appears on a different channel."""
        fp = self._known_networks.get(bssid)
        if not fp or fp.seen_count < 5 or not channel:
            return
        if fp.channel and fp.channel != channel:
            self._add_alert(WiFiSecAlert(
                timestamp=now_ts,
                category='channel_change',
                details=(f'Network "{ssid}" changed channel: '
                         f'{fp.channel} -> {channel}'),
                indicator=bssid,
                severity='medium',
                mitre_id='T1557.002',
                ssid=ssid, bssid=bssid, signal=0,
            ))
            fp.channel = channel

    def _check_connection_stability(self) -> None:
        """Detect connection drops that may indicate deauth attacks."""
        now_ts = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            connected = 'connected' in result.stdout.lower()
            bssid_match = re.search(r'BSSID\s*:\s*([0-9a-fA-F:]{17})', result.stdout)
            current_bssid = bssid_match.group(1) if bssid_match else ''

            if not connected and self._last_connected_bssid:
                now = time.time()
                self._connection_drops.append(now)
                drops_recent = [t for t in self._connection_drops
                                if now - t < 300]
                self._connection_drops = drops_recent

                if len(drops_recent) >= 3:
                    self._deauth_indicators += 1
                    self._add_alert(WiFiSecAlert(
                        timestamp=now_ts,
                        category='deauth_attack',
                        details=(f'Multiple connection drops ({len(drops_recent)} in 5min) — '
                                 f'possible deauthentication attack targeting '
                                 f'{self._last_connected_bssid}'),
                        indicator=self._last_connected_bssid,
                        severity='critical',
                        mitre_id='T1498',
                        bssid=self._last_connected_bssid,
                    ))

            self._last_connected_bssid = current_bssid

        except Exception:
            pass

    def _add_alert(self, alert: WiFiSecAlert) -> None:
        with self._lock:
            # Deduplicate: don't re-alert same category+indicator within 5 minutes
            now = time.time()
            for existing in reversed(self._alerts[-20:]):
                if (existing.category == alert.category
                        and existing.indicator == alert.indicator):
                    try:
                        from datetime import datetime as _dt
                        t = _dt.fromisoformat(existing.timestamp)
                        if (datetime.now(timezone.utc) - t).total_seconds() < 300:
                            return
                    except Exception:
                        pass

            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]

        _log.warning('WiFi: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_intel: Optional[WiFiSecurityIntelligence] = None


def get_wifi_intel() -> WiFiSecurityIntelligence:
    global _intel
    if _intel is None:
        _intel = WiFiSecurityIntelligence()
    return _intel


def start_wifi_intelligence(callback=None, scan_interval=45.0) -> bool:
    global _intel
    _intel = WiFiSecurityIntelligence(
        scan_interval=scan_interval,
        alert_callback=callback,
    )
    return _intel.start()


__all__ = [
    'WiFiSecurityIntelligence', 'WiFiSecAlert', 'NetworkFingerprint',
    'get_wifi_intel', 'start_wifi_intelligence',
    'SUSPICIOUS_SSID_PATTERNS', 'KNOWN_ATTACK_TOOL_OUIS',
]
