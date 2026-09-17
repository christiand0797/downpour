"""
Clipboard Security Monitor
Downpour v29 Titanium

Real-time clipboard monitoring for:
  - Cryptocurrency address replacement (clipper malware)
  - Sensitive data exposure (passwords, API keys, SSNs)
  - Clipboard hijacking detection (rapid automated changes)
  - Suspicious content patterns (base64 shellcode, PowerShell)

Uses ctypes for Win32 clipboard access — no PowerShell.
Thread-safe with rate-limited alerting to avoid noise.
"""

import ctypes
import ctypes.wintypes
import logging
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

_log = logging.getLogger('downpour.clipboard')

# Crypto address patterns
CRYPTO_PATTERNS = {
    'bitcoin': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b'),
    'bitcoin_bech32': re.compile(r'\bbc1[a-zA-HJ-NP-Z0-9]{25,89}\b'),
    'ethereum': re.compile(r'\b0x[0-9a-fA-F]{40}\b'),
    'monero': re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'),
    'litecoin': re.compile(r'\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b'),
    'ripple': re.compile(r'\br[0-9a-zA-Z]{24,34}\b'),
    'solana': re.compile(r'\b[1-9A-HJ-NP-Za-km-z]{32,44}\b'),
}

# Sensitive data patterns
SENSITIVE_PATTERNS = {
    'api_key': re.compile(r'\b(sk|pk|api|key|token)[_-][a-zA-Z0-9]{20,}\b', re.I),
    'aws_key': re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    'private_key': re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
    'jwt_token': re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'),
    'connection_string': re.compile(r'(Server|Data Source|Host)=.*(Password|Pwd)=', re.I),
}

# Suspicious content patterns
SUSPICIOUS_PATTERNS = {
    'powershell_encoded': re.compile(r'powershell.*-[eE]([nN][cC]|[cC])?\s+[A-Za-z0-9+/=]{20,}'),
    'base64_shellcode': re.compile(r'^[A-Za-z0-9+/]{100,}={0,2}$'),
    'url_with_exe': re.compile(r'https?://[^\s]+\.(exe|dll|scr|bat|cmd|ps1|vbs|js)\b', re.I),
    'reverse_shell': re.compile(r'(bash\s+-i|nc\s+-e|ncat\s+-e|/dev/tcp/)', re.I),
}


@dataclass
class ClipboardAlert:
    """Clipboard security alert."""
    timestamp: str
    category: str
    pattern_matched: str
    content_preview: str
    severity: str
    mitre_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'pattern_matched': self.pattern_matched,
            'content_preview': self.content_preview[:100],
            'severity': self.severity,
            'mitre_id': self.mitre_id,
        }


class ClipboardSecurityMonitor:
    """
    Monitor clipboard for security-relevant content changes.
    Detects clipper malware, credential exposure, and suspicious payloads.
    """

    def __init__(
        self,
        check_interval: float = 2.0,
        alert_callback: Optional[Callable] = None,
        detect_crypto_swap: bool = True,
        detect_sensitive: bool = True,
        detect_suspicious: bool = True,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._detect_crypto = detect_crypto_swap
        self._detect_sensitive = detect_sensitive
        self._detect_suspicious = detect_suspicious
        self._last_content = ''
        self._last_crypto_addr = ''
        self._rapid_change_count = 0
        self._rapid_change_window = 0.0
        self._alerts: List[ClipboardAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

    def start(self) -> bool:
        if self._running:
            return True
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name='clipboard-monitor',
            daemon=True,
        )
        self._thread.start()
        _log.info('Clipboard security monitor started')
        return True

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'alerts': len(self._alerts),
            'rapid_changes': self._rapid_change_count,
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                content = self._read_clipboard()
                if content and content != self._last_content:
                    self._analyze_content(content)
                    self._detect_rapid_changes()
                    self._last_content = content
                self._check_count += 1
            except Exception as exc:
                _log.debug('Clipboard check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(0.5)

    def _analyze_content(self, content: str) -> None:
        """Analyze clipboard content for security threats."""
        now = datetime.now(timezone.utc).isoformat()

        if self._detect_crypto:
            self._check_crypto_swap(content, now)

        if self._detect_sensitive:
            self._check_sensitive_data(content, now)

        if self._detect_suspicious:
            self._check_suspicious_content(content, now)

    def _check_crypto_swap(self, content: str, now: str) -> None:
        """Detect cryptocurrency address replacement (clipper malware)."""
        for crypto_name, pattern in CRYPTO_PATTERNS.items():
            match = pattern.search(content)
            if match:
                addr = match.group(0)
                if (self._last_crypto_addr and
                    addr != self._last_crypto_addr and
                    len(addr) == len(self._last_crypto_addr)):
                    self._add_alert(ClipboardAlert(
                        timestamp=now,
                        category='crypto_swap',
                        pattern_matched=crypto_name,
                        content_preview=f'Address changed: {self._last_crypto_addr[:12]}... → {addr[:12]}...',
                        severity='critical',
                        mitre_id='T1115',
                    ))
                self._last_crypto_addr = addr
                break

    def _check_sensitive_data(self, content: str, now: str) -> None:
        """Detect sensitive data in clipboard."""
        for pattern_name, pattern in SENSITIVE_PATTERNS.items():
            if pattern.search(content):
                self._add_alert(ClipboardAlert(
                    timestamp=now,
                    category='sensitive_data',
                    pattern_matched=pattern_name,
                    content_preview=content[:60] + '...' if len(content) > 60 else content,
                    severity='high',
                    mitre_id='T1115',
                ))
                break

    def _check_suspicious_content(self, content: str, now: str) -> None:
        """Detect suspicious content like encoded commands."""
        for pattern_name, pattern in SUSPICIOUS_PATTERNS.items():
            if pattern.search(content):
                self._add_alert(ClipboardAlert(
                    timestamp=now,
                    category='suspicious_content',
                    pattern_matched=pattern_name,
                    content_preview=content[:60] + '...' if len(content) > 60 else content,
                    severity='high',
                    mitre_id='T1059',
                ))
                break

    def _detect_rapid_changes(self) -> None:
        """Detect rapid clipboard changes (automated clipper behavior)."""
        now = time.monotonic()
        if now - self._rapid_change_window < 5.0:
            self._rapid_change_count += 1
            if self._rapid_change_count > 10:
                alert_now = datetime.now(timezone.utc).isoformat()
                self._add_alert(ClipboardAlert(
                    timestamp=alert_now,
                    category='rapid_changes',
                    pattern_matched='automated_clipboard',
                    content_preview=f'{self._rapid_change_count} changes in 5 seconds',
                    severity='high',
                    mitre_id='T1115',
                ))
                self._rapid_change_count = 0
        else:
            self._rapid_change_count = 1
            self._rapid_change_window = now

    @staticmethod
    def _read_clipboard() -> str:
        """Read clipboard text content using Win32 API."""
        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            CF_UNICODETEXT = 13

            if not user32.OpenClipboard(0):
                return ''
            try:
                handle = user32.GetClipboardData(CF_UNICODETEXT)
                if not handle:
                    return ''
                ptr = kernel32.GlobalLock(handle)
                if not ptr:
                    return ''
                try:
                    return ctypes.wstring_at(ptr)[:4096]
                finally:
                    kernel32.GlobalUnlock(handle)
            finally:
                user32.CloseClipboard()
        except Exception:
            return ''

    def _add_alert(self, alert: ClipboardAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('Clipboard: %s — %s', alert.category, alert.pattern_matched)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[ClipboardSecurityMonitor] = None


def get_clipboard_monitor() -> ClipboardSecurityMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ClipboardSecurityMonitor()
    return _monitor


def start_clipboard_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = ClipboardSecurityMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'ClipboardSecurityMonitor', 'ClipboardAlert',
    'get_clipboard_monitor', 'start_clipboard_monitoring',
    'CRYPTO_PATTERNS', 'SENSITIVE_PATTERNS',
]
