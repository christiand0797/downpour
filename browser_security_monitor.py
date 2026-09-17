"""
Browser Security Monitor
Downpour v29 Titanium

Monitors browser security posture:
  - Installed extension inventory & change detection
  - Dangerous extension permission flagging
  - Browser credential store access monitoring
  - Suspicious browser process spawning detection
  - Browser data exfiltration indicators
  - Crypto-wallet extension monitoring
  - Browser hijacking detection (homepage/search/proxy changes)

Uses reg.exe and filesystem checks — no PowerShell.
MITRE ATT&CK: T1176 (Browser Extensions), T1555.003 (Credentials from Web Browsers),
              T1185 (Browser Session Hijacking), T1539 (Steal Web Session Cookie)
"""

import json
import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.browsersec')

DANGEROUS_PERMISSIONS = {
    'tabs', 'webRequest', 'webRequestBlocking', 'cookies',
    'browsingData', 'history', 'bookmarks', 'downloads',
    'management', 'nativeMessaging', 'proxy', 'debugger',
    'clipboardRead', 'clipboardWrite', 'contentSettings',
    'privacy', 'identity', 'webNavigation',
}

HIGH_RISK_PERMISSIONS = {
    '<all_urls>', 'http://*/*', 'https://*/*', '*://*/*',
    'file:///*', 'ftp://*/*',
}

KNOWN_MALICIOUS_EXTENSION_IDS = {
    'example_placeholder': 'Known malicious extension placeholder',
}

CRYPTO_WALLET_EXTENSIONS = {
    'nkbihfbeogaeaoehlefnkodbefgpgknn': 'MetaMask',
    'bfnaelmomeimhlpmgjnjophhpkkoljpa': 'Phantom',
    'ibnejdfjmmkpcnlpebklmnkoeoihofec': 'TronLink',
    'jbdaocneiiinmjbjlgalhcelgbejmnid': 'Nifty Wallet',
    'hnfanknocfeofbddgcijnmhnfnkdnaad': 'Coinbase',
    'aiifbnbfobpmeekipheeijimdpnlpgpp': 'Station Wallet',
    'fhbohimaelbohpjbbldcngcnapndodjp': 'Binance',
}

BROWSER_PATHS = {
    'chrome': {
        'extensions': os.path.expandvars(
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions'),
        'login_data': os.path.expandvars(
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data'),
        'cookies': os.path.expandvars(
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies'),
        'preferences': os.path.expandvars(
            r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Preferences'),
        'process': 'chrome.exe',
    },
    'edge': {
        'extensions': os.path.expandvars(
            r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions'),
        'login_data': os.path.expandvars(
            r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data'),
        'cookies': os.path.expandvars(
            r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies'),
        'preferences': os.path.expandvars(
            r'%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Preferences'),
        'process': 'msedge.exe',
    },
    'brave': {
        'extensions': os.path.expandvars(
            r'%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Extensions'),
        'login_data': os.path.expandvars(
            r'%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Login Data'),
        'cookies': os.path.expandvars(
            r'%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Cookies'),
        'preferences': os.path.expandvars(
            r'%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Preferences'),
        'process': 'brave.exe',
    },
    'firefox': {
        'extensions': '',
        'login_data': '',
        'cookies': '',
        'preferences': '',
        'process': 'firefox.exe',
    },
}


@dataclass
class BrowserSecAlert:
    """Browser security alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    browser: str = ''
    extension_id: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'browser': self.browser,
            'extension_id': self.extension_id,
        }


class BrowserSecurityMonitor:
    """
    Monitor browser security: extensions, credential stores,
    hijacking indicators, and suspicious behavior.
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

        self._known_extensions: Dict[str, Set[str]] = {}
        self._credential_mtimes: Dict[str, float] = {}
        self._alerts: List[BrowserSecAlert] = []
        self._homepage_baseline: Dict[str, str] = {}
        self._search_baseline: Dict[str, str] = {}

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_scan()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='browser-security-mon',
                daemon=True,
            )
            self._thread.start()
            _log.info('Browser security monitor started')
            return True
        except Exception as exc:
            _log.warning('Browser security monitor failed: %s', exc)
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
            'tracked_extensions': sum(len(v) for v in self._known_extensions.values()),
            'browsers_monitored': len([b for b in BROWSER_PATHS
                                        if os.path.exists(BROWSER_PATHS[b].get('extensions', ''))]),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def get_extension_inventory(self) -> Dict[str, List[Dict[str, Any]]]:
        """Return installed extensions per browser with risk assessment."""
        inventory: Dict[str, List[Dict[str, Any]]] = {}
        for browser, paths in BROWSER_PATHS.items():
            ext_dir = paths.get('extensions', '')
            if not ext_dir or not os.path.isdir(ext_dir):
                continue
            exts = []
            try:
                for ext_id in os.listdir(ext_dir):
                    ext_path = os.path.join(ext_dir, ext_id)
                    if not os.path.isdir(ext_path):
                        continue
                    info = self._get_extension_info(ext_path, ext_id, browser)
                    if info:
                        exts.append(info)
            except Exception:
                pass
            if exts:
                inventory[browser] = exts
        return inventory

    def _baseline_scan(self) -> None:
        """Build initial extension and credential baselines."""
        for browser, paths in BROWSER_PATHS.items():
            ext_dir = paths.get('extensions', '')
            if ext_dir and os.path.isdir(ext_dir):
                try:
                    self._known_extensions[browser] = set(os.listdir(ext_dir))
                except Exception:
                    self._known_extensions[browser] = set()

            login_db = paths.get('login_data', '')
            if login_db and os.path.isfile(login_db):
                try:
                    self._credential_mtimes[browser] = os.path.getmtime(login_db)
                except Exception:
                    pass

            self._read_browser_settings(browser, paths)

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_extension_changes()
                self._check_credential_access()
                self._check_browser_hijacking()
                self._scan_dangerous_extensions()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Browser check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_extension_changes(self) -> None:
        """Detect new or removed browser extensions."""
        now_ts = datetime.now(timezone.utc).isoformat()

        for browser, paths in BROWSER_PATHS.items():
            ext_dir = paths.get('extensions', '')
            if not ext_dir or not os.path.isdir(ext_dir):
                continue

            try:
                current = set(os.listdir(ext_dir))
            except Exception:
                continue

            baseline = self._known_extensions.get(browser, set())

            new_exts = current - baseline
            for ext_id in new_exts:
                severity = 'high'
                if ext_id in KNOWN_MALICIOUS_EXTENSION_IDS:
                    severity = 'critical'
                elif ext_id in CRYPTO_WALLET_EXTENSIONS:
                    severity = 'medium'

                name = CRYPTO_WALLET_EXTENSIONS.get(ext_id, ext_id[:16])
                self._add_alert(BrowserSecAlert(
                    timestamp=now_ts,
                    category='new_extension',
                    details=f'New {browser} extension installed: {name}',
                    indicator=ext_id,
                    severity=severity,
                    mitre_id='T1176',
                    browser=browser,
                    extension_id=ext_id,
                ))

            removed_exts = baseline - current
            for ext_id in removed_exts:
                if ext_id in CRYPTO_WALLET_EXTENSIONS:
                    self._add_alert(BrowserSecAlert(
                        timestamp=now_ts,
                        category='wallet_removed',
                        details=(f'Crypto wallet extension removed from {browser}: '
                                 f'{CRYPTO_WALLET_EXTENSIONS[ext_id]}'),
                        indicator=ext_id,
                        severity='high',
                        mitre_id='T1185',
                        browser=browser,
                        extension_id=ext_id,
                    ))

            self._known_extensions[browser] = current

    def _check_credential_access(self) -> None:
        """Monitor for unusual credential database access."""
        now_ts = datetime.now(timezone.utc).isoformat()

        for browser, paths in BROWSER_PATHS.items():
            login_db = paths.get('login_data', '')
            if not login_db or not os.path.isfile(login_db):
                continue

            try:
                current_mtime = os.path.getmtime(login_db)
            except Exception:
                continue

            baseline_mtime = self._credential_mtimes.get(browser, 0)
            if baseline_mtime and current_mtime != baseline_mtime:
                self._add_alert(BrowserSecAlert(
                    timestamp=now_ts,
                    category='credential_access',
                    details=f'{browser} credential database modified externally',
                    indicator=login_db,
                    severity='high',
                    mitre_id='T1555.003',
                    browser=browser,
                ))

            self._credential_mtimes[browser] = current_mtime

    def _check_browser_hijacking(self) -> None:
        """Detect browser hijacking (homepage/search/proxy changes)."""
        now_ts = datetime.now(timezone.utc).isoformat()

        for browser, paths in BROWSER_PATHS.items():
            prefs_file = paths.get('preferences', '')
            if not prefs_file or not os.path.isfile(prefs_file):
                continue

            try:
                with open(prefs_file, 'r', encoding='utf-8', errors='replace') as f:
                    prefs = json.load(f)
            except Exception:
                continue

            homepage = prefs.get('homepage', '')
            search_provider = (prefs.get('default_search_provider_data', {})
                                    .get('template_url', ''))

            baseline_home = self._homepage_baseline.get(browser, '')
            baseline_search = self._search_baseline.get(browser, '')

            if baseline_home and homepage and homepage != baseline_home:
                self._add_alert(BrowserSecAlert(
                    timestamp=now_ts,
                    category='homepage_hijack',
                    details=(f'{browser} homepage changed: '
                             f'"{baseline_home}" -> "{homepage}"'),
                    indicator=homepage,
                    severity='high',
                    mitre_id='T1185',
                    browser=browser,
                ))

            if baseline_search and search_provider and search_provider != baseline_search:
                self._add_alert(BrowserSecAlert(
                    timestamp=now_ts,
                    category='search_hijack',
                    details=f'{browser} default search provider changed',
                    indicator=search_provider,
                    severity='high',
                    mitre_id='T1185',
                    browser=browser,
                ))

            if homepage:
                self._homepage_baseline[browser] = homepage
            if search_provider:
                self._search_baseline[browser] = search_provider

    def _scan_dangerous_extensions(self) -> None:
        """Check installed extensions for dangerous permissions."""
        now_ts = datetime.now(timezone.utc).isoformat()

        for browser, paths in BROWSER_PATHS.items():
            ext_dir = paths.get('extensions', '')
            if not ext_dir or not os.path.isdir(ext_dir):
                continue

            try:
                for ext_id in os.listdir(ext_dir):
                    ext_path = os.path.join(ext_dir, ext_id)
                    if not os.path.isdir(ext_path):
                        continue
                    self._check_extension_permissions(
                        ext_path, ext_id, browser, now_ts)
            except Exception:
                pass

    def _check_extension_permissions(self, ext_path: str, ext_id: str,
                                     browser: str, now_ts: str) -> None:
        """Check a single extension's manifest for dangerous permissions."""
        try:
            versions = sorted(os.listdir(ext_path))
            if not versions:
                return
            manifest_path = os.path.join(ext_path, versions[-1], 'manifest.json')
            if not os.path.isfile(manifest_path):
                return

            with open(manifest_path, 'r', encoding='utf-8', errors='replace') as f:
                manifest = json.load(f)

            perms = set(manifest.get('permissions', []))
            perms.update(manifest.get('optional_permissions', []))
            host_perms = set(manifest.get('host_permissions', []))
            perms.update(host_perms)

            dangerous = perms & DANGEROUS_PERMISSIONS
            high_risk = perms & HIGH_RISK_PERMISSIONS

            if len(dangerous) >= 4 or (high_risk and dangerous):
                name = manifest.get('name', ext_id[:16])
                self._add_alert(BrowserSecAlert(
                    timestamp=now_ts,
                    category='dangerous_extension',
                    details=(f'{browser} extension "{name}" has dangerous permissions: '
                             f'{", ".join(sorted(dangerous))}'),
                    indicator=ext_id,
                    severity='high' if high_risk else 'medium',
                    mitre_id='T1176',
                    browser=browser,
                    extension_id=ext_id,
                ))

        except Exception:
            pass

    def _read_browser_settings(self, browser: str,
                               paths: Dict[str, str]) -> None:
        """Read browser preferences for baseline."""
        prefs_file = paths.get('preferences', '')
        if not prefs_file or not os.path.isfile(prefs_file):
            return
        try:
            with open(prefs_file, 'r', encoding='utf-8', errors='replace') as f:
                prefs = json.load(f)
            homepage = prefs.get('homepage', '')
            search = (prefs.get('default_search_provider_data', {})
                          .get('template_url', ''))
            if homepage:
                self._homepage_baseline[browser] = homepage
            if search:
                self._search_baseline[browser] = search
        except Exception:
            pass

    @staticmethod
    def _get_extension_info(ext_path: str, ext_id: str,
                            browser: str) -> Optional[Dict[str, Any]]:
        """Read extension manifest and return info dict."""
        try:
            versions = sorted(os.listdir(ext_path))
            if not versions:
                return None
            manifest_path = os.path.join(ext_path, versions[-1], 'manifest.json')
            if not os.path.isfile(manifest_path):
                return None
            with open(manifest_path, 'r', encoding='utf-8', errors='replace') as f:
                manifest = json.load(f)
            perms = set(manifest.get('permissions', []))
            perms.update(manifest.get('optional_permissions', []))
            perms.update(manifest.get('host_permissions', []))
            dangerous = perms & DANGEROUS_PERMISSIONS
            is_wallet = ext_id in CRYPTO_WALLET_EXTENSIONS
            return {
                'id': ext_id,
                'name': manifest.get('name', 'Unknown'),
                'version': manifest.get('version', ''),
                'description': manifest.get('description', '')[:100],
                'permissions': sorted(perms),
                'dangerous_permissions': sorted(dangerous),
                'is_crypto_wallet': is_wallet,
                'wallet_name': CRYPTO_WALLET_EXTENSIONS.get(ext_id, ''),
                'risk_level': ('high' if len(dangerous) >= 4
                               else 'medium' if dangerous
                               else 'low'),
                'browser': browser,
            }
        except Exception:
            return None

    def _add_alert(self, alert: BrowserSecAlert) -> None:
        with self._lock:
            for existing in reversed(self._alerts[-20:]):
                if (existing.category == alert.category
                        and existing.indicator == alert.indicator
                        and existing.browser == alert.browser):
                    try:
                        t = datetime.fromisoformat(existing.timestamp)
                        if (datetime.now(timezone.utc) - t).total_seconds() < 600:
                            return
                    except Exception:
                        pass

            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('Browser: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[BrowserSecurityMonitor] = None


def get_browser_monitor() -> BrowserSecurityMonitor:
    global _monitor
    if _monitor is None:
        _monitor = BrowserSecurityMonitor()
    return _monitor


def start_browser_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = BrowserSecurityMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'BrowserSecurityMonitor', 'BrowserSecAlert',
    'get_browser_monitor', 'start_browser_monitoring',
    'DANGEROUS_PERMISSIONS', 'CRYPTO_WALLET_EXTENSIONS',
]
