"""
Firewall Tamper Detector
Downpour v29 Titanium

Detects Windows Firewall tampering and rule manipulation:
  - Firewall profile disable detection (Domain, Private, Public)
  - Firewall rule addition monitoring (allow rules for suspicious ports)
  - Firewall service (MpsSvc) stop detection
  - netsh firewall/advfirewall abuse detection
  - Firewall log disable detection
  - Inbound allow rule creation for common attack ports
  - Firewall exception for suspicious executables

Uses netsh and sc — no PowerShell.
MITRE ATT&CK: T1562.004 (Disable or Modify System Firewall)
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.fwtamper')

FIREWALL_PROFILES = ['domainprofile', 'privateprofile', 'publicprofile']

SUSPICIOUS_ALLOW_PORTS = {
    21, 22, 23, 25, 53, 69, 135, 139, 445, 1433, 1521,
    3306, 3389, 4444, 4445, 5432, 5555, 5900, 5985, 5986,
    6666, 6667, 6697, 8080, 8443, 8888, 9001, 9050,
}

FIREWALL_TAMPER_COMMANDS = [
    re.compile(r'(?i)netsh\s+(advfirewall|firewall)\s+set\s+.*state\s*(off|disable)'),
    re.compile(r'(?i)netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off'),
    re.compile(r'(?i)netsh\s+advfirewall\s+firewall\s+add\s+rule.*dir=in.*action=allow'),
    re.compile(r'(?i)netsh\s+advfirewall\s+set.*logging.*droppedconnections.*disable'),
    re.compile(r'(?i)netsh\s+advfirewall\s+reset'),
    re.compile(r'(?i)sc\s+(stop|config|delete)\s+MpsSvc'),
    re.compile(r'(?i)sc\s+(stop|config|delete)\s+SharedAccess'),
    re.compile(r'(?i)net\s+stop\s+MpsSvc'),
    re.compile(r'(?i)reg\s+add.*EnableFirewall.*0'),
    re.compile(r'(?i)Set-NetFirewallProfile.*-Enabled\s+False'),
    re.compile(r'(?i)Disable-NetFirewallRule'),
]


@dataclass
class FirewallAlert:
    """Firewall tampering alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    profile: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'profile': self.profile,
        }


class FirewallTamperDetector:
    """
    Monitor Windows Firewall state for tampering including
    profile disabling, suspicious rule creation, and service stops.
    """

    def __init__(
        self,
        check_interval: float = 60.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

        self._profile_states: Dict[str, str] = {}
        self._known_rules: Set[str] = set()
        self._alerts: List[FirewallAlert] = []

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._profile_states = self._get_profile_states()
            self._known_rules = self._get_inbound_allow_rules()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='fw-tamper-det',
                daemon=True,
            )
            self._thread.start()
            _log.info('Firewall tamper detector started (%d rules baseline)',
                      len(self._known_rules))
            return True
        except Exception as exc:
            _log.warning('Firewall tamper detector failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'profiles': self._profile_states,
            'tracked_rules': len(self._known_rules),
            'alerts': len(self._alerts),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def scan_command_line(self, proc_name: str,
                          cmdline: str) -> Optional[FirewallAlert]:
        """Scan a command line for firewall tampering."""
        now_ts = datetime.now(timezone.utc).isoformat()
        for pattern in FIREWALL_TAMPER_COMMANDS:
            if pattern.search(cmdline):
                alert = FirewallAlert(
                    timestamp=now_ts,
                    category='firewall_tamper_command',
                    details=f'Firewall tampering: {proc_name} — {cmdline[:160]}',
                    indicator=cmdline[:200],
                    severity='critical',
                    mitre_id='T1562.004',
                )
                self._add_alert(alert)
                return alert
        return None

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_profile_state()
                self._check_new_allow_rules()
                self._check_firewall_service()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Firewall tamper check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_profile_state(self) -> None:
        """Detect firewall profile state changes (enabled -> disabled)."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_profile_states()

        for profile, old_state in self._profile_states.items():
            new_state = current.get(profile, '')
            if old_state.upper() == 'ON' and new_state.upper() == 'OFF':
                self._add_alert(FirewallAlert(
                    timestamp=now_ts,
                    category='firewall_disabled',
                    details=f'Firewall profile disabled: {profile} (ON -> OFF)',
                    indicator=f'{profile}:OFF',
                    severity='critical',
                    mitre_id='T1562.004',
                    profile=profile,
                ))

        self._profile_states = current

    def _check_new_allow_rules(self) -> None:
        """Detect new inbound allow rules."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_inbound_allow_rules()
        new_rules = current - self._known_rules

        for rule in new_rules:
            severity = 'medium'
            for port in SUSPICIOUS_ALLOW_PORTS:
                if str(port) in rule:
                    severity = 'high'
                    break

            self._add_alert(FirewallAlert(
                timestamp=now_ts,
                category='new_inbound_allow_rule',
                details=f'New inbound allow rule: {rule[:120]}',
                indicator=rule[:200],
                severity=severity,
                mitre_id='T1562.004',
            ))

        self._known_rules = current

    def _check_firewall_service(self) -> None:
        """Check if the firewall service is running."""
        now_ts = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ['sc', 'query', 'MpsSvc'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                state_match = re.search(r'STATE\s+:\s+\d+\s+(\S+)', result.stdout)
                if state_match:
                    state = state_match.group(1).upper()
                    if state == 'STOPPED':
                        self._add_alert(FirewallAlert(
                            timestamp=now_ts,
                            category='firewall_service_stopped',
                            details='Windows Firewall service (MpsSvc) is STOPPED',
                            indicator='MpsSvc:STOPPED',
                            severity='critical',
                            mitre_id='T1562.004',
                        ))
        except Exception:
            pass

    @staticmethod
    def _get_profile_states() -> Dict[str, str]:
        """Get firewall profile states via netsh."""
        states: Dict[str, str] = {}
        for profile in FIREWALL_PROFILES:
            try:
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'show', profile, 'state'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        if 'State' in line or 'state' in line:
                            m = re.search(r'(ON|OFF)', line, re.IGNORECASE)
                            if m:
                                states[profile] = m.group(1).upper()
                                break
            except Exception:
                pass
        return states

    @staticmethod
    def _get_inbound_allow_rules() -> Set[str]:
        """Get inbound allow firewall rules."""
        rules: Set[str] = set()
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'show', 'rule',
                 'name=all', 'dir=in'],
                capture_output=True, text=True, timeout=30,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                current_rule = ''
                is_allow = False
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('Rule Name:'):
                        if current_rule and is_allow:
                            rules.add(current_rule)
                        current_rule = line.split(':', 1)[-1].strip()
                        is_allow = False
                    elif line.startswith('Action:') and 'Allow' in line:
                        is_allow = True
                if current_rule and is_allow:
                    rules.add(current_rule)
        except Exception:
            pass
        return rules

    def _add_alert(self, alert: FirewallAlert) -> None:
        with self._lock:
            for existing in reversed(self._alerts[-20:]):
                if (existing.category == alert.category
                        and existing.indicator == alert.indicator):
                    try:
                        t = datetime.fromisoformat(existing.timestamp)
                        if (datetime.now(timezone.utc) - t).total_seconds() < 600:
                            return
                    except Exception:
                        pass
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('FWTamper: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[FirewallTamperDetector] = None


def get_fw_tamper_detector() -> FirewallTamperDetector:
    global _detector
    if _detector is None:
        _detector = FirewallTamperDetector()
    return _detector


def start_fw_tamper_detection(callback=None) -> bool:
    global _detector
    _detector = FirewallTamperDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'FirewallTamperDetector', 'FirewallAlert',
    'get_fw_tamper_detector', 'start_fw_tamper_detection',
    'FIREWALL_TAMPER_COMMANDS', 'SUSPICIOUS_ALLOW_PORTS',
]
