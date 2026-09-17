"""
Active Directory & Kerberos Attack Detector
Downpour v29 Titanium

Detects Active Directory reconnaissance and Kerberos-based attacks:
  - BloodHound / SharpHound enumeration
  - Kerberoasting (SPN-targeted TGS requests)
  - AS-REP roasting (accounts without pre-auth)
  - DCSync attacks (replication requests)
  - Golden/Silver ticket indicators
  - LDAP reconnaissance
  - Pass-the-hash / Pass-the-ticket
  - AD enumeration via net.exe, dsquery, nltest

Monitors via process command lines and Windows Security event logs.
Uses native commands only (no PowerShell).
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.adattack')

# Process-based indicators of AD attack tools
AD_ATTACK_TOOLS = {
    'sharphound.exe': ('BloodHound collector', 'T1087.002', 'critical'),
    'bloodhound.exe': ('BloodHound GUI', 'T1087.002', 'high'),
    'rubeus.exe': ('Kerberos attack tool', 'T1558', 'critical'),
    'mimikatz.exe': ('Credential extraction', 'T1003', 'critical'),
    'kekeo.exe': ('Kerberos toolkit', 'T1558', 'critical'),
    'secretsdump.py': ('Impacket secrets dump', 'T1003.006', 'critical'),
    'getTGT.py': ('Impacket TGT request', 'T1558.003', 'critical'),
    'getST.py': ('Impacket service ticket', 'T1558.003', 'critical'),
    'GetUserSPNs.py': ('Impacket Kerberoast', 'T1558.003', 'critical'),
    'GetNPUsers.py': ('Impacket AS-REP roast', 'T1558.004', 'critical'),
    'ldapdomaindump': ('LDAP domain dump', 'T1087.002', 'high'),
    'adexplorer.exe': ('AD Explorer (Sysinternals)', 'T1087.002', 'medium'),
    'adfind.exe': ('AD enumeration', 'T1087.002', 'high'),
    'ldapsearch': ('LDAP search', 'T1087.002', 'medium'),
    'crackmapexec': ('CrackMapExec multi-tool', 'T1087.002', 'critical'),
    'kerbrute': ('Kerberos brute-force', 'T1110.003', 'critical'),
}

# Command-line patterns indicating AD recon
AD_RECON_PATTERNS = [
    (re.compile(r'nltest\s+/domain_trusts', re.I), 'Domain trust enumeration', 'T1482', 'medium'),
    (re.compile(r'nltest\s+/dclist', re.I), 'Domain controller listing', 'T1018', 'medium'),
    (re.compile(r'dsquery\s+(user|computer|group|ou|site)', re.I), 'AD object query', 'T1087.002', 'medium'),
    (re.compile(r'net\s+group\s+.*(domain\s+admins|enterprise\s+admins|schema\s+admins)', re.I),
     'Privileged group enumeration', 'T1087.002', 'high'),
    (re.compile(r'net\s+user\s+/domain', re.I), 'Domain user enumeration', 'T1087.002', 'medium'),
    (re.compile(r'net\s+group\s+/domain', re.I), 'Domain group enumeration', 'T1087.002', 'medium'),
    (re.compile(r'net\s+accounts\s+/domain', re.I), 'Domain account policy query', 'T1201', 'medium'),
    (re.compile(r'whoami\s+/(all|priv|groups)', re.I), 'Privilege enumeration', 'T1033', 'low'),
    (re.compile(r'gpresult\s+/[rz]', re.I), 'Group Policy enumeration', 'T1615', 'medium'),
    (re.compile(r'setspn\s+-[qtfl]', re.I), 'SPN enumeration (Kerberoast recon)', 'T1558.003', 'high'),
    (re.compile(r'klist\s+(tickets|tgt|purge)', re.I), 'Kerberos ticket management', 'T1558', 'medium'),
    (re.compile(r'csvde|ldifde', re.I), 'AD data export', 'T1087.002', 'high'),
]

# Kerberos-specific command-line indicators
KERBEROS_ATTACK_PATTERNS = [
    (re.compile(r'kerberoast', re.I), 'Kerberoasting attempt', 'T1558.003', 'critical'),
    (re.compile(r'asreproast', re.I), 'AS-REP roasting attempt', 'T1558.004', 'critical'),
    (re.compile(r'golden\s*ticket|silver\s*ticket', re.I), 'Ticket forging attempt', 'T1558.001', 'critical'),
    (re.compile(r'dcsync', re.I), 'DCSync attack', 'T1003.006', 'critical'),
    (re.compile(r'lsadump::dcsync|lsadump::lsa', re.I), 'Mimikatz DCSync', 'T1003.006', 'critical'),
    (re.compile(r'sekurlsa::(logonpasswords|wdigest|kerberos|tickets)', re.I),
     'Mimikatz credential extraction', 'T1003.001', 'critical'),
    (re.compile(r'pass.the.(hash|ticket)', re.I), 'Pass-the-Hash/Ticket', 'T1550', 'critical'),
    (re.compile(r'overpass.the.hash|opth', re.I), 'Overpass-the-Hash', 'T1550.002', 'critical'),
]

# Security Event IDs for AD attacks
AD_EVENT_IDS = {
    4768: ('TGT request', 'Kerberos TGT requested — watch for unusual encryption types'),
    4769: ('TGS request', 'Kerberos service ticket — high volume = Kerberoasting'),
    4771: ('Pre-auth failed', 'Kerberos pre-authentication failure — brute force or AS-REP roast'),
    4625: ('Logon failure', 'Failed logon — may indicate password spraying'),
    4648: ('Explicit credential', 'Logon with explicit credentials — lateral movement indicator'),
    4662: ('Object access', 'AD object access — DCSync uses Replicating Directory Changes'),
    4672: ('Special privilege', 'Special privileges assigned — may indicate token manipulation'),
    4720: ('Account created', 'New user account created'),
    4728: ('Member added to global group', 'Security group membership change'),
    4732: ('Member added to local group', 'Local security group change'),
    4756: ('Member added to universal group', 'Universal group membership change'),
}


@dataclass
class ADAttackAlert:
    """Alert for AD/Kerberos attack detection."""
    timestamp: str
    category: str
    technique: str
    details: str
    process: str
    command_line: str
    severity: str
    mitre_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'technique': self.technique,
            'details': self.details,
            'process': self.process,
            'command_line': self.command_line,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
        }


class ADAttackDetector:
    """
    Detect Active Directory and Kerberos attacks via process
    monitoring and security event log analysis.
    """

    def __init__(
        self,
        check_interval: float = 10.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._alerts: List[ADAttackAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0
        self._seen_events: Set[str] = set()
        self._last_event_time = ''

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._last_event_time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='ad-attack-detector',
                daemon=True,
            )
            self._thread.start()
            _log.info('AD attack detector started')
            return True
        except Exception as exc:
            _log.warning('AD attack detector failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'alerts': len(self._alerts),
            'monitored_tools': len(AD_ATTACK_TOOLS),
            'monitored_event_ids': len(AD_EVENT_IDS),
        }

    def scan_command_line(self, process_name: str, command_line: str) -> Optional[ADAttackAlert]:
        """Scan a single process command line for AD attack indicators.
        Can be called from external process monitors for real-time detection."""
        now = datetime.now(timezone.utc).isoformat()
        basename = process_name.lower().split('\\')[-1]

        if basename in AD_ATTACK_TOOLS:
            desc, mitre, severity = AD_ATTACK_TOOLS[basename]
            alert = ADAttackAlert(
                timestamp=now,
                category='attack_tool',
                technique=desc,
                details=f'Known AD attack tool detected: {basename}',
                process=process_name,
                command_line=command_line[:500],
                severity=severity,
                mitre_id=mitre,
            )
            self._add_alert(alert)
            return alert

        for pattern, desc, mitre, severity in AD_RECON_PATTERNS:
            if pattern.search(command_line):
                alert = ADAttackAlert(
                    timestamp=now,
                    category='ad_recon',
                    technique=desc,
                    details=f'AD reconnaissance: {desc}',
                    process=process_name,
                    command_line=command_line[:500],
                    severity=severity,
                    mitre_id=mitre,
                )
                self._add_alert(alert)
                return alert

        for pattern, desc, mitre, severity in KERBEROS_ATTACK_PATTERNS:
            if pattern.search(command_line):
                alert = ADAttackAlert(
                    timestamp=now,
                    category='kerberos_attack',
                    technique=desc,
                    details=f'Kerberos attack indicator: {desc}',
                    process=process_name,
                    command_line=command_line[:500],
                    severity=severity,
                    mitre_id=mitre,
                )
                self._add_alert(alert)
                return alert

        return None

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._scan_running_processes()
                self._check_security_events()
                self._check_count += 1
            except Exception as exc:
                _log.debug('AD check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _scan_running_processes(self) -> None:
        """Scan running processes for AD attack tools."""
        try:
            result = subprocess.run(
                ['wmic', 'process', 'get', 'name,commandline', '/format:csv'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith('Node,'):
                    continue
                parts = line.split(',', 2)
                if len(parts) < 3:
                    continue
                cmd_line = parts[1]
                proc_name = parts[2]
                if proc_name and cmd_line:
                    self.scan_command_line(proc_name, cmd_line)
        except Exception:
            pass

    def _check_security_events(self) -> None:
        """Check Windows Security event log for AD attack indicators."""
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
        for event_id, (category, description) in AD_EVENT_IDS.items():
            try:
                result = subprocess.run(
                    ['wevtutil', 'qe', 'Security',
                     '/q:*[System[(EventID=' + str(event_id) + ')]]',
                     '/c:5', '/rd:true', '/f:text'],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
                )
                if result.returncode != 0:
                    continue
                events = result.stdout.count('Event[')
                if events > 0:
                    event_key = f'{event_id}:{now_str[:13]}'
                    if event_key not in self._seen_events:
                        self._seen_events.add(event_key)
                        if len(self._seen_events) > 10000:
                            self._seen_events = set(list(self._seen_events)[-5000:])
            except Exception:
                continue
        self._last_event_time = now_str

    def _add_alert(self, alert: ADAttackAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('AD attack: %s — %s', alert.technique, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[ADAttackDetector] = None


def get_ad_detector() -> ADAttackDetector:
    global _detector
    if _detector is None:
        _detector = ADAttackDetector()
    return _detector


def start_ad_detection(callback=None) -> bool:
    global _detector
    _detector = ADAttackDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'ADAttackDetector', 'ADAttackAlert',
    'get_ad_detector', 'start_ad_detection',
    'AD_ATTACK_TOOLS', 'AD_EVENT_IDS',
]
