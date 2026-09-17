"""
Token Manipulation & Impersonation Detector
Downpour v29 Titanium

Detects Windows access token manipulation:
  - Token theft and impersonation
  - SID-History injection
  - Privilege escalation via token duplication
  - Potato family attacks (JuicyPotato, PrintSpoofer, etc.)
  - Process token replacement
  - RunAs credential abuse

Monitors via process command lines and privilege auditing.
Uses native commands only — no PowerShell.
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.tokendet')

TOKEN_ATTACK_TOOLS = {
    'juicypotato.exe': ('JuicyPotato privilege escalation', 'T1134.001', 'critical'),
    'juicypotatong.exe': ('JuicyPotatoNG', 'T1134.001', 'critical'),
    'rottenpotato.exe': ('RottenPotato', 'T1134.001', 'critical'),
    'sweetpotato.exe': ('SweetPotato', 'T1134.001', 'critical'),
    'hotpotato.exe': ('HotPotato', 'T1134.001', 'critical'),
    'godpotato.exe': ('GodPotato', 'T1134.001', 'critical'),
    'printspoofer.exe': ('PrintSpoofer pipe impersonation', 'T1134.001', 'critical'),
    'printspoofer64.exe': ('PrintSpoofer64', 'T1134.001', 'critical'),
    'roguepotato.exe': ('RoguePotato', 'T1134.001', 'critical'),
    'efspotato.exe': ('EfsPotato', 'T1134.001', 'critical'),
    'incognito.exe': ('Incognito token manipulation', 'T1134', 'critical'),
    'tokenvator.exe': ('Tokenvator privilege tool', 'T1134', 'critical'),
    'sharptoken.exe': ('SharpToken', 'T1134', 'critical'),
}

TOKEN_COMMAND_PATTERNS = [
    (re.compile(r'token::elevate', re.I), 'Mimikatz token elevation', 'T1134.001', 'critical'),
    (re.compile(r'token::duplicate', re.I), 'Mimikatz token duplication', 'T1134.001', 'critical'),
    (re.compile(r'token::impersonate', re.I), 'Mimikatz token impersonation', 'T1134.003', 'critical'),
    (re.compile(r'token::revert', re.I), 'Mimikatz token revert', 'T1134', 'high'),
    (re.compile(r'privilege::debug', re.I), 'Mimikatz debug privilege', 'T1134', 'critical'),
    (re.compile(r'incognito.*list_tokens', re.I), 'Incognito token listing', 'T1134', 'critical'),
    (re.compile(r'incognito.*impersonate_token', re.I), 'Incognito impersonation', 'T1134.003', 'critical'),
    (re.compile(r'maketoken|make_token', re.I), 'Token creation command', 'T1134.003', 'high'),
    (re.compile(r'steal_token|stealtoken', re.I), 'Token theft command', 'T1134.001', 'critical'),
    (re.compile(r'rev2self|revert_to_self', re.I), 'Token revert', 'T1134', 'medium'),
    (re.compile(r'runas\s+/user:', re.I), 'RunAs credential usage', 'T1134.002', 'medium'),
    (re.compile(r'runas\s+/netonly', re.I), 'RunAs network-only logon', 'T1134.002', 'high'),
    (re.compile(r'runas\s+/savecred', re.I), 'RunAs saved credentials', 'T1134.002', 'high'),
    (re.compile(r'SeImpersonatePrivilege|SeAssignPrimaryTokenPrivilege', re.I),
     'Impersonation privilege reference', 'T1134', 'medium'),
]

DANGEROUS_PRIVILEGES = {
    'SeDebugPrivilege': ('Debug privilege — access any process', 'T1134', 'high'),
    'SeImpersonatePrivilege': ('Impersonate — service account escalation', 'T1134.001', 'medium'),
    'SeAssignPrimaryTokenPrivilege': ('Assign primary token', 'T1134.002', 'high'),
    'SeTcbPrivilege': ('Act as part of OS', 'T1134', 'critical'),
    'SeBackupPrivilege': ('Backup — read any file', 'T1003', 'high'),
    'SeRestorePrivilege': ('Restore — write any file', 'T1574', 'high'),
    'SeLoadDriverPrivilege': ('Load driver — kernel access', 'T1068', 'critical'),
    'SeTakeOwnershipPrivilege': ('Take ownership of objects', 'T1222', 'high'),
}


@dataclass
class TokenAlert:
    """Token manipulation alert."""
    timestamp: str
    category: str
    technique: str
    details: str
    process: str
    severity: str
    mitre_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'technique': self.technique,
            'details': self.details,
            'process': self.process,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
        }


class TokenManipulationDetector:
    """
    Detect token manipulation and impersonation attacks.
    Monitors processes, privilege usage, and command patterns.
    """

    def __init__(
        self,
        check_interval: float = 10.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._alerts: List[TokenAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0
        self._seen_pids: Set[str] = set()

    def start(self) -> bool:
        if self._running:
            return True
        self._running = True
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name='token-manipulation-detector',
            daemon=True,
        )
        self._thread.start()
        _log.info('Token manipulation detector started')
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
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def scan_command_line(self, process_name: str, command_line: str) -> Optional[TokenAlert]:
        """Scan a single command line for token manipulation indicators."""
        now = datetime.now(timezone.utc).isoformat()
        basename = process_name.lower().split('\\')[-1]

        if basename in TOKEN_ATTACK_TOOLS:
            desc, mitre, severity = TOKEN_ATTACK_TOOLS[basename]
            alert = TokenAlert(
                timestamp=now,
                category='attack_tool',
                technique=desc,
                details=f'Token manipulation tool: {basename}',
                process=process_name,
                severity=severity,
                mitre_id=mitre,
            )
            self._add_alert(alert)
            return alert

        for pattern, desc, mitre, severity in TOKEN_COMMAND_PATTERNS:
            if pattern.search(command_line):
                alert = TokenAlert(
                    timestamp=now,
                    category='token_manipulation',
                    technique=desc,
                    details=f'Token manipulation: {desc}',
                    process=process_name,
                    severity=severity,
                    mitre_id=mitre,
                )
                self._add_alert(alert)
                return alert

        return None

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._scan_processes()
                self._check_privilege_usage()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Token check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _scan_processes(self) -> None:
        """Scan running processes for token manipulation tools."""
        try:
            result = subprocess.run(
                ['wmic', 'process', 'get', 'processid,name,commandline', '/format:csv'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line or line.startswith('Node,'):
                    continue
                parts = line.split(',', 3)
                if len(parts) < 4:
                    continue
                cmd_line = parts[1]
                proc_name = parts[2]
                pid = parts[3]
                if proc_name and cmd_line and pid not in self._seen_pids:
                    self._seen_pids.add(pid)
                    self.scan_command_line(proc_name, cmd_line)
            if len(self._seen_pids) > 10000:
                self._seen_pids = set(list(self._seen_pids)[-5000:])
        except Exception:
            pass

    def _check_privilege_usage(self) -> None:
        """Check for dangerous privilege assignments via whoami."""
        try:
            result = subprocess.run(
                ['whoami', '/priv'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return
            now = datetime.now(timezone.utc).isoformat()
            for priv, (desc, mitre, severity) in DANGEROUS_PRIVILEGES.items():
                if priv in result.stdout and 'Enabled' in result.stdout:
                    lines = result.stdout.splitlines()
                    for line in lines:
                        if priv in line and 'Enabled' in line:
                            self._add_alert(TokenAlert(
                                timestamp=now,
                                category='dangerous_privilege',
                                technique=desc,
                                details=f'Dangerous privilege enabled: {priv}',
                                process='current_process',
                                severity=severity,
                                mitre_id=mitre,
                            ))
                            break
        except Exception:
            pass

    def _add_alert(self, alert: TokenAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('Token: %s — %s', alert.technique, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[TokenManipulationDetector] = None


def get_token_detector() -> TokenManipulationDetector:
    global _detector
    if _detector is None:
        _detector = TokenManipulationDetector()
    return _detector


def start_token_detection(callback=None) -> bool:
    global _detector
    _detector = TokenManipulationDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'TokenManipulationDetector', 'TokenAlert',
    'get_token_detector', 'start_token_detection',
    'TOKEN_ATTACK_TOOLS', 'DANGEROUS_PRIVILEGES',
]
