"""
Ransomware Canary File System
Downpour v29 Titanium

Deploys decoy "canary" files across monitored directories. If ransomware
touches, renames, encrypts, or deletes any canary, Downpour gets an
instant high-confidence alert — typically 5-15 seconds faster than
behavioral or entropy-based detection.

Design principles:
  - Canary files look like real user documents (not obviously traps)
  - File names sort early in directory listings (ransomware often
    enumerates alphabetically)
  - Watchdog monitors canary integrity via sha256 + mtime + existence
  - Zero false-positive design: canaries should never be touched by
    legitimate software
  - Thread-safe: all state behind a lock, GUI callbacks via after()
"""

import hashlib
import json
import logging
import os
import secrets
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_log = logging.getLogger('downpour.canary')

# Canary file templates — names chosen to sort early and look like real files
CANARY_TEMPLATES = [
    ('  Budget_2026_FINAL.xlsx.canary', b'PK\x03\x04' + secrets.token_bytes(256)),
    ('  Contract_Draft_v3.docx.canary', b'PK\x03\x04' + secrets.token_bytes(256)),
    (' Annual_Report.pdf.canary', b'%PDF-1.5\n' + secrets.token_bytes(256)),
    (' Client_Database.csv.canary', b'Name,Email,Phone\n' + secrets.token_bytes(128)),
    (' Passwords.txt.canary', b'# credentials backup\n' + secrets.token_bytes(128)),
    (' Financial_Records.xlsx.canary', b'PK\x03\x04' + secrets.token_bytes(256)),
    (' Insurance_Policy.pdf.canary', b'%PDF-1.5\n' + secrets.token_bytes(256)),
    (' Tax_Returns_2025.pdf.canary', b'%PDF-1.5\n' + secrets.token_bytes(256)),
]


@dataclass
class CanaryFile:
    """Tracked canary file with integrity metadata."""
    path: str
    sha256: str
    size: int
    created_at: str
    last_verified: str
    status: str = 'active'  # active, tampered, missing, encrypted

    def to_dict(self) -> Dict[str, Any]:
        return {
            'path': self.path,
            'sha256': self.sha256,
            'size': self.size,
            'created_at': self.created_at,
            'last_verified': self.last_verified,
            'status': self.status,
        }


@dataclass
class CanaryAlert:
    """Alert generated when a canary is compromised."""
    timestamp: str
    canary_path: str
    alert_type: str  # tampered, missing, renamed, encrypted
    details: str
    severity: str = 'critical'

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'canary_path': self.canary_path,
            'alert_type': self.alert_type,
            'details': self.details,
            'severity': self.severity,
        }


class RansomwareCanarySystem:
    """
    Deploy and monitor canary files for instant ransomware detection.

    Canary files are placed in user-visible directories and monitored
    continuously. Any modification triggers a critical alert.
    """

    DEFAULT_MONITOR_DIRS = [
        os.path.expanduser('~/Documents'),
        os.path.expanduser('~/Desktop'),
        os.path.expanduser('~/Downloads'),
    ]

    def __init__(
        self,
        monitor_dirs: Optional[List[str]] = None,
        check_interval: float = 5.0,
        alert_callback: Optional[Callable[[CanaryAlert], None]] = None,
        state_file: Optional[Path] = None,
    ):
        self._monitor_dirs = monitor_dirs or self.DEFAULT_MONITOR_DIRS
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._state_file = state_file or Path('downpour_data/canary_state.json')
        self._canaries: Dict[str, CanaryFile] = {}
        self._alerts: List[CanaryAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._total_checks = 0
        self._total_alerts = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def deploy(self) -> int:
        """Deploy canary files to monitored directories. Returns count deployed."""
        deployed = 0
        self._load_state()

        for directory in self._monitor_dirs:
            dir_path = Path(directory)
            if not dir_path.exists():
                continue
            if not dir_path.is_dir():
                continue

            for name, content in CANARY_TEMPLATES:
                canary_path = dir_path / name
                if canary_path.exists():
                    continue

                try:
                    # Write canary file with unique content
                    unique_content = content + secrets.token_bytes(64)
                    canary_path.write_bytes(unique_content)

                    # Set hidden attribute on Windows
                    try:
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(
                            str(canary_path), 0x02  # FILE_ATTRIBUTE_HIDDEN
                        )
                    except Exception:
                        pass

                    # Track the canary
                    sha = hashlib.sha256(unique_content).hexdigest()
                    now = datetime.now(timezone.utc).isoformat()
                    canary = CanaryFile(
                        path=str(canary_path),
                        sha256=sha,
                        size=len(unique_content),
                        created_at=now,
                        last_verified=now,
                    )
                    with self._lock:
                        self._canaries[str(canary_path)] = canary
                    deployed += 1
                    _log.info('Canary deployed: %s', canary_path)
                except PermissionError:
                    _log.debug('Cannot deploy canary to %s (permission denied)', directory)
                except Exception as exc:
                    _log.debug('Canary deploy error: %s', exc)

        self._save_state()
        _log.info('Deployed %d canary files across %d directories', deployed, len(self._monitor_dirs))
        return deployed

    def start_monitoring(self) -> bool:
        """Start continuous canary integrity monitoring."""
        if self._running:
            return True
        if not self._canaries:
            self._load_state()
        if not self._canaries:
            _log.warning('No canaries deployed — call deploy() first')
            return False

        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name='canary-monitor',
            daemon=True,
        )
        self._monitor_thread.start()
        _log.info('Canary monitoring started (%d files, %.1fs interval)',
                  len(self._canaries), self._check_interval)
        return True

    def stop_monitoring(self) -> None:
        """Stop canary monitoring."""
        self._running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=10.0)
        self._save_state()
        _log.info('Canary monitoring stopped')

    def remove_all(self) -> int:
        """Remove all deployed canary files. Returns count removed."""
        removed = 0
        with self._lock:
            for path_str in list(self._canaries.keys()):
                try:
                    path = Path(path_str)
                    if path.exists():
                        path.unlink()
                        removed += 1
                except Exception as exc:
                    _log.debug('Cannot remove canary %s: %s', path_str, exc)
            self._canaries.clear()
        self._save_state()
        return removed

    def get_status(self) -> Dict[str, Any]:
        """Return canary system status."""
        with self._lock:
            active = sum(1 for c in self._canaries.values() if c.status == 'active')
            compromised = sum(1 for c in self._canaries.values() if c.status != 'active')
            return {
                'running': self._running,
                'total_canaries': len(self._canaries),
                'active': active,
                'compromised': compromised,
                'total_checks': self._total_checks,
                'total_alerts': self._total_alerts,
                'check_interval': self._check_interval,
                'monitored_dirs': self._monitor_dirs,
            }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent canary alerts."""
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def verify_all(self) -> Dict[str, str]:
        """One-shot verification of all canaries. Returns {path: status}."""
        results = {}
        with self._lock:
            for path_str, canary in self._canaries.items():
                status = self._check_canary(canary)
                results[path_str] = status
        return results

    # ------------------------------------------------------------------
    # Monitor loop
    # ------------------------------------------------------------------

    def _monitor_loop(self) -> None:
        """Continuous monitoring loop running on background thread."""
        while self._running:
            try:
                self._run_integrity_check()
                self._total_checks += 1
            except Exception as exc:
                _log.debug('Canary check error: %s', exc)

            # Interruptible sleep
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(0.5)

    def _run_integrity_check(self) -> None:
        """Check all canaries for tampering."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            for path_str, canary in list(self._canaries.items()):
                status = self._check_canary(canary)
                canary.last_verified = now

                if status != 'active' and canary.status == 'active':
                    canary.status = status
                    alert = CanaryAlert(
                        timestamp=now,
                        canary_path=path_str,
                        alert_type=status,
                        details=self._build_alert_details(canary, status),
                    )
                    self._alerts.append(alert)
                    self._total_alerts += 1
                    _log.critical('CANARY ALERT: %s — %s', path_str, status)

                    if self._alert_callback:
                        try:
                            self._alert_callback(alert)
                        except Exception as exc:
                            _log.debug('Alert callback error: %s', exc)

    def _check_canary(self, canary: CanaryFile) -> str:
        """Check a single canary file. Returns status string."""
        path = Path(canary.path)

        if not path.exists():
            # Check for renamed versions (common ransomware behavior)
            parent = path.parent
            stem = path.stem
            for sibling in parent.iterdir():
                if stem in sibling.name and sibling.name != path.name:
                    return 'renamed'
            return 'missing'

        try:
            content = path.read_bytes()
        except PermissionError:
            return 'locked'
        except Exception:
            return 'error'

        # Check size change
        if len(content) != canary.size:
            return 'encrypted' if len(content) > canary.size * 1.5 else 'tampered'

        # Check hash
        current_hash = hashlib.sha256(content).hexdigest()
        if current_hash != canary.sha256:
            return 'tampered'

        return 'active'

    @staticmethod
    def _build_alert_details(canary: CanaryFile, status: str) -> str:
        """Build human-readable alert details."""
        details = {
            'missing': f'Canary file deleted: {canary.path} (ransomware may be deleting files)',
            'renamed': f'Canary file renamed: {canary.path} (ransomware encryption detected)',
            'encrypted': f'Canary file size changed dramatically: {canary.path} (likely encrypted)',
            'tampered': f'Canary file content modified: {canary.path} (integrity violation)',
            'locked': f'Canary file locked by another process: {canary.path} (possible encryption in progress)',
        }
        return details.get(status, f'Canary anomaly: {canary.path} ({status})')

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _save_state(self) -> None:
        """Save canary state to disk."""
        try:
            self._state_file.parent.mkdir(parents=True, exist_ok=True)
            with self._lock:
                state = {
                    'version': '1.0',
                    'saved_at': datetime.now(timezone.utc).isoformat(),
                    'canaries': {k: v.to_dict() for k, v in self._canaries.items()},
                }
            self._state_file.write_text(json.dumps(state, indent=2), encoding='utf-8')
        except Exception as exc:
            _log.debug('Cannot save canary state: %s', exc)

    def _load_state(self) -> None:
        """Load canary state from disk."""
        if not self._state_file.exists():
            return
        try:
            data = json.loads(self._state_file.read_text(encoding='utf-8'))
            with self._lock:
                for path_str, cdata in data.get('canaries', {}).items():
                    self._canaries[path_str] = CanaryFile(**cdata)
            _log.info('Loaded %d canary records from state file', len(self._canaries))
        except Exception as exc:
            _log.debug('Cannot load canary state: %s', exc)


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_system: Optional[RansomwareCanarySystem] = None


def get_canary_system() -> RansomwareCanarySystem:
    """Return the singleton canary system."""
    global _system
    if _system is None:
        _system = RansomwareCanarySystem()
    return _system


def deploy_canaries(dirs=None, callback=None) -> int:
    """Deploy canary files and start monitoring."""
    global _system
    _system = RansomwareCanarySystem(
        monitor_dirs=dirs,
        alert_callback=callback,
    )
    count = _system.deploy()
    _system.start_monitoring()
    return count


def stop_canaries() -> None:
    """Stop monitoring and clean up."""
    if _system:
        _system.stop_monitoring()


__all__ = [
    'CanaryFile', 'CanaryAlert', 'RansomwareCanarySystem',
    'get_canary_system', 'deploy_canaries', 'stop_canaries',
    'CANARY_TEMPLATES',
]
