"""
Credential Guard & VBS Integrity Monitor
Downpour v29 Titanium

Monitors Windows Virtualization-Based Security (VBS) and Credential Guard
status for tampering attempts. Detects:
  - Credential Guard being disabled via registry
  - HVCI (Hypervisor-enforced Code Integrity) weakening
  - VBS configuration changes
  - Secure Boot status changes
  - LSA protection (RunAsPPL) modifications
  - WDAC/Device Guard policy changes

Uses native Windows commands only (no PowerShell).
"""

import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.credguard')

# Registry paths for VBS/Credential Guard configuration
VBS_REGISTRY = {
    'credential_guard': {
        'key': r'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
        'values': {
            'LsaCfgFlags': {'safe': [1, 2], 'desc': 'Credential Guard enforcement'},
            'RunAsPPL': {'safe': [1, 2], 'desc': 'LSA Protected Process Light'},
        },
    },
    'device_guard': {
        'key': r'HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard',
        'values': {
            'EnableVirtualizationBasedSecurity': {'safe': [1], 'desc': 'VBS enabled'},
            'RequirePlatformSecurityFeatures': {'safe': [1, 3], 'desc': 'Secure Boot + DMA'},
            'HypervisorEnforcedCodeIntegrity': {'safe': [1], 'desc': 'HVCI enabled'},
            'Locked': {'safe': [1], 'desc': 'UEFI lock on VBS'},
        },
    },
    'secure_boot': {
        'key': r'HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State',
        'values': {
            'UEFISecureBootEnabled': {'safe': [1], 'desc': 'UEFI Secure Boot'},
        },
    },
    'wdac': {
        'key': r'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard',
        'values': {
            'DeployConfigCIPolicy': {'safe': [1], 'desc': 'WDAC CI policy deployed'},
            'HVCIMATRequired': {'safe': [1], 'desc': 'HVCI MAT required'},
        },
    },
}


@dataclass
class CredGuardAlert:
    """Alert for credential protection tampering."""
    timestamp: str
    category: str
    registry_key: str
    value_name: str
    old_value: Any
    new_value: Any
    severity: str
    mitre_id: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'registry_key': self.registry_key,
            'value_name': self.value_name,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'description': self.description,
        }


class CredentialGuardMonitor:
    """
    Monitor VBS/Credential Guard/HVCI for tampering.

    Takes a baseline on first run, then diffs every check interval.
    Any weakening of credential protection triggers a critical alert.
    """

    def __init__(
        self,
        check_interval: float = 30.0,
        alert_callback: Optional[Callable] = None,
        state_dir: Optional[Path] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._state_dir = state_dir or Path('downpour_data')
        self._baseline: Dict[str, Dict[str, Any]] = {}
        self._alerts: List[CredGuardAlert] = []
        self._lock = threading.Lock()
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._check_count = 0

    def start(self) -> bool:
        """Start credential guard monitoring."""
        if self._running:
            return True
        try:
            self._baseline = self._read_all_values()
            self._running = True
            self._monitor_thread = threading.Thread(
                target=self._monitor_loop,
                name='credguard-monitor',
                daemon=True,
            )
            self._monitor_thread.start()
            _log.info('Credential Guard monitor started (%d baseline values)',
                     sum(len(v) for v in self._baseline.values()))
            return True
        except Exception as exc:
            _log.warning('Credential Guard monitor failed to start: %s', exc)
            return False

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        """Return current credential protection status."""
        current = self._read_all_values()
        status = {
            'credential_guard': self._check_feature(current, 'credential_guard', 'LsaCfgFlags'),
            'lsa_ppl': self._check_feature(current, 'credential_guard', 'RunAsPPL'),
            'vbs_enabled': self._check_feature(current, 'device_guard', 'EnableVirtualizationBasedSecurity'),
            'hvci_enabled': self._check_feature(current, 'device_guard', 'HypervisorEnforcedCodeIntegrity'),
            'secure_boot': self._check_feature(current, 'secure_boot', 'UEFISecureBootEnabled'),
            'vbs_locked': self._check_feature(current, 'device_guard', 'Locked'),
            'checks_performed': self._check_count,
            'alerts_count': len(self._alerts),
            'running': self._running,
        }
        return status

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return recent alerts."""
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _monitor_loop(self) -> None:
        """Background monitoring loop."""
        while self._running:
            try:
                self._check_for_changes()
                self._check_count += 1
            except Exception as exc:
                _log.debug('CredGuard check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_for_changes(self) -> None:
        """Diff current values against baseline."""
        current = self._read_all_values()
        now = datetime.now(timezone.utc).isoformat()

        for category, values in current.items():
            baseline_values = self._baseline.get(category, {})
            config = VBS_REGISTRY.get(category, {})
            value_specs = config.get('values', {})

            for name, curr_val in values.items():
                old_val = baseline_values.get(name)
                if old_val == curr_val:
                    continue

                spec = value_specs.get(name, {})
                safe_values = spec.get('safe', [])
                desc = spec.get('desc', name)

                is_weakening = (
                    curr_val not in safe_values and old_val in safe_values
                ) if safe_values else (curr_val == 0 and old_val and old_val > 0)

                severity = 'critical' if is_weakening else 'medium'
                mitre = 'T1556' if 'credential' in category else 'T1562.001'

                alert = CredGuardAlert(
                    timestamp=now,
                    category=category,
                    registry_key=config.get('key', ''),
                    value_name=name,
                    old_value=old_val,
                    new_value=curr_val,
                    severity=severity,
                    mitre_id=mitre,
                    description=f'{desc} changed: {old_val} -> {curr_val}'
                    + (' (WEAKENED)' if is_weakening else ''),
                )

                with self._lock:
                    self._alerts.append(alert)
                    if len(self._alerts) > 500:
                        self._alerts = self._alerts[-250:]

                _log.warning('CredGuard: %s', alert.description)
                if self._alert_callback:
                    try:
                        self._alert_callback(alert)
                    except Exception:
                        pass

        self._baseline = current

    def _read_all_values(self) -> Dict[str, Dict[str, Any]]:
        """Read all monitored registry values using reg.exe."""
        result: Dict[str, Dict[str, Any]] = {}
        for category, config in VBS_REGISTRY.items():
            key = config['key']
            values = {}
            for value_name in config.get('values', {}):
                val = self._reg_query(key, value_name)
                if val is not None:
                    values[value_name] = val
            result[category] = values
        return result

    @staticmethod
    def _reg_query(key: str, value_name: str) -> Optional[int]:
        """Query a single registry DWORD value via reg.exe."""
        try:
            result = subprocess.run(
                ['reg', 'query', key, '/v', value_name],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return None
            for line in result.stdout.splitlines():
                line = line.strip()
                if value_name in line and 'REG_DWORD' in line:
                    parts = line.split()
                    for part in parts:
                        if part.startswith('0x'):
                            return int(part, 16)
            return None
        except Exception:
            return None

    @staticmethod
    def _check_feature(values: Dict, category: str, name: str) -> str:
        """Return human-readable status for a feature."""
        cat_vals = values.get(category, {})
        val = cat_vals.get(name)
        if val is None:
            return 'not_configured'
        spec = VBS_REGISTRY.get(category, {}).get('values', {}).get(name, {})
        safe = spec.get('safe', [])
        if val in safe:
            return 'enabled'
        return 'disabled'


_monitor: Optional[CredentialGuardMonitor] = None


def get_credguard_monitor() -> CredentialGuardMonitor:
    global _monitor
    if _monitor is None:
        _monitor = CredentialGuardMonitor()
    return _monitor


def start_credguard_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = CredentialGuardMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'CredentialGuardMonitor', 'CredGuardAlert',
    'get_credguard_monitor', 'start_credguard_monitoring',
    'VBS_REGISTRY',
]
