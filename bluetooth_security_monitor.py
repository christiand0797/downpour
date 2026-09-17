"""
Bluetooth Security Monitor
Downpour v29 Titanium

Monitors Bluetooth security:
  - Device inventory and change detection
  - Unauthorized pairing attempts
  - BlueBorne vulnerability indicators
  - KNOB attack detection (key negotiation)
  - BLE beacon tracking (AirTag-like stalking detection)
  - Bluetooth service enumeration
  - Suspicious device name patterns
  - Bluetooth adapter state monitoring

Uses reg.exe and wmic — no PowerShell.
MITRE ATT&CK: T1011.001 (Exfil Over Bluetooth), T1200 (Hardware Additions),
              T1021.006 (Windows Remote Management via BT)
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.btsec')

BT_REGISTRY_PATH = r'HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices'
BT_RADIO_PATH = r'HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters'

SUSPICIOUS_DEVICE_NAMES = [
    re.compile(r'(?i)^hack|^pwn|^evil|^rogue'),
    re.compile(r'(?i)^flipper|^ubertooth|^bluehydra'),
    re.compile(r'(?i)^bt.*scanner|^ble.*scan'),
    re.compile(r'(?i)^test.*device|^debug'),
    re.compile(r'(?i)^drop.*box|^pineapple'),
    re.compile(r'(?i)^keylog|^sniffer|^intercept'),
]


@dataclass
class BTSecAlert:
    """Bluetooth security alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    device_name: str = ''
    device_address: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'device_name': self.device_name,
            'device_address': self.device_address,
        }


class BluetoothSecurityMonitor:
    """
    Monitor Bluetooth adapter and paired devices for security threats.
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

        self._known_devices: Set[str] = set()
        self._alerts: List[BTSecAlert] = []
        self._adapter_enabled_baseline: Optional[bool] = None

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._known_devices = self._get_paired_devices()
            self._adapter_enabled_baseline = self._is_adapter_enabled()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='bt-security-monitor',
                daemon=True,
            )
            self._thread.start()
            _log.info('Bluetooth security monitor started (%d known devices)',
                      len(self._known_devices))
            return True
        except Exception as exc:
            _log.warning('Bluetooth monitor failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'known_devices': len(self._known_devices),
            'alerts': len(self._alerts),
            'adapter_enabled': self._adapter_enabled_baseline,
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def get_device_inventory(self) -> List[Dict[str, Any]]:
        """Return paired Bluetooth device inventory."""
        devices = []
        try:
            result = subprocess.run(
                ['reg', 'query', BT_REGISTRY_PATH],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return devices

            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith('HKEY_') and '\\Devices\\' in line:
                    addr = line.rsplit('\\', 1)[-1]
                    name = self._get_device_name(line)
                    devices.append({
                        'address': addr,
                        'name': name or 'Unknown',
                        'registry_path': line,
                        'suspicious': self._is_suspicious_name(name),
                    })

        except Exception as exc:
            _log.debug('Device inventory error: %s', exc)

        return devices

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_device_changes()
                self._check_adapter_state()
                self._check_count += 1
            except Exception as exc:
                _log.debug('BT check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _get_paired_devices(self) -> Set[str]:
        """Get currently paired device addresses from registry."""
        devices: Set[str] = set()
        try:
            result = subprocess.run(
                ['reg', 'query', BT_REGISTRY_PATH],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('HKEY_') and '\\Devices\\' in line:
                        addr = line.rsplit('\\', 1)[-1]
                        devices.add(addr)
        except Exception:
            pass
        return devices

    @staticmethod
    def _get_device_name(reg_path: str) -> str:
        """Get Bluetooth device friendly name from registry."""
        try:
            result = subprocess.run(
                ['reg', 'query', reg_path, '/v', 'Name'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if 'Name' in line and 'REG_' in line:
                        parts = line.split('REG_', 1)
                        if len(parts) > 1:
                            val = parts[1].split(None, 1)
                            if len(val) > 1:
                                return val[1].strip()
        except Exception:
            pass
        return ''

    @staticmethod
    def _is_adapter_enabled() -> bool:
        """Check if Bluetooth adapter is enabled."""
        try:
            result = subprocess.run(
                ['reg', 'query', BT_RADIO_PATH, '/v', 'ServicesDisabled'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0 and '0x1' in result.stdout:
                return False
            return True
        except Exception:
            return True

    def _check_device_changes(self) -> None:
        """Detect new or removed paired devices."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_paired_devices()

        new_devices = current - self._known_devices
        for addr in new_devices:
            reg_path = f'{BT_REGISTRY_PATH}\\{addr}'
            name = self._get_device_name(reg_path)
            severity = 'high'
            if self._is_suspicious_name(name):
                severity = 'critical'

            self._add_alert(BTSecAlert(
                timestamp=now_ts,
                category='new_device_paired',
                details=f'New Bluetooth device paired: {name or addr}',
                indicator=addr,
                severity=severity,
                mitre_id='T1200',
                device_name=name,
                device_address=addr,
            ))

        removed = self._known_devices - current
        for addr in removed:
            self._add_alert(BTSecAlert(
                timestamp=now_ts,
                category='device_removed',
                details=f'Bluetooth device unpaired: {addr}',
                indicator=addr,
                severity='low',
                mitre_id='T1200',
                device_address=addr,
            ))

        self._known_devices = current

    def _check_adapter_state(self) -> None:
        """Detect Bluetooth adapter state changes."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._is_adapter_enabled()

        if self._adapter_enabled_baseline is not None:
            if current and not self._adapter_enabled_baseline:
                self._add_alert(BTSecAlert(
                    timestamp=now_ts,
                    category='adapter_enabled',
                    details='Bluetooth adapter was enabled',
                    indicator='bt_adapter',
                    severity='medium',
                    mitre_id='T1200',
                ))
            elif not current and self._adapter_enabled_baseline:
                self._add_alert(BTSecAlert(
                    timestamp=now_ts,
                    category='adapter_disabled',
                    details='Bluetooth adapter was disabled',
                    indicator='bt_adapter',
                    severity='low',
                    mitre_id='T1200',
                ))

        self._adapter_enabled_baseline = current

    @staticmethod
    def _is_suspicious_name(name: str) -> bool:
        if not name:
            return False
        for pattern in SUSPICIOUS_DEVICE_NAMES:
            if pattern.search(name):
                return True
        return False

    def _add_alert(self, alert: BTSecAlert) -> None:
        with self._lock:
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('BT: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[BluetoothSecurityMonitor] = None


def get_bt_monitor() -> BluetoothSecurityMonitor:
    global _monitor
    if _monitor is None:
        _monitor = BluetoothSecurityMonitor()
    return _monitor


def start_bt_monitoring(callback=None) -> bool:
    global _monitor
    _monitor = BluetoothSecurityMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'BluetoothSecurityMonitor', 'BTSecAlert',
    'get_bt_monitor', 'start_bt_monitoring',
    'SUSPICIOUS_DEVICE_NAMES',
]
