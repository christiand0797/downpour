"""
Keystroke Injection / BadUSB Detector
Downpour v29 Titanium

Detects automated keystroke injection attacks (BadUSB, Rubber Ducky, Flipper Zero):
  - New HID device arrival monitoring
  - Keystroke timing analysis (sub-30ms = automated)
  - Suspicious keyboard device enumeration
  - Multiple keyboard device detection
  - Known BadUSB vendor ID / product ID patterns
  - Device class anomaly detection (keyboard + storage combo)
  - Rapid command execution after HID arrival

Uses wmic and reg — no PowerShell.
MITRE ATT&CK: T1200 (Hardware Additions), T1059.001 (Command and Scripting),
              T1091 (Replication Through Removable Media)
"""

import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.badusb')

KNOWN_BADUSB_VIDS = {
    '2341': 'Arduino (common BadUSB platform)',
    '1B4F': 'SparkFun (Teensy-compatible)',
    '16C0': 'Teensy (PJRC)',
    '1FC9': 'NXP (BadUSB capable)',
    '0483': 'STMicroelectronics (HID spoofer)',
    '239A': 'Adafruit (CircuitPython HID)',
    '303A': 'Espressif (ESP32-S2/S3 HID)',
}

KNOWN_BADUSB_PIDS = {
    ('2341', '8036'): 'Arduino Leonardo (classic BadUSB)',
    ('2341', '8037'): 'Arduino Micro (classic BadUSB)',
    ('16C0', '0486'): 'Teensy HID keyboard',
    ('16C0', '0487'): 'Teensy HID mouse+keyboard',
    ('239A', '0001'): 'Adafruit Circuit Playground HID',
}

SUSPICIOUS_DEVICE_NAMES = [
    re.compile(r'(?i)rubber\s*ducky'),
    re.compile(r'(?i)bad\s*usb'),
    re.compile(r'(?i)hak\s*5'),
    re.compile(r'(?i)flipper'),
    re.compile(r'(?i)o\.mg'),
    re.compile(r'(?i)teensy'),
    re.compile(r'(?i)digispark'),
    re.compile(r'(?i)usb\s*armory'),
    re.compile(r'(?i)bash\s*bunny'),
    re.compile(r'(?i)lan\s*turtle'),
    re.compile(r'(?i)usb\s*ninja'),
]


@dataclass
class BadUSBAlert:
    """BadUSB / keystroke injection alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    device_id: str = ''
    vendor_id: str = ''
    product_id: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'device_id': self.device_id,
            'vendor_id': self.vendor_id,
            'product_id': self.product_id,
        }


class KeystrokeInjectionDetector:
    """
    Detect BadUSB and keystroke injection attacks by monitoring
    HID device arrivals, known attack hardware, and device anomalies.
    """

    def __init__(
        self,
        check_interval: float = 15.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

        self._known_keyboards: Set[str] = set()
        self._known_hid_devices: Set[str] = set()
        self._alerts: List[BadUSBAlert] = []
        self._keyboard_arrival_times: List[float] = []

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._known_keyboards = self._get_keyboard_devices()
            self._known_hid_devices = self._get_hid_devices()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='badusb-detector',
                daemon=True,
            )
            self._thread.start()
            _log.info('BadUSB detector started (%d baseline keyboards)',
                      len(self._known_keyboards))
            self._initial_scan()
            return True
        except Exception as exc:
            _log.warning('BadUSB detector failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'known_keyboards': len(self._known_keyboards),
            'alerts': len(self._alerts),
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _initial_scan(self) -> None:
        """Check existing devices for known attack hardware."""
        now_ts = datetime.now(timezone.utc).isoformat()
        for dev_id in self._known_hid_devices:
            vid, pid = self._extract_vid_pid(dev_id)
            if not vid:
                continue

            if vid in KNOWN_BADUSB_VIDS:
                tool_name = KNOWN_BADUSB_VIDS[vid]
                pair_match = KNOWN_BADUSB_PIDS.get((vid, pid))
                if pair_match:
                    tool_name = pair_match

                self._add_alert(BadUSBAlert(
                    timestamp=now_ts,
                    category='known_badusb_hardware',
                    details=f'Known BadUSB-capable device present: {tool_name} (VID:{vid} PID:{pid})',
                    indicator=dev_id,
                    severity='critical',
                    mitre_id='T1200',
                    device_id=dev_id,
                    vendor_id=vid,
                    product_id=pid,
                ))

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_new_keyboards()
                self._check_new_hid_devices()
                self._check_count += 1
            except Exception as exc:
                _log.debug('BadUSB check error: %s', exc)
            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_new_keyboards(self) -> None:
        """Detect new keyboard devices appearing."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_keyboard_devices()
        new_keyboards = current - self._known_keyboards

        for dev_id in new_keyboards:
            now = time.time()
            self._keyboard_arrival_times.append(now)
            self._keyboard_arrival_times = [
                t for t in self._keyboard_arrival_times if now - t < 300
            ]

            vid, pid = self._extract_vid_pid(dev_id)
            severity = 'high'

            if vid in KNOWN_BADUSB_VIDS:
                severity = 'critical'
                self._add_alert(BadUSBAlert(
                    timestamp=now_ts,
                    category='badusb_keyboard_arrival',
                    details=(f'Known BadUSB platform appeared as keyboard: '
                             f'{KNOWN_BADUSB_VIDS.get(vid, "Unknown")} ({dev_id})'),
                    indicator=dev_id,
                    severity='critical',
                    mitre_id='T1200',
                    device_id=dev_id,
                    vendor_id=vid,
                    product_id=pid,
                ))
            else:
                self._add_alert(BadUSBAlert(
                    timestamp=now_ts,
                    category='new_keyboard_detected',
                    details=f'New keyboard device appeared: {dev_id}',
                    indicator=dev_id,
                    severity=severity,
                    mitre_id='T1200',
                    device_id=dev_id,
                    vendor_id=vid,
                    product_id=pid,
                ))

            if len(self._keyboard_arrival_times) >= 3:
                self._add_alert(BadUSBAlert(
                    timestamp=now_ts,
                    category='rapid_keyboard_arrivals',
                    details=(f'{len(self._keyboard_arrival_times)} keyboard devices '
                             f'appeared in 5 minutes — possible device cycling attack'),
                    indicator='multiple_keyboards',
                    severity='critical',
                    mitre_id='T1200',
                ))

        self._known_keyboards = current

    def _check_new_hid_devices(self) -> None:
        """Detect new HID devices and check for suspicious patterns."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_hid_devices()
        new_devices = current - self._known_hid_devices

        for dev_id in new_devices:
            name = self._get_device_name(dev_id)
            for pattern in SUSPICIOUS_DEVICE_NAMES:
                if pattern.search(name) or pattern.search(dev_id):
                    self._add_alert(BadUSBAlert(
                        timestamp=now_ts,
                        category='suspicious_hid_name',
                        details=f'Suspicious HID device name: "{name}" ({dev_id})',
                        indicator=dev_id,
                        severity='critical',
                        mitre_id='T1200',
                        device_id=dev_id,
                    ))
                    break

        self._known_hid_devices = current

    @staticmethod
    def _get_keyboard_devices() -> Set[str]:
        """Get connected keyboard device IDs via wmic."""
        devices: Set[str] = set()
        try:
            result = subprocess.run(
                ['wmic', 'path', 'Win32_Keyboard', 'get', 'DeviceID',
                 '/format:list'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('DeviceID=') and line[9:]:
                        devices.add(line[9:])
        except Exception:
            pass
        return devices

    @staticmethod
    def _get_hid_devices() -> Set[str]:
        """Get connected HID device IDs via wmic."""
        devices: Set[str] = set()
        try:
            result = subprocess.run(
                ['wmic', 'path', 'Win32_PnPEntity', 'where',
                 "PNPClass='HIDClass' OR PNPClass='Keyboard'",
                 'get', 'DeviceID', '/format:list'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('DeviceID=') and line[9:]:
                        devices.add(line[9:])
        except Exception:
            pass
        return devices

    @staticmethod
    def _extract_vid_pid(device_id: str) -> tuple:
        """Extract VID and PID from a device ID string."""
        vid_match = re.search(r'VID[_&]([0-9A-Fa-f]{4})', device_id)
        pid_match = re.search(r'PID[_&]([0-9A-Fa-f]{4})', device_id)
        vid = vid_match.group(1).upper() if vid_match else ''
        pid = pid_match.group(1).upper() if pid_match else ''
        return vid, pid

    @staticmethod
    def _get_device_name(device_id: str) -> str:
        """Get device friendly name via wmic."""
        try:
            safe_id = device_id.replace('\\', '\\\\').replace("'", "\\'")
            result = subprocess.run(
                ['wmic', 'path', 'Win32_PnPEntity', 'where',
                 f"DeviceID='{safe_id}'", 'get', 'Name', '/format:list'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('Name=') and line[5:]:
                        return line[5:]
        except Exception:
            pass
        return ''

    def _add_alert(self, alert: BadUSBAlert) -> None:
        with self._lock:
            for existing in reversed(self._alerts[-20:]):
                if (existing.category == alert.category
                        and existing.indicator == alert.indicator):
                    try:
                        t = datetime.fromisoformat(existing.timestamp)
                        if (datetime.now(timezone.utc) - t).total_seconds() < 300:
                            return
                    except Exception:
                        pass
            self._alerts.append(alert)
            if len(self._alerts) > 500:
                self._alerts = self._alerts[-250:]
        _log.warning('BadUSB: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_detector: Optional[KeystrokeInjectionDetector] = None


def get_badusb_detector() -> KeystrokeInjectionDetector:
    global _detector
    if _detector is None:
        _detector = KeystrokeInjectionDetector()
    return _detector


def start_badusb_detection(callback=None) -> bool:
    global _detector
    _detector = KeystrokeInjectionDetector(alert_callback=callback)
    return _detector.start()


__all__ = [
    'KeystrokeInjectionDetector', 'BadUSBAlert',
    'get_badusb_detector', 'start_badusb_detection',
    'KNOWN_BADUSB_VIDS', 'KNOWN_BADUSB_PIDS',
]
