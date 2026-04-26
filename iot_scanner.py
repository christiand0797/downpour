"""
Downpour IoT Security Scanner
==============================
Scans the local subnet for all devices, fingerprints them to identify
what physical device they are, detects botnet indicators, and provides
one-click blocking and isolation.

Key capabilities:
- Parallel subnet ping sweep (finds every device on your network)
- Device fingerprinting via HTTP/Telnet/mDNS/banner grabbing
- OUI MAC vendor lookup (identifies manufacturer from MAC address)
- Mozi / Mirai / Kimwolf botnet indicator detection per device
- Windows Firewall blocking of specific devices
- Router ACL command generation
- Physical device identification hints ("This is probably a smart plug")
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import struct
import subprocess
import threading
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set

log = logging.getLogger(__name__)
_NO_WIN = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0

# ---------------------------------------------------------------------------
# OUI vendor lookup — top 200 IoT / networking vendors embedded
# ---------------------------------------------------------------------------
OUI_MAP: Dict[str, str] = {
    # Espressif (ESP8266 / ESP32 — cheap smart home IoT)
    'C4:DD:57': 'Espressif Systems (ESP8266/32)',
    'CC:50:E3': 'Espressif Systems (ESP8266/32)',
    'A4:CF:12': 'Espressif Systems (ESP8266/32)',
    '84:F3:EB': 'Espressif Systems (ESP8266/32)',
    '8C:AA:B5': 'Espressif Systems (ESP8266/32)',
    '30:AE:A4': 'Espressif Systems (ESP8266/32)',
    'E8:DB:84': 'Espressif Systems (ESP8266/32)',
    '24:6F:28': 'Espressif Systems (ESP8266/32)',
    'EC:FA:BC': 'Espressif Systems (ESP8266/32)',
    'BC:DD:C2': 'Espressif Systems (ESP8266/32)',
    '10:52:1C': 'Espressif Systems (ESP8266/32)',
    '68:C6:3A': 'Espressif Systems (ESP8266/32)',
    '40:F5:20': 'Espressif Systems (ESP8266/32)',
    # Gaoshengda (WiFi modules in cheap IoT — often Mozi target)
    '94:B3:F7': 'Gaoshengda Technology (IoT WiFi module)',
    'DC:4F:22': 'Gaoshengda Technology (IoT WiFi module)',
    'B0:E4:D5': 'Gaoshengda Technology (IoT WiFi module)',
    'C8:47:8C': 'Gaoshengda Technology (IoT WiFi module)',
    # Tuya (smart home platform — plugs, bulbs, thermostats)
    '50:02:91': 'Tuya Smart (smart plug/bulb/thermostat)',
    'D8:3F:27': 'Tuya Smart (smart plug/bulb)',
    '7C:01:0A': 'Tuya Smart (smart device)',
    # TP-Link
    '50:C7:BF': 'TP-Link (router/smart plug)',
    'E8:65:D4': 'TP-Link Router',
    'B0:BE:76': 'TP-Link Router',
    'F8:D1:11': 'TP-Link (smart home)',
    '14:CC:20': 'TP-Link Router',
    # Netgear
    'A0:63:91': 'Netgear Router',
    '20:E5:2A': 'Netgear Router',
    'C4:04:15': 'Netgear Router',
    # Asus
    'F8:32:E4': 'ASUS Router',
    '2C:4D:54': 'ASUS Router',
    # Xiaomi / Mijia (smart home — often exploited)
    '28:6C:07': 'Xiaomi (smart home device)',
    '64:9E:F3': 'Xiaomi (smart home device)',
    'F4:F5:24': 'Xiaomi (smart home device)',
    '34:CE:00': 'Xiaomi (smart home device)',
    # Realtek (embedded in routers/IoT — CVE-2021-35394 target)
    '00:E0:4C': 'Realtek Semiconductor (router/IoT)',
    # Shenzhen Humax
    '00:22:FD': 'Humax (set-top box)',
    # Ring / Amazon
    'F0:81:73': 'Ring/Amazon (doorbell/camera)',
    '68:37:E9': 'Amazon (Echo/FireTV)',
    'FC:A6:67': 'Amazon (Echo/FireTV)',
    # Google/Nest
    '48:D6:D5': 'Google (Nest/ChromeCast)',
    'F4:F5:D8': 'Google (Nest/ChromeCast)',
    # Apple
    'F8:FF:C2': 'Apple (iPhone/iPad/Mac)',
    '9C:8D:7C': 'Apple (iPhone/iPad)',
    # Samsung
    '8C:79:F5': 'Samsung (phone/TV)',
    '5C:49:79': 'Samsung SmartTV',
    # LG Electronics
    '48:59:29': 'LG Electronics (TV/appliance)',
    # Sony
    '7C:B2:7D': 'Sony (TV/PlayStation)',
    # Nintendo
    '00:22:D7': 'Nintendo (Switch/Wii)',
    'E8:5B:5B': 'Nintendo Clone (SUSPICIOUS)',
    # Hikvision (IP cameras — commonly exploited)
    'E4:24:6C': 'Hikvision IP Camera',
    'A4:14:37': 'Hikvision IP Camera',
    'C4:2F:90': 'Hikvision IP Camera',
    '44:19:B6': 'Hikvision IP Camera',
    # Dahua (IP cameras)
    'E0:50:8B': 'Dahua IP Camera',
    '10:12:FB': 'Dahua IP Camera',
    # Reolink
    'EC:71:DB': 'Reolink Camera',
    # Ubiquiti
    'F0:9F:C2': 'Ubiquiti (network device)',
    '78:8A:20': 'Ubiquiti (network device)',
    # MikroTik
    'CC:2D:E0': 'MikroTik Router',
    'B8:69:F4': 'MikroTik Router',
    # Cisco
    '00:0F:23': 'Cisco (networking)',
    '00:17:94': 'Cisco (networking)',
    # Raspberry Pi
    'B8:27:EB': 'Raspberry Pi Foundation',
    'DC:A6:32': 'Raspberry Pi 4',
    'E4:5F:01': 'Raspberry Pi',
    # Arduino
    '98:D3:31': 'Arduino / HiLetgo (microcontroller)',
    # Shenzhen TVT (cheap IP cameras)
    '00:12:1C': 'TVT Digital (IP camera)',
}

# Device type hints by open ports
PORT_DEVICE_HINTS: Dict[int, str] = {
    23:   'Telnet open (router/IoT — often Mirai target)',
    80:   'HTTP web interface',
    443:  'HTTPS web interface',
    8080: 'HTTP alternate port (router admin)',
    8443: 'HTTPS alternate port',
    554:  'RTSP stream (IP camera)',
    8554: 'RTSP alternate (IP camera)',
    1935: 'RTMP stream (camera/media)',
    9999: 'Mozi botnet C2 port — INFECTED',
    5555: 'Android Debug Bridge (ADB) — Kimwolf target',
    5556: 'ADB alternate',
    4444: 'Metasploit/RAT default port',
    4455: 'ESP8266 OTA firmware update port',
    8266: 'ESP8266 Arduino OTA',
    3000: 'Development server / Grafana',
    8888: 'Jupyter Notebook',
    81:   'HTTP alternate (cheap router admin)',
    8081: 'HTTP alternate admin',
    9000: 'Management interface',
    161:  'SNMP (network device)',
    53:   'DNS server (router)',
    67:   'DHCP server (router)',
    1883: 'MQTT broker (IoT messaging)',
    8883: 'MQTT over TLS',
    502:  'Modbus (industrial IoT)',
    102:  'S7Comm (Siemens PLC)',
    2323: 'Telnet alternate (Mirai spreads here)',
    37777: 'Dahua DVR remote access',
    34567: 'DVR/NVR admin port',
    9527:  'DVR admin alternate',
}

# Botnet indicators by port
BOTNET_PORTS: Dict[int, str] = {
    9999: 'Mozi botnet DHT C2',
    5555: 'Kimwolf/botnet ADB exploitation',
    4444: 'Metasploit/RAT staging',
    2323: 'Mirai Telnet spreader alternate',
    7547: 'TR-069 (Mirai exploits this)',
    37215: 'Huawei HG532 RCE (Mirai)',
    52869: 'UPnP injection (Mirai)',
    65116: 'Realtek RCE variant (Mozi)',
}

# HTTP banners that identify device type
HTTP_BANNER_PATTERNS = [
    (r'hikvision|ipc|dvr|nvr.*login',          'Hikvision camera/DVR'),
    (r'dahua|web service.*dahua',               'Dahua camera/DVR'),
    (r'reolink',                                'Reolink camera'),
    (r'tenda|router.*tenda',                    'Tenda router'),
    (r'tp-link|tplink|archer',                  'TP-Link device'),
    (r'netgear|nighthawk',                      'Netgear router'),
    (r'asus.*router|asuswrt',                   'ASUS router'),
    (r'ubiquiti|unifi|airmax',                  'Ubiquiti device'),
    (r'mikrotik|routeros',                      'MikroTik router'),
    (r'openwrt|luci',                           'OpenWrt router'),
    (r'dd-wrt',                                 'DD-WRT router'),
    (r'synology',                               'Synology NAS'),
    (r'qnap',                                   'QNAP NAS'),
    (r'raspberry.*pi|raspbian',                 'Raspberry Pi'),
    (r'arduino|esp8266|esp32|nodemcu',          'Arduino/ESP device'),
    (r'smart plug|smart.*switch|power.*monitor','Smart plug/switch'),
    (r'wyze|wyzecam',                           'Wyze camera'),
    (r'ring.*doorbell|ring.*camera',            'Ring doorbell/camera'),
    (r'nest',                                   'Google Nest device'),
    (r'philips.*hue|hue bridge',               'Philips Hue hub'),
    (r'sonoff',                                 'Sonoff smart device'),
    (r'tasmota',                                'Tasmota firmware (smart device)'),
    (r'home assistant|hassio',                  'Home Assistant'),
    (r'proxmox',                                'Proxmox server'),
    (r'plex media server',                      'Plex media server'),
]


# ---------------------------------------------------------------------------
# Data class for a scanned device
# ---------------------------------------------------------------------------
@dataclass
class IoTDevice:
    ip: str
    mac: str = ''
    hostname: str = ''
    vendor: str = ''
    open_ports: List[int] = field(default_factory=list)
    device_type: str = 'Unknown'
    http_banner: str = ''
    telnet_banner: str = ''
    botnet_indicators: List[str] = field(default_factory=list)
    risk_level: str = 'LOW'     # LOW / MEDIUM / HIGH / CRITICAL
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    is_blocked: bool = False
    notes: str = ''


# ---------------------------------------------------------------------------
# Main scanner class
# ---------------------------------------------------------------------------
class IoTDeviceScanner:
    """
    Full IoT device scanner for Downpour.

    Usage:
        scanner = IoTDeviceScanner(alert_cb=my_alert_fn)
        scanner.scan_subnet('192.168.4.0/24', progress_cb=my_progress_fn)
        for device in scanner.devices.values():
            print(device.ip, device.device_type, device.risk_level)
    """

    COMMON_PORTS = [21, 22, 23, 25, 53, 67, 80, 81, 443, 554, 1883,
                    2323, 3000, 4444, 4455, 5555, 7547, 8080, 8081,
                    8266, 8443, 8554, 8888, 9000, 9527, 9999, 34567,
                    37215, 37777, 52869, 65116]

    def __init__(self, alert_cb: Optional[Callable] = None):
        self.alert_cb = alert_cb or (lambda msg, level='INFO': None)
        self.devices: Dict[str, IoTDevice] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._blocked_ips: Set[str] = set()

    def _log(self, msg: str, level: str = 'INFO'):
        log.info(msg)
        try:
            self.alert_cb(msg, level)
        except Exception:
            pass

    def stop(self):
        self._stop.set()

    # -----------------------------------------------------------------------
    # 1. Get gateway and subnet automatically
    # -----------------------------------------------------------------------
    def get_local_subnet(self) -> str:
        """Detect local subnet from default gateway."""
        try:
            r = subprocess.run(
                ['ipconfig'], capture_output=True, text=True,
                timeout=5, creationflags=_NO_WIN)
            ip = None
            mask = None
            for line in r.stdout.splitlines():
                ll = line.strip().lower()
                if 'ipv4' in ll and ':' in ll:
                    ip = line.split(':', 1)[1].strip()
                elif 'subnet mask' in ll and ':' in ll:
                    mask = line.split(':', 1)[1].strip()
                if ip and mask:
                    try:
                        net = ipaddress.IPv4Network(
                            f'{ip}/{mask}', strict=False)
                        return str(net)
                    except Exception:
                        pass
                    ip = mask = None
        except Exception:
            pass
        return '192.168.1.0/24'

    # -----------------------------------------------------------------------
    # 2. Ping sweep — find live hosts
    # -----------------------------------------------------------------------
    def _ping_host(self, ip: str) -> bool:
        """Ping a single host. Returns True if alive."""
        try:
            r = subprocess.run(
                ['ping', '-n', '1', '-w', '400', ip],
                capture_output=True, timeout=2,
                creationflags=_NO_WIN)
            return r.returncode == 0
        except Exception:
            return False

    def ping_sweep(self, subnet: str,
                   progress_cb: Optional[Callable] = None) -> List[str]:
        """Ping all hosts in subnet in parallel. Returns list of live IPs."""
        if self._stop.is_set():
            return []
        try:
            network = ipaddress.IPv4Network(subnet, strict=False)
        except Exception:
            return []

        hosts = [str(h) for h in network.hosts()]
        # Cap at /16 to avoid absurdly long scans
        if len(hosts) > 65534:
            hosts = hosts[:65534]

        live = []
        total = len(hosts)
        done = 0

        with ThreadPoolExecutor(max_workers=80) as ex:
            futures = {ex.submit(self._ping_host, ip): ip for ip in hosts}
            for fut in as_completed(futures):
                if self._stop.is_set():
                    break
                ip = futures[fut]
                done += 1
                if fut.result():
                    live.append(ip)
                if progress_cb and done % 10 == 0:
                    pct = int(done / total * 40)  # ping = first 40%
                    progress_cb(pct, f'Pinging {ip}... ({done}/{total})')

        return sorted(live, key=lambda x: [int(p) for p in x.split('.')])

    # -----------------------------------------------------------------------
    # 3. Get MAC from ARP table
    # -----------------------------------------------------------------------
    def get_arp_table(self) -> Dict[str, str]:
        """Return {ip: mac} from ARP table."""
        result = {}
        try:
            r = subprocess.run(
                ['arp', '-a'], capture_output=True, text=True,
                timeout=8, creationflags=_NO_WIN)
            for line in r.stdout.splitlines():
                parts = line.strip().split()
                if (len(parts) >= 2 and
                        re.match(r'\d+\.\d+\.\d+\.\d+', parts[0])):
                    mac = parts[1].lower().replace('-', ':')
                    if re.match(r'([0-9a-f]{2}:){5}[0-9a-f]{2}', mac):
                        result[parts[0]] = mac
        except Exception:
            pass
        return result

    # -----------------------------------------------------------------------
    # 4. OUI vendor lookup
    # -----------------------------------------------------------------------
    def lookup_vendor(self, mac: str) -> str:
        """Look up vendor from MAC OUI."""
        if not mac:
            return 'Unknown'
        # Normalise to uppercase colon-separated
        mac_up = mac.upper().replace('-', ':')
        oui = ':'.join(mac_up.split(':')[:3])
        return OUI_MAP.get(oui, 'Unknown vendor')

    # -----------------------------------------------------------------------
    # 5. Hostname resolution
    # -----------------------------------------------------------------------
    def resolve_hostname(self, ip: str) -> str:
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ''

    # -----------------------------------------------------------------------
    # 6. Port scan a device
    # -----------------------------------------------------------------------
    def _check_port(self, ip: str, port: int, timeout: float = 0.8) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((ip, port)) == 0
        except Exception:
            return False

    def port_scan(self, ip: str, ports: Optional[List[int]] = None) -> List[int]:
        """Fast parallel port scan. Returns list of open ports."""
        ports = ports or self.COMMON_PORTS
        open_ports = []
        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(self._check_port, ip, p): p for p in ports}
            for fut in as_completed(futures):
                if fut.result():
                    open_ports.append(futures[fut])
        return sorted(open_ports)

    # -----------------------------------------------------------------------
    # 7. HTTP banner grab
    # -----------------------------------------------------------------------
    def grab_http_banner(self, ip: str, port: int = 80,
                         https: bool = False) -> str:
        """Grab HTTP response to identify device type."""
        try:
            scheme = 'https' if https else 'http'
            import urllib.request
            import ssl
            ctx = ssl.create_default_context() if https else None
            if ctx:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            url = f'{scheme}://{ip}:{port}/'
            req = urllib.request.Request(
                url, headers={'User-Agent': 'Mozilla/5.0'},
                method='GET')
            with urllib.request.urlopen(req, timeout=3,
                                        context=ctx) as resp:
                data = resp.read(2048).decode('utf-8', errors='ignore').lower()
                title_m = re.search(r'<title[^>]*>(.*?)</title>',
                                    data, re.I | re.S)
                title = title_m.group(1).strip()[:80] if title_m else ''
                server = resp.headers.get('Server', '')
                return f'{title} [{server}]'.strip(' []') or data[:120]
        except Exception:
            return ''

    # -----------------------------------------------------------------------
    # 8. Telnet banner grab (Mirai spreads via Telnet)
    # -----------------------------------------------------------------------
    def grab_telnet_banner(self, ip: str) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((ip, 23))
                data = b''
                deadline = time.time() + 2
                while time.time() < deadline:
                    try:
                        chunk = s.recv(256)
                        if not chunk:
                            break
                        data += chunk
                    except socket.timeout:
                        break
                return data.decode('utf-8', errors='ignore')[:200].strip()
        except Exception:
            return ''

    # -----------------------------------------------------------------------
    # 9. Device type identification
    # -----------------------------------------------------------------------
    def identify_device(self, device: IoTDevice) -> str:
        """Identify device type from all gathered evidence."""
        clues = []

        # From vendor
        vendor_low = device.vendor.lower()
        if 'espressif' in vendor_low:
            clues.append('ESP8266/ESP32 based — likely: smart plug, smart bulb, '
                         'thermostat, DIY sensor, or cheap smart home device')
        elif 'gaoshengda' in vendor_low:
            clues.append('Gaoshengda WiFi module — likely: cheap smart plug, '
                         'WiFi relay, smart appliance, or generic IoT gadget')
        elif 'tuya' in vendor_low:
            clues.append('Tuya platform device — likely: smart plug, smart bulb, '
                         'or Tuya-compatible smart home device')
        elif 'hikvision' in vendor_low or 'dahua' in vendor_low:
            clues.append('IP Security Camera / DVR system')
        elif 'realtek' in vendor_low:
            clues.append('Realtek-based device — likely: router or IoT hub '
                         '(CVE-2021-35394 target)')
        elif 'raspberry' in vendor_low:
            clues.append('Raspberry Pi — single-board computer')
        elif 'arduino' in vendor_low:
            clues.append('Arduino / NodeMCU — microcontroller board')
        elif 'nintendo' in vendor_low:
            clues.append('Nintendo gaming device (Switch/Wii/DS)')
        elif 'tp-link' in vendor_low:
            clues.append('TP-Link device — router or smart plug')

        # From open ports
        if 554 in device.open_ports or 8554 in device.open_ports:
            clues.append('IP Camera (RTSP video stream)')
        if 1883 in device.open_ports:
            clues.append('IoT hub (MQTT broker)')
        if 9999 in device.open_ports:
            clues.append('MOZI BOTNET — port 9999 is Mozi C2')
        if 5555 in device.open_ports:
            clues.append('ADB open — Android device or TV box (Kimwolf target)')
        if 53 in device.open_ports and 67 in device.open_ports:
            clues.append('Router (runs DNS + DHCP)')
        if 4455 in device.open_ports or 8266 in device.open_ports:
            clues.append('ESP8266 with Arduino OTA firmware update enabled')

        # From HTTP banner
        banner_low = device.http_banner.lower()
        for pattern, hint in HTTP_BANNER_PATTERNS:
            if re.search(pattern, banner_low):
                clues.append(f'Web UI: {hint}')
                break

        # From Telnet banner
        if device.telnet_banner:
            tb = device.telnet_banner.lower()
            if 'busybox' in tb:
                clues.append('BusyBox Linux — router/IoT (Mirai primary target)')
            elif 'login:' in tb or 'username:' in tb:
                clues.append('Telnet login prompt (default creds may work)')
            elif 'mozi' in tb:
                clues.append('MOZI BOT STRING IN TELNET BANNER')

        if clues:
            return ' | '.join(clues)
        return 'Unknown device type'

    # -----------------------------------------------------------------------
    # 10. Botnet indicator check per device
    # -----------------------------------------------------------------------
    def check_botnet_indicators(self, device: IoTDevice) -> List[str]:
        indicators = []

        # Mozi botnet
        if 9999 in device.open_ports:
            indicators.append('CRITICAL: Port 9999 open — Mozi botnet DHT C2 port')
        if 7547 in device.open_ports:
            indicators.append('HIGH: Port 7547 (TR-069) open — Mirai exploitation vector')
        if 37215 in device.open_ports:
            indicators.append('HIGH: CVE-2017-17215 Huawei HG532 RCE port open (Mirai)')
        if 52869 in device.open_ports:
            indicators.append('HIGH: CVE-2021-35395 UPnP injection port open (Mozi/Mirai)')
        if 65116 in device.open_ports:
            indicators.append('HIGH: CVE-2021-35394 Realtek RCE port open (Mozi)')

        # Kimwolf / ADB exploitation
        if 5555 in device.open_ports:
            indicators.append('CRITICAL: ADB port 5555 open — Kimwolf botnet primary vector')

        # Telnet (Mirai spreads via default Telnet creds)
        if 23 in device.open_ports:
            indicators.append('HIGH: Telnet open — Mirai/AISURU brute-forces this')
        if 2323 in device.open_ports:
            indicators.append('HIGH: Telnet alt-port 2323 open — Mirai variant spreader')

        # Mozi string in Telnet
        if 'mozi' in device.telnet_banner.lower():
            indicators.append('CRITICAL: Mozi botnet string found in Telnet banner')
        if 'busybox' in device.telnet_banner.lower() and 23 in device.open_ports:
            indicators.append('HIGH: BusyBox Telnet — classic Mirai exploitation target')

        # Known botnet-vulnerable vendors
        if 'gaoshengda' in device.vendor.lower():
            indicators.append('MEDIUM: Gaoshengda module — historically targeted by Mozi botnet')
        if 'espressif' in device.vendor.lower() and (
                5555 in device.open_ports or 9999 in device.open_ports):
            indicators.append('HIGH: Espressif device with botnet port open')

        return indicators

    # -----------------------------------------------------------------------
    # 11. Assign risk level
    # -----------------------------------------------------------------------
    def assign_risk(self, device: IoTDevice) -> str:
        indicators = device.botnet_indicators
        has_critical = any('CRITICAL' in i for i in indicators)
        has_high = any('HIGH' in i for i in indicators)
        if has_critical:
            return 'CRITICAL'
        if has_high or len(indicators) >= 2:
            return 'HIGH'
        if indicators:
            return 'MEDIUM'
        # Unknown device with open ports is at least medium
        if device.open_ports and device.vendor == 'Unknown vendor':
            return 'MEDIUM'
        return 'LOW'

    # -----------------------------------------------------------------------
    # 12. Full device fingerprint
    # -----------------------------------------------------------------------
    def fingerprint_device(self, ip: str, mac: str = '',
                           progress_cb: Optional[Callable] = None) -> IoTDevice:
        """Full fingerprint: ports + banners + identification + botnet check."""
        device = IoTDevice(ip=ip, mac=mac)

        if progress_cb:
            progress_cb(0, f'Scanning {ip}...')

        # Vendor from MAC
        if mac:
            device.vendor = self.lookup_vendor(mac)

        # Hostname
        device.hostname = self.resolve_hostname(ip)

        # Port scan
        device.open_ports = self.port_scan(ip)

        # HTTP banner
        if 80 in device.open_ports:
            device.http_banner = self.grab_http_banner(ip, 80)
        elif 8080 in device.open_ports:
            device.http_banner = self.grab_http_banner(ip, 8080)
        elif 81 in device.open_ports:
            device.http_banner = self.grab_http_banner(ip, 81)
        elif 443 in device.open_ports:
            device.http_banner = self.grab_http_banner(ip, 443, https=True)

        # Telnet banner
        if 23 in device.open_ports or 2323 in device.open_ports:
            port = 23 if 23 in device.open_ports else 2323
            device.telnet_banner = self.grab_telnet_banner(ip)

        # Identify
        device.device_type = self.identify_device(device)

        # Botnet check
        device.botnet_indicators = self.check_botnet_indicators(device)
        device.risk_level = self.assign_risk(device)

        with self._lock:
            self.devices[ip] = device

        return device

    # -----------------------------------------------------------------------
    # 13. Full subnet scan
    # -----------------------------------------------------------------------
    def scan_subnet(self, subnet: Optional[str] = None,
                    progress_cb: Optional[Callable] = None) -> List[IoTDevice]:
        """
        Full scan: ping sweep → ARP lookup → fingerprint each device.
        progress_cb(percent: int, status: str)
        """
        self._stop.clear()
        if not subnet:
            subnet = self.get_local_subnet()

        self._log(f'[IoT SCAN] Starting subnet scan: {subnet}', 'INFO')
        if progress_cb:
            progress_cb(0, f'Scanning subnet {subnet}...')

        # Phase 1: ping sweep
        live_ips = self.ping_sweep(subnet, progress_cb)
        if self._stop.is_set():
            return []

        self._log(f'[IoT SCAN] Found {len(live_ips)} live hosts', 'INFO')
        if progress_cb:
            progress_cb(40, f'Found {len(live_ips)} devices — fingerprinting...')

        # Phase 2: ARP table
        arp = self.get_arp_table()

        # Phase 3: fingerprint each live host
        results = []
        total = len(live_ips)
        done = 0

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {
                ex.submit(self.fingerprint_device, ip,
                          arp.get(ip, '')): ip
                for ip in live_ips
            }
            for fut in as_completed(futures):
                if self._stop.is_set():
                    break
                ip = futures[fut]
                done += 1
                try:
                    device = fut.result()
                    results.append(device)
                    # Alert on critical findings
                    if device.risk_level in ('CRITICAL', 'HIGH'):
                        for ind in device.botnet_indicators:
                            if 'CRITICAL' in ind or 'HIGH' in ind:
                                self._log(
                                    f'[IoT THREAT] {ip} ({device.vendor}): {ind}',
                                    'CRITICAL' if 'CRITICAL' in ind else 'WARNING')
                except Exception as e:
                    log.error(f'Fingerprint {ip}: {e}')

                if progress_cb:
                    pct = 40 + int(done / total * 55)
                    progress_cb(pct, f'Fingerprinted {ip} ({done}/{total})')

        if progress_cb:
            progress_cb(100, f'Scan complete — {len(results)} devices found')

        # Summary alert
        threats = [d for d in results
                   if d.risk_level in ('CRITICAL', 'HIGH')]
        if threats:
            self._log(
                f'[IoT SCAN] COMPLETE: {len(results)} devices, '
                f'{len(threats)} HIGH/CRITICAL threats found',
                'CRITICAL')
        else:
            self._log(
                f'[IoT SCAN] COMPLETE: {len(results)} devices, '
                f'no critical threats detected', 'INFO')

        return sorted(results,
                      key=lambda d: {'CRITICAL': 0, 'HIGH': 1,
                                     'MEDIUM': 2, 'LOW': 3}
                      .get(d.risk_level, 4))

    # -----------------------------------------------------------------------
    # 14. Block a device via Windows Firewall
    # -----------------------------------------------------------------------
    def block_device(self, ip: str, reason: str = 'IoT threat') -> bool:
        """Add Windows Firewall rules to block all traffic to/from device IP."""
        safe_ip = re.sub(r'[^\d.]', '', ip)[:15]
        rule_in  = f'DOWNPOUR_IOT_BLOCK_IN_{safe_ip.replace(".", "_")}'
        rule_out = f'DOWNPOUR_IOT_BLOCK_OUT_{safe_ip.replace(".", "_")}'
        success = True
        for rule, direction in [(rule_in, 'in'), (rule_out, 'out')]:
            try:
                r = subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                     f'name={rule}', f'dir={direction}', 'action=block',
                     'protocol=any', f'remoteip={safe_ip}'],
                    capture_output=True, timeout=10,
                    creationflags=_NO_WIN)
                if r.returncode != 0:
                    success = False
            except Exception:
                success = False

        if success:
            self._blocked_ips.add(ip)
            with self._lock:
                if ip in self.devices:
                    self.devices[ip].is_blocked = True
            self._log(
                f'[IoT BLOCK] {ip} blocked via Windows Firewall ({reason})',
                'WARNING')
        return success

    def unblock_device(self, ip: str) -> bool:
        """Remove Windows Firewall block rules for a device IP."""
        safe_ip = re.sub(r'[^\d.]', '', ip)[:15]
        for direction in ['IN', 'OUT']:
            rule = f'DOWNPOUR_IOT_BLOCK_{direction}_{safe_ip.replace(".", "_")}'
            try:
                subprocess.run(
                    ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                     f'name={rule}'],
                    capture_output=True, timeout=10,
                    creationflags=_NO_WIN)
            except Exception:
                pass
        self._blocked_ips.discard(ip)
        with self._lock:
            if ip in self.devices:
                self.devices[ip].is_blocked = False
        return True

    # -----------------------------------------------------------------------
    # 15. Generate router ACL commands
    # -----------------------------------------------------------------------
    def get_router_commands(self, ip: str) -> str:
        """Generate router-level blocking commands for common router types."""
        safe_ip = re.sub(r'[^\d.]', '', ip)[:15]
        lines = [
            f'# Block {safe_ip} on your router:',
            '',
            '# === OPTION 1: Windows host-level block (already applied) ===',
            f'netsh advfirewall firewall add rule name="BLOCK_{safe_ip}" dir=in action=block remoteip={safe_ip}',
            f'netsh advfirewall firewall add rule name="BLOCK_{safe_ip}_OUT" dir=out action=block remoteip={safe_ip}',
            '',
            '# === OPTION 2: Router admin page ===',
            '# Log in to your router (usually http://192.168.1.1 or http://192.168.4.1)',
            '# Go to: Security > Access Control (or Firewall > IP Filtering)',
            f'# Add rule: Block IP {safe_ip} — all protocols — permanent',
            '',
            '# === OPTION 3: OpenWrt / DD-WRT / Tomato router ===',
            f'iptables -I FORWARD -s {safe_ip} -j DROP',
            f'iptables -I FORWARD -d {safe_ip} -j DROP',
            f'iptables -I INPUT -s {safe_ip} -j DROP',
            '',
            '# === OPTION 4: MikroTik router ===',
            f'/ip firewall filter add chain=forward src-address={safe_ip} action=drop',
            f'/ip firewall filter add chain=forward dst-address={safe_ip} action=drop',
            '',
            '# === OPTION 5: Disable device on router (recommended) ===',
            '# Log in to router > Connected Devices / DHCP Lease list',
            f'# Find device with IP {safe_ip}',
            '# Select "Block" or "Remove from network" or set DHCP to deny this MAC',
            '',
            '# After blocking, power cycle the device if possible.',
            '# If you cannot identify or locate the device,',
            '# change your WiFi password to force all devices to re-authenticate.',
        ]
        return '\n'.join(lines)

    # -----------------------------------------------------------------------
    # 16. Mozi botnet deep scan on specific device
    # -----------------------------------------------------------------------
    def scan_mozi(self, ip: str) -> List[str]:
        """Deep Mozi botnet scan on a specific device."""
        findings = []

        # Port 9999 — Mozi DHT
        if self._check_port(ip, 9999, timeout=2.0):
            findings.append(f'CRITICAL: Port 9999 open — Mozi botnet DHT C2 active on {ip}')
            # Try to grab banner
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(2)
                    s.connect((ip, 9999))
                    s.send(b'GET / HTTP/1.0\r\n\r\n')
                    banner = s.recv(256).decode('utf-8', errors='ignore')
                    if banner:
                        findings.append(f'  Mozi port banner: {banner[:100]}')
            except Exception:
                pass

        # TR-069 (Mirai exploits this to persist)
        if self._check_port(ip, 7547, timeout=1.5):
            findings.append(f'HIGH: TR-069 port 7547 open — Mirai/Mozi persistence vector')

        # Realtek exploit ports
        for port, cve in [(52869, 'CVE-2021-35395'),
                          (65116, 'CVE-2021-35394'),
                          (37215, 'CVE-2017-17215')]:
            if self._check_port(ip, port, timeout=1.0):
                findings.append(f'HIGH: {cve} exploit port {port} open on {ip}')

        # Telnet with BusyBox check
        if self._check_port(ip, 23, timeout=1.5):
            banner = self.grab_telnet_banner(ip)
            if 'busybox' in banner.lower():
                findings.append(f'HIGH: BusyBox Telnet on {ip} — classic Mirai target')
            if 'mozi' in banner.lower():
                findings.append(f'CRITICAL: MOZI string in Telnet banner on {ip}!')
            elif banner:
                findings.append(f'MEDIUM: Telnet open on {ip}: {banner[:60]}')

        # ADB check (Kimwolf)
        if self._check_port(ip, 5555, timeout=1.5):
            findings.append(f'CRITICAL: ADB port 5555 on {ip} — Kimwolf botnet target!')

        if not findings:
            findings.append(f'No Mozi/botnet indicators found on {ip}')

        return findings
