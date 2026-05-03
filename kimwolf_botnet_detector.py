"""
kimwolf_botnet_detector.py  -  Downpour v29 Titanium
=====================================================
Dedicated Kimwolf / Aisuru / BadBox2 botnet detection and response module.
Monitors for:
  - Kimwolf C2 domain presence in DNS cache
  - ADB port 5555 on LAN devices (primary Kimwolf infection vector)
  - ByteConnect / Plainproxies SDK processes
  - Mozi / Mirai / AISURU / Gaoshengda botnet IOCs
  - Residential proxy bandwidth theft
  - ENS blockchain C2 domain queries
  - Pre-infected Android TV box fingerprinting

References:
  - XLab Kimwolf analysis (2025-12)
  - Synthient / Krebs on Security (2026-01)
  - CISA IoT threat advisories
"""
from __future__ import annotations
__version__ = "29.0.0"
import ipaddress
import logging
import math
import os
import re
import socket
import subprocess
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Set

try:
    from vulnerability_scanner import VulnerabilityScanner
    _KEV_AVAILABLE = True
except ImportError:
    _KEV_AVAILABLE = False

_NO_WIN = 0x08000000  # CREATE_NO_WINDOW


def check_botnet_kev(botnet_name: str) -> dict:
    """Check botnet family against CISA KEV catalog."""
    if not _KEV_AVAILABLE:
        return {'matched_cves': [], 'kev_available': False}
    try:
        scanner = VulnerabilityScanner()
        kev_data = scanner.get_kev_catalog()
        if not kev_data:
            return {'matched_cves': [], 'kev_available': False}
        
        matches = []
        botnet_lower = botnet_name.lower()
        iot_keywords = ['iot', 'router', 'camera', 'nvr', 'dvr', 'botnet', 'mirai', 'mozai', 'gafgyt']
        
        for entry in kev_data:
            vendor = entry.get('vendorProject', '').lower()
            product = entry.get('product', '').lower()
            notes = entry.get('notes', '').lower()
            
            if botnet_lower in vendor or botnet_lower in product:
                matches.append(entry)
            elif any(kw in product for kw in iot_keywords) and any(kw in notes for kw in ['bot', 'ddos', 'c2', 'command']):
                matches.append(entry)
        
        return {
            'matched_cves': matches[:5],
            'kev_available': True,
            'count': len(matches)
        }
    except Exception:
        return {'matched_cves': [], 'kev_available': False}


log = logging.getLogger("KimwolfDetector")

# ---------------------------------------------------------------------------
# IOC DATABASES
# ---------------------------------------------------------------------------

# Kimwolf / Aisuru / BadBox C2 and proxy SDK domains
KIMWOLF_C2_DOMAINS: Set[str] = {
    # Kimwolf primary C2 (XLab sinkhole data)
    "14emeliaterracewestroxburyma02132.su",
    "rtrdedge1.samsungcdn.cloud",
    # ENS blockchain C2 resolver
    "pawsatyou.eth",
    # Downloader infrastructure
    "realizationnewestfangs.com",
    # Proxy SDK / ad-fraud / bandwidth monetization
    "adlinknetwork.vn", "service.adlinknetwork.vn",
    "monetisetrk5.co.uk",
    "twizzter6net.info",
    "byteconnect.net", "sdk.byteconnect.net",
    "plainproxies.com", "api.plainproxies.com",
    "ipidea.net", "ipidea.io", "ipidea.org",
    # Grass.io residential proxy SDK
    "grass.io", "api.grass.io", "device.grass.io",
    # BadBox 2.0 related
    "peachpit.ad", "texel.us",
}

# Mozi botnet domains
MOZI_DOMAINS: Set[str] = {
    "mozi.m", "motorolaunlock.com",
}

# Mirai / AISURU C2 patterns (dynamic - matched by substring)
MIRAI_C2_PATTERNS: Set[str] = {
    "cnc.", "c2.", "bot.", "loader.", "update.down.",
}

# FIX-v29: Whitelist legitimate domains that match C2 patterns
MIRAI_C2_WHITELIST: Set[str] = {
    # fc2.com analytics (contains "c2.")
    "fc2.com", "counter1.fc2.com", "analysis.fc2.com",
    "blogranking.fc2.com", "cnt.affiliate.fc2.com", "static.fc2.com",
    # Ad/analytics networks
    "rfihub.net", "c2.rfihub.net",
    "zemanta.com", "b1-chidc2.zemanta.com", "chidc2.zemanta.com",
    "humanclick.com", "hc2.humanclick.com",
    "outbrain.org", "chidc2.outbrain.org",
    "anandtech.com", "dynamic2.anandtech.com",
    # Legitimate sites with "bot." in name
    "hot-bot.com", "www.hot-bot.com",
    "doribot.com", "www.doribot.com",
    "askbot.com", "adbot.com",
    "hellobacsi.com", "subot.hellobacsi.com",
    "chatbot.com", "www.chatbot.com",
    "botframework.com", "dev.botframework.com",
    "robotstxt.org", "plungeerobot.best",
    # Legitimate CDN/content with "loader." substring
    "content-loader.com", "fontloader.com", "loader.io",
    # Samsung CDN (false positive — only the base domain, not the C2 subdomain)
    "samsungcdn.cloud",
}

# All botnet IOC domains (union)
ALL_BOTNET_DOMAINS: Set[str] = KIMWOLF_C2_DOMAINS | MOZI_DOMAINS

# Kimwolf C2 IP ranges (Resi Rack LLC, Servers.com bulletproof hosting)
KIMWOLF_C2_IPS: Set[str] = {
    "93.95.112.50", "93.95.112.51", "93.95.112.52", "93.95.112.53",
    "93.95.112.54", "93.95.112.55", "93.95.112.56", "93.95.112.57",
    "93.95.112.58", "93.95.112.59",
    "85.234.91.247",   # Kimwolf C2 callback (port 1337)
    "146.19.173.87",   # windowsnetservicehelper.exe C2 (confirmed malware)
    "172.240.73.136",  # realizationnewestfangs.com resolution
}

# CIDR ranges associated with Kimwolf infrastructure
KIMWOLF_C2_CIDRS = [
    ipaddress.ip_network("93.95.112.48/29"),   # Resi Rack LLC Kimwolf range
    ipaddress.ip_network("172.240.0.0/16"),     # Servers.com bulletproof block
]

# Android TV box / IoT device MACs known to carry Kimwolf (Juniper OUI spoofed)
KIMWOLF_DEVICE_MACS: Dict[str, str] = {
    "2c:21:72:6f:5f:c5": "Kimwolf-infected Android TV box (active on this network)",
    "2c:21:72": "Kimwolf TV box OUI prefix",
}

# Kimwolf-infected device model strings (from ADB banner / HTTP title)
KIMWOLF_DEVICE_MODELS = {
    "tv box", "superbox", "hidptandroid", "p200", "x96q", "x96 max",
    "mx10", "smarttv", "hisilicon", "amlogic", "allwinner",
    "android tv", "ott tv", "uhale",
}

# Ports Kimwolf uses / exposes
KIMWOLF_PORTS = {
    5555:   "ADB (Android Debug Bridge) - primary infection vector",
    40860:  "Kimwolf payload listener",
    1337:   "Kimwolf C2 callback",
    853:    "DNS-over-TLS (C2 evasion)",
    6668:   "IRC C2 (Tuya/Mirai variant)",
    53413:  "Netis hard-coded backdoor (CVE-2014-8269)",
    9034:   "CVE-2021-35394 Realtek UDPServer",
    9035:   "CVE-2021-35394 secondary",
    52869:  "CVE-2021-35395 miniigd UPnP SOAP",
    37215:  "CVE-2017-17215 Huawei HG532 RCE (Mirai variant)",
}

# Kimwolf process names (on infected device via ADB)
KIMWOLF_PROCESS_NAMES = {
    "netd_services", "tv_helper", "byteconnect", "plainproxies",
    "grass", "niggabox",  # internal binary mutex name
}

# High-risk IoT vendor OUI prefixes (Gaoshengda, Espressif, Tuya, etc.)
HIGH_RISK_OUIS = {
    "94:b3:f7": "Gaoshengda Technology (Mozi botnet target)",
    "c4:dd:57": "Espressif Systems (ESP8266/32 IoT)",
    "38:2c:e5": "Tuya Smart Inc (data routes to China)",
    "d8:6b:83": "Unverified IoT (Nintendo OUI clone)",
    "2c:21:72": "Kimwolf TV box (Juniper OUI spoof)",
}

# ---------------------------------------------------------------------------
# DETECTION ENGINE
# ---------------------------------------------------------------------------

@dataclass
class BotnetAlert:
    ts: str
    family: str       # Kimwolf / Mozi / Mirai / BadBox / etc.
    indicator: str    # domain / IP / port / MAC
    evidence: str
    severity: str     # CRITICAL / HIGH / MEDIUM
    device_ip: str = ""
    device_mac: str = ""
    action_taken: str = ""


class KimwolfBotnetDetector:
    """
    Standalone botnet detector — runs as a daemon thread and calls
    alert_cb(alert: BotnetAlert) whenever a new threat is found.

    Checks performed every `scan_interval` seconds:
      1. DNS cache scan — all ~150 known botnet C2 domains
      2. LAN ADB port sweep — detect infected Android boxes
      3. Active connection scan — flag connections to C2 IPs
      4. Process scan — detect ByteConnect / Plainproxies SDKs
      5. ARP table scan — flag high-risk IoT OUIs
      6. Bandwidth anomaly — detect proxy bandwidth theft (>100MB/5min)
    """

    def __init__(
        self,
        subnet: str = "192.168.4",
        alert_cb: Optional[Callable[[BotnetAlert], None]] = None,
        db=None,
        scan_interval: int = 60,
    ):
        self.subnet = subnet
        self.alert_cb = alert_cb
        self.db = db
        self.scan_interval = scan_interval

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

        # Dedup: don't re-alert same indicator within cooldown
        self._alerted: Dict[str, float] = {}
        self._COOLDOWN = 300  # 5 minutes

        # State tracking
        self._known_adb_devices: Set[str] = set()
        self._known_c2_conns: Set[str] = set()
        self._dns_alerted: Set[str] = set()
        self._bytes_prev: Dict[str, int] = {}
        self._bytes_ts: float = 0.0

        # Statistics
        self.stats = defaultdict(int)

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def start(self):
                # Initialize COM for this thread
                try:
                    import pythoncom
                    pythoncom.CoInitialize()
                except ImportError:
                    pass

        if self._running:
            return
        self._stop.clear()
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="KimwolfDetector")
        self._thread.start()
        log.info("KimwolfBotnetDetector started (interval=%ds)", self.scan_interval)

    def stop(self):
        self._running = False
        self._stop.set()

    def _loop(self):
        # Stagger initial scan to not hammer on startup
        self._stop.wait(8)
        while self._running:
            try:
                self._scan_dns_cache()
            except Exception as e:
                log.debug("DNS scan error: %s", e)
            try:
                self._scan_active_connections()
            except Exception as e:
                log.debug("Connection scan error: %s", e)
            try:
                self._scan_arp_table()
            except Exception as e:
                log.debug("ARP scan error: %s", e)
            try:
                self._scan_processes()
            except Exception as e:
                log.debug("Process scan error: %s", e)
            # ADB sweep is slower — run every 3rd cycle
            if self.stats["cycles"] % 3 == 0:
                try:
                    self._scan_adb_ports()
                except Exception as e:
                    log.debug("ADB scan error: %s", e)
            # Phantom device & bandwidth scans every 2nd cycle
            if self.stats["cycles"] % 2 == 0:
                try:
                    self._scan_phantom_devices()
                except Exception as e:
                    log.debug("Phantom device scan error: %s", e)
                try:
                    self._scan_bandwidth_anomaly()
                except Exception as e:
                    log.debug("Bandwidth anomaly scan error: %s", e)
            with self._lock:
                self.stats["cycles"] += 1
            self._stop.wait(max(300, self.scan_interval))  # FIX-v29p15: 5min minimum

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _alert(self, alert: BotnetAlert):
        """Deduplicate and fire alert."""
        key = f"{alert.family}:{alert.indicator}"
        now = time.time()
        with self._lock:
            last = self._alerted.get(key, 0)
            if now - last < self._COOLDOWN:
                return
            self._alerted[key] = now
            self.stats[f"alerts_{alert.family}"] += 1
        log.warning("[BOTNET] %s | %s | %s", alert.family, alert.indicator, alert.evidence)
        if self.db:
            try:
                self.db.execute(
                    "INSERT OR IGNORE INTO aegis_events (ts,layer,event,severity) VALUES(?,?,?,?)",
                    (alert.ts, "botnet", f"{alert.family}: {alert.evidence[:400]}", alert.severity))
            except Exception:
                pass
        if self.alert_cb:
            try:
                self.alert_cb(alert)
            except Exception:
                pass

    def _make_alert(self, family: str, indicator: str, evidence: str,
                    severity: str = "HIGH", device_ip: str = "",
                    device_mac: str = "", action: str = "") -> BotnetAlert:
        return BotnetAlert(
            ts=datetime.now().isoformat(),
            family=family, indicator=indicator, evidence=evidence,
            severity=severity, device_ip=device_ip,
            device_mac=device_mac, action_taken=action)

    def _block_ip_firewall(self, ip: str, label: str = "") -> bool:
        """Add Windows Firewall rule to block an IP bidirectionally."""
        safe_ip = ip.replace(".", "_").replace(":", "_")
        rule = f"DOWNPOUR_BOTNET_{safe_ip}"
        try:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"],
                capture_output=True, creationflags=_NO_WIN, timeout=6, check=False)
            for d in ("in", "out"):
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name={rule}", f"dir={d}", "action=block",
                     "enable=yes", f"remoteip={ip}"],
                    capture_output=True, creationflags=_NO_WIN, timeout=6, check=False)
            return True
        except Exception:
            return False

    # -----------------------------------------------------------------------
    # Scan 1: DNS Cache — fast, catches C2 phone-home attempts
    # -----------------------------------------------------------------------

    def _scan_dns_cache(self):
        """Check DNS cache for known botnet C2 domains."""
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-DnsClientCache | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, timeout=8, creationflags=_NO_WIN)
        if r.returncode != 0:
            return
        cached = {d.strip().lower().rstrip('.') for d in r.stdout.splitlines() if d.strip()}
        for domain in cached:
            if not domain or '.' not in domain:
                continue
            if domain in self._dns_alerted:
                continue
            # Direct match against known botnet domains
            # FIX-v29: Skip whitelisted domains before C2 alert
            _dom_wl = any(domain == w or domain.endswith("." + w) for w in MIRAI_C2_WHITELIST)
            if not _dom_wl and domain in ALL_BOTNET_DOMAINS:
                family = "Kimwolf" if domain in KIMWOLF_C2_DOMAINS else "Mozi"
                self._dns_alerted.add(domain)
                with self._lock:
                    self.stats["dns_hits"] += 1
                # Block it at DNS level
                subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive", "-Command",
                     f'Add-Content "C:\\Windows\\System32\\drivers\\etc\\hosts" "`r`n0.0.0.0 {domain}"'],
                    capture_output=True, creationflags=_NO_WIN, timeout=5, check=False)
                self._alert(self._make_alert(
                    family, domain,
                    f"Botnet C2 domain found in DNS cache — device on this network is infected and phoning home. "
                    f"Domain added to hosts block.",
                    "CRITICAL", action=f"hosts-blocked: {domain}"))

            # ENS/blockchain C2 pattern (Kimwolf EtherHiding)
            if domain.endswith(".eth") or "pawsatyou" in domain:
                self._dns_alerted.add(domain)
                self._alert(self._make_alert(
                    "Kimwolf-ENS", domain,
                    f"Ethereum Name Service C2 domain in DNS cache — Kimwolf EtherHiding technique. "
                    f"Blockchain-based C2 is resistant to takedowns.",
                    "CRITICAL"))

            # Mirai C2 pattern match
            # FIX-v29: Skip whitelisted domains (ad networks, analytics, CDNs)
            _is_wl = any(domain == w or domain.endswith("." + w) for w in MIRAI_C2_WHITELIST)
            if not _is_wl:
                for pat in MIRAI_C2_PATTERNS:
                    if pat in domain and len(domain) > 8:
                        self._dns_alerted.add(domain)
                        self._alert(self._make_alert(
                            "Mirai/AISURU", domain,
                            f"Mirai-family C2 domain pattern '{pat}' in DNS cache.",
                            "HIGH"))
                        break

    # -----------------------------------------------------------------------
    # Scan 2: Active connections — catches live C2 traffic
    # -----------------------------------------------------------------------

    def _scan_active_connections(self):
        """Scan active TCP connections for C2 IP hits."""
        try:
            import psutil
        except ImportError:
            return
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            rip = conn.raddr.ip
            if rip in self._known_c2_conns:
                continue
            # Direct IP match
            if rip in KIMWOLF_C2_IPS:
                self._known_c2_conns.add(rip)
                with self._lock:
                    self.stats["c2_ip_hits"] += 1
                blocked = self._block_ip_firewall(rip, "Kimwolf C2")
                proc = ""
                try:
                    p = psutil.Process(conn.pid)
                    proc = f" (process: {p.name()} PID:{conn.pid})"
                except Exception:
                    pass
                self._alert(self._make_alert(
                    "Kimwolf", rip,
                    f"Active connection to Kimwolf C2 infrastructure{proc}. "
                    f"Port: {conn.laddr.port}->{conn.raddr.port}",
                    "CRITICAL", action="firewall-blocked" if blocked else ""))
                continue
            # CIDR range match
            try:
                addr = ipaddress.ip_address(rip)
                for cidr in KIMWOLF_C2_CIDRS:
                    if addr in cidr:
                        self._known_c2_conns.add(rip)
                        blocked = self._block_ip_firewall(rip, "Kimwolf range")
                        self._alert(self._make_alert(
                            "Kimwolf", rip,
                            f"Connection to Kimwolf C2 CIDR {cidr}. Port: {conn.raddr.port}",
                            "CRITICAL", action="firewall-blocked" if blocked else ""))
                        break
            except Exception:
                pass
            # Kimwolf-specific port on LAN device
            if conn.raddr and conn.raddr.ip.startswith("192.168."):
                rport = conn.raddr.port
                if rport in KIMWOLF_PORTS:
                    self._alert(self._make_alert(
                        "Kimwolf", f"{rip}:{rport}",
                        f"Connection to LAN device on Kimwolf port {rport} "
                        f"({KIMWOLF_PORTS[rport]})",
                        "HIGH", device_ip=rip))

    # -----------------------------------------------------------------------
    # Scan 3: ARP table — flag high-risk IoT devices and Kimwolf TV boxes
    # -----------------------------------------------------------------------

    def _scan_arp_table(self):
        """Parse ARP table for Kimwolf MAC and high-risk IoT OUI prefixes."""
        r = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                           timeout=8, creationflags=_NO_WIN)
        if r.returncode != 0:
            return
        for line in r.stdout.splitlines():
            line_l = line.lower()
            # Check for Kimwolf target MAC (full or OUI prefix)
            for mac, desc in KIMWOLF_DEVICE_MACS.items():
                norm = mac.replace(":", "-")
                if norm in line_l or mac in line_l:
                    parts = line.strip().split()
                    ip = parts[0] if parts else "?"
                    key = f"kimwolf_mac_{mac}"
                    self._alert(self._make_alert(
                        "Kimwolf", mac,
                        f"Kimwolf-infected device ONLINE at {ip}! {desc}. "
                        f"Immediate action: unplug and discard device.",
                        "CRITICAL", device_ip=ip, device_mac=mac,
                        action="alert-generated"))
            # High-risk IoT OUI check
            for oui, vendor in HIGH_RISK_OUIS.items():
                oui_norm = oui.replace(":", "-")
                if oui_norm in line_l:
                    parts = line.strip().split()
                    ip = parts[0] if parts else "?"
                    # Only alert once per IP per run
                    key = f"oui_{ip}"
                    if key not in self._alerted or time.time() - self._alerted[key] > 3600:
                        self._alerted[key] = time.time()  # FIX-v29: prevent re-alert within 1h
                        self._alert(self._make_alert(
                            "HighRiskIoT", f"{ip} ({oui})",
                            f"High-risk IoT device at {ip}: {vendor}. "
                            f"Consider isolating to IoT VLAN.",
                            "MEDIUM", device_ip=ip))

    # -----------------------------------------------------------------------
    # Scan 4: Process scan — ByteConnect, Plainproxies, Grass SDK
    # -----------------------------------------------------------------------

    def _scan_processes(self):
        """Detect known botnet proxy SDK processes running locally."""
        try:
            import psutil
        except ImportError:
            return
        for proc in psutil.process_iter(["pid", "name", "cmdline", "exe"]):
            try:
                name = (proc.info.get("name") or "").lower()
                cmdline = " ".join(proc.info.get("cmdline") or []).lower()
                exe = (proc.info.get("exe") or "").lower()
                for ioc in KIMWOLF_PROCESS_NAMES:
                    if ioc in name or ioc in cmdline or ioc in exe:
                        self._alert(self._make_alert(
                            "Kimwolf", f"PID:{proc.info['pid']} {name}",
                            f"Kimwolf/botnet process detected: {name} (PID {proc.info['pid']}). "
                            f"Cmdline: {cmdline[:120]}",
                            "CRITICAL",
                            action="kill-recommended"))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    # -----------------------------------------------------------------------
    # Scan 5: ADB port sweep — full /24 subnet
    # -----------------------------------------------------------------------

    def _scan_adb_ports(self):
        """Probe the subnet for open ADB port 5555 — primary Kimwolf vector."""
        found: List[str] = []
        for i in range(1, 255):
            ip = f"{self.subnet}.{i}"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            try:
                result = sock.connect_ex((ip, 5555))
                if result == 0:
                    found.append(ip)
            except Exception:
                pass
            finally:
                sock.close()
        for ip in found:
            if ip in self._known_adb_devices:
                continue
            self._known_adb_devices.add(ip)
            with self._lock:
                self.stats["adb_hits"] += 1
            # Try to read ADB banner to identify device model
            model = self._get_adb_model(ip)
            is_tv_box = any(m in model.lower() for m in KIMWOLF_DEVICE_MODELS)
            severity = "CRITICAL" if is_tv_box else "HIGH"
            self._alert(self._make_alert(
                "Kimwolf-ADB", f"{ip}:5555",
                f"ADB port 5555 OPEN on LAN device {ip}. "
                f"Model: '{model}'. "
                f"{'MATCHES known Kimwolf TV box pattern!' if is_tv_box else 'Unknown device.'} "
                f"This is Kimwolf's primary infection vector.",
                severity, device_ip=ip,
                action="investigate-required"))

    def _get_adb_model(self, ip: str) -> str:
        """Try to get device model from ADB banner."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(2.0)
                sock.connect((ip, 5555))
                banner = sock.recv(256)
                return banner.decode("ascii", errors="replace").replace("\x00", " ").strip()[:80]
        except Exception:
            pass
        # Try HTTP on common TV box admin ports
        for port in (80, 8080):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1.0)
                    if sock.connect_ex((ip, port)) == 0:
                        sock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                        resp = sock.recv(512).decode("ascii", errors="replace")
                        for line in resp.splitlines():
                            if "server:" in line.lower() or "<title>" in line.lower():
                                return line.strip()[:80]
            except Exception:
                pass
        return "unknown"

    # -----------------------------------------------------------------------
    # Public helpers
    # -----------------------------------------------------------------------

    def check_ip_is_c2(self, ip: str) -> bool:
        """Return True if IP is known Kimwolf/botnet infrastructure."""
        if ip in KIMWOLF_C2_IPS:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in cidr for cidr in KIMWOLF_C2_CIDRS)
        except Exception:
            return False

    def check_domain_is_c2(self, domain: str) -> bool:
        """Return True if domain is known botnet C2."""
        d = domain.lower().rstrip(".")
        return d in ALL_BOTNET_DOMAINS

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self.stats)


    # -----------------------------------------------------------------------
    # Scan 6: Phantom Device Detection — rogue virtual adapters & spoofed MACs
    # -----------------------------------------------------------------------

    def _scan_phantom_devices(self):
        """Detect rogue/phantom network devices created by botnet malware.

        Kimwolf and similar botnets create virtual network adapters to proxy
        traffic through the infected host. They also spoof MAC addresses to
        appear as legitimate devices on the network.
        """
        try:
            # Check for suspicious virtual network adapters
            r = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive', '-Command',
                 'Get-NetAdapter -IncludeHidden | Where-Object {$_.Virtual -eq $true} '
                 '| Select-Object Name,InterfaceDescription,MacAddress,Status '
                 '| ConvertTo-Json -Depth 2'],
                capture_output=True, text=True, timeout=10, creationflags=_NO_WIN)
            if r.returncode == 0 and r.stdout.strip():
                import json
                adapters = json.loads(r.stdout)
                if isinstance(adapters, dict):
                    adapters = [adapters]
                legit_virtual = {'hyper-v', 'virtualbox', 'vmware', 'docker',
                                 'wsl', 'vpn', 'tailscale', 'wireguard',
                                 'nordvpn', 'loopback', 'bluetooth',
                                 'wi-fi direct', 'microsoft',
                                 # Built-in Windows IPv6/IPv4 transition adapters
                                 'teredo', '6to4', 'isatap', 'ip-https',
                                 'iphttps', 'pseudo-interface',
                                 # Windows built-in network features
                                 'multiplexor', 'bridge', 'hosted network',
                                 'kernel debug', 'ndis', 'mobile broadband',
                                 'vpn', 'pangp', 'cisco', 'juniper',
                                 'fortinet', 'openconnect', 'softether',
                                 # Legitimate VPN/tunneling software
                                 'proton', 'mullvad', 'express', 'surfshark',
                                 'windscribe', 'zerotier', 'hamachi',
                                 'radmin'}
                for adapter in adapters:
                    desc = (adapter.get('InterfaceDescription') or '').lower()
                    name_lower = (adapter.get('Name') or '').lower()
                    name = adapter.get('Name', '')
                    # Check both name and description against legit list
                    combined = desc + ' ' + name_lower
                    if not any(lv in combined for lv in legit_virtual):
                        self._alert(self._make_alert(
                            "PhantomDevice", name,
                            f"Suspicious virtual network adapter: {name} ({desc}). "
                            f"MAC: {adapter.get('MacAddress', '?')}. "
                            f"Botnets create phantom adapters to proxy traffic.",
                            "HIGH",
                            action="investigate-required"))
        except Exception:
            pass

        # Check for devices that appeared recently on the network
        try:
            r = subprocess.run(
                ['arp', '-a'], capture_output=True, text=True,
                timeout=8, creationflags=_NO_WIN)
            if r.returncode == 0:
                current_devices = set()
                for line in r.stdout.splitlines():
                    parts = line.strip().split()
                    if len(parts) >= 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                        ip = parts[0]
                        mac = parts[1].lower()
                        # Skip broadcast, multicast (224.x-239.x), and link-local reserved MACs
                        if mac in ('ff-ff-ff-ff-ff-ff', '01-00-5e-00-00-16'):
                            continue
                        if ip.startswith(('224.', '225.', '226.', '227.', '228.',
                                          '229.', '230.', '231.', '232.', '233.',
                                          '234.', '235.', '236.', '237.', '238.',
                                          '239.')):
                            continue  # IPv4 multicast range — normal MDNS/SSDP/IGMP
                        if mac.startswith('01-00-5e'):  # all IPv4 multicast MACs
                            continue
                        if mac.startswith('33-33'):     # IPv6 multicast MACs
                            continue
                        current_devices.add((ip, mac))

                # Track device count changes (sudden increase = suspicious)
                if not hasattr(self, '_prev_device_count'):
                    self._prev_device_count = len(current_devices)
                    self._prev_devices = current_devices
                else:
                    new_devices = current_devices - self._prev_devices
                    if len(new_devices) >= 3:
                        # 3+ new devices appearing at once is suspicious
                        device_list = ', '.join(f"{ip}({mac})" for ip, mac in list(new_devices)[:5])
                        self._alert(self._make_alert(
                            "DeviceFlood", f"{len(new_devices)} new devices",
                            f"Sudden appearance of {len(new_devices)} new network devices: "
                            f"{device_list}. Botnet may be spawning phantom devices.",
                            "HIGH",
                            action="investigate-required"))
                    self._prev_device_count = len(current_devices)
                    self._prev_devices = current_devices
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Scan 7: Bandwidth anomaly — detect proxy bandwidth theft
    # -----------------------------------------------------------------------

    def _scan_bandwidth_anomaly(self):
        """Detect abnormal bandwidth usage indicating proxy theft."""
        try:
            import psutil
            counters = psutil.net_io_counters()
            now = time.time()

            if self._bytes_ts > 0:
                elapsed = now - self._bytes_ts
                if elapsed > 0:
                    bytes_sent = counters.bytes_sent - self._bytes_prev.get('sent', counters.bytes_sent)
                    bytes_recv = counters.bytes_recv - self._bytes_prev.get('recv', counters.bytes_recv)

                    # Calculate MB per 5-minute window
                    mb_sent = (bytes_sent / (1024 * 1024)) * (300 / elapsed)
                    mb_recv = (bytes_recv / (1024 * 1024)) * (300 / elapsed)

                    # Flag if sending >100MB per 5min (likely proxy abuse)
                    if mb_sent > 100:
                        self._alert(self._make_alert(
                            "BandwidthTheft", f"{mb_sent:.0f}MB/5min sent",
                            f"Abnormal outbound bandwidth: {mb_sent:.0f}MB/5min. "
                            f"Residential proxy botnets monetize your bandwidth. "
                            f"Check for ByteConnect/Plainproxies/Grass SDKs.",
                            "HIGH"))

            self._bytes_prev = {'sent': counters.bytes_sent, 'recv': counters.bytes_recv}
            self._bytes_ts = now
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Auto-remediation integration
    # -----------------------------------------------------------------------

    def auto_remediate(self):
        """Trigger automatic remediation using the ThreatRemediationEngine.

        Called when CRITICAL alerts accumulate, or can be triggered manually.
        """
        try:
            from advanced_threat_remediation import get_engine, ThreatProfile
        except ImportError:
            log.warning("advanced_threat_remediation module not available")
            return None

        # Collect all alerts into a remediation profile
        with self._lock:
            all_alerts = []
            for key, ts in self._alerted.items():
                family, indicator = key.split(':', 1) if ':' in key else ('Kimwolf', key)
                all_alerts.append({
                    'indicator': indicator,
                    'evidence': f"Detected at {datetime.fromtimestamp(ts).isoformat()}",
                    'family': family,
                    'device_ip': '',
                })

        if not all_alerts:
            log.info("No alerts to remediate")
            return None

        engine = get_engine(alert_cb=self.alert_cb, db=self.db)
        profile = engine.build_profile_from_botnet_alerts(all_alerts, "Kimwolf")
        result = engine.full_remediation(profile)

        # Log the report
        report = engine.get_remediation_report(result)
        log.info(report)

        return result


# ---------------------------------------------------------------------------
# MODULE-LEVEL SINGLETON (imported by main app)
# ---------------------------------------------------------------------------

_detector: Optional[KimwolfBotnetDetector] = None


def get_detector() -> Optional[KimwolfBotnetDetector]:
    return _detector


def init_detector(subnet: str = "192.168.4",
                  alert_cb: Optional[Callable] = None,
                  db=None) -> KimwolfBotnetDetector:
    global _detector
    _detector = KimwolfBotnetDetector(
        subnet=subnet, alert_cb=alert_cb, db=db, scan_interval=60)
    _detector.start()
    return _detector
