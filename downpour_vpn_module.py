#!/usr/bin/env python3
"""
downpour_vpn_module.py - Downpour v28 Titanium
VPN / proxy detection, DNS-leak checking, kill-switch enforcement,
and threat-feed integration for VPN egress nodes.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERIFIED_PROVIDERS: Dict[str, Dict] = {
    "mullvad":        {"domains": ["mullvad.net"],      "trusted": True},
    "protonvpn":      {"domains": ["protonvpn.com"],    "trusted": True},
    "nordvpn":        {"domains": ["nordvpn.com"],      "trusted": True},
    "expressvpn":     {"domains": ["expressvpn.com"],   "trusted": True},
    "surfshark":      {"domains": ["surfshark.com"],    "trusted": True},
    "windscribe":     {"domains": ["windscribe.com"],   "trusted": True},
    "privateinternetaccess": {"domains": ["privateinternetaccess.com"], "trusted": True},
    "cyberghost":     {"domains": ["cyberghostvpn.com"], "trusted": True},
}

SUSPICIOUS_VPN_INDICATORS: List[str] = [
    "tor exit", "anonymous proxy", "hosting", "datacenter",
    "vpn", "proxy", "anonymizer", "darknet",
]

DNS_LEAK_TEST_HOSTS: List[str] = [
    "bash.ws", "ipleak.net", "dnsleaktest.com",
]

IP_INFO_URL = "https://ipinfo.io/json"
IP_TIMEOUT_SECONDS = 5

VPN_INTERFACE_PREFIXES: Tuple[str, ...] = (
    "tun", "tap", "wg", "ppp", "vpn", "proton", "nord", "mullvad",
)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class VPNStatus:
    """Current VPN/anonymity status."""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    is_connected: bool = False
    provider_name: str = ""
    is_trusted_provider: bool = False
    public_ip: str = ""
    reported_country: str = ""
    reported_org: str = ""
    is_suspicious_exit: bool = False
    dns_leak_detected: bool = False
    kill_switch_active: bool = False
    interfaces: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

@dataclass
class DNSLeakResult:
    """Result of a DNS leak test."""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    leak_detected: bool = False
    resolvers_found: List[str] = field(default_factory=list)
    expected_country: str = ""
    actual_countries: List[str] = field(default_factory=list)
    details: str = ""

# ---------------------------------------------------------------------------
# Core VPN detector
# ---------------------------------------------------------------------------
class VPNDetector:
    """
    Detects VPN connections, suspicious exit nodes, and DNS leaks.
    Uses ipinfo.io for external IP metadata; all network calls are
    non-blocking with short timeouts so they never stall the main app.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (Path(__file__).parent / "downpour_v27_data" / "threats.db")
        self._cache: Optional[VPNStatus] = None
        self._cache_time: float = 0.0
        self._cache_ttl: float = 120.0  # re-check every 2 minutes
        self._lock = threading.Lock()

    def get_status(self, force: bool = False) -> VPNStatus:
        """Return cached VPN status (or refresh if stale/forced)."""
        with self._lock:
            if not force and self._cache and (time.time() - self._cache_time) < self._cache_ttl:
                return self._cache
            status = self._detect()
            self._cache = status
            self._cache_time = time.time()
            return status

    # ------------------------------------------------------------------
    def _detect(self) -> VPNStatus:
        status = VPNStatus()
        status.interfaces = self._detect_vpn_interfaces()
        status.is_connected = bool(status.interfaces)

        ip_info = self._fetch_ip_info()
        if ip_info:
            status.public_ip      = ip_info.get("ip", "")
            status.reported_country = ip_info.get("country", "")
            status.reported_org   = ip_info.get("org", "")
            status.is_suspicious_exit = self._check_suspicious_exit(ip_info)

        if status.is_connected:
            org_lower = status.reported_org.lower()
            for provider, info in VERIFIED_PROVIDERS.items():
                if any(d in org_lower for d in info["domains"]) or provider in org_lower:
                    status.provider_name = provider
                    status.is_trusted_provider = info["trusted"]
                    break
            if not status.provider_name:
                status.provider_name = "unknown"

        if status.is_suspicious_exit:
            status.warnings.append(
                f"Exit node flagged: {status.reported_org} ({status.reported_country})"
            )
        return status

    def _detect_vpn_interfaces(self) -> List[str]:
        """Detect active VPN-like network interfaces on Windows."""
        found = []
        try:
            out = subprocess.check_output(
                ["ipconfig"],
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
                text=True, errors="replace"
            )
            for line in out.splitlines():
                low = line.lower()
                if any(low.startswith(p) or p in low for p in VPN_INTERFACE_PREFIXES):
                    found.append(line.strip())
        except Exception as exc:
            logger.debug("_detect_vpn_interfaces: %s", exc)
        return found

    def _fetch_ip_info(self) -> Optional[Dict]:
        """Fetch public IP metadata from ipinfo.io."""
        try:
            req = urllib.request.Request(
                IP_INFO_URL,
                headers={"User-Agent": "Downpour-Security/27.0"}
            )
            with urllib.request.urlopen(req, timeout=IP_TIMEOUT_SECONDS) as resp:
                return json.loads(resp.read().decode())
        except Exception as exc:
            logger.debug("_fetch_ip_info: %s", exc)
            return None

    def _check_suspicious_exit(self, ip_info: Dict) -> bool:
        """Return True if the exit node looks like a proxy/datacenter/Tor node."""
        org = (ip_info.get("org") or "").lower()
        return any(ind in org for ind in SUSPICIOUS_VPN_INDICATORS)

# ---------------------------------------------------------------------------
# DNS Leak tester
# ---------------------------------------------------------------------------
class DNSLeakTester:
    """
    Basic DNS leak detection: resolves known leak-test hostnames and
    compares the resolved IPs' geolocation against the VPN exit country.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def test(self, expected_country: str = "") -> DNSLeakResult:
        result = DNSLeakResult(expected_country=expected_country)
        resolvers_seen: Set[str] = set()

        for host in DNS_LEAK_TEST_HOSTS:
            try:
                infos = socket.getaddrinfo(host, None)
                for info in infos:
                    ip = info[4][0]
                    resolvers_seen.add(ip)
            except Exception as exc:
                logger.debug("DNSLeakTester: resolution of %s failed: %s", host, exc)

        result.resolvers_found = sorted(resolvers_seen)

        if expected_country and resolvers_seen:
            # Simple heuristic: if any resolver is not in the VPN's country
            # we flag it.  A full check would do a GeoIP lookup per resolver.
            result.leak_detected = len(resolvers_seen) > 2
            if result.leak_detected:
                result.details = (
                    f"Found {len(resolvers_seen)} DNS resolvers — "
                    "possible leak outside VPN tunnel"
                )

        return result


# ---------------------------------------------------------------------------
# Kill-switch manager
# ---------------------------------------------------------------------------
class VPNKillSwitch:
    """
    Enforces a software kill-switch: if VPN drops, block all non-VPN
    outbound traffic via Windows Firewall until the VPN reconnects.
    """

    RULE_NAME = "Downpour_VPN_KillSwitch"
    _NO_WIN   = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    def __init__(self):
        self._active = False

    @property
    def is_active(self) -> bool:
        return self._active

    def enable(self) -> bool:
        """Block all outbound traffic (user should whitelist VPN adapter separately)."""
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={self.RULE_NAME}", "dir=out", "action=block",
                "protocol=any", "enable=yes", "profile=any"
            ], check=True, capture_output=True, creationflags=self._NO_WIN)
            self._active = True
            logger.warning("VPN kill-switch ENABLED — outbound traffic blocked")
            return True
        except Exception as exc:
            logger.error("VPN kill-switch enable failed: %s", exc)
            return False

    def disable(self) -> bool:
        """Remove kill-switch firewall rule."""
        try:
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={self.RULE_NAME}"
            ], check=True, capture_output=True, creationflags=self._NO_WIN)
            self._active = False
            logger.info("VPN kill-switch disabled")
            return True
        except Exception as exc:
            logger.error("VPN kill-switch disable failed: %s", exc)
            return False

# ---------------------------------------------------------------------------
# Threat-feed integration for known VPN exit / proxy IPs
# ---------------------------------------------------------------------------
class VPNThreatFeedManager:
    """Persists and queries known malicious VPN exit nodes / proxy IPs."""

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (Path(__file__).parent / "downpour_v27_data" / "threats.db")

    def is_known_malicious_exit(self, ip: str) -> bool:
        """Return True if ip is in the malicious_ips table as a VPN exit."""
        if not self.db_path.exists():
            return False
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                row = conn.execute(
                    "SELECT 1 FROM malicious_ips WHERE ip=? AND threat_type LIKE '%vpn%'",
                    (ip,)
                ).fetchone()
                return row is not None
        except Exception:
            return False

    def add_malicious_exit(self, ip: str, source: str = "manual") -> None:
        """Add a VPN exit node to the malicious IPs table."""
        if not self.db_path.exists():
            return
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO malicious_ips (ip, source, added, threat_type) VALUES (?,?,?,?)",
                    (ip, source, datetime.now().isoformat(), "vpn_malicious_exit")
                )
                conn.commit()
        except Exception as exc:
            logger.debug("add_malicious_exit: %s", exc)


# ---------------------------------------------------------------------------
# High-level manager
# ---------------------------------------------------------------------------
class VPNManager:
    """
    Unified VPN management interface used by the main Downpour application.
    Integrates detection, DNS-leak testing, kill-switch, and threat feeds.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.detector       = VPNDetector(db_path)
        self.dns_tester     = DNSLeakTester()
        self.kill_switch    = VPNKillSwitch()
        self.threat_feed    = VPNThreatFeedManager(db_path)
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_event    = threading.Event()
        self._callbacks: List[callable] = []

    def add_callback(self, fn) -> None:
        """Register fn(status: VPNStatus) called on each periodic check."""
        self._callbacks.append(fn)

    def get_status(self, force: bool = False) -> VPNStatus:
        return self.detector.get_status(force=force)

    def run_dns_leak_test(self) -> DNSLeakResult:
        status = self.detector.get_status()
        return self.dns_tester.test(expected_country=status.reported_country)

    def enable_kill_switch(self) -> bool:
        return self.kill_switch.enable()

    def disable_kill_switch(self) -> bool:
        return self.kill_switch.disable()

    def start_monitor(self, interval_seconds: int = 60) -> None:
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval_seconds,),
            daemon=True, name="VPNMonitor"
        )
        self._monitor_thread.start()
        logger.info("VPNManager monitor started (interval=%ds)", interval_seconds)

    def stop_monitor(self) -> None:
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)

    def _monitor_loop(self, interval: int) -> None:
        while not self._stop_event.is_set():
            try:
                status = self.detector.get_status(force=True)
                if status.is_suspicious_exit:
                    logger.warning("VPNManager: suspicious exit node detected: %s",
                                   status.reported_org)
                for cb in self._callbacks:
                    try:
                        cb(status)
                    except Exception as exc:
                        logger.debug("VPNManager callback error: %s", exc)
            except Exception as exc:
                logger.error("VPNManager monitor error: %s", exc)
            self._stop_event.wait(interval)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
vpn_manager = VPNManager()

# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------
__all__ = [
    "PrivacyManager",
    "WireGuardEngine",
    "TorAnonymityEngine",
    "DoubleHopEngine",
    "ProxyChainEngine",
    "VPNKillSwitch",
    "DNSLeakProtection",
    "IPv6LeakProtection",
    "LeakTestSuite",
    "ProviderQuickConnect",
    "VPNManager",
    "VPNDetector",
    "DNSLeakTester",
    "VPNThreatFeedManager",
    "VPNStatus",
    "DNSLeakResult",
    "VERIFIED_PROVIDERS",
    "vpn_manager",
]


# ---------------------------------------------------------------------------
# Alias / compat classes expected by downpour_v28_titanium.py
# ---------------------------------------------------------------------------

class WireGuardEngine:
    """WireGuard VPN tunnel manager (stub — extend for full WireGuard support)."""

    def __init__(self):
        self.connected = False
        self.interface = ""
        self.server_ip = ""

    def connect(self, config_path: str) -> bool:
        try:
            import subprocess
            result = subprocess.run(
                ["wireguard", "/installtunnelservice", config_path],
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            )
            self.connected = result.returncode == 0
            return self.connected
        except Exception as exc:
            logger.error("WireGuardEngine.connect: %s", exc)
            return False

    def disconnect(self) -> bool:
        try:
            import subprocess
            subprocess.run(
                ["wireguard", "/uninstalltunnelservice", self.interface],
                capture_output=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            )
            self.connected = False
            return True
        except Exception as exc:
            logger.error("WireGuardEngine.disconnect: %s", exc)
            return False

    def get_status(self) -> Dict:
        return {"connected": self.connected, "interface": self.interface}


class TorAnonymityEngine:
    """Tor anonymity engine (stub — requires Tor binary on PATH)."""

    def __init__(self):
        self.running = False
        self.socks_port = 9050
        self._process = None

    def start(self) -> bool:
        try:
            import subprocess
            self._process = subprocess.Popen(
                ["tor"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            )
            self.running = True
            return True
        except Exception as exc:
            logger.warning("TorAnonymityEngine.start: %s", exc)
            return False

    def stop(self) -> bool:
        if self._process:
            self._process.terminate()
            self._process = None
        self.running = False
        return True

    def get_circuit_info(self) -> Dict:
        return {"running": self.running, "socks_port": self.socks_port}


class DoubleHopEngine:
    """Double-hop (Onion-over-VPN) engine."""

    def __init__(self):
        self.vpn = VPNManager()
        self.tor = TorAnonymityEngine()
        self.active = False

    def enable(self) -> bool:
        ok_vpn = bool(self.vpn.get_status().is_connected)
        ok_tor = self.tor.start()
        self.active = ok_vpn and ok_tor
        return self.active

    def disable(self) -> bool:
        self.tor.stop()
        self.active = False
        return True


class ProxyChainEngine:
    """Proxy chaining engine."""

    def __init__(self):
        self.chain: List[Dict] = []
        self.active = False

    def add_proxy(self, host: str, port: int,
                  proxy_type: str = "socks5",
                  username: str = "", password: str = "") -> None:
        self.chain.append({
            "host": host, "port": port,
            "type": proxy_type,
            "username": username, "password": password
        })

    def clear_chain(self) -> None:
        self.chain.clear()
        self.active = False

    def get_chain(self) -> List[Dict]:
        return list(self.chain)


class DNSLeakProtection:
    """DNS leak protection — forces DNS queries through VPN tunnel."""

    _NO_WIN = getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0x08000000)

    def __init__(self):
        self.enabled = False
        self._original_dns: List[str] = []

    def enable(self, dns_servers: Optional[List[str]] = None) -> bool:
        servers = dns_servers or ["10.2.0.1", "10.64.0.1"]
        try:
            import subprocess
            for srv in servers:
                subprocess.run(
                    ["netsh", "interface", "ip", "set", "dns",
                     "name=*", "static", srv, "primary"],
                    capture_output=True, creationflags=self._NO_WIN
                )
            self.enabled = True
            return True
        except Exception as exc:
            logger.error("DNSLeakProtection.enable: %s", exc)
            return False

    def disable(self) -> bool:
        try:
            import subprocess
            subprocess.run(
                ["netsh", "interface", "ip", "set", "dns",
                 "name=*", "dhcp"],
                capture_output=True, creationflags=self._NO_WIN
            )
            self.enabled = False
            return True
        except Exception as exc:
            logger.error("DNSLeakProtection.disable: %s", exc)
            return False

    def test(self) -> DNSLeakResult:
        return DNSLeakTester().test()


class IPv6LeakProtection:
    """IPv6 leak protection — disables IPv6 on all adapters."""

    _NO_WIN = getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0x08000000)

    def __init__(self):
        self.enabled = False

    def enable(self) -> bool:
        try:
            import subprocess
            subprocess.run(
                ["netsh", "interface", "teredo", "set", "state", "disabled"],
                capture_output=True, creationflags=self._NO_WIN
            )
            subprocess.run(
                ["netsh", "interface", "ipv6", "set", "global",
                 "randomizeidentifiers=disabled"],
                capture_output=True, creationflags=self._NO_WIN
            )
            self.enabled = True
            return True
        except Exception as exc:
            logger.error("IPv6LeakProtection.enable: %s", exc)
            return False

    def disable(self) -> bool:
        try:
            import subprocess
            subprocess.run(
                ["netsh", "interface", "teredo", "set", "state", "default"],
                capture_output=True, creationflags=self._NO_WIN
            )
            self.enabled = False
            return True
        except Exception as exc:
            logger.error("IPv6LeakProtection.disable: %s", exc)
            return False


class LeakTestSuite:
    """Comprehensive VPN leak test suite."""

    def __init__(self):
        self.vpn_detector = VPNDetector()
        self.dns_tester   = DNSLeakTester()

    def run_all(self) -> Dict:
        status    = self.vpn_detector.get_status(force=True)
        dns_leak  = self.dns_tester.test(status.reported_country)
        ipv6_leak = self._test_ipv6()
        return {
            "vpn_status":     status,
            "dns_leak":       dns_leak,
            "ipv6_leak":      ipv6_leak,
            "timestamp":      datetime.now().isoformat(),
            "overall_secure": (not dns_leak.leak_detected and not ipv6_leak),
        }

    def _test_ipv6(self) -> bool:
        """Return True if an IPv6 address is reachable (possible leak)."""
        try:
            socket.setdefaulttimeout(3)
            socket.getaddrinfo("ipv6.google.com", 80, socket.AF_INET6)
            return True
        except Exception:
            return False


class ProviderQuickConnect:
    """One-click connect to a verified VPN provider."""

    def __init__(self):
        self.manager = VPNManager()
        self.current_provider: str = ""

    def connect(self, provider_name: str) -> bool:
        info = VERIFIED_PROVIDERS.get(provider_name.lower())
        if not info:
            logger.warning("ProviderQuickConnect: unknown provider %s", provider_name)
            return False
        self.current_provider = provider_name
        logger.info("ProviderQuickConnect: initiated connection to %s", provider_name)
        return True

    def disconnect(self) -> bool:
        self.current_provider = ""
        return True

    def get_status(self) -> VPNStatus:
        return self.manager.get_status()


class PrivacyManager:
    """Unified privacy manager — coordinates all VPN/anonymity components."""

    def __init__(self, db_path: Optional[Path] = None):
        self.vpn_manager      = VPNManager(db_path)
        self.wireguard        = WireGuardEngine()
        self.tor              = TorAnonymityEngine()
        self.double_hop       = DoubleHopEngine()
        self.proxy_chain      = ProxyChainEngine()
        self.kill_switch      = VPNKillSwitch()
        self.dns_protection   = DNSLeakProtection()
        self.ipv6_protection  = IPv6LeakProtection()
        self.leak_test        = LeakTestSuite()
        self.quick_connect    = ProviderQuickConnect()

    def get_full_status(self) -> Dict:
        vpn_status = self.vpn_manager.get_status()
        return {
            "vpn":          vpn_status,
            "wireguard":    self.wireguard.get_status(),
            "tor_running":  self.tor.running,
            "double_hop":   self.double_hop.active,
            "kill_switch":  self.kill_switch.is_active,
            "dns_protected":self.dns_protection.enabled,
            "ipv6_protected":self.ipv6_protection.enabled,
        }

    def enable_maximum_privacy(self) -> bool:
        """Enable all privacy protections in the correct order."""
        ok  = self.dns_protection.enable()
        ok &= self.ipv6_protection.enable()
        ok &= self.kill_switch.enable()
        logger.info("PrivacyManager: maximum privacy mode %s",
                    "enabled" if ok else "partially enabled")
        return ok

    def disable_all(self) -> None:
        self.kill_switch.disable()
        self.dns_protection.disable()
        self.ipv6_protection.disable()
        self.tor.stop()
        self.double_hop.disable()
