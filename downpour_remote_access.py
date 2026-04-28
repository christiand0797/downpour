#!/usr/bin/env python3
"""
downpour_remote_access.py - Downpour v29 Titanium
Remote-access threat detection, monitoring, and blocking.
Detects RATs, reverse shells, C2 beacons, and unauthorised remote-desktop
sessions; integrates with the main threat database and AEGIS framework.
"""
__version__ = "29.0.0"
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import socket
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

try:
    from vulnerability_scanner import VulnerabilityScanner
    _KEV_AVAILABLE = True
except ImportError:
    _KEV_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REMOTE_ACCESS_VECTORS: Dict[str, Dict] = {
    "rdp":         {"ports": [3389], "risk": "high",   "desc": "Remote Desktop Protocol"},
    "vnc":         {"ports": [5900, 5901, 5902], "risk": "medium", "desc": "Virtual Network Computing"},
    "teamviewer":  {"ports": [5938], "risk": "medium", "desc": "TeamViewer"},
    "anydesk":     {"ports": [7070], "risk": "medium", "desc": "AnyDesk"},
    "ssh":         {"ports": [22],   "risk": "medium", "desc": "Secure Shell"},
    "telnet":      {"ports": [23],   "risk": "high",   "desc": "Telnet (unencrypted)"},
    "reverse_tcp": {"ports": [4444, 4445, 1234, 8080, 8443], "risk": "critical", "desc": "Common reverse-shell ports"},
    "cobalt_strike":{"ports": [50050], "risk": "critical", "desc": "Cobalt Strike default listener"},
    "metasploit":  {"ports": [4444, 5555], "risk": "critical", "desc": "Metasploit handler"},
    "ngrok":       {"ports": [4040], "risk": "high",   "desc": "ngrok tunnel"},
    "winrm":       {"ports": [5985, 5986], "risk": "high", "desc": "Windows Remote Management"},
}

SUSPICIOUS_REMOTE_PROCESSES: Set[str] = {
    "teamviewer.exe", "anydesk.exe", "ammyy.exe", "radmin.exe",
    "logmein.exe", "screenconnect.exe", "connectwise.exe",
    "ncat.exe", "nc.exe", "netcat.exe", "plink.exe", "putty.exe",
    "mstsc.exe",  # only suspicious if spawned by unusual parent
    "psexec.exe", "psexecsvc.exe",
    "remcos.exe", "njrat.exe", "darkcomet.exe", "quasar.exe",
}

C2_BEACON_INTERVALS_SECONDS: Tuple[int, ...] = (30, 60, 120, 300)  # common beacon intervals

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class RemoteAccessEvent:
    """Represents a detected remote-access event."""
    timestamp: str
    event_type: str       # "rat", "reverse_shell", "c2_beacon", "rdp", "vnc", etc.
    process_name: str
    pid: int
    local_port: int
    remote_ip: str
    remote_port: int
    risk_level: str       # "low", "medium", "high", "critical"
    indicators: List[str] = field(default_factory=list)
    blocked: bool = False
    action_taken: str = ""

@dataclass
class RemoteAccessScanResult:
    """Result of a remote-access scan pass."""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    events: List[RemoteAccessEvent] = field(default_factory=list)
    suspicious_processes: List[Dict] = field(default_factory=list)
    open_remote_ports: List[Dict] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(1 for e in self.events if e.risk_level == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for e in self.events if e.risk_level == "high")

# ---------------------------------------------------------------------------
# Core detector
# ---------------------------------------------------------------------------
class RemoteAccessDetector:
    """
    Monitors network connections and running processes for remote-access
    threats.  Uses psutil when available, falls back to netstat/tasklist.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or (Path(__file__).parent / "downpour_v28_data" / "threats.db")
        self._lock  = threading.Lock()
        self._connection_history: Dict[str, List[float]] = {}  # ip -> [timestamps]
        self._blocked_ips: Set[str] = set()
        self._known_safe_pids: Set[int] = set()
        self._load_blocked_ips()

        try:
            import psutil as _psutil
            self._psutil = _psutil
        except ImportError:
            self._psutil = None
            logger.warning("psutil not available; falling back to netstat/tasklist")

    # ------------------------------------------------------------------
    def scan(self) -> RemoteAccessScanResult:
        """Run a full remote-access scan and return results."""
        t0 = time.monotonic()
        result = RemoteAccessScanResult()

        with self._lock:
            result.open_remote_ports  = self._scan_open_ports()
            result.suspicious_processes = self._scan_processes()
            connections = self._get_active_connections()
            for conn in connections:
                event = self._classify_connection(conn)
                if event:
                    result.events.append(event)
                    self._persist_event(event)

        result.duration_seconds = time.monotonic() - t0
        if result.critical_count or result.high_count:
            logger.warning("RemoteAccessDetector: %d critical, %d high events",
                           result.critical_count, result.high_count)
        return result

    # ------------------------------------------------------------------
    def block_ip(self, ip: str, reason: str = "") -> bool:
        """Add a Windows Firewall rule to block an IP address."""
        try:
            rule_name = f"Downpour_Block_{ip.replace('.', '_')}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", "dir=in", "action=block",
                f"remoteip={ip}", "enable=yes"
            ], check=True, capture_output=True,
               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
            self._blocked_ips.add(ip)
            logger.info("Blocked IP %s via firewall (%s)", ip, reason)
            return True
        except Exception as exc:
            logger.error("Failed to block IP %s: %s", ip, exc)
            return False

    def unblock_ip(self, ip: str) -> bool:
        """Remove a Downpour firewall block rule for an IP."""
        try:
            rule_name = f"Downpour_Block_{ip.replace('.', '_')}"
            subprocess.run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}"
            ], check=True, capture_output=True,
               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
            self._blocked_ips.discard(ip)
            return True
        except Exception as exc:
            logger.error("Failed to unblock IP %s: %s", ip, exc)
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _scan_open_ports(self) -> List[Dict]:
        """Return list of listening ports that match known remote-access vectors."""
        open_ports = []
        try:
            if self._psutil:
                for conn in self._psutil.net_connections(kind="inet"):
                    if conn.status == "LISTEN":
                        port = conn.laddr.port
                        for vec_name, vec_info in REMOTE_ACCESS_VECTORS.items():
                            if port in vec_info["ports"]:
                                open_ports.append({
                                    "port": port, "vector": vec_name,
                                    "risk": vec_info["risk"], "desc": vec_info["desc"],
                                    "pid": conn.pid
                                })
        except Exception as exc:
            logger.debug("_scan_open_ports error: %s", exc)
        return open_ports

    def _scan_processes(self) -> List[Dict]:
        """Return suspicious remote-access processes that are currently running."""
        found = []
        try:
            if self._psutil:
                for proc in self._psutil.process_iter(["pid", "name", "exe", "ppid"]):
                    try:
                        name = (proc.info.get("name") or "").lower()
                        if name in SUSPICIOUS_REMOTE_PROCESSES:
                            found.append({
                                "pid": proc.info["pid"],
                                "name": proc.info["name"],
                                "exe":  proc.info.get("exe", ""),
                                "ppid": proc.info.get("ppid"),
                            })
                    except (self._psutil.NoSuchProcess, self._psutil.AccessDenied):
                        pass
        except Exception as exc:
            logger.debug("_scan_processes error: %s", exc)
        return found

    def _get_active_connections(self) -> List[Dict]:
        """Return all active outbound TCP connections."""
        connections = []
        try:
            if self._psutil:
                for conn in self._psutil.net_connections(kind="tcp"):
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        connections.append({
                            "pid":         conn.pid,
                            "local_port":  conn.laddr.port,
                            "remote_ip":   conn.raddr.ip,
                            "remote_port": conn.raddr.port,
                        })
        except Exception as exc:
            logger.debug("_get_active_connections error: %s", exc)
        return connections

    def _classify_connection(self, conn: Dict) -> Optional[RemoteAccessEvent]:
        """Classify a connection; return RemoteAccessEvent if suspicious, else None."""
        rip  = conn.get("remote_ip", "")
        rport = conn.get("remote_port", 0)
        lport = conn.get("local_port", 0)
        pid   = conn.get("pid") or 0

        # Skip loopback and already-known-safe
        try:
            if ipaddress.ip_address(rip).is_loopback:
                return None
        except ValueError:
            pass

        indicators = []
        risk_level = "low"
        event_type = "connection"

        for vec_name, vec_info in REMOTE_ACCESS_VECTORS.items():
            if rport in vec_info["ports"] or lport in vec_info["ports"]:
                indicators.append(f"Port matches {vec_name} ({vec_info['desc']})")
                risk_level = vec_info["risk"]
                event_type = vec_name
                break

        # C2 beacon detection: recurring connection to same IP
        now = time.time()
        history = self._connection_history.setdefault(rip, [])
        history.append(now)
        # Keep only last 10 minutes
        self._connection_history[rip] = [t for t in history if now - t < 600]
        if len(self._connection_history[rip]) >= 3:
            intervals = [
                self._connection_history[rip][i+1] - self._connection_history[rip][i]
                for i in range(len(self._connection_history[rip]) - 1)
            ]
            avg = sum(intervals) / len(intervals) if intervals else 0
            for beacon_interval in C2_BEACON_INTERVALS_SECONDS:
                if abs(avg - beacon_interval) < 5:
                    indicators.append(f"C2 beacon pattern (~{beacon_interval}s interval)")
                    risk_level = "critical"
                    event_type = "c2_beacon"
                    break

        if not indicators:
            return None

        proc_name = ""
        if self._psutil and pid:
            try:
                proc_name = self._psutil.Process(pid).name()
            except Exception:
                pass

        return RemoteAccessEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            process_name=proc_name,
            pid=pid,
            local_port=lport,
            remote_ip=rip,
            remote_port=rport,
            risk_level=risk_level,
            indicators=indicators,
        )

    def _persist_event(self, event: RemoteAccessEvent) -> None:
        """Save event to the threats database."""
        if not self.db_path.exists():
            return
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO rat_detections
                        (process_name, pid, rat_type, indicators, detected_at, action)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (event.process_name, event.pid, event.event_type,
                      "; ".join(event.indicators), event.timestamp, event.action_taken))
                conn.commit()
        except sqlite3.OperationalError:
            pass  # Table not yet created — main app hasn't initialized DB yet
        except Exception as exc:
            logger.debug("_persist_event error: %s", exc)

    def _load_blocked_ips(self) -> None:
        """Load previously blocked IPs from DB."""
        if not self.db_path.exists():
            return
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                rows = conn.execute(
                    "SELECT ip FROM malicious_ips WHERE threat_type='blocked'"
                ).fetchall()
                self._blocked_ips = {r[0] for r in rows}
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Continuous monitor (background thread)
# ---------------------------------------------------------------------------
class RemoteAccessMonitor:
    """
    Runs RemoteAccessDetector.scan() on a background thread at a
    configurable interval and fires callbacks on detections.
    """

    def __init__(self, interval_seconds: int = 30,
                 db_path: Optional[Path] = None):
        self.interval = interval_seconds
        self.detector = RemoteAccessDetector(db_path)
        self._callbacks: List[callable] = []
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.last_result: Optional[RemoteAccessScanResult] = None

    def add_callback(self, fn) -> None:
        """Register a callback(result: RemoteAccessScanResult) for new events."""
        self._callbacks.append(fn)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="RemoteAccessMonitor"
        )
        self._thread.start()
        logger.info("RemoteAccessMonitor started (interval=%ds)", self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("RemoteAccessMonitor stopped")

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                result = self.detector.scan()
                self.last_result = result
                if result.events:
                    for cb in self._callbacks:
                        try:
                            cb(result)
                        except Exception as exc:
                            logger.debug("RemoteAccessMonitor callback error: %s", exc)
            except Exception as exc:
                logger.error("RemoteAccessMonitor scan error: %s", exc)
            self._stop_event.wait(self.interval)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
remote_access_monitor = RemoteAccessMonitor()

# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------
__all__ = [
    "RemoteAccessDetector",
    "RemoteAccessMonitor",
    "RemoteAccessEvent",
    "RemoteAccessScanResult",
    "REMOTE_ACCESS_VECTORS",
    "SUSPICIOUS_REMOTE_PROCESSES",
    "remote_access_monitor",
]


# ---------------------------------------------------------------------------
# Classes expected by downpour_v28_titanium.py
# ---------------------------------------------------------------------------

import winreg as _winreg

@dataclass
class ServiceThreatResult:
    """Result of evaluating a single Windows service for threats."""
    service_name: str
    display_name: str
    status: str
    start_type: str
    executable: str
    risk_level: str          # "safe", "low", "medium", "high", "critical"
    indicators: List[str] = field(default_factory=list)
    recommended_action: str = "monitor"

    @property
    def findings(self) -> List[str]:
        """Alias for GUI code that expects ``findings`` (same as ``indicators``)."""
        return self.indicators


class SmartServicesScanner:
    """
    Scans Windows services for remote-access and persistence threats.
    Flags suspicious start types, executables, and known-malicious service names.
    """

    _SUSPICIOUS_NAMES: Set[str] = {
        "remoteregistry", "termservice", "tlntsvr", "snmptrap",
        "w3svc", "msftpsvc", "simptcp", "xblgamesave",
    }
    _SAFE_START_TYPES = {"manual", "disabled"}

    def __init__(self):
        try:
            import psutil as _p
            self._psutil = _p
        except ImportError:
            self._psutil = None

    def scan_all(self) -> List[ServiceThreatResult]:
        """Enumerate all Windows services and evaluate each."""
        results: List[ServiceThreatResult] = []
        try:
            import subprocess
            out = subprocess.check_output(
                ["sc", "query", "type=", "all", "state=", "all"],
                text=True, errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
            )
            # Parse service names from sc query output
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("SERVICE_NAME:"):
                    svc_name = line.split(":", 1)[1].strip()
                    result = self._evaluate_service(svc_name)
                    if result:
                        results.append(result)
        except Exception as exc:
            logger.debug("SmartServicesScanner.scan_all: %s", exc)
        return results

    def _evaluate_service(self, service_name: str) -> Optional[ServiceThreatResult]:
        indicators = []
        risk_level = "safe"
        display_name = service_name
        status = "unknown"
        start_type = "unknown"
        executable = ""

        try:
            key = _winreg.OpenKey(
                _winreg.HKEY_LOCAL_MACHINE,
                f"SYSTEM\\CurrentControlSet\\Services\\{service_name}"
            )
            try:
                display_name = _winreg.QueryValueEx(key, "DisplayName")[0]
            except Exception:
                pass
            try:
                start_val = _winreg.QueryValueEx(key, "Start")[0]
                start_map = {0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}
                start_type = start_map.get(start_val, str(start_val))
            except Exception:
                pass
            try:
                executable = _winreg.QueryValueEx(key, "ImagePath")[0]
            except Exception:
                pass
            _winreg.CloseKey(key)
        except FileNotFoundError:
            return None
        except Exception:
            pass

        name_lower = service_name.lower()
        if name_lower in self._SUSPICIOUS_NAMES:
            indicators.append(f"Service '{service_name}' is a known remote-access vector")
            risk_level = "high"

        if start_type == "auto" and name_lower in self._SUSPICIOUS_NAMES:
            indicators.append("Auto-start remote-access service")
            risk_level = "high"

        for vec_name, vec_info in REMOTE_ACCESS_VECTORS.items():
            if vec_name in name_lower or vec_name in (executable or "").lower():
                indicators.append(f"Matches remote-access vector: {vec_name}")
                risk_level = vec_info["risk"]
                break

        if not indicators:
            return None  # clean — skip

        return ServiceThreatResult(
            service_name=service_name,
            display_name=display_name,
            status=status,
            start_type=start_type,
            executable=executable,
            risk_level=risk_level,
            indicators=indicators,
        )


class RemoteAccessController:
    """
    High-level remote-access controller used by the main Downpour GUI.
    Wraps RemoteAccessDetector + SmartServicesScanner into a single interface.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.detector        = RemoteAccessDetector(db_path)
        self.services_scanner = SmartServicesScanner()
        self.monitor         = RemoteAccessMonitor(db_path=db_path)
        self._callbacks: List[callable] = []

    def add_callback(self, fn) -> None:
        self._callbacks.append(fn)
        self.monitor.add_callback(fn)

    def start_monitoring(self, interval: int = 30) -> None:
        self.monitor.interval = interval
        self.monitor.start()

    def stop_monitoring(self) -> None:
        self.monitor.stop()

    def scan_now(self) -> RemoteAccessScanResult:
        return self.detector.scan()

    def scan_services(self) -> List[ServiceThreatResult]:
        return self.services_scanner.scan_all()

    def block_ip(self, ip: str, reason: str = "") -> bool:
        return self.detector.block_ip(ip, reason)

    def unblock_ip(self, ip: str) -> bool:
        return self.detector.unblock_ip(ip)

    def get_last_result(self) -> Optional[RemoteAccessScanResult]:
        return self.monitor.last_result


# Update __all__
__all__ = [
    "RemoteAccessController",
    "RemoteAccessDetector",
    "RemoteAccessMonitor",
    "SmartServicesScanner",
    "RemoteAccessEvent",
    "RemoteAccessScanResult",
    "ServiceThreatResult",
    "REMOTE_ACCESS_VECTORS",
    "SUSPICIOUS_REMOTE_PROCESSES",
    "remote_access_monitor",
]
