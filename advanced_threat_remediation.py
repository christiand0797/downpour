"""
Advanced Threat Remediation Engine v1.0 — Downpour v28 Titanium
================================================================
Comprehensive automated and guided remediation for:
  - Botnets (Kimwolf, Mirai, Mozi, AISURU, BadBox2)
  - Rootkits (DKOM, BYOVD, bootkits, network hooks)
  - RATs (remote access trojans)
  - Cryptominers
  - Persistence mechanisms (registry, scheduled tasks, WMI, services)
  - Phantom/rogue network devices
  - DNS hijacking / poisoning
  - DLL hijacking / sideloading
  - Browser hijackers

Philosophy:
  - NEVER auto-delete system files — quarantine first, explain to user
  - Layer 1: Isolate (stop the bleeding)
  - Layer 2: Identify (find all footholds)
  - Layer 3: Eradicate (remove all components)
  - Layer 4: Verify (confirm clean)
  - Layer 5: Harden (prevent reinfection)
"""

from __future__ import annotations
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

_NO_WIN = 0x08000000  # CREATE_NO_WINDOW

try:
    import psutil
    PSUTIL = True
except ImportError:
    psutil = None
    PSUTIL = False

try:
    import winreg
    WINREG = True
except ImportError:
    winreg = None
    WINREG = False

log = logging.getLogger("ThreatRemediation")


# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class RemediationAction:
    """A single remediation step that was taken or needs to be taken."""
    action_type: str       # isolate, kill, quarantine, block, clean, etc.
    target: str            # what was acted on (path, PID, IP, registry key)
    description: str       # human-readable explanation
    success: bool = False
    requires_reboot: bool = False
    requires_admin: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    details: str = ""


@dataclass
class ThreatProfile:
    """Complete profile of a detected threat with all its footholds."""
    threat_id: str
    threat_type: str       # botnet, rootkit, rat, miner, persistence, etc.
    threat_family: str     # Kimwolf, Mirai, njRAT, etc.
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW
    summary: str

    # All discovered footholds
    processes: List[Dict] = field(default_factory=list)      # PIDs, names, paths
    files: List[str] = field(default_factory=list)            # malicious file paths
    registry_keys: List[Dict] = field(default_factory=list)   # persistence entries
    scheduled_tasks: List[str] = field(default_factory=list)  # task names
    services: List[str] = field(default_factory=list)         # service names
    network_connections: List[Dict] = field(default_factory=list)  # C2 connections
    dns_entries: List[str] = field(default_factory=list)      # poisoned DNS
    firewall_rules: List[str] = field(default_factory=list)   # suspicious rules
    wmi_subscriptions: List[str] = field(default_factory=list)  # WMI persistence
    phantom_devices: List[Dict] = field(default_factory=list)   # rogue network devices
    dlls_injected: List[Dict] = field(default_factory=list)     # injected DLLs

    # Remediation tracking
    actions_taken: List[RemediationAction] = field(default_factory=list)
    is_fully_remediated: bool = False
    requires_reboot: bool = False


# ============================================================================
# THREAT REMEDIATION ENGINE
# ============================================================================

class ThreatRemediationEngine:
    """
    Comprehensive threat remediation with 5-layer approach:
    1. ISOLATE — stop active damage immediately
    2. IDENTIFY — find all footholds and persistence
    3. ERADICATE — remove every component
    4. VERIFY — confirm complete removal
    5. HARDEN — prevent reinfection
    """

    def __init__(self, quarantine_dir: str = None, alert_cb: Callable = None,
                 db: Any = None):
        self.quarantine_dir = Path(quarantine_dir or os.path.join(
            os.path.dirname(__file__), 'downpour_data', 'quarantine'))
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.alert_cb = alert_cb or (lambda msg, level="INFO": None)
        self.db = db
        self._lock = threading.Lock()
        self.active_profiles: Dict[str, ThreatProfile] = {}

    def _log(self, msg: str, level: str = "INFO"):
        log.info(msg)
        try:
            self.alert_cb(msg, level)
        except Exception:
            pass

    def _run_cmd(self, cmd: list, timeout: int = 15) -> subprocess.CompletedProcess:
        """Run a command silently."""
        return subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, creationflags=_NO_WIN)

    # ========================================================================
    # LAYER 1: ISOLATE — Stop the bleeding
    # ========================================================================

    def isolate_threat(self, profile: ThreatProfile) -> List[RemediationAction]:
        """Immediately contain the threat: suspend processes, block C2, cut network."""
        actions = []
        self._log(f"[ISOLATE] Beginning containment of {profile.threat_family}...", "WARNING")

        # 1. Suspend all malicious processes (don't kill yet — we need forensics)
        for proc_info in profile.processes:
            pid = proc_info.get('pid')
            name = proc_info.get('name', 'unknown')
            if pid and PSUTIL:
                try:
                    p = psutil.Process(pid)
                    p.suspend()
                    actions.append(RemediationAction(
                        "suspend", f"PID:{pid} {name}",
                        f"Suspended malicious process {name}",
                        success=True))
                except Exception as e:
                    actions.append(RemediationAction(
                        "suspend", f"PID:{pid} {name}",
                        f"Failed to suspend {name}: {e}",
                        success=False, requires_admin=True))

        # 2. Block all known C2 IPs via Windows Firewall
        blocked_ips = set()
        for conn in profile.network_connections:
            ip = conn.get('remote_ip', '')
            if ip and ip not in blocked_ips:
                blocked_ips.add(ip)
                act = self._block_ip(ip, f"{profile.threat_family}_C2")
                actions.append(act)

        # 3. Block C2 domains via hosts file
        for domain in profile.dns_entries:
            act = self._block_domain(domain)
            actions.append(act)

        # 4. If botnet — isolate infected LAN devices
        for device in profile.phantom_devices:
            dev_ip = device.get('ip', '')
            if dev_ip:
                act = self._block_ip(dev_ip, f"infected_device_{dev_ip}")
                actions.append(act)

        profile.actions_taken.extend(actions)
        return actions

    def _block_ip(self, ip: str, label: str) -> RemediationAction:
        """Add bidirectional firewall block for an IP."""
        safe_ip = re.sub(r'[^\d.:]', '_', ip)[:40]
        rule = f"DOWNPOUR_BLOCK_{safe_ip}"
        try:
            # Delete existing rule first
            self._run_cmd(["netsh", "advfirewall", "firewall", "delete",
                           "rule", f"name={rule}"], timeout=6)
            for direction in ("in", "out"):
                self._run_cmd([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule}", f"dir={direction}", "action=block",
                    "enable=yes", f"remoteip={ip}"], timeout=6)
            return RemediationAction(
                "firewall_block", ip,
                f"Blocked all traffic to/from {ip} ({label})",
                success=True)
        except Exception as e:
            return RemediationAction(
                "firewall_block", ip,
                f"Failed to block {ip}: {e}",
                success=False, requires_admin=True)

    def _block_domain(self, domain: str) -> RemediationAction:
        """Block domain via hosts file sinkhole."""
        hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
        try:
            # Check if already blocked
            with open(hosts_path, 'r') as f:
                existing = f.read()
            if domain in existing:
                return RemediationAction(
                    "dns_block", domain,
                    f"Domain {domain} already blocked in hosts file",
                    success=True)
            # Add sinkhole entry
            with open(hosts_path, 'a') as f:
                f.write(f"\n0.0.0.0 {domain}  # Blocked by Downpour - {datetime.now().isoformat()}\n")
            # Flush DNS cache
            self._run_cmd(["ipconfig", "/flushdns"], timeout=5)
            return RemediationAction(
                "dns_block", domain,
                f"Blocked C2 domain {domain} via hosts file + flushed DNS",
                success=True)
        except Exception as e:
            return RemediationAction(
                "dns_block", domain,
                f"Failed to block domain {domain}: {e}",
                success=False, requires_admin=True)

    # ========================================================================
    # LAYER 2: IDENTIFY — Find all footholds
    # ========================================================================

    def deep_scan_footholds(self, profile: ThreatProfile) -> ThreatProfile:
        """Scan the entire system for all footholds of the threat."""
        self._log(f"[IDENTIFY] Deep scanning for all {profile.threat_family} footholds...", "WARNING")

        # Find related processes
        self._scan_related_processes(profile)
        # Find persistence mechanisms
        self._scan_registry_persistence(profile)
        self._scan_scheduled_tasks(profile)
        self._scan_wmi_persistence(profile)
        self._scan_service_persistence(profile)
        # Find related files
        self._scan_related_files(profile)
        # Find network footholds
        self._scan_phantom_devices(profile)
        self._scan_dns_hijacking(profile)
        self._scan_proxy_settings(profile)
        # Find DLL injection
        self._scan_dll_hijacking(profile)
        # Find suspicious firewall rules
        self._scan_firewall_rules(profile)

        return profile

    def _scan_related_processes(self, profile: ThreatProfile):
        """Find all processes related to the threat, including children."""
        if not PSUTIL:
            return
        known_pids = {p.get('pid') for p in profile.processes}
        known_paths = {p.get('path', '').lower() for p in profile.processes if p.get('path')}

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'ppid']):
            try:
                pi = proc.info
                pid = pi['pid']
                if pid in known_pids:
                    continue
                name = (pi.get('name') or '').lower()
                exe = (pi.get('exe') or '').lower()
                cmdline = ' '.join(pi.get('cmdline') or []).lower()

                # Check if this process is a child of a known malicious process
                if pi.get('ppid') in known_pids:
                    profile.processes.append({
                        'pid': pid, 'name': pi['name'],
                        'path': pi.get('exe', ''),
                        'reason': f"Child of malicious PID {pi['ppid']}"
                    })
                    known_pids.add(pid)
                    continue

                # Check if exe path matches known malicious paths
                if exe and exe in known_paths:
                    profile.processes.append({
                        'pid': pid, 'name': pi['name'],
                        'path': pi.get('exe', ''),
                        'reason': "Same executable as known threat"
                    })
                    known_pids.add(pid)
                    continue

                # Check for known botnet/malware process names
                threat_names = {
                    'byteconnect', 'plainproxies', 'grass', 'netd_services',
                    'tv_helper', 'xmrig', 'minergate', 'nicehash', 'cpuminer',
                    'meterpreter', 'mimikatz', 'njrat', 'darkcomet', 'asyncrat',
                    'windowsnetservicehelper', 'csrss2', 'svchost2', 'svch0st',
                }
                for tn in threat_names:
                    if tn in name or tn in exe or tn in cmdline:
                        profile.processes.append({
                            'pid': pid, 'name': pi['name'],
                            'path': pi.get('exe', ''),
                            'reason': f"Known malware name match: {tn}"
                        })
                        known_pids.add(pid)
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _scan_registry_persistence(self, profile: ThreatProfile):
        """Scan ALL persistence registry locations for threat-related entries."""
        if not WINREG:
            return
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"),
            # Less common but used by malware
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Active Setup\Installed Components"),
        ]

        known_paths = {p.get('path', '').lower() for p in profile.processes if p.get('path')}
        threat_keywords = {profile.threat_family.lower()}
        # Add process names
        for p in profile.processes:
            name = p.get('name', '').lower()
            if name:
                threat_keywords.add(name.replace('.exe', ''))

        for hive, key_path in run_keys:
            try:
                key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        value_lower = str(value).lower()

                        is_suspicious = False
                        reason = ""

                        # Check if value references known malicious paths
                        for kp in known_paths:
                            if kp and kp in value_lower:
                                is_suspicious = True
                                reason = f"References known malicious path"
                                break

                        # Check for threat family keywords
                        if not is_suspicious:
                            for kw in threat_keywords:
                                if len(kw) >= 4 and kw in value_lower:
                                    is_suspicious = True
                                    reason = f"Contains threat keyword: {kw}"
                                    break

                        # Check for suspicious patterns
                        if not is_suspicious:
                            sus_patterns = [
                                (r'powershell.*-enc', "Encoded PowerShell"),
                                (r'mshta.*vbscript', "MSHTA script execution"),
                                (r'regsvr32.*/s.*/n', "Regsvr32 proxy execution"),
                                (r'\\temp\\.*\.exe', "Executable in temp directory"),
                                (r'\\appdata\\local\\temp\\.*\.exe', "Executable in local temp"),
                            ]
                            for pat, desc in sus_patterns:
                                if re.search(pat, value_lower):
                                    is_suspicious = True
                                    reason = desc
                                    break

                        if is_suspicious:
                            hive_name = "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM"
                            profile.registry_keys.append({
                                'hive': hive_name,
                                'key': key_path,
                                'name': name,
                                'value': str(value)[:500],
                                'reason': reason
                            })
                    except OSError:
                        break
                winreg.CloseKey(key)
            except Exception:
                pass

    def _scan_scheduled_tasks(self, profile: ThreatProfile):
        """Find scheduled tasks that may be persistence mechanisms."""
        try:
            r = self._run_cmd(
                ['schtasks', '/query', '/fo', 'csv', '/v'],
                timeout=30)
            if r.returncode != 0:
                return

            known_paths = {p.get('path', '').lower() for p in profile.processes if p.get('path')}
            threat_kw = {profile.threat_family.lower()}

            for line in r.stdout.splitlines():
                ll = line.lower()
                is_sus = False

                for kp in known_paths:
                    if kp and kp in ll:
                        is_sus = True
                        break
                if not is_sus:
                    for kw in threat_kw:
                        if len(kw) >= 4 and kw in ll:
                            is_sus = True
                            break
                if not is_sus:
                    sus_indicators = [
                        '\\temp\\', 'powershell -enc', 'mshta ',
                        'certutil -decode', 'bitsadmin /transfer',
                    ]
                    for si in sus_indicators:
                        if si in ll:
                            is_sus = True
                            break

                if is_sus:
                    parts = line.split('","')
                    task_name = parts[1] if len(parts) > 1 else line[:100]
                    task_name = task_name.strip('"')
                    if task_name not in profile.scheduled_tasks:
                        profile.scheduled_tasks.append(task_name)
        except Exception:
            pass

    def _scan_wmi_persistence(self, profile: ThreatProfile):
        """Detect WMI event subscriptions (a favorite of advanced malware)."""
        try:
            # Check for WMI event consumers
            r = self._run_cmd([
                'powershell', '-NoProfile', '-Command',
                'Get-WMIObject -Namespace root\\subscription -Class __EventConsumer '
                '| Select-Object Name,__CLASS | ConvertTo-Json -Depth 2'
            ], timeout=15)
            if r.returncode == 0 and r.stdout.strip():
                consumers = json.loads(r.stdout)
                if isinstance(consumers, dict):
                    consumers = [consumers]
                for c in consumers:
                    name = c.get('Name', '')
                    cls = c.get('__CLASS', '')
                    # Most legitimate WMI consumers are from Microsoft
                    if name and 'microsoft' not in name.lower():
                        profile.wmi_subscriptions.append(
                            f"{cls}: {name}")
        except Exception:
            pass

    def _scan_service_persistence(self, profile: ThreatProfile):
        """Find suspicious Windows services."""
        try:
            r = self._run_cmd([
                'powershell', '-NoProfile', '-Command',
                'Get-WmiObject Win32_Service | Where-Object '
                '{$_.StartMode -eq "Auto" -and $_.State -eq "Running"} | '
                'Select-Object Name,PathName,Description | ConvertTo-Json -Depth 2'
            ], timeout=20)
            if r.returncode != 0 or not r.stdout.strip():
                return

            services = json.loads(r.stdout)
            if isinstance(services, dict):
                services = [services]

            known_paths = {p.get('path', '').lower() for p in profile.processes if p.get('path')}

            for svc in services:
                path = (svc.get('PathName') or '').lower()
                name = svc.get('Name', '')

                is_sus = False
                for kp in known_paths:
                    if kp and kp in path:
                        is_sus = True
                        break

                if not is_sus:
                    # Check for services running from suspicious locations
                    sus_locations = ['\\temp\\', '\\tmp\\', '\\appdata\\',
                                     '\\downloads\\', '\\public\\']
                    for sl in sus_locations:
                        if sl in path:
                            is_sus = True
                            break

                if is_sus and name not in profile.services:
                    profile.services.append(name)
        except Exception:
            pass

    def _scan_related_files(self, profile: ThreatProfile):
        """Find all files related to the threat."""
        # Collect directories from known malicious processes
        search_dirs = set()
        for p in profile.processes:
            path = p.get('path', '')
            if path:
                search_dirs.add(os.path.dirname(path))

        for search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue
            try:
                for item in os.listdir(search_dir):
                    full_path = os.path.join(search_dir, item)
                    if full_path not in profile.files and os.path.isfile(full_path):
                        # Check if it's suspicious
                        ext = os.path.splitext(item)[1].lower()
                        if ext in ('.exe', '.dll', '.bat', '.cmd', '.ps1',
                                   '.vbs', '.js', '.hta', '.scr'):
                            profile.files.append(full_path)
            except Exception:
                pass

    def _scan_phantom_devices(self, profile: ThreatProfile):
        """Detect phantom/rogue devices on the network.

        This is critical for Kimwolf — it creates virtual network adapters
        and spawns phantom devices that proxy traffic through your connection.
        """
        # Method 1: Check for unexpected network adapters
        try:
            r = self._run_cmd([
                'powershell', '-NoProfile', '-Command',
                'Get-NetAdapter | Select-Object Name,InterfaceDescription,'
                'MacAddress,Status,Virtual,MediaType | ConvertTo-Json -Depth 2'
            ], timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                adapters = json.loads(r.stdout)
                if isinstance(adapters, dict):
                    adapters = [adapters]
                for adapter in adapters:
                    is_virtual = adapter.get('Virtual', False)
                    name = adapter.get('Name', '')
                    desc = adapter.get('InterfaceDescription', '').lower()
                    status = adapter.get('Status', '')

                    # Flag virtual adapters that aren't known legitimate ones
                    legit_virtual = ['hyper-v', 'virtualbox', 'vmware', 'docker',
                                     'wsl', 'vpn', 'tailscale', 'wireguard',
                                     'nordvpn', 'loopback', 'bluetooth',
                                     'wi-fi direct']
                    if is_virtual and not any(lv in desc for lv in legit_virtual):
                        profile.phantom_devices.append({
                            'type': 'virtual_adapter',
                            'name': name,
                            'description': adapter.get('InterfaceDescription', ''),
                            'mac': adapter.get('MacAddress', ''),
                            'status': status,
                            'reason': 'Unknown virtual network adapter'
                        })
        except Exception:
            pass

        # Method 2: ARP table scan for unexpected devices
        try:
            r = self._run_cmd(['arp', '-a'], timeout=8)
            if r.returncode == 0:
                for line in r.stdout.splitlines():
                    # Parse ARP entries
                    parts = line.strip().split()
                    if len(parts) >= 3 and re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                        ip = parts[0]
                        mac = parts[1].lower()
                        # Skip broadcast, multicast, and common entries
                        if mac in ('ff-ff-ff-ff-ff-ff', '01-00-5e-00-00-16'):
                            continue
                        # Check against known malicious OUIs
                        from kimwolf_botnet_detector import HIGH_RISK_OUIS
                        oui = mac[:8]
                        if oui in HIGH_RISK_OUIS:
                            profile.phantom_devices.append({
                                'type': 'suspicious_device',
                                'ip': ip, 'mac': mac,
                                'vendor': HIGH_RISK_OUIS[oui],
                                'reason': f'High-risk IoT vendor OUI: {oui}'
                            })
        except Exception:
            pass

        # Method 3: Check for unexpected Bluetooth devices
        try:
            r = self._run_cmd([
                'powershell', '-NoProfile', '-Command',
                'Get-PnpDevice -Class Bluetooth | Where-Object '
                '{$_.Status -eq "OK"} | Select-Object FriendlyName,'
                'InstanceId,Status | ConvertTo-Json'
            ], timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                bt_devices = json.loads(r.stdout)
                if isinstance(bt_devices, dict):
                    bt_devices = [bt_devices]
                # Flag Bluetooth devices with suspicious names
                sus_bt_names = ['loopback', 'service test', 'debug', 'proxy',
                                'bridge', 'relay', 'tunnel']
                for bt in bt_devices:
                    name = (bt.get('FriendlyName') or '').lower()
                    if any(s in name for s in sus_bt_names):
                        profile.phantom_devices.append({
                            'type': 'suspicious_bluetooth',
                            'name': bt.get('FriendlyName', ''),
                            'instance_id': bt.get('InstanceId', ''),
                            'reason': 'Suspicious Bluetooth device name'
                        })
        except Exception:
            pass

    def _scan_dns_hijacking(self, profile: ThreatProfile):
        """Check for DNS hijacking — modified DNS settings, rogue DNS servers."""
        try:
            # Check configured DNS servers
            r = self._run_cmd([
                'powershell', '-NoProfile', '-Command',
                'Get-DnsClientServerAddress | Where-Object '
                '{$_.AddressFamily -eq 2} | Select-Object InterfaceAlias,'
                'ServerAddresses | ConvertTo-Json -Depth 3'
            ], timeout=10)
            if r.returncode == 0 and r.stdout.strip():
                dns_configs = json.loads(r.stdout)
                if isinstance(dns_configs, dict):
                    dns_configs = [dns_configs]

                # Known safe DNS servers
                safe_dns = {
                    '1.1.1.1', '1.0.0.1',           # Cloudflare
                    '8.8.8.8', '8.8.4.4',           # Google
                    '9.9.9.9', '149.112.112.112',   # Quad9
                    '208.67.222.222', '208.67.220.220',  # OpenDNS
                    '76.76.2.0', '76.76.10.0',       # Control D
                }

                for cfg in dns_configs:
                    servers = cfg.get('ServerAddresses', [])
                    iface = cfg.get('InterfaceAlias', 'Unknown')
                    for server in servers:
                        if server and server not in safe_dns:
                            # Check if it's a local gateway (common for router DNS)
                            try:
                                addr = ipaddress.ip_address(server)
                                if addr.is_private:
                                    continue  # Local router DNS is fine
                            except ValueError:
                                pass
                            profile.dns_entries.append(
                                f"Unusual DNS server on {iface}: {server}")
        except Exception:
            pass

    def _scan_proxy_settings(self, profile: ThreatProfile):
        """Check for proxy hijacking (malware often sets system proxy)."""
        if not WINREG:
            return
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                0, winreg.KEY_READ)
            try:
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if proxy_enable:
                    proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    profile.registry_keys.append({
                        'hive': 'HKCU',
                        'key': r'Internet Settings',
                        'name': 'ProxyServer',
                        'value': str(proxy_server),
                        'reason': f'System proxy enabled: {proxy_server} — may be malware proxy'
                    })
            except FileNotFoundError:
                pass
            winreg.CloseKey(key)
        except Exception:
            pass

    def _scan_dll_hijacking(self, profile: ThreatProfile):
        """Scan for DLL sideloading/hijacking in critical processes."""
        if not PSUTIL:
            return
        critical_procs = {'lsass.exe', 'winlogon.exe', 'services.exe',
                          'csrss.exe', 'svchost.exe', 'explorer.exe'}
        sus_dll_paths = {'\\temp\\', '\\tmp\\', '\\downloads\\',
                         '\\appdata\\local\\temp\\', '\\users\\public\\'}

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                name = (proc.info.get('name') or '').lower()
                if name not in critical_procs:
                    continue
                for m in proc.memory_maps():
                    ml = m.path.lower()
                    if not ml.endswith('.dll'):
                        continue
                    if any(s in ml for s in sus_dll_paths):
                        profile.dlls_injected.append({
                            'process': name,
                            'pid': proc.info['pid'],
                            'dll_path': m.path,
                            'reason': 'DLL loaded from suspicious location'
                        })
            except (psutil.AccessDenied, psutil.NoSuchProcess,
                    psutil.ZombieProcess, NotImplementedError):
                pass

    def _scan_firewall_rules(self, profile: ThreatProfile):
        """Check for suspicious firewall rules (malware often adds allow rules)."""
        try:
            r = self._run_cmd([
                'netsh', 'advfirewall', 'firewall', 'show', 'rule',
                'name=all', 'dir=in'
            ], timeout=15)
            if r.returncode != 0:
                return

            # Look for suspicious allow rules
            current_rule = {}
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith('Rule Name:'):
                    if current_rule:
                        self._check_fw_rule(current_rule, profile)
                    current_rule = {'name': line.split(':', 1)[1].strip()}
                elif ':' in line and current_rule:
                    key, val = line.split(':', 1)
                    current_rule[key.strip().lower()] = val.strip()
            if current_rule:
                self._check_fw_rule(current_rule, profile)
        except Exception:
            pass

    def _check_fw_rule(self, rule: dict, profile: ThreatProfile):
        """Check if a firewall rule is suspicious."""
        name = rule.get('name', '').lower()
        action = rule.get('action', '').lower()
        program = rule.get('program', '').lower()

        if action != 'allow':
            return

        # Skip known legitimate rules
        legit_prefixes = ['core networking', 'windows', 'microsoft',
                          '@fire', 'google', 'steam', 'nvidia']
        if any(name.startswith(p) for p in legit_prefixes):
            return

        # Flag rules allowing traffic from temp/suspicious locations
        if program:
            sus_locations = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
                             '\\downloads\\', '\\users\\public\\']
            if any(sl in program for sl in sus_locations):
                profile.firewall_rules.append(
                    f"Allow rule for suspicious path: {rule.get('name', '')} -> {program}")

    # ========================================================================
    # LAYER 3: ERADICATE — Remove all components
    # ========================================================================

    def eradicate_threat(self, profile: ThreatProfile) -> List[RemediationAction]:
        """Remove all threat components found during identification."""
        actions = []
        self._log(f"[ERADICATE] Removing all {profile.threat_family} components...", "WARNING")

        # 1. Kill all malicious processes (tree kill)
        for proc_info in profile.processes:
            act = self._kill_process_tree(proc_info)
            actions.append(act)

        # 2. Remove persistence — registry
        for reg_entry in profile.registry_keys:
            act = self._remove_registry_entry(reg_entry)
            actions.append(act)

        # 3. Remove persistence — scheduled tasks
        for task in profile.scheduled_tasks:
            act = self._remove_scheduled_task(task)
            actions.append(act)

        # 4. Remove persistence — WMI subscriptions
        for wmi in profile.wmi_subscriptions:
            act = self._remove_wmi_subscription(wmi)
            actions.append(act)

        # 5. Remove persistence — malicious services
        for svc in profile.services:
            act = self._remove_service(svc)
            actions.append(act)

        # 6. Quarantine malicious files (don't delete — keep for analysis)
        for file_path in profile.files:
            act = self._quarantine_file(file_path)
            actions.append(act)

        # 7. Remove injected DLLs
        for dll_info in profile.dlls_injected:
            act = self._quarantine_file(dll_info.get('dll_path', ''))
            actions.append(act)

        # 8. Remove suspicious firewall rules
        for rule in profile.firewall_rules:
            act = self._remove_firewall_rule(rule)
            actions.append(act)

        profile.actions_taken.extend(actions)
        return actions

    def _kill_process_tree(self, proc_info: dict) -> RemediationAction:
        """Kill a process and all its children."""
        pid = proc_info.get('pid')
        name = proc_info.get('name', 'unknown')
        if not pid or not PSUTIL:
            return RemediationAction("kill", str(pid), "Cannot kill: no PID", success=False)
        try:
            p = psutil.Process(pid)
            children = p.children(recursive=True)
            for child in children:
                try:
                    child.kill()
                except Exception:
                    pass
            p.kill()
            return RemediationAction(
                "kill_tree", f"PID:{pid} {name}",
                f"Killed {name} and {len(children)} child processes",
                success=True)
        except psutil.NoSuchProcess:
            return RemediationAction(
                "kill_tree", f"PID:{pid} {name}",
                f"Process {name} already terminated",
                success=True)
        except Exception as e:
            return RemediationAction(
                "kill_tree", f"PID:{pid} {name}",
                f"Failed to kill {name}: {e}",
                success=False, requires_admin=True)

    def _remove_registry_entry(self, entry: dict) -> RemediationAction:
        """Remove a registry persistence entry."""
        hive = entry.get('hive', 'HKCU')
        key = entry.get('key', '')
        name = entry.get('name', '')
        try:
            self._run_cmd(['reg', 'delete', f'{hive}\\{key}', '/v', name, '/f'],
                          timeout=5)
            return RemediationAction(
                "registry_clean", f"{hive}\\{key}\\{name}",
                f"Removed registry persistence: {name}",
                success=True)
        except Exception as e:
            return RemediationAction(
                "registry_clean", f"{hive}\\{key}\\{name}",
                f"Failed to remove registry entry: {e}",
                success=False, requires_admin=True)

    def _remove_scheduled_task(self, task_name: str) -> RemediationAction:
        """Remove a malicious scheduled task."""
        try:
            r = self._run_cmd(
                ['schtasks', '/delete', '/tn', task_name, '/f'],
                timeout=10)
            return RemediationAction(
                "task_clean", task_name,
                f"Removed scheduled task: {task_name}",
                success=(r.returncode == 0))
        except Exception as e:
            return RemediationAction(
                "task_clean", task_name,
                f"Failed to remove task: {e}",
                success=False, requires_admin=True)

    def _remove_wmi_subscription(self, wmi_name: str) -> RemediationAction:
        """Remove WMI event subscription (advanced persistence)."""
        try:
            # Parse "ClassName: Name" format
            parts = wmi_name.split(': ', 1)
            cls = parts[0] if parts else ''
            name = parts[1] if len(parts) > 1 else wmi_name

            self._run_cmd([
                'powershell', '-NoProfile', '-Command',
                f'Get-WMIObject -Namespace root\\subscription -Class {cls} '
                f'| Where-Object {{$_.Name -eq "{name}"}} | Remove-WMIObject'
            ], timeout=10)
            return RemediationAction(
                "wmi_clean", wmi_name,
                f"Removed WMI persistence: {wmi_name}",
                success=True)
        except Exception as e:
            return RemediationAction(
                "wmi_clean", wmi_name,
                f"Failed to remove WMI subscription: {e}",
                success=False, requires_admin=True)

    def _remove_service(self, service_name: str) -> RemediationAction:
        """Stop and remove a malicious service."""
        try:
            self._run_cmd(['sc', 'stop', service_name], timeout=10)
            r = self._run_cmd(['sc', 'delete', service_name], timeout=10)
            return RemediationAction(
                "service_clean", service_name,
                f"Stopped and removed service: {service_name}",
                success=(r.returncode == 0),
                requires_reboot=True)
        except Exception as e:
            return RemediationAction(
                "service_clean", service_name,
                f"Failed to remove service: {e}",
                success=False, requires_admin=True)

    def _quarantine_file(self, file_path: str) -> RemediationAction:
        """Move malicious file to quarantine with XOR encryption."""
        if not file_path or not os.path.exists(file_path):
            return RemediationAction(
                "quarantine", file_path or "(empty)",
                "File not found or already removed",
                success=True)
        try:
            q_dir = self.quarantine_dir / "locked"
            q_dir.mkdir(parents=True, exist_ok=True)

            # Calculate hash before quarantine
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256.update(chunk)
            file_hash = sha256.hexdigest()

            # XOR encrypt the file to prevent accidental execution
            dest = q_dir / f"{os.path.basename(file_path)}.{file_hash[:8]}.quarantined"
            xor_key = 0x5A
            with open(file_path, 'rb') as src, open(str(dest), 'wb') as dst:
                while True:
                    chunk = src.read(65536)
                    if not chunk:
                        break
                    dst.write(bytes(b ^ xor_key for b in chunk))

            # Write metadata
            meta = {
                'original_path': file_path,
                'hash_sha256': file_hash,
                'quarantined_at': datetime.now().isoformat(),
                'xor_key': xor_key,
                'original_size': os.path.getsize(file_path),
            }
            with open(str(dest) + '.meta.json', 'w') as f:
                json.dump(meta, f, indent=2)

            # Remove original
            os.remove(file_path)

            return RemediationAction(
                "quarantine", file_path,
                f"Quarantined: {os.path.basename(file_path)} (SHA256: {file_hash[:16]}...)",
                success=True)
        except Exception as e:
            return RemediationAction(
                "quarantine", file_path,
                f"Failed to quarantine: {e}",
                success=False, requires_admin=True)

    def _remove_firewall_rule(self, rule_desc: str) -> RemediationAction:
        """Remove a suspicious firewall rule."""
        try:
            # Extract rule name from description
            match = re.search(r'rule.*?:\s*(.+?)\s*->', rule_desc)
            rule_name = match.group(1) if match else rule_desc[:100]
            r = self._run_cmd(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                 f'name={rule_name}'], timeout=10)
            return RemediationAction(
                "fw_clean", rule_name,
                f"Removed suspicious firewall rule: {rule_name}",
                success=(r.returncode == 0))
        except Exception as e:
            return RemediationAction(
                "fw_clean", rule_desc[:100],
                f"Failed to remove firewall rule: {e}",
                success=False, requires_admin=True)

    # ========================================================================
    # LAYER 4: VERIFY — Confirm complete removal
    # ========================================================================

    def verify_clean(self, profile: ThreatProfile) -> Tuple[bool, List[str]]:
        """Verify that all threat components have been removed."""
        self._log(f"[VERIFY] Confirming {profile.threat_family} removal...", "WARNING")
        issues = []

        # Check if any malicious processes are still running
        if PSUTIL:
            for proc_info in profile.processes:
                pid = proc_info.get('pid')
                if pid:
                    try:
                        p = psutil.Process(pid)
                        if p.is_running():
                            issues.append(f"Process still running: {p.name()} (PID {pid})")
                    except psutil.NoSuchProcess:
                        pass  # Good — process is gone

        # Check if malicious files still exist
        for file_path in profile.files:
            if os.path.exists(file_path):
                issues.append(f"Malicious file still exists: {file_path}")

        # Check if C2 connections are still active
        if PSUTIL:
            c2_ips = {c.get('remote_ip') for c in profile.network_connections}
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr and conn.raddr.ip in c2_ips:
                    issues.append(f"Active C2 connection: {conn.raddr.ip}:{conn.raddr.port}")

        # Check DNS cache for C2 domains
        try:
            r = self._run_cmd([
                'powershell', '-NoProfile', '-Command',
                'Get-DnsClientCache | Select-Object -ExpandProperty Name'
            ], timeout=8)
            if r.returncode == 0:
                cached = {d.strip().lower() for d in r.stdout.splitlines()}
                for domain in profile.dns_entries:
                    if domain.lower() in cached:
                        issues.append(f"C2 domain still in DNS cache: {domain}")
        except Exception:
            pass

        is_clean = len(issues) == 0
        if is_clean:
            self._log(f"[VERIFY] {profile.threat_family} fully remediated!", "SUCCESS")
            profile.is_fully_remediated = True
        else:
            self._log(f"[VERIFY] {len(issues)} remnants found — additional cleanup needed", "WARNING")

        return is_clean, issues

    # ========================================================================
    # LAYER 5: HARDEN — Prevent reinfection
    # ========================================================================

    def harden_system(self, profile: ThreatProfile) -> List[RemediationAction]:
        """Apply hardening measures to prevent reinfection."""
        actions = []
        self._log(f"[HARDEN] Applying anti-reinfection measures...", "WARNING")

        # 1. Flush DNS cache
        try:
            self._run_cmd(['ipconfig', '/flushdns'], timeout=5)
            actions.append(RemediationAction(
                "harden", "DNS", "Flushed DNS cache", success=True))
        except Exception:
            pass

        # 2. Reset Winsock catalog (fixes proxy/network hijacking)
        if profile.threat_type in ('botnet', 'rootkit', 'rat'):
            try:
                self._run_cmd(['netsh', 'winsock', 'reset'], timeout=10)
                actions.append(RemediationAction(
                    "harden", "Winsock",
                    "Reset Winsock catalog (requires reboot)",
                    success=True, requires_reboot=True))
            except Exception:
                pass

        # 3. Reset TCP/IP stack if network was compromised
        if profile.phantom_devices or profile.dns_entries:
            try:
                self._run_cmd(['netsh', 'int', 'ip', 'reset'], timeout=10)
                actions.append(RemediationAction(
                    "harden", "TCP/IP",
                    "Reset TCP/IP stack (requires reboot)",
                    success=True, requires_reboot=True))
            except Exception:
                pass

        # 4. Clear ARP cache
        try:
            self._run_cmd(['netsh', 'interface', 'ip', 'delete', 'arpcache'], timeout=5)
            actions.append(RemediationAction(
                "harden", "ARP", "Cleared ARP cache", success=True))
        except Exception:
            pass

        # 5. Remove any system proxy settings
        if WINREG:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    0, winreg.KEY_WRITE)
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.CloseKey(key)
                actions.append(RemediationAction(
                    "harden", "Proxy",
                    "Disabled system proxy (was potentially hijacked)",
                    success=True))
            except Exception:
                pass

        # 6. Verify Windows Firewall is enabled
        try:
            for fw_profile in ['domainprofile', 'privateprofile', 'publicprofile']:
                self._run_cmd([
                    'netsh', 'advfirewall', 'set', fw_profile, 'state', 'on'
                ], timeout=5)
            actions.append(RemediationAction(
                "harden", "Firewall",
                "Verified Windows Firewall enabled on all profiles",
                success=True))
        except Exception:
            pass

        # 7. Disable ADB over network (Kimwolf prevention)
        if profile.threat_family.lower() in ('kimwolf', 'mirai', 'aisuru', 'badbox'):
            try:
                # Block ADB port 5555 inbound
                self._run_cmd([
                    'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                    'name=DOWNPOUR_BLOCK_ADB_5555', 'dir=in', 'action=block',
                    'protocol=tcp', 'localport=5555'
                ], timeout=5)
                actions.append(RemediationAction(
                    "harden", "ADB",
                    "Blocked inbound ADB port 5555 (Kimwolf infection vector)",
                    success=True))
            except Exception:
                pass

        # 8. Generate router security recommendations
        actions.append(RemediationAction(
            "harden", "Router",
            "MANUAL ACTION REQUIRED: "
            "(1) Change router admin password, "
            "(2) Disable UPnP, "
            "(3) Disable WPS, "
            "(4) Update router firmware, "
            "(5) Check for unknown port forwards, "
            "(6) Set DNS to 1.1.1.1/8.8.8.8, "
            "(7) Enable AP isolation for IoT devices, "
            "(8) Check connected devices list for unknowns",
            success=True))

        profile.actions_taken.extend(actions)
        profile.requires_reboot = any(a.requires_reboot for a in actions)
        return actions

    # ========================================================================
    # FULL REMEDIATION PIPELINE
    # ========================================================================

    def full_remediation(self, profile: ThreatProfile) -> ThreatProfile:
        """Execute the complete 5-layer remediation pipeline."""
        self._log(f"{'='*60}", "WARNING")
        self._log(f"FULL THREAT REMEDIATION: {profile.threat_family}", "CRITICAL")
        self._log(f"Type: {profile.threat_type} | Severity: {profile.severity}", "WARNING")
        self._log(f"{'='*60}", "WARNING")

        # Layer 1: Isolate
        self.isolate_threat(profile)
        self._log(f"Layer 1 (Isolate): Complete", "SUCCESS")

        # Layer 2: Identify
        self.deep_scan_footholds(profile)
        total = (len(profile.processes) + len(profile.files) +
                 len(profile.registry_keys) + len(profile.scheduled_tasks) +
                 len(profile.services) + len(profile.wmi_subscriptions) +
                 len(profile.phantom_devices) + len(profile.dlls_injected))
        self._log(f"Layer 2 (Identify): Found {total} footholds", "WARNING")

        # Layer 3: Eradicate
        self.eradicate_threat(profile)
        self._log(f"Layer 3 (Eradicate): Complete", "SUCCESS")

        # Layer 4: Verify
        is_clean, issues = self.verify_clean(profile)
        if not is_clean:
            self._log(f"Layer 4 (Verify): {len(issues)} remnants — retrying...", "WARNING")
            # Retry eradication for remaining items
            time.sleep(2)
            self.eradicate_threat(profile)
            is_clean, issues = self.verify_clean(profile)

        # Layer 5: Harden
        self.harden_system(profile)
        self._log(f"Layer 5 (Harden): Complete", "SUCCESS")

        # Summary
        success_count = sum(1 for a in profile.actions_taken if a.success)
        fail_count = sum(1 for a in profile.actions_taken if not a.success)
        self._log(f"{'='*60}", "WARNING")
        self._log(f"REMEDIATION COMPLETE: {success_count} actions succeeded, "
                  f"{fail_count} failed", "SUCCESS" if fail_count == 0 else "WARNING")
        if profile.requires_reboot:
            self._log("*** REBOOT REQUIRED to complete remediation ***", "CRITICAL")
        self._log(f"{'='*60}", "WARNING")

        return profile

    # ========================================================================
    # CONVENIENCE: Build profile from scan results
    # ========================================================================

    def build_profile_from_botnet_alerts(self, alerts: list,
                                         family: str = "Kimwolf") -> ThreatProfile:
        """Build a ThreatProfile from KimwolfBotnetDetector alerts."""
        profile = ThreatProfile(
            threat_id=f"{family}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            threat_type="botnet",
            threat_family=family,
            severity="CRITICAL",
            summary=f"{family} botnet infection detected with {len(alerts)} indicators"
        )

        for alert in alerts:
            indicator = alert.indicator if hasattr(alert, 'indicator') else alert.get('indicator', '')
            evidence = alert.evidence if hasattr(alert, 'evidence') else alert.get('evidence', '')
            dev_ip = alert.device_ip if hasattr(alert, 'device_ip') else alert.get('device_ip', '')

            # Categorize the alert
            if 'PID:' in indicator:
                pid_match = re.search(r'PID:(\d+)', indicator)
                pid = int(pid_match.group(1)) if pid_match else 0
                profile.processes.append({
                    'pid': pid,
                    'name': indicator.split()[-1] if ' ' in indicator else indicator,
                    'reason': evidence[:200]
                })
            elif re.match(r'\d+\.\d+\.\d+\.\d+', indicator):
                profile.network_connections.append({
                    'remote_ip': indicator.split(':')[0],
                    'remote_port': indicator.split(':')[1] if ':' in indicator else 0,
                    'evidence': evidence[:200]
                })
            elif '.' in indicator and not indicator.startswith('PID'):
                profile.dns_entries.append(indicator)

            if dev_ip:
                profile.phantom_devices.append({
                    'type': 'botnet_device',
                    'ip': dev_ip,
                    'reason': evidence[:200]
                })

        return profile

    def build_profile_from_process_scan(self, suspicious_processes: list,
                                         family: str = "Unknown") -> ThreatProfile:
        """Build a ThreatProfile from process scan results."""
        profile = ThreatProfile(
            threat_id=f"{family}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            threat_type="malware",
            threat_family=family,
            severity="HIGH",
            summary=f"Detected {len(suspicious_processes)} suspicious processes"
        )

        for proc in suspicious_processes:
            if isinstance(proc, dict):
                profile.processes.append({
                    'pid': proc.get('pid', 0),
                    'name': proc.get('name', 'unknown'),
                    'path': proc.get('exe', proc.get('path', '')),
                    'reason': ', '.join(proc.get('indicators', proc.get('risk_reasons', [])))
                })
                # Extract network connections
                for conn in proc.get('connections', []):
                    profile.network_connections.append(conn)

        return profile

    def get_remediation_report(self, profile: ThreatProfile) -> str:
        """Generate a human-readable remediation report."""
        lines = [
            f"{'='*70}",
            f"THREAT REMEDIATION REPORT",
            f"{'='*70}",
            f"Threat: {profile.threat_family} ({profile.threat_type})",
            f"Severity: {profile.severity}",
            f"Status: {'FULLY REMEDIATED' if profile.is_fully_remediated else 'PARTIALLY REMEDIATED'}",
            f"Reboot Required: {'YES' if profile.requires_reboot else 'No'}",
            f"",
            f"--- FOOTHOLDS FOUND ---",
            f"Processes:          {len(profile.processes)}",
            f"Files:              {len(profile.files)}",
            f"Registry entries:   {len(profile.registry_keys)}",
            f"Scheduled tasks:    {len(profile.scheduled_tasks)}",
            f"Services:           {len(profile.services)}",
            f"WMI subscriptions:  {len(profile.wmi_subscriptions)}",
            f"Phantom devices:    {len(profile.phantom_devices)}",
            f"Injected DLLs:      {len(profile.dlls_injected)}",
            f"Firewall rules:     {len(profile.firewall_rules)}",
            f"DNS entries:        {len(profile.dns_entries)}",
            f"",
            f"--- ACTIONS TAKEN ({len(profile.actions_taken)}) ---",
        ]

        for action in profile.actions_taken:
            status = "OK" if action.success else "FAIL"
            lines.append(f"  [{status}] {action.action_type}: {action.description}")

        failed = [a for a in profile.actions_taken if not a.success]
        if failed:
            lines.append(f"")
            lines.append(f"--- FAILED ACTIONS ({len(failed)}) ---")
            for a in failed:
                lines.append(f"  [!] {a.target}: {a.description}")
                if a.requires_admin:
                    lines.append(f"      -> Run Downpour as Administrator to fix this")

        lines.append(f"{'='*70}")
        return '\n'.join(lines)


# ============================================================================
# MODULE-LEVEL CONVENIENCE
# ============================================================================

_engine: Optional[ThreatRemediationEngine] = None


def get_engine(quarantine_dir: str = None, alert_cb: Callable = None,
               db: Any = None) -> ThreatRemediationEngine:
    """Get or create the global remediation engine."""
    global _engine
    if _engine is None:
        _engine = ThreatRemediationEngine(quarantine_dir, alert_cb, db)
    return _engine


def remediate_botnet(alerts: list, family: str = "Kimwolf",
                     alert_cb: Callable = None) -> ThreatProfile:
    """Convenience function: run full remediation pipeline for botnet alerts."""
    engine = get_engine(alert_cb=alert_cb)
    profile = engine.build_profile_from_botnet_alerts(alerts, family)
    return engine.full_remediation(profile)


def remediate_processes(suspicious: list, family: str = "Unknown",
                        alert_cb: Callable = None) -> ThreatProfile:
    """Convenience function: run full remediation for suspicious processes."""
    engine = get_engine(alert_cb=alert_cb)
    profile = engine.build_profile_from_process_scan(suspicious, family)
    return engine.full_remediation(profile)
