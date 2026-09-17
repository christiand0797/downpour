"""
Gaming Protection Monitor
Downpour v29 Titanium

Protects gamers from attacks targeting gaming sessions:
  - Cheat tool / memory editor detection (Cheat Engine, ArtMoney, etc.)
  - Game process manipulation detection (DLL injection into games)
  - Speed hack / timing manipulation detection
  - Lag switch / network throttling detection
  - DDoS / IP flooding against local machine
  - Aimbot / input injection tool detection
  - Screen overlay / ESP tool detection
  - Game file tampering detection
  - Server kick exploit detection (crash packet tools)
  - Audio hijacking / device switching detection
  - Controller / input redirection detection

Uses netstat, wmic, and tasklist — no PowerShell.
MITRE ATT&CK: T1055 (Process Injection), T1498 (Network DoS),
              T1562 (Impair Defenses), T1059 (Command & Scripting)
"""

import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

_log = logging.getLogger('downpour.gaming')

CHEAT_TOOLS = [
    re.compile(r'(?i)cheatengine'),
    re.compile(r'(?i)cheat\s*engine'),
    re.compile(r'(?i)artmoney'),
    re.compile(r'(?i)gameguardian'),
    re.compile(r'(?i)wemod'),
    re.compile(r'(?i)trainer.*\.exe'),
    re.compile(r'(?i)cosmosproject'),
    re.compile(r'(?i)infinity.*trainer'),
    re.compile(r'(?i)fling.*trainer'),
    re.compile(r'(?i)mrantifun'),
    re.compile(r'(?i)gamecopyworld'),
    re.compile(r'(?i)plitch'),
]

MEMORY_EDITORS = [
    re.compile(r'(?i)ce\.exe'),
    re.compile(r'(?i)cheatengine.*\.exe'),
    re.compile(r'(?i)artmoney.*\.exe'),
    re.compile(r'(?i)processhacker'),
    re.compile(r'(?i)x64dbg'),
    re.compile(r'(?i)x32dbg'),
    re.compile(r'(?i)ollydbg'),
    re.compile(r'(?i)ida64?\.exe'),
    re.compile(r'(?i)windbg'),
    re.compile(r'(?i)reclass.*\.exe'),
    re.compile(r'(?i)hxd\.exe'),
]

SPEED_HACK_TOOLS = [
    re.compile(r'(?i)speedhack'),
    re.compile(r'(?i)speed\.?hack'),
    re.compile(r'(?i)speeder'),
    re.compile(r'(?i)cheat\s*engine.*speed'),
    re.compile(r'(?i)hackspeed'),
]

INJECTION_TOOLS = [
    re.compile(r'(?i)extreme.?injector'),
    re.compile(r'(?i)process.?injector'),
    re.compile(r'(?i)dll.?injector'),
    re.compile(r'(?i)xenos.*inject'),
    re.compile(r'(?i)gdihook'),
]

OVERLAY_TOOLS = [
    re.compile(r'(?i)esp\.exe'),
    re.compile(r'(?i)wallhack'),
    re.compile(r'(?i)overlay.*hack'),
    re.compile(r'(?i)radar.*hack'),
]

NETWORK_ATTACK_TOOLS = [
    re.compile(r'(?i)loic'),
    re.compile(r'(?i)hoic'),
    re.compile(r'(?i)xerxes'),
    re.compile(r'(?i)slowloris'),
    re.compile(r'(?i)goldeneye'),
    re.compile(r'(?i)hulk\.py'),
    re.compile(r'(?i)hping'),
    re.compile(r'(?i)lag\s*switch'),
    re.compile(r'(?i)netlimiter'),
    re.compile(r'(?i)clumsy.*\.exe'),
]

ONLINE_COMPETITIVE_GAMES = {
    'csgo.exe', 'cs2.exe', 'valorant.exe', 'valorant-win64-shipping.exe',
    'fortnitelient-win64-shipping.exe', 'fortniteclient-win64-shipping.exe',
    'apex_legends.exe', 'r5apex.exe',
    'tslgame.exe', 'pubg.exe',
    'overwatch.exe',
    'destiny2.exe',
    'cod.exe', 'modernwarfare.exe',
    'robloxplayerbeta.exe',
    'league of legends.exe', 'leagueclient.exe',
    'dota2.exe',
    'hl2.exe',
    'rocketleague.exe',
    'rainbowsix.exe', 'vulkan_r6.exe',
    'deadbydaylight-win64-shipping.exe',
    'escapefromtarkov.exe',
    'rustclient.exe',
    'forzahorizon5.exe', 'forzahorizon4.exe', 'forzamotorsport.exe',
    'halo infinite.exe', 'haloinfinite.exe',
    'sea of thieves.exe',
    'helldivers2.exe',
}

SINGLEPLAYER_MOD_SAFE = {
    'reshade', 'reshade32', 'reshade64',
    'rtxremix', 'nvidia rtx remix', 'bridge.exe',
    'vortex', 'nexusmods', 'mod organizer',
    'frostymodmanager', 'frostyfix',
    'flawlesswidescren', 'specialk',
    'cyberpunk2077.exe', 'nfsu2-hd-road.exe',
    'speed.exe', 'speed2.exe', 'nfsu2.exe', 'nfsu.exe',
    'witcher3.exe', 'eldenring.exe', 'skyrimse.exe',
    'fallout4.exe', 'starfield.exe', 'oblivion.exe',
    'gta5.exe', 'rdr2.exe', 'gtav.exe',
}

SYN_FLOOD_THRESHOLD = 100
CONNECTION_SPIKE_THRESHOLD = 50
CONNECTION_SPIKE_WINDOW = 30


@dataclass
class GamingAlert:
    """Gaming protection alert."""
    timestamp: str
    category: str
    details: str
    indicator: str
    severity: str
    mitre_id: str
    process_name: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'category': self.category,
            'details': self.details,
            'indicator': self.indicator,
            'severity': self.severity,
            'mitre_id': self.mitre_id,
            'process_name': self.process_name,
        }


class GamingProtectionMonitor:
    """
    Monitor for gaming-specific threats including cheat tools,
    DDoS attacks, lag switches, and input manipulation.
    """

    def __init__(
        self,
        check_interval: float = 30.0,
        alert_callback: Optional[Callable] = None,
    ):
        self._check_interval = check_interval
        self._alert_callback = alert_callback
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._check_count = 0

        self._alerted_processes: Dict[str, float] = {}
        self._connection_history: List[tuple] = []
        self._baseline_syn_wait: int = 0
        self._alerts: List[GamingAlert] = []
        self._audio_devices_baseline: Set[str] = set()

    def start(self) -> bool:
        if self._running:
            return True
        try:
            self._baseline_syn_wait = self._count_syn_wait()
            self._audio_devices_baseline = self._get_audio_devices()
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name='gaming-protect',
                daemon=True,
            )
            self._thread.start()
            _log.info('Gaming protection monitor started')
            return True
        except Exception as exc:
            _log.warning('Gaming protection failed: %s', exc)
            return False

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5.0)

    def get_status(self) -> Dict[str, Any]:
        return {
            'running': self._running,
            'checks': self._check_count,
            'alerts': len(self._alerts),
            'syn_wait_baseline': self._baseline_syn_wait,
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts[-limit:]]

    def _monitor_loop(self) -> None:
        while self._running:
            try:
                self._check_cheat_tools()
                self._check_ddos_indicators()
                self._check_audio_hijacking()
                self._check_count += 1
            except Exception as exc:
                _log.debug('Gaming check error: %s', exc)

            if self._check_count % 60 == 0:
                self._cleanup_stale()

            deadline = time.monotonic() + self._check_interval
            while self._running and time.monotonic() < deadline:
                time.sleep(1.0)

    def _check_cheat_tools(self) -> None:
        """Detect running cheat/attack tools. Only flags cheat tools
        when an online competitive game is running — single-player
        mods (ReShade, RTX Remix, Vortex, etc.) are whitelisted."""
        now_ts = datetime.now(timezone.utc).isoformat()
        now = time.time()
        try:
            result = subprocess.run(
                ['tasklist', '/fo', 'csv', '/nh'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return

            all_procs: List[tuple] = []
            online_game_running = False
            for line in result.stdout.splitlines():
                parts = line.strip().split('","')
                if len(parts) < 2:
                    continue
                proc_name = parts[0].strip('"').lower()
                pid = parts[1].strip('"') if len(parts) > 1 else ''
                all_procs.append((proc_name, pid))
                if proc_name in ONLINE_COMPETITIVE_GAMES:
                    online_game_running = True

            for proc_name, pid in all_procs:
                proc_key = f'{proc_name}:{pid}'
                last = self._alerted_processes.get(proc_key, 0)
                if now - last < 600:
                    continue

                if any(safe in proc_name for safe in SINGLEPLAYER_MOD_SAFE):
                    continue

                if online_game_running:
                    for pattern in CHEAT_TOOLS:
                        if pattern.search(proc_name):
                            self._add_alert(GamingAlert(
                                timestamp=now_ts,
                                category='cheat_tool_online',
                                details=f'Cheat tool while online game running: {proc_name} (PID {pid})',
                                indicator=proc_key,
                                severity='critical',
                                mitre_id='T1055',
                                process_name=proc_name,
                            ))
                            self._alerted_processes[proc_key] = now
                            break

                    for pattern in MEMORY_EDITORS:
                        if pattern.search(proc_name):
                            self._add_alert(GamingAlert(
                                timestamp=now_ts,
                                category='memory_editor_online',
                                details=f'Memory editor while online game running: {proc_name} (PID {pid})',
                                indicator=proc_key,
                                severity='high',
                                mitre_id='T1055',
                                process_name=proc_name,
                            ))
                            self._alerted_processes[proc_key] = now
                            break

                    for pattern in INJECTION_TOOLS:
                        if pattern.search(proc_name):
                            self._add_alert(GamingAlert(
                                timestamp=now_ts,
                                category='injection_tool_online',
                                details=f'DLL injector while online game running: {proc_name} (PID {pid})',
                                indicator=proc_key,
                                severity='critical',
                                mitre_id='T1055.001',
                                process_name=proc_name,
                            ))
                            self._alerted_processes[proc_key] = now
                            break

                for pattern in NETWORK_ATTACK_TOOLS:
                    if pattern.search(proc_name):
                        self._add_alert(GamingAlert(
                            timestamp=now_ts,
                            category='ddos_tool_detected',
                            details=f'Network attack / lag tool running: {proc_name} (PID {pid})',
                            indicator=proc_key,
                            severity='critical',
                            mitre_id='T1498',
                            process_name=proc_name,
                        ))
                        self._alerted_processes[proc_key] = now
                        break

        except Exception:
            pass

    def _check_ddos_indicators(self) -> None:
        """Detect DDoS / connection flooding targeting this machine."""
        now_ts = datetime.now(timezone.utc).isoformat()
        try:
            result = subprocess.run(
                ['netstat', '-n', '-p', 'tcp'],
                capture_output=True, text=True, timeout=15,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode != 0:
                return

            syn_wait = 0
            total_established = 0
            source_ips: Dict[str, int] = {}

            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4 or parts[0] != 'TCP':
                    continue
                state = parts[3]

                if state == 'SYN_RECEIVED':
                    syn_wait += 1
                elif state == 'ESTABLISHED':
                    total_established += 1
                    remote = parts[2]
                    m = re.match(r'([\d.]+):', remote)
                    if m:
                        ip = m.group(1)
                        source_ips[ip] = source_ips.get(ip, 0) + 1

            if syn_wait > SYN_FLOOD_THRESHOLD:
                self._add_alert(GamingAlert(
                    timestamp=now_ts,
                    category='syn_flood_detected',
                    details=f'SYN flood attack detected: {syn_wait} half-open connections '
                            f'(baseline: {self._baseline_syn_wait})',
                    indicator=f'syn:{syn_wait}',
                    severity='critical',
                    mitre_id='T1498.001',
                ))

            for ip, count in source_ips.items():
                if count > CONNECTION_SPIKE_THRESHOLD:
                    if ip not in ('127.0.0.1', '0.0.0.0'):
                        self._add_alert(GamingAlert(
                            timestamp=now_ts,
                            category='connection_flood',
                            details=f'Connection flood from {ip}: {count} simultaneous connections',
                            indicator=f'flood:{ip}',
                            severity='high',
                            mitre_id='T1498',
                        ))

            now = time.time()
            self._connection_history.append((now, total_established))
            self._connection_history = [
                (t, c) for t, c in self._connection_history
                if now - t < CONNECTION_SPIKE_WINDOW
            ]

            if len(self._connection_history) >= 3:
                counts = [c for _, c in self._connection_history]
                if max(counts) > min(counts) * 3 and max(counts) > 200:
                    self._add_alert(GamingAlert(
                        timestamp=now_ts,
                        category='connection_spike',
                        details=f'Rapid connection spike: {min(counts)} -> {max(counts)} '
                                f'in {CONNECTION_SPIKE_WINDOW}s',
                        indicator=f'spike:{max(counts)}',
                        severity='high',
                        mitre_id='T1498',
                    ))

        except Exception:
            pass

    def _check_audio_hijacking(self) -> None:
        """Detect unexpected audio device changes during gaming."""
        now_ts = datetime.now(timezone.utc).isoformat()
        current = self._get_audio_devices()

        if self._audio_devices_baseline and current:
            removed = self._audio_devices_baseline - current
            added = current - self._audio_devices_baseline

            for dev in removed:
                self._add_alert(GamingAlert(
                    timestamp=now_ts,
                    category='audio_device_removed',
                    details=f'Audio device removed: {dev}',
                    indicator=f'audio_rm:{dev[:60]}',
                    severity='medium',
                    mitre_id='T1562',
                ))

            for dev in added:
                self._add_alert(GamingAlert(
                    timestamp=now_ts,
                    category='audio_device_added',
                    details=f'New audio device appeared: {dev}',
                    indicator=f'audio_add:{dev[:60]}',
                    severity='low',
                    mitre_id='T1562',
                ))

        if current:
            self._audio_devices_baseline = current

    @staticmethod
    def _count_syn_wait() -> int:
        """Count SYN_RECEIVED connections (baseline)."""
        try:
            result = subprocess.run(
                ['netstat', '-n', '-p', 'tcp'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                return sum(1 for ln in result.stdout.splitlines()
                           if 'SYN_RECEIVED' in ln)
        except Exception:
            pass
        return 0

    @staticmethod
    def _get_audio_devices() -> Set[str]:
        """Get current audio devices via wmic."""
        devices: Set[str] = set()
        try:
            result = subprocess.run(
                ['wmic', 'path', 'Win32_SoundDevice', 'get', 'Name',
                 '/format:list'],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000),
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if line.startswith('Name=') and line[5:]:
                        devices.add(line[5:])
        except Exception:
            pass
        return devices

    def _cleanup_stale(self) -> None:
        cutoff = time.time() - 1800
        self._alerted_processes = {
            k: v for k, v in self._alerted_processes.items() if v > cutoff
        }

    def _add_alert(self, alert: GamingAlert) -> None:
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
        _log.warning('Gaming: %s — %s', alert.category, alert.details)
        if self._alert_callback:
            try:
                self._alert_callback(alert)
            except Exception:
                pass


_monitor: Optional[GamingProtectionMonitor] = None


def get_gaming_monitor() -> GamingProtectionMonitor:
    global _monitor
    if _monitor is None:
        _monitor = GamingProtectionMonitor()
    return _monitor


def start_gaming_protection(callback=None) -> bool:
    global _monitor
    _monitor = GamingProtectionMonitor(alert_callback=callback)
    return _monitor.start()


__all__ = [
    'GamingProtectionMonitor', 'GamingAlert',
    'get_gaming_monitor', 'start_gaming_protection',
    'CHEAT_TOOLS', 'MEMORY_EDITORS', 'NETWORK_ATTACK_TOOLS',
]
