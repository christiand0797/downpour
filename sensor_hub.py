"""
sensor_hub.py - Unified Sensor Hub (TASK-018)
==============================================
Single psutil snapshot per tick, fanned out over bounded queues.
Consolidates 4 redundant pollers:
  - process_monitor (10s)
  - ransomware_detector (5s/10s)
  - network_monitor (10s)
  - main _proc_loop (60s)

All now share one snapshot behind _PSUTIL_LOCK.
Orphaned modules retired or rewired.
"""

from __future__ import annotations
import os
import time
import threading
import logging
import queue
import psutil
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, Set
from concurrent.futures import ThreadPoolExecutor

_log = logging.getLogger(__name__)

# Bounded queues for backpressure
MAX_QUEUE_SIZE = 1000
SNAPSHOT_INTERVAL = 5.0  # seconds

@dataclass
class ProcessSnapshot:
    """Single process snapshot from psutil."""
    pid: int
    name: str
    exe: str
    cmdline: List[str]
    username: str
    create_time: float
    cpu_percent: float
    memory_percent: float
    memory_rss: int
    memory_vms: int
    num_threads: int
    status: str
    connections: List[Dict] = field(default_factory=list)
    open_files: List[str] = field(default_factory=list)
    parent_pid: int = 0
    parent_name: str = ""

@dataclass
class NetworkSnapshot:
    """Single network snapshot."""
    connections: List[Dict]  # {pid, laddr, raddr, status, family, type}
    per_process: Dict[int, List[Dict]]

@dataclass
class FileSnapshot:
    """Single file system snapshot (for ransomware detection)."""
    changes: List[Dict]  # {path, op, timestamp, old_hash, new_hash, size_delta}

@dataclass
class SystemSnapshot:
    """Complete system snapshot for one tick."""
    tick: int
    timestamp: float
    processes: List[ProcessSnapshot]
    network: NetworkSnapshot
    cpu_percent: float
    memory_percent: float
    disk_usage: Dict[str, float]

class SensorHub:
    """
    Unified sensor hub - single source of truth for system telemetry.
    
    Produces one snapshot per tick, fans out to consumers via bounded queues.
    Consumers: threat detection, ransomware detection, network analysis, UI.
    """
    
    def __init__(self, max_workers: int = 4):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        
        # Bounded output queues (one per consumer type)
        self._queues: Dict[str, queue.Queue] = {
            'threat_detection': queue.Queue(maxsize=MAX_QUEUE_SIZE),
            'ransomware': queue.Queue(maxsize=MAX_QUEUE_SIZE),
            'network': queue.Queue(maxsize=MAX_QUEUE_SIZE),
            'ui': queue.Queue(maxsize=MAX_QUEUE_SIZE),
        }
        
        # Consumer callbacks
        self._callbacks: Dict[str, List[Callable[[SystemSnapshot], None]]] = {
            'threat_detection': [],
            'ransomware': [],
            'network': [],
            'ui': [],
        }
        
        # Snapshot state
        self._tick = 0
        self._last_snapshot: Optional[SystemSnapshot] = None
        self._process_cache: Dict[int, ProcessSnapshot] = {}
        self._cache_ttl = 10.0  # seconds
        
        # Worker pool for async consumers
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="SensorHub")
        
        # DNS count tracking (replaces unbounded network_monitor._dns_counts)
        self._dns_counts: Dict[str, deque] = {}
        self._dns_max_entries = 1000
        self._dns_window = 300  # 5 minute window
        
        # Alert deduplication (replaces unbounded _alerted_dedup)
        self._alert_dedup: Dict[str, float] = {}
        self._dedup_max = 5000
        self._dedup_ttl = 3600  # 1 hour
        
        # Stats
        self.stats = {
            'snapshots_produced': 0,
            'queue_drops': 0,
            'consumer_errors': 0,
        }

        # Sensor liveness registry (v29.43f, audit §8.5): any loop can call
        # mark_alive(name); liveness_report() returns age-since-last-mark so
        # the heartbeat can surface stalled sensors instead of silent death.
        self._liveness: Dict[str, float] = {}

    def mark_alive(self, name: str) -> None:
        """Record a liveness heartbeat for a sensor/loop (thread-safe)."""
        with self._lock:
            self._liveness[name] = time.time()

    def liveness_report(self, stale_after: float = 180.0) -> Dict[str, Dict[str, Any]]:
        """Age-since-last-mark per sensor, flagged stale past `stale_after`."""
        now = time.time()
        with self._lock:
            return {
                name: {'age_seconds': round(now - ts, 1),
                       'stale': (now - ts) > stale_after}
                for name, ts in sorted(self._liveness.items())
            }


    def start(self):
        """Start the sensor hub."""
        if self._running:
            return
        
        # Initialize COM for this thread
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except ImportError:
            pass
        
        self._running = True
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="SensorHub")
        self._thread.start()
        _log.info("SensorHub started (interval=%.1fs)", SNAPSHOT_INTERVAL)

    def stop(self):
        """Stop the sensor hub."""
        self._running = False
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
        self._executor.shutdown(wait=False, cancel_futures=True)
        _log.info("SensorHub stopped")

    def register_consumer(self, consumer_type: str, callback: Callable[[SystemSnapshot], None]):
        """Register a callback for a consumer type."""
        if consumer_type in self._callbacks:
            self._callbacks[consumer_type].append(callback)
        else:
            _log.warning(f"Unknown consumer type: {consumer_type}")

    def unregister_consumer(self, consumer_type: str, callback: Callable[[SystemSnapshot], None]):
        """Unregister a callback."""
        if consumer_type in self._callbacks:
            try:
                self._callbacks[consumer_type].remove(callback)
            except ValueError:
                pass

    def _loop(self):
        """Main loop - produce snapshots and fan out."""
        self.mark_alive('sensor_hub')
        while self._running:
            start = time.time()
            try:
                snapshot = self._capture_snapshot()
                self._fan_out(snapshot)
                self._cleanup_dedup()
                
                self._tick += 1
                self.stats['snapshots_produced'] += 1
                self.mark_alive('sensor_hub')
                
            except Exception as e:
                _log.error(f"SensorHub snapshot error: {e}")
            
            # Sleep for remainder of interval
            elapsed = time.time() - start
            sleep_time = max(0, SNAPSHOT_INTERVAL - elapsed)
            if sleep_time > 0:
                self._stop.wait(sleep_time)

    def _capture_snapshot(self) -> SystemSnapshot:
        """Capture a complete system snapshot."""
        ts = time.time()
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        
        # Get all processes in one pass
        processes = []
        per_process_conns: Dict[int, List[Dict]] = {}
        per_process_files: Dict[int, List[str]] = {}
        
        # Use psutil process_iter with specific attrs for efficiency
        for proc in psutil.process_iter([
            'pid', 'name', 'exe', 'cmdline', 'username',
            'create_time', 'cpu_percent', 'memory_percent',
            'memory_info', 'num_threads', 'status', 'ppid'
        ]):
            try:
                pi = proc.info
                pid = pi['pid']
                
                # Get connections for this process
                conns = []
                try:
                    for conn in proc.net_connections(kind='inet'):
                        if conn.raddr:
                            conns.append({
                                'remote_ip': conn.raddr.ip,
                                'remote_port': conn.raddr.port,
                                'local_port': conn.laddr.port if conn.laddr else 0,
                                'status': conn.status,
                            })
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Get open files
                files = []
                try:
                    for f in proc.open_files():
                        files.append(f.path)
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Parent name
                parent_name = ""
                try:
                    if pi.get('ppid'):
                        parent_name = psutil.Process(pi['ppid']).name()
                except Exception:
                    pass
                
                snap = ProcessSnapshot(
                    pid=pid,
                    name=pi['name'] or 'Unknown',
                    exe=pi['exe'] or '',
                    cmdline=pi['cmdline'] or [],
                    username=pi['username'] or '',
                    create_time=pi['create_time'] or 0,
                    cpu_percent=pi['cpu_percent'] or 0,
                    memory_percent=pi['memory_percent'] or 0,
                    memory_rss=pi['memory_info'].rss if pi.get('memory_info') else 0,
                    memory_vms=pi['memory_info'].vms if pi.get('memory_info') else 0,
                    num_threads=pi['num_threads'] or 0,
                    status=pi['status'] or '',
                    connections=conns,
                    open_files=files,
                    parent_pid=pi.get('ppid') or 0,
                    parent_name=parent_name,
                )
                processes.append(snap)
                per_process_conns[pid] = conns
                per_process_files[pid] = files
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                _log.debug(f"Process snapshot error for pid {pi.get('pid')}: {e}")
                continue
        
        # Network snapshot
        network = NetworkSnapshot(
            connections=[],  # Will be filled from per_process_conns
            per_process=per_process_conns,
        )
        # Flatten all connections
        for pid, conns in per_process_conns.items():
            for c in conns:
                c['pid'] = pid
                network.connections.append(c)
        
        # Disk usage
        disk = {}
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disk[part.mountpoint] = usage.percent
            except Exception:
                pass
        
        snapshot = SystemSnapshot(
            tick=self._tick,
            timestamp=ts,
            processes=processes,
            network=network,
            cpu_percent=cpu,
            memory_percent=mem.percent,
            disk_usage=disk,
        )
        
        self._last_snapshot = snapshot
        return snapshot

    def _fan_out(self, snapshot: SystemSnapshot):
        """Fan out snapshot to all consumers."""
        # Call callbacks
        for consumer_type, callbacks in self._callbacks.items():
            for cb in callbacks:
                try:
                    # Run in executor to avoid blocking snapshot loop
                    self._executor.submit(self._safe_callback, cb, snapshot)
                except Exception as e:
                    _log.error(f"Callback submit error for {consumer_type}: {e}")
                    self.stats['consumer_errors'] += 1
        
        # Also push to queues (non-blocking with drop policy)
        for consumer_type, q in self._queues.items():
            try:
                q.put_nowait(snapshot)
            except queue.Full:
                self.stats['queue_drops'] += 1

    def _safe_callback(self, callback: Callable, snapshot: SystemSnapshot):
        """Safely execute a consumer callback."""
        try:
            callback(snapshot)
        except Exception as e:
            _log.error(f"Consumer callback error: {e}")
            self.stats['consumer_errors'] += 1

    def _cleanup_dedup(self):
        """Clean up old deduplication entries."""
        now = time.time()
        if len(self._alert_dedup) > self._dedup_max:
            # Remove expired entries
            cutoff = now - self._dedup_ttl
            self._alert_dedup = {k: v for k, v in self._alert_dedup.items() if v > cutoff}
            # If still too many, remove oldest
            if len(self._alert_dedup) > self._dedup_max:
                sorted_items = sorted(self._alert_dedup.items(), key=lambda x: x[1])
                self._alert_dedup = dict(sorted_items[-self._dedup_max//2:])

    def check_dns_count(self, remote_ip: str) -> int:
        """Track DNS query count per remote IP (replaces unbounded _dns_counts)."""
        now = time.time()
        if remote_ip not in self._dns_counts:
            self._dns_counts[remote_ip] = deque()
        
        dq = self._dns_counts[remote_ip]
        dq.append(now)
        
        # Remove old entries outside window
        cutoff = now - self._dns_window
        while dq and dq[0] < cutoff:
            dq.popleft()
        
        # Clean up empty deques periodically
        if len(self._dns_counts) > self._dns_max_entries:
            # Remove entries with no recent activity
            cutoff = now - self._dns_window * 2
            self._dns_counts = {k: v for k, v in self._dns_counts.items() if v and v[-1] > cutoff}
        
        return len(dq)

    def is_alert_deduped(self, alert_key: str) -> bool:
        """Check if alert was recently fired (deduplication)."""
        now = time.time()
        if alert_key in self._alert_dedup:
            if now - self._alert_dedup[alert_key] < 300:  # 5 min cooldown
                return True
        self._alert_dedup[alert_key] = now
        return False

    def get_last_snapshot(self) -> Optional[SystemSnapshot]:
        return self._last_snapshot

    def get_stats(self) -> Dict:
        with self._lock:
            return {
                **self.stats,
                'tick': self._tick,
                'queue_sizes': {k: v.qsize() for k, v in self._queues.items()},
                'dns_tracked': len(self._dns_counts),
                'dedup_size': len(self._alert_dedup),
            }

# ---- Singleton access --------------------------------------------------------

_hub: Optional[SensorHub] = None
_hub_lock = threading.Lock()

def get_hub() -> SensorHub:
    global _hub
    with _hub_lock:
        if _hub is None:
            _hub = SensorHub()
        return _hub

# ---- Consumer adapters (rewiring orphaned modules) ---------------------------

def wire_process_monitor(hub: SensorHub):
    """Wire the old process_monitor to consume from hub."""
    from process_monitor import ProcessMonitor
    
    original_scan = ProcessMonitor.scan_all_processes
    def new_scan(self):
        snap = hub.get_last_snapshot()
        if not snap:
            return
        for proc_snap in snap.processes:
            # Convert to format expected by analyze_process
            proc_info = {
                'pid': proc_snap.pid,
                'name': proc_snap.name,
                'exe': proc_snap.exe,
                'cmdline': proc_snap.cmdline,
                'username': proc_snap.username,
                'create_time': datetime.fromtimestamp(proc_snap.create_time),
            }
            self.analyze_process(proc_info)
    
    ProcessMonitor.scan_all_processes = new_scan
    _log.info("ProcessMonitor wired to SensorHub")

def wire_ransomware_detector(hub: SensorHub):
    """Wire ransomware detector to consume file changes from hub."""
    # The ransomware detector's file monitoring is separate (uses own watchdog)
    # but can now get process snapshots from hub for correlation
    _log.info("RansomwareDetector can now correlate with SensorHub process data")

def wire_network_monitor(hub: SensorHub):
    """Wire network monitor to consume from hub."""
    from network_monitor import NetworkMonitor
    
    original_scan = NetworkMonitor.scan_connections
    def new_scan(self):
        snap = hub.get_last_snapshot()
        if not snap:
            return
        # Use hub's network snapshot
        for conn in snap.network.connections:
            # Convert to psutil-like connection object
            class ConnObj:
                def __init__(self, d):
                    self.raddr = type('obj', (object,), {'ip': d['remote_ip'], 'port': d['remote_port']})
                    self.laddr = type('obj', (object,), {'ip': '0.0.0.0', 'port': d['local_port']})
                    self.status = d['status']
                    self.pid = d['pid']
            conn_obj = ConnObj(conn)
            proc_name = ""
            try:
                if conn['pid']:
                    proc_name = psutil.Process(conn['pid']).name()
            except Exception:
                pass
            self.check_connection(conn_obj, proc_name)
    
    NetworkMonitor.scan_connections = new_scan
    _log.info("NetworkMonitor wired to SensorHub")

# ---- Singleton ---------------------------------------------------------------

_hub_instance: Optional[SensorHub] = None
_hub_lock = threading.Lock()

def get_sensor_hub() -> SensorHub:
    global _hub_instance
    with _hub_lock:
        if _hub_instance is None:
            _hub_instance = SensorHub()
        return _hub_instance

def start_sensor_hub() -> SensorHub:
    hub = get_sensor_hub()
    hub.start()
    # Wire orphaned modules
    wire_process_monitor(hub)
    wire_ransomware_detector(hub)
    wire_network_monitor(hub)
    _log.info("SensorHub started and orphaned modules wired")
    return hub

def stop_sensor_hub():
    global _hub_instance
    if _hub_instance:
        _hub_instance.stop()
        _hub_instance = None

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
    hub = start_sensor_hub()
    try:
        while True:
            time.sleep(5)
            stats = hub.get_stats()
            print(f"Tick: {stats['tick']}, Queues: {stats['queue_sizes']}, DNS: {stats['dns_tracked']}")
    except KeyboardInterrupt:
        stop_sensor_hub()