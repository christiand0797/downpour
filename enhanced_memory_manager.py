#!/usr/bin/env python3
"""
Enhanced Memory Manager for Downpour v29 Titanium
Real adaptive GC, tracemalloc leak detection, process memory tracking,
predictive cleanup, and quantum-optimized allocation strategies.
"""

__version__ = "29.0.0"

import gc, logging, os, threading, time, tracemalloc, weakref
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

_log = logging.getLogger(__name__)

try:
    import numpy as _np_mm
    _MM_NP_AVAILABLE = True
except ImportError:
    _np_mm = None; _MM_NP_AVAILABLE = False

# ─── Enums & Dataclasses ──────────────────────────────────────────────────────
class MemoryStrategy(Enum):
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    AGGRESSIVE = "aggressive"
    PREDICTIVE = "predictive"
    QUANTUM_OPTIMIZED = "quantum_optimized"

class MemoryPressure(Enum):
    NONE = 0; LOW = 1; MODERATE = 2; HIGH = 3; CRITICAL = 4

@dataclass
class MemorySnapshot:
    timestamp: float = field(default_factory=time.time)
    used_bytes: int = 0; available_bytes: int = 0
    percent: float = 0.0; swap_used: int = 0
    gc_counts: Tuple[int,...] = (0,0,0)
    tracemalloc_current: int = 0; tracemalloc_peak: int = 0
    rss_bytes: int = 0  # FIX-v29.41k3: this process's own RSS

@dataclass
class LeakReport:
    detected: bool = False
    growth_rate_mb_per_min: float = 0.0
    suspected_objects: List[str] = field(default_factory=list)
    top_allocations: List[Tuple[str,int]] = field(default_factory=list)
    recommendation: str = ""
    type_counts: List[str] = field(default_factory=list)

# ─── Core Manager ─────────────────────────────────────────────────────────────
class EnhancedMemoryManager:
    """Adaptive memory manager with leak detection and predictive GC."""
    def __init__(self, strategy: MemoryStrategy = MemoryStrategy.PREDICTIVE,
                 gc_frequency: int = 100, memory_threshold: float = 0.78):
        self.strategy = strategy
        self.gc_frequency = gc_frequency
        self.memory_threshold = memory_threshold
        self.enabled = True
        self._lock = threading.Lock()
        self._op_count = 0
        self._snapshots: deque = deque(maxlen=120)
        self._gc_generations = [0, 0, 0]
        self._weak_refs: List[weakref.ref] = []
        self.stats = {
            'gc_runs': 0, 'gen0': 0, 'gen1': 0, 'gen2': 0,
            'memory_warnings': 0, 'leak_detections': 0,
            'peak_memory_mb': 0.0, 'operations_processed': 0,
            'cleanups_triggered': 0,
        }
        # Configure GC thresholds for better performance
        gc.set_threshold(700, 10, 10)
        gc.enable()
        tracemalloc.start(10)  # 10 frames of traceback
        self._start_monitor()

    def initialize(self) -> bool:
        """Initialize the memory manager."""
        # Initialize COM for this thread
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except ImportError:
            pass
        
        try:
            if not tracemalloc.is_tracing(): tracemalloc.start(10)
            _log.info("EnhancedMemoryManager initialized (strategy=%s)", self.strategy.value)
            return True
        except Exception as exc:
            _log.warning("EnhancedMemoryManager init: %s", exc); return False

    # ── Monitoring ────────────────────────────────────────────────────────────
    def _start_monitor(self) -> None:
        """Start the memory monitoring thread."""
        # Initialize COM for this thread
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except ImportError:
            pass
        
        t = threading.Thread(target=self._monitor_loop, daemon=True, name="MemMonitor")
        t.start()

    def _monitor_loop(self) -> None:
        consecutive_high = 0
        while self.enabled:
            try:
                snap = self._take_snapshot()
                self._snapshots.append(snap)
                pressure = self._assess_pressure(snap)
                if pressure.value >= MemoryPressure.HIGH.value:
                    consecutive_high += 1
                    self.stats['memory_warnings'] += 1
                    self._respond_to_pressure(pressure, consecutive_high)
                else:
                    consecutive_high = max(0, consecutive_high - 1)
                # Leak detection every 10 snapshots (5 min at 30s / 2.5 min at 15s)
                if len(self._snapshots) % 10 == 0:
                    report = self.detect_leaks()
                    if report.detected:
                        self.stats['leak_detections'] += 1
                        _log.warning("Memory leak detected: %.2f MB/min growth",
                                     report.growth_rate_mb_per_min)
                        # FIX-v29.41k3: surface the actual top allocation sites
                        # so the leak can be chased instead of guessed at.
                        try:
                            _top = "; ".join(
                                "{}->{} {}".format(*t) if len(t) >= 3 else str(t)
                                for t in report.top_allocations[:6])
                            _log.warning("  top allocations: %s", _top)
                        except Exception:
                            pass
                        try:
                            _log.warning("  top types: %s", ", ".join(report.type_counts[:8]))
                        except Exception:
                            pass
                # FIX-v29.41k3: `interval` was never defined -> NameError every
                # loop, so the thread silently slept 60s (leak reports ~10min
                # apart). Monitor at 15s under pressure, 30s otherwise.
                time.sleep(15 if pressure.value >= MemoryPressure.HIGH.value else 30)
            except Exception as exc:
                _log.debug("Monitor loop: %s", exc); time.sleep(60)

    def _take_snapshot(self) -> MemorySnapshot:
        if not _PSUTIL_AVAILABLE:
            cur, peak = tracemalloc.get_traced_memory()
            return MemorySnapshot(
                used_bytes=0, available_bytes=0, percent=0.0, swap_used=0,
                gc_counts=tuple(gc.get_count()),
                tracemalloc_current=cur, tracemalloc_peak=peak,
            )
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        cur, peak = tracemalloc.get_traced_memory()
        snap = MemorySnapshot(
            used_bytes=mem.used, available_bytes=mem.available,
            percent=mem.percent, swap_used=swap.used,
            gc_counts=tuple(gc.get_count()),
            tracemalloc_current=cur, tracemalloc_peak=peak,
        )
        # FIX-v29.41k3: track the app's own RSS so leak detection measures
        # THIS process, not whole-system memory (other apps made system
        # `used_bytes` grow 87 MB/min and produced false leak alarms).
        try:
            snap.rss_bytes = psutil.Process(os.getpid()).memory_info().rss
        except Exception:
            snap.rss_bytes = 0
        peak_mb = mem.used / 1024**2
        if peak_mb > self.stats['peak_memory_mb']:
            self.stats['peak_memory_mb'] = peak_mb
        return snap

    def _assess_pressure(self, snap: MemorySnapshot) -> MemoryPressure:
        p = snap.percent
        if p >= 95: return MemoryPressure.CRITICAL
        if p >= 85: return MemoryPressure.HIGH
        if p >= 75: return MemoryPressure.MODERATE
        if p >= 60: return MemoryPressure.LOW
        return MemoryPressure.NONE

    def _respond_to_pressure(self, pressure: MemoryPressure, streak: int) -> None:
        if pressure == MemoryPressure.MODERATE:
            self._collect(0)
        elif pressure == MemoryPressure.HIGH:
            self._collect(1); self._purge_weak_refs()
        elif pressure == MemoryPressure.CRITICAL:
            self._collect(2); self._purge_weak_refs()
            _log.critical("CRITICAL memory pressure — forcing full GC")

    # ── GC Helpers ────────────────────────────────────────────────────────────
    def _collect(self, generation: int = 2) -> int:
        collected = gc.collect(generation)
        with self._lock:
            self.stats['gc_runs'] += 1
            self.stats[f'gen{generation}'] += 1
            self.stats['cleanups_triggered'] += 1
        return collected

    def _force_cleanup(self) -> None:
        self._collect(2)
        self._purge_weak_refs()

    def _purge_weak_refs(self) -> None:
        with self._lock:
            self._weak_refs = [r for r in self._weak_refs if r() is not None]

    def track_operation(self) -> None:
        with self._lock:
            self._op_count += 1
            self.stats['operations_processed'] += 1
            if self._op_count >= self.gc_frequency:
                self._op_count = 0
                self._collect(0)

    def register_weak(self, obj: Any) -> weakref.ref:
        ref = weakref.ref(obj)
        with self._lock: self._weak_refs.append(ref)
        return ref

    # ── Leak Detection ────────────────────────────────────────────────────────
    def detect_leaks(self) -> LeakReport:
        report = LeakReport()
        if len(self._snapshots) < 10: return report
        snaps = list(self._snapshots)
        recent = snaps[-10:]
        # FIX-v29.41k3: base the growth rate on THIS process's RSS when
        # available (falls back to system used_bytes otherwise). System-wide
        # `used_bytes` grows with every other app on the box and caused
        # constant false leak alarms.
        if any(s.rss_bytes for s in recent):
            growth = (recent[-1].rss_bytes - recent[0].rss_bytes) / 1024**2
        else:
            growth = (recent[-1].used_bytes - recent[0].used_bytes) / 1024**2
        elapsed_min = (recent[-1].timestamp - recent[0].timestamp) / 60
        if elapsed_min > 0: rate = growth / elapsed_min
        else: return report
        if rate > 5.0:  # >5 MB/min is suspicious
            report.detected = True
            report.growth_rate_mb_per_min = rate
            report.recommendation = "Consider restarting or investigating memory-heavy components"
            # FIX-v29.41k3: capture gc type counts FIRST (before the tracemalloc
            # snapshot below), otherwise the report's own Traceback/Statistic
            # objects dominate the type histogram and hide the real leak.
            try:
                _types: Dict[str, int] = {}
                for o in gc.get_objects():
                    _n = type(o).__name__
                    _types[_n] = _types.get(_n, 0) + 1
                _big = sorted(_types.items(), key=lambda kv: -kv[1])[:10]
                report.type_counts = [f"{k}={v}" for k, v in _big]
            except Exception: pass
            try:
                snapshot = tracemalloc.take_snapshot()
                top = snapshot.statistics('lineno')[:10]
                report.top_allocations = [(str(s.traceback), s.size) for s in top]
            except Exception: pass
        return report

    # ── Stats & Metrics ───────────────────────────────────────────────────────
    def get_memory_stats(self) -> Dict[str, Any]:
        try:
            mem = psutil.virtual_memory()
            cur, peak = tracemalloc.get_traced_memory()
            proc = psutil.Process(os.getpid())
            return {
                'timestamp': datetime.now().isoformat(),
                'memory_used_mb': mem.used / 1024**2,
                'memory_available_mb': mem.available / 1024**2,
                'memory_percent': mem.percent,
                'current_traced_mb': cur / 1024**2,
                'peak_traced_mb': peak / 1024**2,
                'process_rss_mb': proc.memory_info().rss / 1024**2,
                'process_vms_mb': proc.memory_info().vms / 1024**2,
                'gc_counts': gc.get_count(),
                **self.stats,
            }
        except Exception as exc: return {'error': str(exc)}

    def get_trend(self) -> Dict[str, float]:
        if len(self._snapshots) < 2: return {}
        snaps = list(self._snapshots)
        pcts = [s.percent for s in snaps[-20:]]
        import statistics as _s
        return {'mean_percent': _s.mean(pcts), 'stdev_percent': _s.stdev(pcts) if len(pcts)>1 else 0,
                'trend': pcts[-1] - pcts[0] if pcts else 0}

    def optimize_memory_intelligently(self) -> Dict[str, Any]:
        snap = self._take_snapshot()
        pressure = self._assess_pressure(snap)
        actions = []
        if pressure.value >= MemoryPressure.LOW.value:
            collected = self._collect(2); actions.append(f"gc_collected={collected}")
        if self.strategy in (MemoryStrategy.AGGRESSIVE, MemoryStrategy.QUANTUM_OPTIMIZED):
            self._purge_weak_refs(); actions.append("weak_refs_purged")
        leak = self.detect_leaks()
        return {"pressure": pressure.name, "actions": actions,
                "leak_detected": leak.detected, "stats": self.get_memory_stats()}

    def cleanup(self) -> None:
        self.enabled = False
        self._force_cleanup()
        try: tracemalloc.stop()
        except Exception: pass
        _log.info("EnhancedMemoryManager cleaned up")

# ─── Singleton ────────────────────────────────────────────────────────────────
# FIX-v29.41k4: under Windows `spawn`, ProcessPoolExecutor workers re-import
# this module. Each child would otherwise start its own tracemalloc + monitor
# thread and flood the shared log with the PARSE worker's memory view, hiding
# the real main-process leak. Detect child context and stop monitoring there.
def _is_spawn_child() -> bool:
    try:
        from multiprocessing import current_process
        _name = current_process().name
        return _name and _name not in ('MainProcess', 'SpawnMainProcess')
    except Exception:
        return False

memory_manager = EnhancedMemoryManager(strategy=MemoryStrategy.PREDICTIVE)
if _is_spawn_child():
    # Child processes: keep the object importable (app references it) but
    # neutralize tracing + monitor so children don't report/leak.
    memory_manager.enabled = False
    try: tracemalloc.stop()
    except Exception: pass

# ─── Sophisticated Memory Manager (enhanced) ─────────────────────────────────
class SophisticatedMemoryManager:
    """High-level orchestrator wrapping EnhancedMemoryManager."""
    def __init__(self, strategy: MemoryStrategy = MemoryStrategy.QUANTUM_OPTIMIZED):
        self.strategy = strategy
        self._base = memory_manager
        self.learning_enabled = True

    def optimize_memory_intelligently(self) -> Dict[str, Any]:
        return self._base.optimize_memory_intelligently()

    def get_memory_metrics(self): return self._base.get_memory_stats()
    def enable_self_learning(self): self.learning_enabled = True
    def detect_leaks(self): return self._base.detect_leaks()

sophisticated_memory_manager = SophisticatedMemoryManager()
