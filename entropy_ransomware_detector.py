#!/usr/bin/env python3
"""
Hierarchical Entropy Disruption (HED) Ransomware Detector
Based on Minerva (file-level behavioral profiles) and HED framework research.
Detects ransomware encryption activity by monitoring entropy variations
across hierarchical system levels (file, directory, process, system).
"""
from __future__ import annotations
import os
import time
import math
import threading
import logging
import hashlib
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import psutil

_log = logging.getLogger(__name__)

# Configuration
ENTROPY_WINDOW_SIZE = 100  # Number of operations per window
ENTROPY_THRESHOLD_HIGH = 7.5  # High entropy threshold (near 8.0 = encrypted)
ENTROPY_THRESHOLD_LOW = 3.0  # Low entropy threshold
ENTROPY_DELTA_THRESHOLD = 2.0  # Significant entropy change
SCAN_INTERVAL = 2.0  # Seconds between scans
MAX_FILES_PER_SCAN = 500  # Limit files per scan for performance
HISTORY_RETENTION = 3600  # 1 hour history
USER_DIRS = [
    os.path.expanduser("~"),
    os.path.join(os.environ.get("SYSTEMDRIVE", "C:"), "Users"),
]
EXCLUDE_DIRS = {
    os.path.join(os.environ.get("WINDIR", "C:\\Windows"), "Temp"),
    os.path.join(os.environ.get("TEMP", "C:\\Temp")),
    os.path.join(os.environ.get("APPDATA", ""), "Local", "Temp"),
}

@dataclass
class FileEntropyProfile:
    """Behavioral profile for a single file based on I/O operations."""
    path: str
    operations: deque = field(default_factory=lambda: deque(maxlen=ENTROPY_WINDOW_SIZE))
    entropy_history: deque = field(default_factory=lambda: deque(maxlen=100))
    last_scan: float = 0.0
    size_history: deque = field(default_factory=lambda: deque(maxlen=50))
    read_bytes: int = 0
    write_bytes: int = 0
    operation_count: int = 0
    avg_entropy: float = 0.0
    entropy_trend: float = 0.0  # Positive = increasing entropy
    is_suspicious: bool = False
    suspicion_score: float = 0.0
    last_alert: float = 0.0

@dataclass
class DirectoryEntropyProfile:
    """Aggregated entropy profile for a directory."""
    path: str
    file_profiles: Dict[str, FileEntropyProfile] = field(default_factory=dict)
    avg_entropy: float = 0.0
    entropy_trend: float = 0.0
    high_entropy_files: int = 0
    total_files: int = 0
    last_update: float = 0.0
    is_suspicious: bool = False
    suspicion_score: float = 0.0

@dataclass
class ProcessEntropyProfile:
    """Entropy profile for a process based on file operations."""
    pid: int
    name: str
    exe: str = ""
    file_operations: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_read: int = 0
    total_write: int = 0
    entropy_samples: deque = field(default_factory=lambda: deque(maxlen=50))
    avg_entropy: float = 0.0
    suspicion_score: float = 0.0
    is_suspicious: bool = False
    last_update: float = 0.0

class EntropyCalculator:
    """Fast entropy calculation with multiple methods."""
    
    @staticmethod
    def shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of byte data."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        entropy = 0.0
        n = len(data)
        for count in freq:
            if count > 0:
                p = count / n
                entropy -= p * math.log2(p)
        return entropy
    
    @staticmethod
    def chi_squared(data: bytes) -> float:
        """Chi-squared test for randomness."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        n = len(data)
        expected = n / 256
        chi2 = sum((count - expected) ** 2 / expected for count in freq if expected > 0)
        return chi2
    
    @staticmethod
    def serial_correlation(data: bytes) -> float:
        """Serial correlation coefficient."""
        if len(data) < 2:
            return 0.0
        n = len(data)
        mean = sum(data) / n
        cov = sum((data[i] - mean) * (data[i-1] - mean) for i in range(1, n))
        var = sum((b - mean) ** 2 for b in data)
        return cov / var if var > 0 else 0.0
    
    @staticmethod
    def multi_method_entropy(data: bytes) -> Dict[str, float]:
        """Calculate entropy using multiple methods."""
        return {
            'shannon': EntropyCalculator.shannon_entropy(data),
            'chi_squared': EntropyCalculator.chi_squared(data),
            'serial_corr': EntropyCalculator.serial_correlation(data),
        }

class FileOperationMonitor:
    """Monitors file I/O operations using psutil and Windows APIs."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._process_cache: Dict[int, psutil.Process] = {}
        self._last_open_files: Dict[int, Set[str]] = defaultdict(set)
    
    def get_process_open_files(self, pid: int) -> List[str]:
        """Get open files for a process."""
        try:
            proc = psutil.Process(pid)
            files = []
            for f in proc.open_files():
                files.append(f.path)
            return files
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []
    
    def get_all_process_files(self) -> Dict[int, List[str]]:
        """Get open files for all processes."""
        result = {}
        for proc in psutil.process_iter(['pid']):
            try:
                pid = proc.info['pid']
                files = self.get_process_open_files(pid)
                if files:
                    result[pid] = files
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return result
    
    def detect_new_file_operations(self) -> Dict[int, Set[str]]:
        """Detect new file operations since last scan."""
        current = self.get_all_process_files()
        new_ops = {}
        with self._lock:
            for pid, files in current.items():
                prev = self._last_open_files.get(pid, set())
                new_files = set(files) - prev
                if new_files:
                    new_ops[pid] = new_files
            self._last_open_files = {pid: set(files) for pid, files in current.items()}
        return new_ops

class HierarchicalEntropyDetector:
    """
    Main detector implementing Hierarchical Entropy Disruption (HED)
    for ransomware detection across file, directory, process, and system levels.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Profiles at each hierarchy level
        self.file_profiles: Dict[str, FileEntropyProfile] = {}
        self.dir_profiles: Dict[str, DirectoryEntropyProfile] = {}
        self.process_profiles: Dict[int, ProcessEntropyProfile] = {}
        
        # Monitoring components
        self.file_monitor = FileOperationMonitor()
        self.entropy_calc = EntropyCalculator()
        
        # Alert system
        self.alerts: deque = deque(maxlen=1000)
        self.alert_callbacks: List[callable] = []
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'dirs_analyzed': 0,
            'processes_monitored': 0,
            'alerts_generated': 0,
            'ransomware_detected': 0,
            'scan_errors': 0,
        }
        
        # Baseline entropy for common file types
        self.baseline_entropy = {
            '.txt': 4.0, '.log': 4.0, '.csv': 4.5,
            '.doc': 5.0, '.docx': 5.5, '.pdf': 6.0,
            '.jpg': 7.5, '.png': 7.5, '.mp4': 7.8,
            '.zip': 7.5, '.exe': 6.5, '.dll': 6.5,
            '.db': 5.0, '.sqlite': 5.0,
        }
    
    def start(self):
        """Start the detector."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="HED-Ransomware")
        self._thread.start()
        _log.info("Hierarchical Entropy Disruption Ransomware Detector started")
    
    def stop(self):
        """Stop the detector."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        _log.info("HED Ransomware Detector stopped")
    
    def register_alert_callback(self, callback: callable):
        """Register callback for alerts."""
        self.alert_callbacks.append(callback)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running and not self._stop_event.is_set():
            start = time.time()
            try:
                self._scan_cycle()
            except Exception as e:
                _log.error(f"HED scan cycle error: {e}")
                self.stats['scan_errors'] += 1
            
            elapsed = time.time() - start
            sleep_time = max(0, SCAN_INTERVAL - elapsed)
            if sleep_time > 0:
                self._stop_event.wait(sleep_time)
    
    def _scan_cycle(self):
        """Perform one complete scan cycle."""
        # 1. Detect new file operations
        new_ops = self.file_monitor.detect_new_file_operations()
        
        # 2. Update process profiles
        self._update_process_profiles(new_ops)
        
        # 3. Scan user directories for entropy changes
        self._scan_user_directories()
        
        # 4. Analyze hierarchical entropy
        self._analyze_hierarchical_entropy()
        
        # 5. Check for ransomware patterns
        self._check_ransomware_patterns()
        
        # 6. Cleanup old data
        self._cleanup_old_data()
    
    def _update_process_profiles(self, new_ops: Dict[int, Set[str]]):
        """Update process entropy profiles based on file operations."""
        for pid, files in new_ops.items():
            with self._lock:
                profile = self.process_profiles.get(pid)
                if not profile:
                    try:
                        proc = psutil.Process(pid)
                        profile = ProcessEntropyProfile(
                            pid=pid,
                            name=proc.name(),
                            exe=proc.exe() or "",
                        )
                        self.process_profiles[pid] = profile
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                profile.last_update = time.time()
                for fpath in files:
                    profile.file_operations[fpath] += 1
                    profile.total_write += 1
                    
                    # Sample entropy of written files
                    if len(profile.entropy_samples) < 50:
                        try:
                            with open(fpath, 'rb') as f:
                                sample = f.read(4096)
                                if sample:
                                    entropy = self.entropy_calc.shannon_entropy(sample)
                                    profile.entropy_samples.append(entropy)
                        except Exception:
                            pass
                
                # Update average entropy
                if profile.entropy_samples:
                    profile.avg_entropy = sum(profile.entropy_samples) / len(profile.entropy_samples)
    
    def _scan_user_directories(self):
        """Scan user directories for entropy changes."""
        for user_dir in USER_DIRS:
            if not os.path.exists(user_dir):
                continue
            self._scan_directory_recursive(user_dir)
    
    def _scan_directory_recursive(self, root: str, depth: int = 0):
        """Recursively scan directory for file entropy."""
        if depth > 3:  # Limit depth
            return
        
        try:
            entries = os.listdir(root)
        except (PermissionError, OSError):
            return
        
        dir_profile = self.dir_profiles.get(root)
        if not dir_profile:
            dir_profile = DirectoryEntropyProfile(path=root)
            self.dir_profiles[root] = dir_profile
        
        file_count = 0
        high_entropy_count = 0
        entropy_sum = 0.0
        
        for entry in entries[:MAX_FILES_PER_SCAN]:
            fpath = os.path.join(root, entry)
            if os.path.isdir(fpath):
                if fpath not in EXCLUDE_DIRS:
                    self._scan_directory_recursive(fpath, depth + 1)
            elif os.path.isfile(fpath):
                file_count += 1
                entropy = self._get_file_entropy(fpath)
                if entropy > 0:
                    entropy_sum += entropy
                    if entropy > ENTROPY_THRESHOLD_HIGH:
                        high_entropy_count += 1
                    
                    # Update file profile
                    self._update_file_profile(fpath, entropy)
        
        # Update directory profile
        dir_profile.total_files = file_count
        dir_profile.high_entropy_files = high_entropy_count
        dir_profile.avg_entropy = entropy_sum / file_count if file_count > 0 else 0.0
        dir_profile.last_update = time.time()
        self.stats['files_scanned'] += file_count
        self.stats['dirs_analyzed'] += 1
    
    def _get_file_entropy(self, fpath: str) -> float:
        """Get file entropy, using cache if available."""
        try:
            stat = os.stat(fpath)
            # Only sample if file was modified recently or not cached
            profile = self.file_profiles.get(fpath)
            if profile and profile.last_scan > stat.st_mtime - 10:
                return profile.avg_entropy
            
            # Sample file entropy
            with open(fpath, 'rb') as f:
                sample = f.read(8192)
                if not sample:
                    return 0.0
                entropy = self.entropy_calc.shannon_entropy(sample)
            
            return entropy
        except Exception:
            return 0.0
    
    def _update_file_profile(self, fpath: str, entropy: float):
        """Update file entropy profile."""
        with self._lock:
            profile = self.file_profiles.get(fpath)
            if not profile:
                profile = FileEntropyProfile(path=fpath)
                self.file_profiles[fpath] = profile
            
            now = time.time()
            profile.last_scan = now
            profile.entropy_history.append((now, entropy))
            
            # Calculate trend
            if len(profile.entropy_history) >= 3:
                recent = list(profile.entropy_history)[-3:]
                entropies = [e for _, e in recent]
                if len(entropies) >= 2:
                    profile.entropy_trend = entropies[-1] - entropies[0]
            
            # Update average
            profile.avg_entropy = sum(e for _, e in profile.entropy_history) / len(profile.entropy_history)
            
            # Check for suspicious entropy changes
            ext = os.path.splitext(fpath)[1].lower()
            baseline = self.baseline_entropy.get(ext, 5.0)
            
            if entropy > ENTROPY_THRESHOLD_HIGH and entropy - baseline > ENTROPY_DELTA_THRESHOLD:
                profile.is_suspicious = True
                profile.suspicion_score = min(100.0, (entropy - baseline) * 20)
            elif entropy > baseline + ENTROPY_DELTA_THRESHOLD:
                profile.suspicion_score = min(50.0, (entropy - baseline) * 10)
    
    def _analyze_hierarchical_entropy(self):
        """Analyze entropy across hierarchy levels."""
        with self._lock:
            # Directory level analysis
            for dir_path, dprof in self.dir_profiles.items():
                if dprof.total_files > 5:
                    high_ratio = dprof.high_entropy_files / dprof.total_files
                    if high_ratio > 0.3 and dprof.avg_entropy > ENTROPY_THRESHOLD_HIGH:
                        dprof.is_suspicious = True
                        dprof.suspicion_score = min(100.0, high_ratio * 100 + (dprof.avg_entropy - 7.0) * 20)
            
            # Process level analysis
            for pid, pprof in self.process_profiles.items():
                if pprof.avg_entropy > ENTROPY_THRESHOLD_HIGH and pprof.total_write > 10:
                    pprof.is_suspicious = True
                    pprof.suspicion_score = min(100.0, (pprof.avg_entropy - 7.0) * 25 + pprof.total_write)
    
    def _check_ransomware_patterns(self):
        """Check for ransomware-specific patterns."""
        now = time.time()
        
        # Pattern 1: Mass file encryption (many files with sudden high entropy)
        suspicious_dirs = [d for d in self.dir_profiles.values() 
                          if d.is_suspicious and d.suspicion_score > 50]
        
        if len(suspicious_dirs) >= 2:
            self._generate_alert(
                "MASS_ENCRYPTION",
                f"Multiple directories showing high entropy: {[d.path for d in suspicious_dirs[:3]]}",
                severity="CRITICAL",
                mitre_technique="T1486",
                details={"dirs": len(suspicious_dirs), "avg_score": sum(d.suspicion_score for d in suspicious_dirs) / len(suspicious_dirs)}
            )
        
        # Pattern 2: Single process encrypting many files
        suspicious_procs = [p for p in self.process_profiles.values() 
                           if p.is_suspicious and p.suspicion_score > 60 and p.total_write > 20]
        
        for proc in suspicious_procs:
            self._generate_alert(
                "PROCESS_ENCRYPTION",
                f"Process {proc.name} (PID {proc.pid}) writing high-entropy files: {proc.total_write} operations",
                severity="HIGH",
                mitre_technique="T1486",
                details={"pid": proc.pid, "name": proc.name, "exe": proc.exe, "write_count": proc.total_write, "avg_entropy": proc.avg_entropy}
            )
        
        # Pattern 3: Shadow copy deletion (CISA CM0097)
        self._check_shadow_copy_deletion()
        
        # Pattern 4: VSS/WMI/CMD indicators
        self._check_ransomware_indicators()
    
    def _check_shadow_copy_deletion(self):
        """Check for shadow copy deletion commands (CISA CM0097)."""
        # This would integrate with process command line monitoring
        # Looking for: vssadmin.exe delete shadows, wmic shadowcopy delete, etc.
        pass
    
    def _check_ransomware_indicators(self):
        """Check for known ransomware indicators in process behavior."""
        # VSSAdmin, WMIC, bcdedit, wbadmin usage
        pass
    
    def _generate_alert(self, alert_type: str, message: str, severity: str, mitre_technique: str, details: Dict):
        """Generate an alert."""
        alert = {
            'timestamp': time.time(),
            'type': alert_type,
            'message': message,
            'severity': severity,
            'mitre': mitre_technique,
            'details': details,
        }
        self.alerts.append(alert)
        self.stats['alerts_generated'] += 1
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                _log.error(f"Alert callback error: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old profiles and history."""
        now = time.time()
        cutoff = now - HISTORY_RETENTION
        
        with self._lock:
            # Clean file profiles
            to_remove = [p for p, prof in self.file_profiles.items() 
                        if prof.last_scan < cutoff and not prof.is_suspicious]
            for p in to_remove:
                del self.file_profiles[p]
            
            # Clean process profiles
            to_remove = [pid for pid, prof in self.process_profiles.items() 
                        if prof.last_update < cutoff and not prof.is_suspicious]
            for pid in to_remove:
                del self.process_profiles[pid]
            
            # Clean directory profiles
            to_remove = [p for p, prof in self.dir_profiles.items() 
                        if prof.last_update < cutoff and not prof.is_suspicious]
            for p in to_remove:
                del self.dir_profiles[p]
    
    def get_status(self) -> Dict:
        """Get detector status."""
        with self._lock:
            return {
                'running': self._running,
                'files_monitored': len(self.file_profiles),
                'dirs_monitored': len(self.dir_profiles),
                'processes_monitored': len(self.process_profiles),
                'suspicious_files': sum(1 for p in self.file_profiles.values() if p.is_suspicious),
                'suspicious_dirs': sum(1 for d in self.dir_profiles.values() if d.is_suspicious),
                'suspicious_procs': sum(1 for p in self.process_profiles.values() if p.is_suspicious),
                'recent_alerts': list(self.alerts)[-10:],
                'stats': self.stats.copy(),
            }
    
    def get_file_risk(self, fpath: str) -> Dict:
        """Get risk assessment for a specific file."""
        with self._lock:
            profile = self.file_profiles.get(fpath)
            if not profile:
                return {'risk': 'unknown', 'score': 0}
            
            ext = os.path.splitext(fpath)[1].lower()
            baseline = self.baseline_entropy.get(ext, 5.0)
            
            return {
                'path': fpath,
                'entropy': profile.avg_entropy,
                'baseline': baseline,
                'trend': profile.entropy_trend,
                'suspicious': profile.is_suspicious,
                'score': profile.suspicion_score,
                'risk': 'critical' if profile.suspicion_score > 80 else 
                       'high' if profile.suspicion_score > 50 else
                       'medium' if profile.suspicion_score > 20 else 'low',
            }

# Singleton instance
_hed_detector: Optional[HierarchicalEntropyDetector] = None
_hed_lock = threading.Lock()

def get_hed_detector() -> HierarchicalEntropyDetector:
    global _hed_detector
    with _hed_lock:
        if _hed_detector is None:
            _hed_detector = HierarchicalEntropyDetector()
        return _hed_detector

def start_hed_detector() -> HierarchicalEntropyDetector:
    detector = get_hed_detector()
    detector.start()
    return detector

def stop_hed_detector():
    global _hed_detector
    if _hed_detector:
        _hed_detector.stop()
        _hed_detector = None

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    detector = start_hed_detector()
    try:
        while True:
            time.sleep(10)
            status = detector.get_status()
            print(f"Files: {status['files_monitored']}, Suspicious: {status['suspicious_files']}, Alerts: {status['stats']['alerts_generated']}")
    except KeyboardInterrupt:
        stop_hed_detector()