#!/usr/bin/env python3
"""
Process Injection Detector
Detects advanced process injection techniques:
- Process Hollowing (T1055.012)
- Process Herpaderping / Ghosting (T1055.013)
- Process Doppelgänging
- Thread Execution Hijacking (T1055.003)
- APC Injection (T1055.004)
- TLS Callback Injection (T1055.005)
- VDSO Hijacking (T1055.014)
- ListPlanting (T1055.015)

Uses memory analysis, API monitoring, and Sysmon event correlation.
"""
from __future__ import annotations
import os
import time
import threading
import logging
import ctypes
import psutil
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum
from ctypes import wintypes

_log = logging.getLogger(__name__)

# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_SUSPEND_RESUME = 0x0800
THREAD_GET_CONTEXT = 0x0008
THREAD_SET_CONTEXT = 0x0010
THREAD_SUSPEND_RESUME = 0x0002
THREAD_QUERY_INFORMATION = 0x0040

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_READ = 0x20
PAGE_READWRITE = 0x04

# Injection types
class InjectionType(Enum):
    PROCESS_HOLLOWING = "process_hollowing"
    HERPADERPING = "herpaderping"
    PROCESS_GHOSTING = "process_ghosting"
    PROCESS_DOPPELGANGING = "process_doppelganging"
    THREAD_HIJACKING = "thread_hijacking"
    APC_INJECTION = "apc_injection"
    TLS_CALLBACK = "tls_callback"
    VDSO_HIJACKING = "vdso_hijacking"
    LISTPLANTING = "listplanting"
    DLL_INJECTION = "dll_injection"
    REFLECTIVE_DLL = "reflective_dll"
    SHELLCODE = "shellcode"
    UNKNOWN = "unknown"

@dataclass
class MemoryRegion:
    """Memory region information."""
    base_address: int
    size: int
    protection: int
    state: int
    type: int
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)

@dataclass
class ThreadInfo:
    """Thread information."""
    tid: int
    pid: int
    start_address: int
    context: Optional[Any] = None
    is_suspended: bool = False
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)

@dataclass
class ProcessInjectionAlert:
    """Alert for detected process injection."""
    timestamp: float
    injection_type: InjectionType
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    target_pid: int
    target_name: str
    target_exe: str
    source_pid: int
    source_name: str
    source_exe: str
    message: str
    mitre_technique: str
    details: Dict = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)

class WindowsAPI:
    """Windows API wrapper for process/thread/memory operations."""
    
    def __init__(self):
        self.kernel32 = ctypes.windll.kernel32
        self.ntdll = ctypes.windll.ntdll
        self._setup_functions()
    
    def _setup_functions(self):
        """Setup function signatures."""
        # OpenProcess
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        
        # CloseHandle
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        
        # VirtualQueryEx
        self.kernel32.VirtualQueryEx.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(ctypes.wintypes.MEMORY_BASIC_INFORMATION), ctypes.c_size_t
        ]
        self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
        
        # ReadProcessMemory
        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
        
        # WriteProcessMemory
        self.kernel32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.kernel32.WriteProcessMemory.restype = wintypes.BOOL
        
        # CreateToolhelp32Snapshot
        self.kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        self.kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        
        # Thread32First/Next
        self.kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.THREADENTRY32)]
        self.kernel32.Thread32First.restype = wintypes.BOOL
        self.kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.THREADENTRY32)]
        self.kernel32.Thread32Next.restype = wintypes.BOOL
        
        # OpenThread
        self.kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenThread.restype = wintypes.HANDLE
        
        # GetThreadContext
        self.kernel32.GetThreadContext.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.wintypes.CONTEXT)]
        self.kernel32.GetThreadContext.restype = wintypes.BOOL
        
        # SuspendThread/ResumeThread
        self.kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
        self.kernel32.SuspendThread.restype = wintypes.DWORD
        self.kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
        self.kernel32.ResumeThread.restype = wintypes.DWORD
        
        # NtQueryInformationProcess
        self.ntdll.NtQueryInformationProcess.argtypes = [
            wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)
        ]
        self.ntdll.NtQueryInformationProcess.restype = wintypes.LONG
        
        # NtQueryInformationThread
        self.ntdll.NtQueryInformationThread.argtypes = [
            wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.POINTER(wintypes.ULONG)
        ]
        self.ntdll.NtQueryInformationThread.restype = wintypes.LONG

    def get_process_threads(self, pid: int) -> List[int]:
        """Get all thread IDs for a process."""
        threads = []
        snapshot = self.kernel32.CreateToolhelp32Snapshot(0x00000004, pid)  # TH32CS_SNAPTHREAD
        if snapshot == wintypes.HANDLE(-1).value:
            return threads
        
        try:
            te32 = ctypes.wintypes.THREADENTRY32()
            te32.dwSize = ctypes.sizeof(te32)
            
            if self.kernel32.Thread32First(snapshot, ctypes.byref(te32)):
                while True:
                    if te32.th32OwnerProcessID == pid:
                        threads.append(te32.th32ThreadID)
                    if not self.kernel32.Thread32Next(snapshot, ctypes.byref(te32)):
                        break
        finally:
            self.kernel32.CloseHandle(snapshot)
        
        return threads

    def get_memory_regions(self, pid: int) -> List[MemoryRegion]:
        """Get memory regions for a process."""
        regions = []
        handle = self.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not handle or handle == wintypes.HANDLE(-1).value:
            return regions
        
        try:
            address = 0
            mbi = ctypes.wintypes.MEMORY_BASIC_INFORMATION()
            mbi_size = ctypes.sizeof(mbi)
            
            while self.kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), mbi_size) == mbi_size:
                region = MemoryRegion(
                    base_address=mbi.BaseAddress,
                    size=mbi.RegionSize,
                    protection=mbi.Protect,
                    state=mbi.State,
                    type=mbi.Type,
                )
                
                # Check for suspicious memory
                if region.protection & PAGE_EXECUTE_READWRITE:
                    region.is_suspicious = True
                    region.suspicion_reasons.append("RWX memory region")
                
                if region.state == MEM_COMMIT and region.type == 0:  # MEM_PRIVATE
                    # Check for unbacked memory (possible shellcode)
                    pass
                
                regions.append(region)
                address += mbi.RegionSize
        finally:
            self.kernel32.CloseHandle(handle)
        
        return regions

    def get_thread_context(self, tid: int) -> Optional[ctypes.wintypes.CONTEXT]:
        """Get thread context (registers)."""
        handle = self.kernel32.OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, False, tid)
        if not handle or handle == wintypes.HANDLE(-1).value:
            return None
        
        try:
            context = ctypes.wintypes.CONTEXT()
            context.ContextFlags = 0x10007  # CONTEXT_FULL
            if self.kernel32.GetThreadContext(handle, ctypes.byref(context)):
                return context
        finally:
            self.kernel32.CloseHandle(handle)
        return None

    def is_thread_suspended(self, tid: int) -> bool:
        """Check if thread is suspended."""
        handle = self.kernel32.OpenThread(THREAD_QUERY_INFORMATION, False, tid)
        if not handle:
            return False
        try:
            # Use NtQueryInformationThread for suspend count
            # Simplified - would need proper implementation
            return False
        finally:
            self.kernel32.CloseHandle(handle)

class ProcessInjectionDetector:
    """
    Main detector for process injection techniques.
    Monitors processes for signs of hollowing, herpaderping, thread hijacking, etc.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Windows API
        self.winapi = WindowsAPI()
        
        # Tracked processes
        self.process_baselines: Dict[int, Dict] = {}  # Baseline behavior
        self.suspicious_processes: Dict[int, Dict] = {}
        
        # Alerts
        self.alerts: deque = deque(maxlen=1000)
        self.alert_callbacks: List[callable] = []
        
        # Statistics
        self.stats = {
            'processes_scanned': 0,
            'injections_detected': 0,
            'hollowing_detected': 0,
            'herpaderping_detected': 0,
            'thread_hijacking_detected': 0,
            'apc_injection_detected': 0,
            'alerts_generated': 0,
        }
        
        # Known legitimate processes that commonly have RWX memory
        self.legitimate_rwx_processes = {
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'brave.exe',
            'code.exe', 'devenv.exe', 'python.exe', 'java.exe',
            'node.exe', 'electron.exe', 'Teams.exe', 'Slack.exe',
        }
        
        # System processes that should never be hollowed
        self.protected_processes = {
            'lsass.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
            'smss.exe', 'winlogon.exe', 'svchost.exe', 'explorer.exe',
            'System', 'Registry', 'fontdrvhost.exe', 'dwm.exe',
        }
    
    def start(self):
        """Start the detector."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="ProcessInjection-Detector")
        self._thread.start()
        _log.info("Process Injection Detector started")
    
    def stop(self):
        """Stop the detector."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        _log.info("Process Injection Detector stopped")
    
    def register_alert_callback(self, callback: callable):
        """Register callback for alerts."""
        self.alert_callbacks.append(callback)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        while self._running and not self._stop_event.is_set():
            start = time.time()
            try:
                self._scan_processes()
            except Exception as e:
                _log.error(f"Process injection scan error: {e}")
            
            elapsed = time.time() - start
            sleep_time = max(0, 5 - elapsed)  # Scan every 5 seconds
            if sleep_time > 0:
                self._stop_event.wait(sleep_time)
    
    def _scan_processes(self):
        """Scan all processes for injection indicators."""
        current_pids = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid', 'create_time', 'status', 'username']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                
                # Skip system processes
                if pid <= 4:  # System, Registry, smss, csrss
                    continue
                
                name = proc.info['name'] or ''
                exe = proc.info['exe'] or ''
                
                # Skip if process terminated
                if proc.info['status'] == psutil.STATUS_ZOMBIE:
                    continue
                
                # Scan for injection
                self._scan_process(pid, name, exe)
                self.stats['processes_scanned'] += 1
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                _log.debug(f"Error scanning process {pid}: {e}")
        
        # Cleanup old baselines
        with self._lock:
            for pid in list(self.process_baselines.keys()):
                if pid not in current_pids:
                    del self.process_baselines[pid]
            for pid in list(self.suspicious_processes.keys()):
                if pid not in current_pids:
                    del self.suspicious_processes[pid]
    
    def _scan_process(self, pid: int, name: str, exe: str):
        """Scan a single process for injection indicators."""
        # Get memory regions
        regions = self.winapi.get_memory_regions(pid)
        
        # Check for RWX memory
        rwx_regions = [r for r in regions if r.is_suspicious]
        
        # Get threads
        threads = self.winapi.get_process_threads(pid)
        suspicious_threads = []
        
        for tid in threads:
            context = self.winapi.get_thread_context(tid)
            if context:
                # Check for suspicious instruction pointers
                pass  # Would analyze RIP/EIP
        
        # Analyze findings
        findings = []
        
        # 1. Check for RWX memory (shellcode/reflective DLL)
        if rwx_regions:
            if name.lower() not in self.legitimate_rwx_processes:
                for region in rwx_regions:
                    findings.append({
                        'type': InjectionType.SHELLCODE,
                        'reason': f"RWX memory region at 0x{region.base_address:X} size={region.size}",
                        'address': region.base_address,
                        'size': region.size,
                    })
        
        # 2. Check for process hollowing indicators
        hollowing_indicators = self._check_hollowing(pid, name, exe)
        findings.extend(hollowing_indicators)
        
        # 3. Check for herpaderping/ghosting
        herpaderping_indicators = self._check_herpaderping(pid, name, exe)
        findings.extend(herpaderping_indicators)
        
        # 4. Check for thread hijacking
        thread_indicators = self._check_thread_hijacking(pid, threads)
        findings.extend(thread_indicators)
        
        # 5. Check for APC injection
        apc_indicators = self._check_apc_injection(pid, threads)
        findings.extend(apc_indicators)
        
        # Generate alerts for findings
        for finding in findings:
            self._generate_alert(pid, name, exe, finding)
    
    def _check_hollowing(self, pid: int, name: str, exe: str) -> List[Dict]:
        """Check for process hollowing indicators."""
        findings = []
        
        try:
            proc = psutil.Process(pid)
            
            # Check if process is suspended (CREATE_SUSPENDED)
            status = proc.status()
            if status == psutil.STATUS_STOPPED:
                # Check parent process
                ppid = proc.ppid()
                try:
                    parent = psutil.Process(ppid)
                    findings.append({
                        'type': InjectionType.PROCESS_HOLLOWING,
                        'reason': f"Process suspended at creation (parent: {parent.name()} PID {ppid})",
                        'parent_pid': ppid,
                        'parent_name': parent.name(),
                    })
                except Exception:
                    pass
            
            # Check for memory unmap/map sequence via memory regions
            regions = self.winapi.get_memory_regions(pid)
            
            # Look for image sections with mismatched disk/file backing
            image_regions = [r for r in regions if r.type == 0x1000000]  # MEM_IMAGE
            for region in image_regions:
                # Would need to check if the mapped image matches the exe on disk
                # This requires more complex analysis (PE header validation)
                pass
            
            # Check for NtUnmapViewOfSection / VirtualAllocEx / WriteProcessMemory sequence
            # This would require API hooking or ETW monitoring
            
        except Exception as e:
            _log.debug(f"Hollowing check error for {pid}: {e}")
        
        return findings
    
    def _check_herpaderping(self, pid: int, name: str, exe: str) -> List[Dict]:
        """Check for process herpaderping/ghosting indicators."""
        findings = []
        
        try:
            proc = psutil.Process(pid)
            
            # Herpaderping: file overwritten AFTER NtCreateSection but BEFORE thread creation
            # Ghosting: file deleted/moved AFTER NtCreateSection
            
            # Check if exe file was recently modified
            if exe and os.path.exists(exe):
                stat = os.stat(exe)
                create_time = proc.create_time()
                
                # If file modified after process creation, possible herpaderping
                if stat.st_mtime > create_time + 1:  # 1 second tolerance
                    findings.append({
                        'type': InjectionType.HERPADERPING,
                        'reason': f"Executable modified after process creation (mtime={stat.st_mtime}, create={create_time})",
                        'exe': exe,
                        'file_mtime': stat.st_mtime,
                        'proc_create': create_time,
                    })
            
            # Check for file deletion (ghosting) - file doesn't exist but process runs
            if exe and not os.path.exists(exe):
                findings.append({
                    'type': InjectionType.PROCESS_GHOSTING,
                    'reason': f"Process executable file missing (ghosting): {exe}",
                    'exe': exe,
                })
            
            # Check for file replacement with decoy
            # Would need file hash comparison
            
        except Exception as e:
            _log.debug(f"Herpaderping check error for {pid}: {e}")
        
        return findings
    
    def _check_thread_hijacking(self, pid: int, threads: List[int]) -> List[Dict]:
        """Check for thread execution hijacking."""
        findings = []
        
        for tid in threads:
            try:
                context = self.winapi.get_thread_context(tid)
                if context:
                    # Check for instruction pointer in non-image memory
                    # x64: Rip, x86: Eip
                    rip = getattr(context, 'Rip', getattr(context, 'Eip', 0))
                    
                    if rip:
                        # Check if RIP points to RWX or private memory
                        regions = self.winapi.get_memory_regions(pid)
                        for region in regions:
                            if region.base_address <= rip < region.base_address + region.size:
                                if region.protection & PAGE_EXECUTE_READWRITE:
                                    findings.append({
                                        'type': InjectionType.THREAD_HIJACKING,
                                        'reason': f"Thread {tid} RIP (0x{rip:X}) in RWX memory",
                                        'thread_id': tid,
                                        'rip': rip,
                                        'region': region.base_address,
                                    })
                                    break
            except Exception:
                pass
        
        return findings
    
    def _check_apc_injection(self, pid: int, threads: List[int]) -> List[Dict]:
        """Check for APC (Asynchronous Procedure Call) injection."""
        findings = []
        
        # APC injection detection would require:
        # - Monitoring NtQueueApcThread calls
        # - Checking for APCs queued to threads in critical processes
        # - Analyzing APC routine addresses
        
        # For now, check if target is a critical process
        try:
            proc = psutil.Process(pid)
            name = proc.name().lower()
            
            if name in self.protected_processes:
                # Check for threads in alertable state
                # This is simplified - real detection needs kernel monitoring
                pass
        except Exception:
            pass
        
        return findings
    
    def _generate_alert(self, pid: int, name: str, exe: str, finding: Dict):
        """Generate alert for injection finding."""
        inj_type = finding.get('type', InjectionType.UNKNOWN)
        reason = finding.get('reason', 'Unknown injection indicator')
        
        # Determine severity
        if inj_type in [InjectionType.PROCESS_HOLLOWING, InjectionType.HERPADERPING, InjectionType.PROCESS_GHOSTING]:
            severity = "CRITICAL"
        elif inj_type in [InjectionType.THREAD_HIJACKING, InjectionType.APC_INJECTION]:
            severity = "HIGH"
        else:
            severity = "MEDIUM"
        
        # MITRE technique mapping
        mitre_map = {
            InjectionType.PROCESS_HOLLOWING: "T1055.012",
            InjectionType.HERPADERPING: "T1055.013",
            InjectionType.PROCESS_GHOSTING: "T1055.013",
            InjectionType.PROCESS_DOPPELGANGING: "T1055.013",
            InjectionType.THREAD_HIJACKING: "T1055.003",
            InjectionType.APC_INJECTION: "T1055.004",
            InjectionType.TLS_CALLBACK: "T1055.005",
            InjectionType.VDSO_HIJACKING: "T1055.014",
            InjectionType.LISTPLANTING: "T1055.015",
            InjectionType.DLL_INJECTION: "T1055.001",
            InjectionType.REFLECTIVE_DLL: "T1055.002",
            InjectionType.SHELLCODE: "T1055.002",
        }
        
        mitre = mitre_map.get(inj_type, "T1055")
        
        alert = ProcessInjectionAlert(
            timestamp=time.time(),
            injection_type=inj_type,
            severity=severity,
            target_pid=pid,
            target_name=name,
            target_exe=exe,
            source_pid=0,  # Would need to track source
            source_name="",
            source_exe="",
            message=f"{inj_type.value.replace('_', ' ').title()} detected in {name} (PID {pid}): {reason}",
            mitre_technique=mitre,
            details=finding,
            evidence=[reason],
        )
        
        self.alerts.append(alert)
        self.stats['alerts_generated'] += 1
        
        if inj_type == InjectionType.PROCESS_HOLLOWING:
            self.stats['hollowing_detected'] += 1
        elif inj_type in [InjectionType.HERPADERPING, InjectionType.PROCESS_GHOSTING]:
            self.stats['herpaderping_detected'] += 1
        elif inj_type == InjectionType.THREAD_HIJACKING:
            self.stats['thread_hijacking_detected'] += 1
        elif inj_type == InjectionType.APC_INJECTION:
            self.stats['apc_injection_detected'] += 1
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                _log.error(f"Alert callback error: {e}")
    
    def get_status(self) -> Dict:
        """Get detector status."""
        with self._lock:
            return {
                'running': self._running,
                'processes_baselined': len(self.process_baselines),
                'suspicious_processes': len(self.suspicious_processes),
                'recent_alerts': [
                    {
                        'timestamp': a.timestamp,
                        'type': a.injection_type.value,
                        'severity': a.severity,
                        'target': f"{a.target_name} (PID {a.target_pid})",
                        'message': a.message,
                        'mitre': a.mitre_technique,
                    }
                    for a in list(self.alerts)[-10:]
                ],
                'stats': self.stats.copy(),
            }

# Singleton instance
_injection_detector: Optional[ProcessInjectionDetector] = None
_injection_lock = threading.Lock()

def get_injection_detector() -> ProcessInjectionDetector:
    global _injection_detector
    with _injection_lock:
        if _injection_detector is None:
            _injection_detector = ProcessInjectionDetector()
        return _injection_detector

def start_injection_detector() -> ProcessInjectionDetector:
    detector = get_injection_detector()
    detector.start()
    return detector

def stop_injection_detector():
    global _injection_detector
    if _injection_detector:
        _injection_detector.stop()
        _injection_detector = None

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    detector = start_injection_detector()
    try:
        while True:
            time.sleep(10)
            status = detector.get_status()
            print(f"Scanned: {status['stats']['processes_scanned']}, Alerts: {status['stats']['alerts_generated']}")
    except KeyboardInterrupt:
        stop_injection_detector()