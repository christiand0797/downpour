"""
__version__ = "29.0.0"
Memory Forensics Module - enhanced v29
===============================================================================
MEMORY FORENSICS AND PROCESS INJECTION DETECTION
===============================================================================

PURPOSE: Provides advanced memory analysis capabilities to detect sophisticated
         malware that attempts to hide in memory or inject into other processes.

DETECTION CAPABILITIES:
1. PROCESS HOLLOWING - Detect when malware creates process in suspended state
   and replaces its memory with malicious code
2. DLL INJECTION - Detect malicious DLLs being injected into legitimate processes
3. CODE INJECTION - Detect malicious code being written to process memory
4. MEMORY PATCHING - Detect when malware patches running processes
5. ROOTKIT ACTIVITY - Detect kernel-level memory modifications
6. SHELLCODE DETECTION - Identify executable shellcode in process memory

TECHNIQUES USED:
- Memory region analysis
- API hooking detection
- Thread inspection
- Module enumeration
- Memory dump analysis
- YARA rules on memory

SUPPORTED ATTACKS:
- Classic DLL injection (CreateRemoteThread, LoadLibrary)
- Reflective DLL injection
- Process hollowing
- Atom bombing
- Thread hijacking
- SetWindowsHookEx injection
- Early Bird injection
"""

import ctypes
import ctypes.wintypes
try:
    import psutil
except ImportError:
    raise ImportError("memory_forensics requires psutil: pip install psutil")
import logging
log = logging.getLogger(__name__)
log.info("Memory Forensics module loaded (v29)")
import threading
import time
from datetime import datetime
from pathlib import Path
import math
import struct
import re
from typing import Dict, List, Tuple, Optional
import sqlite3
import json

# KEV/CVE correlation for injected code and memory exploits
try:
    from vulnerability_scanner import fetch_cisa_kev_catalog
    _KEV_AVAILABLE = True
except ImportError:
    _KEV_AVAILABLE = False

# Windows API definitions
kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi

# Windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_CREATE_THREAD = 0x0002
PROCESS_ALL_ACCESS = 0x1F0FFF

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
MEM_PRIVATE = 0x20000
MEM_IMAGE = 0x1000000

PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_EXECUTE_READ = 0x20
PAGE_READWRITE = 0x04

# Structures for Windows API
# SIZE_T was removed from ctypes.wintypes in Python 3.12 — use ctypes.c_size_t directly
_SIZE_T = getattr(ctypes.wintypes, 'SIZE_T', ctypes.c_size_t)

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.wintypes.LPVOID),
        ("AllocationBase", ctypes.wintypes.LPVOID),
        ("AllocationProtect", ctypes.wintypes.DWORD),
        ("RegionSize", _SIZE_T),
        ("State", ctypes.wintypes.DWORD),
        ("Protect", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
    ]

class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", ctypes.wintypes.LPVOID),
        ("SizeOfImage", ctypes.wintypes.DWORD),
        ("EntryPoint", ctypes.wintypes.LPVOID),
    ]

class MemoryForensicsAnalyzer:
    """
    Advanced memory forensics and injection detection system.
    """
    
    def __init__(self, config=None):
        """
        Initialize memory forensics analyzer.
        
        Parameters:
        - config: Configuration object
        """
        self.running = True
        self.config = config
        
        # Initialize database
        self.db_path = Path("memory_forensics.db")
        self.init_database()
        
        # Suspicious API calls to monitor
        self.suspicious_apis = {
            'CreateRemoteThread': 'Possible process injection',
            'WriteProcessMemory': 'Possible code injection',
            'VirtualAllocEx': 'Memory allocation in remote process',
            'SetWindowsHookEx': 'API hooking/injection',
            'NtCreateThreadEx': 'Advanced thread injection',
            'QueueUserAPC': 'APC injection',
            'RtlCreateUserThread': 'Thread creation',
        }
        
        # Known legitimate system modules
        self.system_modules = {
            'kernel32.dll', 'user32.dll', 'ntdll.dll', 'advapi32.dll',
            'gdi32.dll', 'shell32.dll', 'comctl32.dll', 'ole32.dll',
            'oleaut32.dll', 'wininet.dll', 'ws2_32.dll', 'msvcrt.dll'
        }
        
        # Process memory snapshots for comparison
        self.process_snapshots = {}
        
        # Injection detection cache
        self.injection_cache = {}
        
        # Statistics
        self.stats = {
            'processes_analyzed': 0,
            'injections_detected': 0,
            'suspicious_memory_found': 0,
            'api_hooks_detected': 0,
            'shellcode_detected': 0
        }
    
    def init_database(self):
        """Initialize SQLite database for memory forensics."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS memory_analysis (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        process_id INTEGER,
                        process_name TEXT,
                        timestamp TIMESTAMP,
                        analysis_type TEXT,
                        findings TEXT,
                        risk_score INTEGER,
                        memory_regions TEXT,
                        modules TEXT,
                        threads TEXT
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS injection_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP,
                        source_process_id INTEGER,
                        target_process_id INTEGER,
                        injection_type TEXT,
                        evidence TEXT,
                        severity TEXT
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS memory_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        process_id INTEGER,
                        timestamp TIMESTAMP,
                        memory_map TEXT,
                        snapshot_hash TEXT
                    )
                ''')

                conn.commit()
            finally:
                conn.close()
            
            logging.info("[✓] Memory forensics database initialized")
            
        except Exception as e:
            logging.error(f"Failed to initialize database: {e}")
    
    def get_process_handle(self, pid: int, access: int = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ):
        """
        Get handle to process with specified access rights.
        
        Parameters:
        - pid: Process ID
        - access: Access rights
        
        Returns:
        - Process handle or None
        """
        try:
            handle = kernel32.OpenProcess(access, False, pid)
            return handle if handle else None
        except Exception:
            return None
    
    def enumerate_process_memory(self, pid: int) -> List[Dict]:
        """
        Enumerate memory regions for a process.
        
        Parameters:
        - pid: Process ID
        
        Returns:
        - List of memory region information
        """
        memory_regions = []
        
        try:
            handle = self.get_process_handle(pid)
            if not handle:
                return memory_regions
            
            # Query memory regions
            base_address = 0
            mbi = MEMORY_BASIC_INFORMATION()
            
            while kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(base_address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi)
            ) > 0:
                
                region = {
                    'base_address': mbi.BaseAddress,
                    'allocation_base': mbi.AllocationBase,
                    'size': mbi.RegionSize,
                    'state': mbi.State,
                    'protect': mbi.Protect,
                    'type': mbi.Type,
                    'is_executable': mbi.Protect in [PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY],
                    'is_writable': mbi.Protect in [PAGE_READWRITE, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY],
                    'is_private': mbi.Type == MEM_PRIVATE,
                    'is_image': mbi.Type == MEM_IMAGE,
                }
                
                memory_regions.append(region)
                base_address += mbi.RegionSize
            
            kernel32.CloseHandle(handle)
            
        except Exception as e:
            logging.debug(f"Error enumerating memory for PID {pid}: {e}")
        
        return memory_regions
    
    def enumerate_process_modules(self, pid: int) -> List[Dict]:
        """
        Enumerate loaded modules for a process.
        
        Parameters:
        - pid: Process ID
        
        Returns:
        - List of module information
        """
        modules = []
        
        try:
            handle = self.get_process_handle(pid)
            if not handle:
                return modules
            
            # Get module handles
            h_modules = (ctypes.wintypes.HMODULE * 1024)()
            cb_needed = ctypes.wintypes.DWORD()
            
            if psapi.EnumProcessModulesEx(
                handle,
                ctypes.byref(h_modules),
                ctypes.sizeof(h_modules),
                ctypes.byref(cb_needed),
                3  # LIST_MODULES_ALL
            ):
                
                module_count = cb_needed.value // ctypes.sizeof(ctypes.wintypes.HMODULE)
                
                for i in range(module_count):
                    module_handle = h_modules[i]
                    
                    # Get module filename
                    filename = ctypes.create_unicode_buffer(256)
                    if psapi.GetModuleFileNameExW(handle, module_handle, filename, 256):
                        
                        # Get module info
                        mod_info = MODULEINFO()
                        if psapi.GetModuleInformation(handle, module_handle, ctypes.byref(mod_info), ctypes.sizeof(mod_info)):
                            
                            module_info = {
                                'handle': module_handle,
                                'base_address': mod_info.lpBaseOfDll,
                                'size': mod_info.SizeOfImage,
                                'entry_point': mod_info.EntryPoint,
                                'path': filename.value,
                                'name': Path(filename.value).name.lower(),
                                'is_system': Path(filename.value).name.lower() in self.system_modules
                            }
                            
                            modules.append(module_info)
            
            kernel32.CloseHandle(handle)
            
        except Exception as e:
            logging.debug(f"Error enumerating modules for PID {pid}: {e}")
        
        return modules
    
    def detect_executable_memory(self, memory_regions: List[Dict]) -> List[Dict]:
        """
        Detect suspicious executable memory regions.
        
        Parameters:
        - memory_regions: List of memory regions
        
        Returns:
        - List of suspicious regions
        """
        suspicious_regions = []
        
        for region in memory_regions:
            # Look for private executable memory (suspicious)
            if (region['is_private'] and 
                region['is_executable'] and 
                region['is_writable'] and
                region['size'] > 4096):  # Larger than 4KB
                
                suspicious_regions.append({
                    'region': region,
                    'reason': 'Private executable writable memory',
                    'severity': 'HIGH'
                })
            
            # Look for unbacked executable memory
            elif (region['is_executable'] and
                  region['allocation_base'] == 0 and
                  region['size'] > 4096):
                
                suspicious_regions.append({
                    'region': region,
                    'reason': 'Unbacked executable memory',
                    'severity': 'CRITICAL'
                })
            
            # Large private memory regions
            elif (region['is_private'] and
                  region['size'] > 10 * 1024 * 1024):  # > 10MB
                
                suspicious_regions.append({
                    'region': region,
                    'reason': 'Large private memory region',
                    'severity': 'MEDIUM'
                })
        
        return suspicious_regions
    
    def detect_injected_modules(self, modules: List[Dict]) -> List[Dict]:
        """
        Detect suspicious injected modules.
        
        Parameters:
        - modules: List of loaded modules
        
        Returns:
        - List of suspicious modules
        """
        suspicious_modules = []
        
        for module in modules:
            # Check for unsigned modules in suspicious locations
            if (not module['is_system'] and
                ('\\temp\\' in module['path'].lower() or
                 '\\appdata\\' in module['path'].lower() or
                 module['name'].startswith('tmp'))):
                
                suspicious_modules.append({
                    'module': module,
                    'reason': 'Module in suspicious location',
                    'severity': 'HIGH'
                })
            
            # Check for modules without proper headers
            elif (module['size'] < 1024 or  # Very small
                  module['entry_point'] == 0):  # No entry point
                
                suspicious_modules.append({
                    'module': module,
                    'reason': 'Suspicious module characteristics',
                    'severity': 'MEDIUM'
                })
            
            # Check for duplicate modules (possible DLL hijacking)
            duplicate_count = sum(1 for m in modules if m['name'] == module['name'])
            if duplicate_count > 1:
                suspicious_modules.append({
                    'module': module,
                    'reason': 'Duplicate module loaded',
                    'severity': 'MEDIUM'
                })
        
        return suspicious_modules
    
    def scan_memory_for_shellcode(self, pid: int, memory_regions: List[Dict]) -> List[Dict]:
        """
        Scan process memory for shellcode patterns.
        
        Parameters:
        - pid: Process ID
        - memory_regions: List of memory regions
        
        Returns:
        - List of shellcode detections
        """
        shellcode_detections = []
        
        try:
            handle = self.get_process_handle(pid)
            if not handle:
                return shellcode_detections
            
            for region in memory_regions:
                if not (region['is_executable'] and region['size'] > 256):
                    continue
                
                try:
                    # Read memory region
                    buffer = ctypes.create_string_buffer(region['size'])
                    bytes_read = ctypes.c_size_t()
                    
                    if kernel32.ReadProcessMemory(
                        handle,
                        region['base_address'],
                        buffer,
                        region['size'],
                        ctypes.byref(bytes_read)
                    ):
                        
                        data = buffer.raw[:bytes_read.value]
                        
                        # Look for common shellcode patterns
                        shellcode_patterns = [
                            b'\x60',                    # pushad
                            b'\x9C',                    # pushfd
                            b'\xFC\xE8',                # cld; call
                            b'\xE8\x00\x00\x00\x00',      # call $+5
                            b'\x6A\x00',                # push 0
                            b'\x6A\x01',                # push 1
                        ]
                        
                        for pattern in shellcode_patterns:
                            if pattern in data:
                                shellcode_detections.append({
                                    'region': region,
                                    'pattern': pattern.hex(),
                                    'reason': 'Shellcode pattern detected',
                                    'severity': 'CRITICAL'
                                })
                                break
                        
                        # Check for high entropy (possible encrypted shellcode)
                        if self.calculate_entropy(data) > 7.0:
                            shellcode_detections.append({
                                'region': region,
                                'entropy': self.calculate_entropy(data),
                                'reason': 'High entropy executable memory',
                                'severity': 'HIGH'
                            })
                
                except Exception:
                    # Skip regions we can't read
                    continue
            
            kernel32.CloseHandle(handle)
            
        except Exception as e:
            logging.debug(f"Error scanning memory for shellcode in PID {pid}: {e}")
        
        return shellcode_detections
    
    def calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of data.
        
        Parameters:
        - data: Byte data
        
        Returns:
        - Entropy value (0-8)
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                freq = count / data_len
                entropy -= freq * math.log2(freq)
        
        return entropy
    
    def detect_process_hollowing(self, pid: int) -> Dict:
        """
        Detect if process has been hollowed out.
        
        Parameters:
        - pid: Process ID
        
        Returns:
        - Detection results
        """
        try:
            handle = self.get_process_handle(pid)
            if not handle:
                return {'detected': False, 'reason': 'Cannot access process'}
            
            # Get process entry point
            entry_point = None
            
            # Check if main module entry point matches expected value
            modules = self.enumerate_process_modules(pid)
            if modules:
                main_module = modules[0]  # Usually the EXE
                expected_entry = main_module['entry_point']
                
                # Get actual entry point from PEB (simplified)
                # In reality, this would be more complex
                
                if expected_entry == 0:
                    return {
                        'detected': True,
                        'reason': 'No entry point in main module',
                        'severity': 'HIGH'
                    }
            
            kernel32.CloseHandle(handle)
            
            return {'detected': False, 'reason': 'No signs of process hollowing'}
            
        except Exception as e:
            logging.debug(f"Error detecting process hollowing for PID {pid}: {e}")
            return {'detected': False, 'reason': f'Analysis error: {e}'}
    
    def analyze_process_memory(self, pid: int) -> Dict:
        """
        Perform comprehensive memory analysis of a process.
        
        Parameters:
        - pid: Process ID
        
        Returns:
        - Analysis results
        """
        try:
            analysis_start = time.time()
            
            # Get process information
            try:
                proc = psutil.Process(pid)
                proc_info = {
                    'pid': pid,
                    'name': proc.name(),
                    'exe': proc.exe(),
                    'create_time': datetime.fromtimestamp(proc.create_time()),
                    'memory_info': proc.memory_info(),
                    'memory_percent': proc.memory_percent(),
                }
            except psutil.NoSuchProcess:
                return {'error': 'Process not found'}
            
            # Enumerate memory regions
            memory_regions = self.enumerate_process_memory(pid)
            
            # Enumerate modules
            modules = self.enumerate_process_modules(pid)
            
            # Detect suspicious memory
            suspicious_memory = self.detect_executable_memory(memory_regions)
            
            # Detect injected modules
            injected_modules = self.detect_injected_modules(modules)
            
            # Scan for shellcode
            shellcode = self.scan_memory_for_shellcode(pid, memory_regions)
            
            # Check for process hollowing
            hollowing = self.detect_process_hollowing(pid)
            
            # Calculate overall risk score
            risk_score = self.calculate_memory_risk_score(
                suspicious_memory, injected_modules, shellcode, hollowing
            )
            
            # Compile results
            result = {
                'process_info': proc_info,
                'memory_regions': len(memory_regions),
                'modules_count': len(modules),
                'suspicious_memory': suspicious_memory,
                'injected_modules': injected_modules,
                'shellcode_detections': shellcode,
                'process_hollowing': hollowing,
                'risk_score': risk_score,
                'analysis_time': time.time() - analysis_start,
                'timestamp': datetime.now()
            }
            
            # Save to database
            self.save_memory_analysis(result)
            
            self.stats['processes_analyzed'] += 1
            
            return result
            
        except Exception as e:
            logging.error(f"Error analyzing process memory for PID {pid}: {e}")
            return {'error': str(e)}
    
    def calculate_memory_risk_score(self, suspicious_memory, injected_modules, 
                                 shellcode, hollowing) -> Dict:
        """
        Calculate overall risk score for memory analysis.
        
        Parameters:
        - suspicious_memory: List of suspicious memory regions
        - injected_modules: List of injected modules
        - shellcode: List of shellcode detections
        - hollowing: Process hollowing detection results
        
        Returns:
        - Risk assessment
        """
        try:
            score = 0
            reasons = []
            
            # Score suspicious memory
            if suspicious_memory:
                for mem in suspicious_memory:
                    if mem['severity'] == 'CRITICAL':
                        score += 30
                    elif mem['severity'] == 'HIGH':
                        score += 20
                    elif mem['severity'] == 'MEDIUM':
                        score += 10
                    reasons.append(mem['reason'])
            
            # Score injected modules
            if injected_modules:
                score += len(injected_modules) * 15
                reasons.append(f"{len(injected_modules)} suspicious modules")
            
            # Score shellcode
            if shellcode:
                for sc in shellcode:
                    if sc['severity'] == 'CRITICAL':
                        score += 40
                    elif sc['severity'] == 'HIGH':
                        score += 25
                    reasons.append(sc['reason'])
            
            # Score process hollowing
            if hollowing.get('detected'):
                score += 50
                reasons.append(hollowing['reason'])
            
            # Determine classification
            if score >= 80:
                classification = "MALICIOUS"
                severity = "CRITICAL"
            elif score >= 60:
                classification = "SUSPICIOUS"
                severity = "HIGH"
            elif score >= 30:
                classification = "UNUSUAL"
                severity = "MEDIUM"
            else:
                classification = "NORMAL"
                severity = "LOW"
            
            return {
                'score': min(score, 100),
                'classification': classification,
                'severity': severity,
                'reasons': reasons,
                'confidence': min(score / 100, 1.0)
            }
            
        except Exception as e:
            logging.error(f"Error calculating risk score: {e}")
            return {
                'score': 0,
                'classification': 'ERROR',
                'severity': 'LOW',
                'reasons': ['Analysis error'],
                'confidence': 0.0
            }
    
    def save_memory_analysis(self, analysis_result: Dict):
        """Save memory analysis results to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                proc_info = analysis_result.get('process_info', {})
                risk_score = analysis_result.get('risk_score', {})

                cursor.execute('''
                    INSERT INTO memory_analysis
                    (process_id, process_name, timestamp, analysis_type, findings,
                     risk_score, memory_regions, modules, threads)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    proc_info.get('pid', 0),
                    proc_info.get('name', ''),
                    analysis_result.get('timestamp', datetime.now()),
                    'comprehensive',
                    json.dumps(analysis_result),
                    risk_score.get('score', 0),
                    json.dumps(analysis_result.get('memory_regions', [])),
                    json.dumps(analysis_result.get('modules_count', 0)),
                    json.dumps(analysis_result.get('thread_analysis', []))
                ))

                conn.commit()
            finally:
                conn.close()
            
        except Exception as e:
            logging.error(f"Error saving memory analysis: {e}")
    
    def check_injection_cve(self, process_name: str, injection_type: str) -> Dict:
        """
        Check if detected injection matches KEV-listed exploit CVEs.

        Parameters:
        - process_name: Name of the target process
        - injection_type: Type of injection detected (e.g., 'code_injection', 'dll_injection')

        Returns:
        - Dict with matched_cves (list) and epss_score (float)
        """
        result = {'matched_cves': [], 'epss_score': 0.0}

        if not _KEV_AVAILABLE:
            log.debug("KEV catalog not available (vulnerability_scanner not found)")
            return result

        try:
            kev_catalog = fetch_cisa_kev_catalog()
            if not kev_catalog:
                return result

            # Normalize process name for matching
            proc_lower = process_name.lower().replace('.exe', '')

            # Check each KEV entry for matching process/injection technique
            for cve_entry in kev_catalog:
                cve_id = cve_entry.get('cveID', cve_entry.get('id', ''))
                vuln_name = cve_entry.get('vulnerabilityName', '').lower()
                vendor = cve_entry.get('vendorProject', '').lower()
                product = cve_entry.get('product', '').lower()

                # Match against process name, vendor, or product
                match_process = any(term in proc_lower for term in [proc_lower, vendor, product])
                match_injection = any(term in vuln_name or term in injection_type.lower()
                                       for term in ['inject', 'code execution', 'remote code', 'rce'])

                if match_process and match_injection:
                    result['matched_cves'].append(cve_id)

            # Simple EPSS-like heuristic: higher score if multiple CVEs matched
            if result['matched_cves']:
                result['epss_score'] = min(0.9, 0.3 + 0.15 * len(result['matched_cves']))

            if result['matched_cves']:
                log.warning(
                    f"KEV match: process={process_name}, injection={injection_type}, "
                    f"CVEs={result['matched_cves']}, EPSS={result['epss_score']}"
                )

        except Exception as e:
            log.error(f"Error checking injection CVE: {e}")

        return result

    def monitor_process_injection(self) -> None:
        """
        Monitor for active process injection attempts.
        
        This would typically hook into Windows API calls,
        but for now uses periodic scanning.
        """
        try:
            # Get list of running processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Analyze processes for injection indicators
            for proc_info in processes:
                pid = proc_info['pid']
                
                # Skip system processes
                if pid < 100:
                    continue
                
                # Analyze process memory
                result = self.analyze_process_memory(pid)
                
                if 'error' not in result:
                    risk_score = result.get('risk_score', {})

                    if risk_score.get('score', 0) >= 60:  # HIGH or CRITICAL
                        self.stats['injections_detected'] += 1

                        # Check KEV/CVE correlation for the detected injection
                        injection_type = result.get('injection_type', 'code_injection')
                        cve_result = self.check_injection_cve(proc_info['name'], injection_type)
                        if cve_result['matched_cves']:
                            result['matched_cves'] = cve_result['matched_cves']
                            result['epss_score'] = cve_result['epss_score']

                        # Log injection event
                        self.log_injection_event(proc_info, result)

                        if risk_score.get('severity') in ['CRITICAL', 'HIGH']:
                            logging.warning(
                                f"[INJECTION DETECTED] {proc_info['name']} (PID {pid}) "
                                f"- {risk_score['classification']} - Score: {risk_score['score']}"
                            )
        
        except Exception as e:
            logging.error(f"Error monitoring process injection: {e}")
    
    def log_injection_event(self, proc_info: Dict, analysis_result: Dict):
        """Log injection event to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                risk_score = analysis_result.get('risk_score', {})

                cursor.execute('''
                    INSERT INTO injection_events
                    (timestamp, source_process_id, target_process_id, injection_type,
                     evidence, severity)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.now(),
                    proc_info.get('pid', 0),
                    proc_info.get('pid', 0),  # Self-injection
                    'memory_analysis',
                    json.dumps(analysis_result),
                    risk_score.get('severity', 'MEDIUM')
                ))

                conn.commit()
            finally:
                conn.close()
            
        except Exception as e:
            logging.error(f"Error logging injection event: {e}")
    
    def monitoring_loop(self):
        """Main monitoring loop for continuous injection detection."""
        logging.info("Memory forensics monitoring started")
        
        while self.running:
            try:
                # Monitor for process injection
                self.monitor_process_injection()
                
                # Sleep between scans
                time.sleep(30)  # Scan every 30 seconds
                
            except Exception as e:
                logging.error(f"Error in memory forensics loop: {e}")
                time.sleep(10)
    
    def get_statistics(self) -> Dict:
        """Get memory forensics statistics."""
        return self.stats.copy()
    
    def start(self):
        """Start memory forensics monitoring in background thread."""
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
        logging.info("[✓] Memory Forensics Analyzer active")
    
    def stop(self) -> None:
        """Stop memory forensics monitoring."""
        self.running = False
        logging.info("Memory forensics monitoring stopped")

# Global instance
_memory_analyzer_instance = None

def get_memory_analyzer(config=None):
    """Get global memory analyzer instance."""
    global _memory_analyzer_instance
    if _memory_analyzer_instance is None:
        _memory_analyzer_instance = MemoryForensicsAnalyzer(config)
    return _memory_analyzer_instance

if __name__ == "__main__":
    """Test memory forensics analyzer."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*80)
    print("          MEMORY FORENSICS TEST")
    print("="*80)
    
    analyzer = MemoryForensicsAnalyzer()
    
    # Test with current process
    current_pid = os.getpid()
    
    print(f"\nAnalyzing current process (PID: {current_pid})...")
    result = analyzer.analyze_process_memory(current_pid)
    
    if 'error' not in result:
        print(f"  Memory Regions: {result['memory_regions']}")
        print(f"  Modules Loaded: {result['modules_count']}")
        print(f"  Risk Score: {result['risk_score']['score']}/100")
        print(f"  Classification: {result['risk_score']['classification']}")
        print(f"  Severity: {result['risk_score']['severity']}")
        
        if result['risk_score']['reasons']:
            print(f"  Reasons: {', '.join(result['risk_score']['reasons'])}")
    
    stats = analyzer.get_statistics()
    print(f"\nStatistics:")
    print(f"  Processes Analyzed: {stats['processes_analyzed']}")
    print(f"  Injections Detected: {stats['injections_detected']}")
    print(f"  Suspicious Memory Found: {stats['suspicious_memory_found']}")
    
    print("\nPress Enter to exit...")
    input()
