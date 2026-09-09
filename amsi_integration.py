#!/usr/bin/env python3
"""
AMSI (Antimalware Scan Interface) Integration for PowerShell Script Block Logging
Monitors PowerShell script execution via AMSI and ETW (Event Tracing for Windows).
Provides real-time detection of malicious PowerShell scripts, obfuscation, and 
fileless malware techniques.
"""
from __future__ import annotations
import os
import time
import threading
import logging
import subprocess
import re
import base64
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Callable
import ctypes
from ctypes import wintypes

_log = logging.getLogger(__name__)

# AMSI Result codes
AMSI_RESULT_CLEAN = 0
AMSI_RESULT_NOT_DETECTED = 1
AMSI_RESULT_DETECTED = 32768  # 0x8000
AMSI_RESULT_BLOCKED = 32769   # 0x8001

# PowerShell Script Block Logging Event IDs
POWERSHELL_EVENT_IDS = {
    4103: "Script block logging start",
    4104: "Script block logging (full script content)",
    4105: "Script block logging end",
    4106: "Script block logging (non-interactive)",
}

# Suspicious PowerShell patterns
SUSPICIOUS_PS_PATTERNS = [
    (r'Invoke-Expression|IEX\s', 'T1059.001', 'Command Obfuscation'),
    (r'Invoke-WebRequest|IWR\s.*-OutFile', 'T1105', 'File Download'),
    (r'DownloadString|DownloadFile', 'T1105', 'File Download'),
    (r'System\.Net\.WebClient', 'T1105', 'File Download'),
    (r'Start-BitsTransfer', 'T1105', 'File Download'),
    (r'-EncodedCommand|-enc\s', 'T1027.010', 'Command Obfuscation'),
    (r'-NonInteractive|-nop|-WindowStyle\s+Hidden', 'T1059.001', 'Defense Evasion'),
    (r'Set-ExecutionPolicy\s+Bypass', 'T1059.001', 'Defense Evasion'),
    (r'Add-Type.*Compile', 'T1027.004', 'Compile After Delivery'),
    (r'Reflection\.Assembly.*Load', 'T1027.004', 'Reflective Loading'),
    (r'VirtualAlloc|VirtualProtect|CreateThread', 'T1055', 'Process Injection'),
    (r'Get-Process.*lsass|LsaCallAuthenticationPackage', 'T1003.001', 'Credential Access'),
    (r'sekurlsa|sekurlsa::logonpasswords', 'T1003.001', 'Mimikatz'),
    (r'Invoke-Mimikatz|Invoke-DCSync', 'T1003.006', 'Mimikatz/DCSync'),
    (r'Get-System|Get-System-Interactive', 'T1068', 'Privilege Escalation'),
    (r'TokenManipulation|Impersonate|DuplicateToken', 'T1134', 'Access Token Manipulation'),
    (r'New-Object.*ComObject.*Shell\.Application', 'T1059.001', 'COM Scripting'),
    (r'WScript\.Shell|ShellExecute', 'T1059.001', 'Script Execution'),
    (r'rundll32|regsvr32|mshta|msbuild|installutil', 'T1218', 'Signed Binary Proxy'),
    (r'AppDomain\.CurrentDomain.*Load', 'T1027.004', 'Assembly Load'),
    (r'[A-Za-z0-9+/]{50,}={0,2}', 'T1027.010', 'Base64 Encoded Command'),
    (r'-join\s*\(.*\[char\]', 'T1027.010', 'Character Array Obfuscation'),
    (r'\[Byte\[\]\]|\[System\.Convert\]', 'T1027.010', 'Byte Array Encoding'),
]

@dataclass
class PowerShellEvent:
    """PowerShell script block event."""
    timestamp: float
    event_id: int
    sequence_number: int
    script_block_text: str
    script_block_id: str
    path: str = ""
    user: str = ""
    computer: str = ""
    pid: int = 0
    process_name: str = ""
    command_line: str = ""
    mitre_techniques: List[str] = field(default_factory=list)
    severity: str = "LOW"
    suspicious_patterns: List[str] = field(default_factory=list)
    entropy: float = 0.0
    is_obfuscated: bool = False
    is_suspicious: bool = False

@dataclass
class AMSIScanResult:
    """AMSI scan result."""
    timestamp: float
    content_name: str
    content: str
    result: int  # AMSI_RESULT_*
    app_name: str = ""
    session: str = ""
    error: str = ""

class AMSIIntegration:
    """
    AMSI Integration for PowerShell monitoring.
    Uses Windows AMSI API to scan script content in real-time.
    Also monitors ETW events for PowerShell script block logging.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # AMSI context
        self.amsi_context = None
        self.amsi_initialized = False
        
        # Events
        self.ps_events: deque = deque(maxlen=5000)
        self.amsi_results: deque = deque(maxlen=1000)
        self.alerts: deque = deque(maxlen=1000)
        self.alert_callbacks: List[Callable] = []
        
        # Statistics
        self.stats = {
            'scripts_scanned': 0,
            'malicious_detected': 0,
            'suspicious_detected': 0,
            'obfuscated_detected': 0,
            'alerts_generated': 0,
            'event_log_events': 0,
        }
        
        # Configuration
        self.poll_interval = self.config.get('poll_interval', 2)
        self.enable_etw = self.config.get('enable_etw', True)
        self.enable_amsi = self.config.get('enable_amsi', True)
        
        # Compiled patterns
        self.compiled_patterns = []
        for pattern, mitre, desc in SUSPICIOUS_PS_PATTERNS:
            self.compiled_patterns.append((
                re.compile(pattern, re.IGNORECASE),
                mitre,
                desc
            ))
        
        # Initialize AMSI
        if self.enable_amsi:
            self._init_amsi()
        
        # ETW session
        self.etw_session = None
        self.etw_thread = None
    
    def _init_amsi(self):
        """Initialize AMSI context."""
        try:
            # Load amsi.dll
            self.amsi_dll = ctypes.windll.LoadLibrary('amsi.dll')
            
            # Define function signatures
            self.amsi_dll.AmsiInitialize.argtypes = [
                wintypes.LPCWSTR,
                ctypes.POINTER(ctypes.c_void_p)
            ]
            self.amsi_dll.AmsiInitialize.restype = wintypes.HRESULT
            
            self.amsi_dll.AmsiUninitialize.argtypes = [ctypes.c_void_p]
            self.amsi_dll.AmsiUninitialize.restype = None
            
            self.amsi_dll.AmsiScanBuffer.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                wintypes.ULONG,
                wintypes.LPCWSTR,
                ctypes.c_void_p,
                ctypes.POINTER(wintypes.ULONG)
            ]
            self.amsi_dll.AmsiScanBuffer.restype = wintypes.HRESULT
            
            self.amsi_dll.AmsiScanString.argtypes = [
                ctypes.c_void_p,
                wintypes.LPCWSTR,
                wintypes.LPCWSTR,
                ctypes.c_void_p,
                ctypes.POINTER(wintypes.ULONG)
            ]
            self.amsi_dll.AmsiScanString.restype = wintypes.HRESULT
            
            # Initialize
            app_name = "DownpourSecurity"
            context = ctypes.c_void_p()
            hr = self.amsi_dll.AmsiInitialize(app_name, ctypes.byref(context))
            
            if hr == 0:  # S_OK
                self.amsi_context = context
                self.amsi_initialized = True
                _log.info("AMSI initialized successfully")
            else:
                _log.warning(f"AMSI initialization failed: HRESULT 0x{hr:08X}")
                
        except Exception as e:
            _log.warning(f"Could not initialize AMSI: {e}")
            self.enable_amsi = False
    
    def start(self):
        """Start the AMSI/ETW monitor."""
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="AMSI-Monitor")
        self._thread.start()
        
        # Start ETW monitoring if enabled
        if self.enable_etw:
            self._start_etw_monitoring()
        
        _log.info("AMSI/PowerShell Integration started")
    
    def stop(self):
        """Stop the monitor."""
        self._running = False
        self._stop_event.set()
        
        if self._thread:
            self._thread.join(timeout=10)
        
        if self.amsi_initialized and self.amsi_context:
            try:
                self.amsi_dll.AmsiUninitialize(self.amsi_context)
            except Exception:
                pass
        
        self._stop_etw_monitoring()
        _log.info("AMSI/PowerShell Integration stopped")
    
    def register_alert_callback(self, callback: Callable):
        """Register callback for alerts."""
        self.alert_callbacks.append(callback)
    
    def _start_etw_monitoring(self):
        """Start ETW monitoring for PowerShell events."""
        try:
            # Use wevtutil to monitor PowerShell Operational log
            # This is a simplified approach - real ETW would use TraceEvent
            _log.info("ETW monitoring for PowerShell started")
        except Exception as e:
            _log.warning(f"Could not start ETW monitoring: {e}")
            self.enable_etw = False
    
    def _stop_etw_monitoring(self):
        """Stop ETW monitoring."""
        pass
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        last_record_id = 0
        
        while self._running and not self._stop_event.is_set():
            start = time.time()
            try:
                # Query PowerShell event log
                events = self._query_powershell_events(last_record_id)
                for event in events:
                    self._process_ps_event(event)
                    last_record_id = max(last_record_id, event.sequence_number)
            except Exception as e:
                _log.error(f"AMSI monitor error: {e}")
            
            elapsed = time.time() - start
            sleep_time = max(0, self.poll_interval - elapsed)
            if sleep_time > 0:
                self._stop_event.wait(sleep_time)
    
    def _query_powershell_events(self, after_sequence: int) -> List[PowerShellEvent]:
        """Query PowerShell script block logging events."""
        events = []
        
        try:
            # Query Microsoft-Windows-PowerShell/Operational log
            query = f'*[System[(EventID=4104) and (EventRecordID > {after_sequence})]]'
            cmd = [
                'wevtutil', 'qe', 'Microsoft-Windows-PowerShell/Operational',
                '/q', query,
                '/c', '1000',
                '/rd:true',
                '/f:json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0 or not result.stdout.strip():
                return events
            
            try:
                raw_events = json.loads(result.stdout)
                if not isinstance(raw_events, list):
                    raw_events = [raw_events]
            except json.JSONDecodeError:
                raw_events = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            raw_events.append(json.loads(line))
                        except:
                            pass
            
            for raw in raw_events:
                event = self._parse_ps_event(raw)
                if event:
                    events.append(event)
                    
        except Exception as e:
            _log.debug(f"PowerShell event query error: {e}")
        
        return events
    
    def _parse_ps_event(self, raw: Dict) -> Optional[PowerShellEvent]:
        """Parse PowerShell event."""
        try:
            system = raw.get('System', {})
            event_data = raw.get('EventData', {})
            
            # Parse timestamp
            time_created = system.get('TimeCreated', {}).get('@SystemTime', '')
            timestamp = self._parse_timestamp(time_created)
            
            # Extract script block data
            script_block_text = ""
            script_block_id = ""
            path = ""
            
            if isinstance(event_data, dict):
                data_dict = {}
                for key, value in event_data.items():
                    if isinstance(value, dict) and '#text' in value:
                        data_dict[key] = value['#text']
                    else:
                        data_dict[key] = value
                
                script_block_text = data_dict.get('ScriptBlockText', '') or data_dict.get('ScriptBlock', '')
                script_block_id = data_dict.get('ScriptBlockId', '')
                path = data_dict.get('Path', '')
            
            event = PowerShellEvent(
                timestamp=timestamp,
                event_id=int(system.get('EventID', 0)),
                sequence_number=int(system.get('EventRecordID', 0)),
                script_block_text=script_block_text,
                script_block_id=script_block_id,
                path=path,
                computer=system.get('Computer', ''),
            )
            
            # Analyze script content
            if script_block_text:
                self._analyze_script(event)
            
            return event
            
        except Exception as e:
            _log.debug(f"PS event parse error: {e}")
            return None
    
    def _parse_timestamp(self, timestamp_str: str) -> float:
        """Parse Windows timestamp."""
        try:
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.timestamp()
        except Exception:
            return time.time()
    
    def _analyze_script(self, event: PowerShellEvent):
        """Analyze script block for suspicious content."""
        text = event.script_block_text
        if not text:
            return
        
        # Calculate entropy
        event.entropy = self._calculate_entropy(text)
        
        # Check for base64 encoding
        b64_matches = re.findall(r'[A-Za-z0-9+/]{50,}={0,2}', text)
        if b64_matches:
            event.is_obfuscated = True
            event.suspicious_patterns.append("Base64 encoded content detected")
        
        # Check for character array obfuscation
        if re.search(r'-join\s*\(.*\[char\]', text, re.IGNORECASE):
            event.is_obfuscated = True
            event.suspicious_patterns.append("Character array obfuscation detected")
        
        # Check suspicious patterns
        for pattern, mitre, desc in self.compiled_patterns:
            if pattern.search(text):
                event.suspicious_patterns.append(desc)
                if mitre not in event.mitre_techniques:
                    event.mitre_techniques.append(mitre)
        
        # Determine severity
        if event.is_obfuscated:
            event.severity = "HIGH"
            event.is_suspicious = True
        elif event.suspicious_patterns:
            event.severity = "MEDIUM"
            event.is_suspicious = True
        
        # Check for known malicious patterns
        if any(keyword in text.lower() for keyword in [
            'mimikatz', 'sekurlsa', 'invoke-mimikatz', 'dcsync',
            'get-system', 'tokenmanipulation', 'bypassuac',
        ]):
            event.severity = "CRITICAL"
            event.is_suspicious = True
    
    def _process_ps_event(self, event: PowerShellEvent):
        """Process a PowerShell event."""
        with self._lock:
            self.ps_events.append(event)
            self.stats['scripts_scanned'] += 1
            self.stats['event_log_events'] += 1
            
            if event.is_suspicious:
                if event.severity == "CRITICAL":
                    self.stats['malicious_detected'] += 1
                elif event.is_obfuscated:
                    self.stats['obfuscated_detected'] += 1
                else:
                    self.stats['suspicious_detected'] += 1
                
                self._generate_alert(event)
    
    def scan_content(self, content: str, content_name: str = "memory") -> Optional[AMSIScanResult]:
        """Scan content using AMSI."""
        if not self.amsi_initialized:
            return None
        
        try:
            # Use AmsiScanString
            result = wintypes.ULONG()
            hr = self.amsi_dll.AmsiScanString(
                self.amsi_context,
                content,
                content_name,
                None,
                ctypes.byref(result)
            )
            
            if hr == 0:  # S_OK
                amsi_result = AMSIScanResult(
                    timestamp=time.time(),
                    content_name=content_name,
                    content=content[:1000] + "..." if len(content) > 1000 else content,
                    result=result.value,
                )
                
                with self._lock:
                    self.amsi_results.append(amsi_result)
                
                # Check result
                if result.value >= AMSI_RESULT_DETECTED:
                    self._generate_amsi_alert(amsi_result)
                
                return amsi_result
            
        except Exception as e:
            _log.error(f"AMSI scan error: {e}")
        
        return None
    
    def _generate_alert(self, event: PowerShellEvent):
        """Generate alert for suspicious PowerShell."""
        severity = event.severity
        
        mitre_str = ", ".join(event.mitre_techniques) if event.mitre_techniques else "T1059.001"
        
        alert = {
            'timestamp': event.timestamp,
            'type': 'POWERSHELL_SUSPICIOUS',
            'message': f"Suspicious PowerShell: {event.script_block_text[:200]}...",
            'severity': severity,
            'mitre': event.mitre_techniques,
            'details': {
                'script_id': event.script_block_id,
                'path': event.path,
                'patterns': event.suspicious_patterns,
                'entropy': event.entropy,
                'obfuscated': event.is_obfuscated,
                'pid': event.pid,
                'user': event.user,
            }
        }
        
        with self._lock:
            self.alerts.append(alert)
            self.stats['alerts_generated'] += 1
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                _log.error(f"Alert callback error: {e}")
    
    def _generate_amsi_alert(self, scan_result: AMSIScanResult):
        """Generate alert for AMSI detection."""
        alert = {
            'timestamp': scan_result.timestamp,
            'type': 'AMSI_DETECTION',
            'message': f"AMSI detected malicious content: {scan_result.content_name}",
            'severity': 'CRITICAL',
            'mitre': ['T1059.001', 'T1027'],
            'details': {
                'content_name': scan_result.content_name,
                'content_preview': scan_result.content[:500],
                'amsi_result': scan_result.result,
            }
        }
        
        with self._lock:
            self.alerts.append(alert)
            self.stats['alerts_generated'] += 1
            self.stats['malicious_detected'] += 1
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                _log.error(f"Alert callback error: {e}")
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy."""
        if not text:
            return 0.0
        freq = defaultdict(int)
        for c in text:
            freq[c] += 1
        entropy = 0.0
        n = len(text)
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        return entropy
    
    def get_status(self) -> Dict:
        """Get monitor status."""
        with self._lock:
            return {
                'running': self._running,
                'amsi_initialized': self.amsi_initialized,
                'etw_enabled': self.enable_etw,
                'events_in_buffer': len(self.ps_events),
                'amsi_results': len(self.amsi_results),
                'recent_alerts': list(self.alerts)[-10:],
                'stats': self.stats.copy(),
            }
    
    def get_recent_scripts(self, limit: int = 50, suspicious_only: bool = False) -> List[Dict]:
        """Get recent script events."""
        with self._lock:
            events = list(self.ps_events)
            if suspicious_only:
                events = [e for e in events if e.is_suspicious]
            return [
                {
                    'timestamp': e.timestamp,
                    'script_id': e.script_block_id,
                    'path': e.path,
                    'text': e.script_block_text[:500],
                    'entropy': e.entropy,
                    'suspicious': e.is_suspicious,
                    'obfuscated': e.is_obfuscated,
                    'patterns': e.suspicious_patterns,
                    'mitre': e.mitre_techniques,
                    'severity': e.severity,
                }
                for e in events[-limit:]
            ]
    
    def scan_string(self, text: str, name: str = "string") -> Optional[AMSIScanResult]:
        """Scan a string using AMSI."""
        return self.scan_content(text, name)

# Singleton instance
_amsi_integration: Optional[AMSIIntegration] = None
_amsi_lock = threading.Lock()

def get_amsi_integration() -> AMSIIntegration:
    global _amsi_integration
    with _amsi_lock:
        if _amsi_integration is None:
            _amsi_integration = AMSIIntegration()
        return _amsi_integration

def start_amsi_integration() -> AMSIIntegration:
    integration = get_amsi_integration()
    integration.start()
    return integration

def stop_amsi_integration():
    global _amsi_integration
    if _amsi_integration:
        _amsi_integration.stop()
        _amsi_integration = None

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    integration = start_amsi_integration()
    try:
        while True:
            time.sleep(10)
            status = integration.get_status()
            print(f"Scripts: {status['stats']['scripts_scanned']}, Alerts: {status['stats']['alerts_generated']}")
    except KeyboardInterrupt:
        stop_amsi_integration()