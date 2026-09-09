#!/usr/bin/env python3
"""
Sysmon Native Windows Event Monitor
Monitors Windows Event Logs for Sysmon events (built into Windows 11/Server 2025+).
Provides real-time detection of process creation, network connections, 
file creation, registry changes, and process tampering.
"""
from __future__ import annotations
import os
import time
import threading
import logging
import json
import subprocess
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Callable
from datetime import datetime
import re

_log = logging.getLogger(__name__)

# Sysmon Event IDs
class SysmonEventID:
    PROCESS_CREATE = 1
    FILE_CREATE_TIME = 2
    NETWORK_CONNECT = 3
    PROCESS_TERMINATE = 5
    DRIVER_LOAD = 6
    IMAGE_LOAD = 7
    CREATE_REMOTE_THREAD = 8
    RAW_ACCESS_READ = 9
    PROCESS_ACCESS = 10
    FILE_CREATE = 11
    REGISTRY_CREATE = 12
    REGISTRY_VALUE_SET = 13
    REGISTRY_DELETE = 14
    FILE_CREATE_STREAM_HASH = 15
    SYSMON_CONFIG_CHANGE = 16
    PIPE_CREATE = 17
    PIPE_CONNECT = 18
    WMI_EVENT_FILTER = 19
    WMI_EVENT_CONSUMER = 20
    WMI_EVENT_BINDING = 21
    DNS_QUERY = 22
    FILE_DELETE = 23
    CLIPBOARD_CHANGE = 24
    PROCESS_TAMPERING = 25  # Herpaderping, hollowing, etc.
    FILE_DELETE_ARCHIVED = 26

# MITRE ATT&CK mapping for Sysmon events
SYSMON_MITRE_MAP = {
    SysmonEventID.PROCESS_CREATE: ["T1059", "T1059.001", "T1059.003", "T1059.005", "T1569"],
    SysmonEventID.FILE_CREATE: ["T1105", "T1027", "T1547"],
    SysmonEventID.NETWORK_CONNECT: ["T1071", "T1071.001", "T1571"],
    SysmonEventID.DRIVER_LOAD: ["T1068", "T1547.006"],
    SysmonEventID.IMAGE_LOAD: ["T1055", "T1055.001", "T1055.002"],
    SysmonEventID.CREATE_REMOTE_THREAD: ["T1055", "T1055.002"],
    SysmonEventID.PROCESS_ACCESS: ["T1003", "T1055", "T1055.004"],
    SysmonEventID.FILE_CREATE_STREAM_HASH: ["T1564.004"],
    SysmonEventID.REGISTRY_CREATE: ["T1547", "T1112"],
    SysmonEventID.REGISTRY_VALUE_SET: ["T1547", "T1112", "T1112"],
    SysmonEventID.PIPE_CREATE: ["T1570"],
    SysmonEventID.PIPE_CONNECT: ["T1570"],
    SysmonEventID.WMI_EVENT_FILTER: ["T1546.003"],
    SysmonEventID.WMI_EVENT_CONSUMER: ["T1546.003"],
    SysmonEventID.WMI_EVENT_BINDING: ["T1546.003"],
    SysmonEventID.DNS_QUERY: ["T1071.004", "T1568"],
    SysmonEventID.FILE_DELETE: ["T1070.004", "T1485"],
    SysmonEventID.PROCESS_TAMPERING: ["T1055.012", "T1055.013"],
    SysmonEventID.FILE_DELETE_ARCHIVED: ["T1070.004"],
}

@dataclass
class SysmonEvent:
    """Parsed Sysmon event."""
    event_id: int
    timestamp: float
    event_record_id: int
    computer: str
    channel: str
    level: str
    task: str
    opcode: str
    keywords: str
    # Event-specific fields
    data: Dict[str, Any] = field(default_factory=dict)
    # Parsed fields
    pid: int = 0
    ppid: int = 0
    process_name: str = ""
    command_line: str = ""
    parent_command_line: str = ""
    image: str = ""
    parent_image: str = ""
    user: str = ""
    integrity_level: str = ""
    hashes: Dict[str, str] = field(default_factory=dict)
    dst_ip: str = ""
    dst_port: int = 0
    src_ip: str = ""
    src_port: int = 0
    protocol: str = ""
    target_filename: str = ""
    target_object: str = ""
    details: str = ""
    # MITRE tags
    mitre_techniques: List[str] = field(default_factory=list)

class SysmonMonitor:
    """
    Monitors Windows Event Log for Sysmon events.
    Uses wevtutil for querying events (native Windows tool).
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Event storage
        self.recent_events: deque = deque(maxlen=10000)
        self.event_counts: Dict[int, int] = defaultdict(int)
        
        # Alerts
        self.alerts: deque = deque(maxlen=1000)
        self.alert_callbacks: List[Callable] = []
        
        # Statistics
        self.stats = {
            'events_processed': 0,
            'events_by_id': defaultdict(int),
            'alerts_generated': 0,
            'process_creates': 0,
            'network_connects': 0,
            'file_creates': 0,
            'process_tampering': 0,
            'dns_queries': 0,
            'registry_changes': 0,
        }
        
        # Configuration
        self.poll_interval = self.config.get('poll_interval', 5)  # seconds
        self.max_events_per_poll = self.config.get('max_events_per_poll', 1000)
        self.event_log_name = self.config.get('event_log', 'Microsoft-Windows-Sysmon/Operational')
        
        # Suspicious patterns
        self.suspicious_commands = [
            r'powershell.*-enc', r'powershell.*-nop', r'powershell.*-w hidden',
            r'cmd.*/c.*powershell', r'wscript', r'cscript', r'mshta',
            r'rundll32.*javascript', r'regsvr32.*scrobj', r'certutil.*-decode',
            r'bitsadmin.*/transfer', r'wmic.*process.*call.*create',
            r'schtasks.*/create', r'at.*\\.*cmd', r'psexec', r'wmiexec',
            r'invoke-expression', r'iex\s', r'downloadstring', r'webclient',
            r'net\.webclient', r'http.*://.*\.exe', r'ftp.*\.exe',
        ]
        
        self.suspicious_ports = {
            4444, 5555, 6666, 7777, 8888, 9999, 31337, 12345, 54321,
            8080, 8443, 9000, 9001, 9999, 10000, 65535
        }
        
        self.suspicious_domains_patterns = [
            r'.*\.onion$', r'.*\.bit$', r'[a-z0-9]{20,}\.com$',
            r'[a-z0-9]{30,}\.(com|net|org)', r'dga-', r'-dga\.',
        ]
        
        # Process tracking
        self.process_tree: Dict[int, Dict] = {}  # pid -> process info
        
        # Check if Sysmon is available
        self.sysmon_available = self._check_sysmon_available()
    
    def _check_sysmon_available(self) -> bool:
        """Check if Sysmon is installed and running."""
        try:
            # Check if Sysmon service exists
            result = subprocess.run(
                ['sc', 'query', 'Sysmon'],
                capture_output=True, text=True, timeout=5
            )
            if 'RUNNING' in result.stdout:
                return True
            
            # Check if Sysmon event log exists
            result = subprocess.run(
                ['wevtutil', 'gl', 'Microsoft-Windows-Sysmon/Operational'],
                capture_output=True, text=True, timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def start(self):
        """Start the monitor."""
        if self._running:
            return
        
        if not self.sysmon_available:
            _log.warning("Sysmon not available - monitor will not collect events")
        
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="Sysmon-Monitor")
        self._thread.start()
        _log.info("Sysmon Native Windows Event Monitor started")
    
    def stop(self):
        """Stop the monitor."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        _log.info("Sysmon Monitor stopped")
    
    def register_alert_callback(self, callback: Callable):
        """Register callback for alerts."""
        self.alert_callbacks.append(callback)
    
    def _monitor_loop(self):
        """Main monitoring loop."""
        last_record_id = 0
        
        while self._running and not self._stop_event.is_set():
            start = time.time()
            try:
                if self.sysmon_available:
                    events = self._query_events(last_record_id)
                    for event in events:
                        self._process_event(event)
                        last_record_id = max(last_record_id, event.event_record_id)
            except Exception as e:
                _log.error(f"Sysmon monitor error: {e}")
            
            elapsed = time.time() - start
            sleep_time = max(0, self.poll_interval - elapsed)
            if sleep_time > 0:
                self._stop_event.wait(sleep_time)
    
    def _query_events(self, after_record_id: int) -> List[SysmonEvent]:
        """Query Sysmon events from Windows Event Log."""
        events = []
        
        try:
            # Use wevtutil to query events
            query = f'*[System[EventRecordID > {after_record_id}]]'
            cmd = [
                'wevtutil', 'qe', self.event_log_name,
                '/q', query,
                '/c', str(self.max_events_per_poll),
                '/rd:true',  # Reverse direction (newest first)
                '/f:json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                _log.debug(f"wevtutil error: {result.stderr}")
                return events
            
            if not result.stdout.strip():
                return events
            
            # Parse JSON output
            try:
                raw_events = json.loads(result.stdout)
                if not isinstance(raw_events, list):
                    raw_events = [raw_events]
            except json.JSONDecodeError:
                # Try parsing as JSON lines
                raw_events = []
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            raw_events.append(json.loads(line))
                        except:
                            pass
            
            for raw in raw_events:
                event = self._parse_event(raw)
                if event:
                    events.append(event)
                    
        except subprocess.TimeoutExpired:
            _log.warning("wevtutil query timed out")
        except Exception as e:
            _log.error(f"Event query error: {e}")
        
        return events
    
    def _parse_event(self, raw: Dict) -> Optional[SysmonEvent]:
        """Parse raw event JSON into SysmonEvent."""
        try:
            system = raw.get('System', {})
            event_data = raw.get('EventData', {})
            
            # Parse timestamp
            time_created = system.get('TimeCreated', {}).get('@SystemTime', '')
            timestamp = self._parse_timestamp(time_created)
            
            event = SysmonEvent(
                event_id=int(system.get('EventID', 0)),
                timestamp=timestamp,
                event_record_id=int(system.get('EventRecordID', 0)),
                computer=system.get('Computer', ''),
                channel=system.get('Channel', ''),
                level=system.get('Level', ''),
                task=system.get('Task', ''),
                opcode=system.get('Opcode', ''),
                keywords=system.get('Keywords', ''),
            )
            
            # Parse EventData
            if isinstance(event_data, dict):
                data_dict = {}
                for key, value in event_data.items():
                    if isinstance(value, dict) and '#text' in value:
                        data_dict[key] = value['#text']
                    else:
                        data_dict[key] = value
                event.data = data_dict
            elif isinstance(event_data, list):
                data_dict = {}
                for item in event_data:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            if isinstance(v, dict) and '#text' in v:
                                data_dict[k] = v['#text']
                            else:
                                data_dict[k] = v
                event.data = data_dict
            
            # Extract common fields
            self._extract_common_fields(event)
            
            # Add MITRE techniques
            event.mitre_techniques = SYSMON_MITRE_MAP.get(event.event_id, [])
            
            return event
            
        except Exception as e:
            _log.debug(f"Event parse error: {e}")
            return None
    
    def _parse_timestamp(self, timestamp_str: str) -> float:
        """Parse Windows timestamp to Unix timestamp."""
        try:
            # Format: 2024-01-15T10:30:45.1234567Z
            dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            return dt.timestamp()
        except Exception:
            return time.time()
    
    def _extract_common_fields(self, event: SysmonEvent):
        """Extract common fields from event data."""
        data = event.data
        
        # Process fields
        event.pid = int(data.get('ProcessId', 0) or data.get('PID', 0) or 0)
        event.ppid = int(data.get('ParentProcessId', 0) or data.get('PPID', 0) or 0)
        event.process_name = data.get('Image', '') or data.get('ImageName', '')
        event.command_line = data.get('CommandLine', '') or data.get('Command', '')
        event.parent_command_line = data.get('ParentCommandLine', '')
        event.image = event.process_name
        event.parent_image = data.get('ParentImage', '')
        event.user = data.get('User', '') or data.get('UserName', '')
        event.integrity_level = data.get('IntegrityLevel', '')
        
        # Hashes
        for h in ['MD5', 'SHA1', 'SHA256', 'IMPHASH']:
            if h in data:
                event.hashes[h.lower()] = data[h]
        
        # Network fields
        event.dst_ip = data.get('DestinationIp', '') or data.get('DstIp', '')
        event.dst_port = int(data.get('DestinationPort', 0) or data.get('DstPort', 0) or 0)
        event.src_ip = data.get('SourceIp', '') or data.get('SrcIp', '')
        event.src_port = int(data.get('SourcePort', 0) or data.get('SrcPort', 0) or 0)
        event.protocol = data.get('Protocol', '')
        
        # File/Registry fields
        event.target_filename = data.get('TargetFilename', '') or data.get('FileName', '')
        event.target_object = data.get('TargetObject', '') or data.get('RegistryPath', '')
        event.details = data.get('Details', '')
    
    def _process_event(self, event: SysmonEvent):
        """Process a Sysmon event."""
        with self._lock:
            self.recent_events.append(event)
            self.stats['events_processed'] += 1
            self.stats['events_by_id'][event.event_id] += 1
            
            # Update specific stats
            if event.event_id == SysmonEventID.PROCESS_CREATE:
                self.stats['process_creates'] += 1
                self._process_create(event)
            elif event.event_id == SysmonEventID.NETWORK_CONNECT:
                self.stats['network_connects'] += 1
                self._process_network(event)
            elif event.event_id == SysmonEventID.FILE_CREATE:
                self.stats['file_creates'] += 1
                self._process_file_create(event)
            elif event.event_id == SysmonEventID.PROCESS_TAMPERING:
                self.stats['process_tampering'] += 1
                self._process_tampering(event)
            elif event.event_id == SysmonEventID.DNS_QUERY:
                self.stats['dns_queries'] += 1
                self._process_dns(event)
            elif event.event_id in [SysmonEventID.REGISTRY_CREATE, SysmonEventID.REGISTRY_VALUE_SET, SysmonEventID.REGISTRY_DELETE]:
                self.stats['registry_changes'] += 1
                self._process_registry(event)
            elif event.event_id == SysmonEventID.CREATE_REMOTE_THREAD:
                self._process_remote_thread(event)
            elif event.event_id == SysmonEventID.PROCESS_ACCESS:
                self._process_access(event)
            elif event.event_id == SysmonEventID.IMAGE_LOAD:
                self._process_image_load(event)
        
        # Check for suspicious activity
        self._check_suspicious_activity(event)
    
    def _process_create(self, event: SysmonEvent):
        """Process process creation event."""
        # Track process
        proc_info = {
            'pid': event.pid,
            'ppid': event.ppid,
            'name': event.process_name,
            'image': event.image,
            'command_line': event.command_line,
            'parent_image': event.parent_image,
            'parent_command_line': event.parent_command_line,
            'user': event.user,
            'integrity': event.integrity_level,
            'hashes': event.hashes,
            'create_time': event.timestamp,
        }
        
        self.process_tree[event.pid] = proc_info
        
        # Check for suspicious command lines
        if event.command_line:
            self._check_suspicious_command(event)
        
        # Check for suspicious parent-child relationships
        self._check_suspicious_parent_child(event)
    
    def _process_network(self, event: SysmonEvent):
        """Process network connection event."""
        # Check suspicious ports
        if event.dst_port in self.suspicious_ports:
            self._generate_alert(
                "SUSPICIOUS_PORT",
                f"Connection to suspicious port {event.dst_port}: {event.image} (PID {event.pid}) -> {event.dst_ip}:{event.dst_port}",
                "HIGH",
                "T1071.001",
                {
                    'pid': event.pid,
                    'process': event.image,
                    'dst_ip': event.dst_ip,
                    'dst_port': event.dst_port,
                    'protocol': event.protocol,
                }
            )
        
        # Check for connections to known bad IPs (would integrate with threat intel)
        # Check for internal network scanning
    
    def _process_file_create(self, event: SysmonEvent):
        """Process file creation event."""
        # Check for suspicious file locations
        suspicious_paths = [
            r'C:\\Windows\\Temp',
            r'C:\\Users\\.*\\AppData\\Local\\Temp',
            r'C:\\ProgramData',
            r'C:\\Windows\\Tasks',
            r'C:\\Windows\\System32\\Tasks',
            r'.*\\Startup\\',
        ]
        
        for pattern in suspicious_paths:
            if re.search(pattern, event.target_filename, re.IGNORECASE):
                self._generate_alert(
                    "SUSPICIOUS_FILE_CREATE",
                    f"File created in suspicious location: {event.target_filename} by {event.image} (PID {event.pid})",
                    "MEDIUM",
                    "T1105",
                    {
                        'pid': event.pid,
                        'process': event.image,
                        'file': event.target_filename,
                        'hashes': event.hashes,
                    }
                )
                break
        
        # Check for executable files in temp
        if event.target_filename.lower().endswith(('.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar')):
            if 'temp' in event.target_filename.lower() or 'tmp' in event.target_filename.lower():
                self._generate_alert(
                    "EXECUTABLE_IN_TEMP",
                    f"Executable created in temp directory: {event.target_filename} by {event.image} (PID {event.pid})",
                    "HIGH",
                    "T1105",
                    {
                        'pid': event.pid,
                        'process': event.image,
                        'file': event.target_filename,
                        'hashes': event.hashes,
                    }
                )
    
    def _process_tampering(self, event: SysmonEvent):
        """Process tampering event (herpaderping, hollowing, etc.)."""
        self._generate_alert(
            "PROCESS_TAMPERING",
            f"Process tampering detected: {event.image} (PID {event.pid}) - {event.details}",
            "CRITICAL",
            "T1055.012",
            {
                'pid': event.pid,
                'process': event.image,
                'details': event.details,
                'tampering_type': event.data.get('Type', 'Unknown'),
            }
        )
    
    def _process_dns(self, event: SysmonEvent):
        """Process DNS query event."""
        # Check for DGA domains
        query = event.data.get('QueryName', '') or data.get('Query', '')
        if query:
            entropy = self._calculate_entropy(query)
            if entropy > 3.5 and len(query) > 15:
                self._generate_alert(
                    "DGA_DOMAIN",
                    f"Potential DGA domain: {query} (entropy={entropy:.2f}) from {event.image} (PID {event.pid})",
                    "HIGH",
                    "T1568.002",
                    {
                        'pid': event.pid,
                        'process': event.image,
                        'domain': query,
                        'entropy': entropy,
                    }
                )
    
    def _process_registry(self, event: SysmonEvent):
        """Process registry change event."""
        # Check for persistence locations
        persistence_keys = [
            r'.*\\Run$', r'.*\\RunOnce$', r'.*\\Winlogon\\Userinit',
            r'.*\\Services\\.*\\ImagePath', r'.*\\ActiveSetup',
            r'.*\\Schedule\\TaskCache\\Tasks',
        ]
        
        target = event.target_object
        for pattern in persistence_keys:
            if re.search(pattern, target, re.IGNORECASE):
                self._generate_alert(
                    "PERSISTENCE_REGISTRY",
                    f"Registry persistence modification: {target} by {event.image} (PID {event.pid})",
                    "HIGH",
                    "T1547",
                    {
                        'pid': event.pid,
                        'process': event.image,
                        'registry_key': target,
                        'event_type': event.event_id,
                    }
                )
                break
    
    def _process_remote_thread(self, event: SysmonEvent):
        """Process CreateRemoteThread event."""
        self._generate_alert(
            "CREATE_REMOTE_THREAD",
            f"CreateRemoteThread: {event.image} (PID {event.pid}) -> Target PID {event.data.get('TargetProcessId', 'unknown')}",
            "CRITICAL",
            "T1055.002",
            {
                'pid': event.pid,
                'process': event.image,
                'target_pid': event.data.get('TargetProcessId'),
                'start_address': event.data.get('StartAddress'),
                'start_function': event.data.get('StartFunction'),
            }
        )
    
    def _process_access(self, event: SysmonEvent):
        """Process process access event."""
        access = event.data.get('GrantedAccess', '')
        target_pid = event.data.get('TargetProcessId', 0)
        target_image = event.data.get('TargetImage', '')
        
        # Check for suspicious access (VM_READ, VM_WRITE, PROCESS_CREATE_THREAD)
        suspicious_access = ['0x1fffff', '0x1f0fff', 'vm_write', 'vm_read', 'create_thread']
        
        for sus in suspicious_access:
            if sus.lower() in access.lower():
                self._generate_alert(
                    "SUSPICIOUS_PROCESS_ACCESS",
                    f"Suspicious process access: {event.image} (PID {event.pid}) -> {target_image} (PID {target_pid}) Access: {access}",
                    "HIGH",
                    "T1003",
                    {
                        'pid': event.pid,
                        'process': event.image,
                        'target_pid': target_pid,
                        'target_image': target_image,
                        'granted_access': access,
                    }
                )
                break
    
    def _process_image_load(self, event: SysmonEvent):
        """Process image load event."""
        # Check for suspicious DLL loads
        image = event.data.get('Image', '') or event.data.get('ImageLoaded', '')
        
        suspicious_dlls = [
            'dbghelp.dll', 'dbgcore.dll', 'ntdll.dll', 'kernel32.dll',
            'advapi32.dll', 'crypt32.dll', 'winscard.dll',
        ]
        
        for dll in suspicious_dlls:
            if dll.lower() in image.lower():
                # Could be legitimate, but worth noting for LSASS dumping
                if 'lsass' in event.image.lower():
                    self._generate_alert(
                        "LSASS_DLL_LOAD",
                        f"Suspicious DLL loaded by LSASS: {image} by {event.image} (PID {event.pid})",
                        "CRITICAL",
                        "T1003.001",
                        {
                            'pid': event.pid,
                            'process': event.image,
                            'dll': image,
                        }
                    )
                break
    
    def _check_suspicious_command(self, event: SysmonEvent):
        """Check command line for suspicious patterns."""
        cmd = event.command_line.lower()
        for pattern in self.suspicious_commands:
            if re.search(pattern, cmd, re.IGNORECASE):
                self._generate_alert(
                    "SUSPICIOUS_COMMAND",
                    f"Suspicious command: {event.command_line} by {event.image} (PID {event.pid})",
                    "HIGH",
                    "T1059",
                    {
                        'pid': event.pid,
                        'process': event.image,
                        'command': event.command_line,
                        'pattern': pattern,
                    }
                )
                break
    
    def _check_suspicious_parent_child(self, event: SysmonEvent):
        """Check for suspicious parent-child process relationships."""
        suspicious_parents = {
            'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
            'wordpad.exe', 'notepad.exe', 'acrord32.exe', 'foxitreader.exe',
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe',
            'adobe reader', 'acrord32',
        }
        
        parent = event.parent_image.lower()
        child = event.image.lower()
        
        for sus_parent in suspicious_parents:
            if sus_parent in parent and child in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe']:
                self._generate_alert(
                    "SUSPICIOUS_PARENT_CHILD",
                    f"Suspicious parent-child: {event.parent_image} (PID {event.ppid}) -> {event.image} (PID {event.pid})",
                    "HIGH",
                    "T1059",
                    {
                        'pid': event.pid,
                        'ppid': event.ppid,
                        'parent': event.parent_image,
                        'child': event.image,
                        'child_cmd': event.command_line,
                    }
                )
                break
    
    def _check_suspicious_activity(self, event: SysmonEvent):
        """General suspicious activity checks."""
        # Check for LSASS access
        if 'lsass' in event.image.lower() and event.event_id == SysmonEventID.PROCESS_ACCESS:
            self._generate_alert(
                "LSASS_ACCESS",
                f"LSASS process access: {event.data.get('SourceImage', 'unknown')} (PID {event.pid}) -> LSASS",
                "CRITICAL",
                "T1003.001",
                {
                    'pid': event.pid,
                    'source_image': event.data.get('SourceImage'),
                    'granted_access': event.data.get('GrantedAccess'),
                }
            )
    
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
    
    def _generate_alert(self, alert_type: str, message: str, severity: str, mitre: str, details: Dict):
        """Generate alert."""
        alert = {
            'timestamp': time.time(),
            'type': alert_type,
            'message': message,
            'severity': severity,
            'mitre': mitre,
            'details': details,
        }
        self.alerts.append(alert)
        self.stats['alerts_generated'] += 1
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                _log.error(f"Alert callback error: {e}")
    
    def get_status(self) -> Dict:
        """Get monitor status."""
        with self._lock:
            return {
                'running': self._running,
                'sysmon_available': self.sysmon_available,
                'events_in_buffer': len(self.recent_events),
                'recent_alerts': list(self.alerts)[-10:],
                'stats': self.stats.copy(),
                'tracked_processes': len(self.process_tree),
            }
    
    def get_recent_events(self, event_id: Optional[int] = None, limit: int = 100) -> List[Dict]:
        """Get recent events, optionally filtered by event ID."""
        with self._lock:
            events = list(self.recent_events)
            if event_id:
                events = [e for e in events if e.event_id == event_id]
            return [
                {
                    'timestamp': e.timestamp,
                    'event_id': e.event_id,
                    'pid': e.pid,
                    'process': e.process_name,
                    'command': e.command_line,
                    'dst_ip': e.dst_ip,
                    'dst_port': e.dst_port,
                    'file': e.target_filename,
                    'registry': e.target_object,
                    'mitre': e.mitre_techniques,
                }
                for e in events[-limit:]
            ]

# Singleton instance
_sysmon_monitor: Optional[SysmonMonitor] = None
_sysmon_lock = threading.Lock()

def get_sysmon_monitor() -> SysmonMonitor:
    global _sysmon_monitor
    with _sysmon_lock:
        if _sysmon_monitor is None:
            _sysmon_monitor = SysmonMonitor()
        return _sysmon_monitor

def start_sysmon_monitor() -> SysmonMonitor:
    monitor = get_sysmon_monitor()
    monitor.start()
    return monitor

def stop_sysmon_monitor():
    global _sysmon_monitor
    if _sysmon_monitor:
        _sysmon_monitor.stop()
        _sysmon_monitor = None

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    monitor = start_sysmon_monitor()
    try:
        while True:
            time.sleep(10)
            status = monitor.get_status()
            print(f"Events: {status['stats']['events_processed']}, Alerts: {status['stats']['alerts_generated']}")
    except KeyboardInterrupt:
        stop_sysmon_monitor()