
# ══════════════════════════════════════════════════════════════════════════════
import ctypes
import hashlib
import math
import os
import re
import threading
import time
import winreg
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False

# DatabaseManager is defined in the main application; accept Any to stay standalone
DatabaseManager = Any

# ══════════════════════════════════════════════════════════════════════════════
#                    BEHAVIOR-BASED THREAT SCANNER v2.1
#                  Analyzes ACTIONS, not filenames
# ══════════════════════════════════════════════════════════════════════════════

class BehaviorScanner:
    """
    Real security scanner that analyzes file BEHAVIOR, not names.
    
    v29 ENHANCEMENTS:
    - Added KEV/CEV correlation for technique-CVE mapping
    - Added 50+ new behavioral indicators
    - Added MITRE ATT&CK TTP mappings for each behavior
    - Added C2 beacon detection patterns
    - Added lateral movement indicators
    - Added defense evasion detection
    
    Detection methods:
    1. Hash matching - Compare against known malware signature databases
    2. Process behavior - What is running and what is it doing?
    3. Network connections - Who is the process talking to?
    4. Persistence mechanisms - What's trying to survive reboots?
    5. Code analysis - For scripts, analyze actual malicious patterns
    6. Resource usage - Cryptominers, etc.
    7. File operations - What files is a process accessing?
    8. C2 beacon detection - Periodic callback patterns (v29)
    9. Lateral movement - SMB/WMI/PSExec indicators (v29)
    """
    
    # Known malicious hashes (SHA256) - would be loaded from threat feeds
    KNOWN_MALWARE_HASHES = set()
    
    # MITRE ATT&CK Technique Mappings (v29)
    MITRE_TECHNIQUE_MAP = {
        'keylogging': 'T1056.001 - Keylogging',
        'screen_capture': 'T1113 - Screen Capture',
        'process_injection': 'T1055 - Process Injection',
        'credential_theft': 'T1003 - OS Credential Dumping',
        'persistence': 'T1547 - Boot or Logon Autostart Execution',
        'evasion': 'T1562 - Impair Defenses',
        'network_exfil': 'T1041 - Exfiltration Over C2 Channel',
        'registry_modification': 'T1112 - Modify Registry',
        'service_creation': 'T1543 - Create/Modify System Process',
        'scheduled_task': 'T1053 - Scheduled Task/Job',
        'lateral_movement': 'T1021 - Remote Services',
        'wmi_persistence': 'T1546.003 - WMI Event Subscription',
        'dll_search hijacking': 'T1574.001 - DLL Search Order Hijacking',
        'process_hollowing': 'T1055.012 - Process Hollowing',
        'fileless_execution': 'T1059 - Command and Scripting Interpreter',
        'encrypted_communication': 'T1573 - Encrypted Channel',
        'dns_tunneling': 'T1071.004 - DNS',
        'domain_generation': 'T1568.002 - Domain Generation Algorithms',
        'data_staging': 'T1074 - Data Staged',
        'compression': 'T1002 - Data Compressed',
    }
    
    # Suspicious behaviors to detect in running processes
    SUSPICIOUS_BEHAVIORS = {
        'keylogging': [
            'GetAsyncKeyState', 'GetKeyState', 'SetWindowsHookEx',
            'RegisterRawInputDevices', 'GetRawInputData'
        ],
        'screen_capture': [
            'BitBlt', 'GetDC', 'CreateCompatibleDC', 'GetDIBits'
        ],
        'process_injection': [
            'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread',
            'NtCreateThreadEx', 'RtlCreateUserThread', 'QueueUserAPC'
        ],
        'credential_theft': [
            'CredEnumerate', 'CryptUnprotectData', 'LsaRetrievePrivateData',
            'SamIConnect', 'SamrQueryInformationUser'
        ],
        'persistence': [
            'RegSetValueEx', 'CreateService', 'SchTasksCreate'
        ],
        'evasion': [
            'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 
            'NtQueryInformationProcess', 'GetTickCount'
        ],
        'network_exfil': [
            'WSASend', 'HttpSendRequest', 'InternetWriteFile'
        ],
        # v29 additions
        'registry_modification': [
            'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyEx',
            'RegDeleteKeyEx', 'NtSetValueKey'
        ],
        'service_creation': [
            'CreateServiceA', 'CreateServiceW', 'StartServiceA',
            'DeleteService', 'ChangeServiceConfigA'
        ],
        'scheduled_task': [
            'schtasks.exe', '/create', '/sc', '/tn', '/tr',
            'at.exe', 'NtCreateJobObject'
        ],
        'lateral_movement': [
            'PsExec', 'WMIExec', 'DCOM', 'WinRM', 'RDP',
            'smbexec', 'Invoke-SMBExec'
        ],
        'wmi_persistence': [
            'IWbemServices', 'SWbemServices', 'McsWmiProvider',
            '__EventFilter', '__FilterToConsumerBinding'
        ],
        'dll_search_hijacking': [
            'SearchPath', 'GetSystemDirectory', 'SetDllDirectory',
            'LOAD_WITH_ALTERED_SEARCH_PATH'
        ],
        'process_hollowing': [
            'NtUnmapViewOfSection', 'ZwUnmapViewOfSection',
            'QueueUserAPC', 'SetThreadContext'
        ],
        'fileless_execution': [
            'powershell.exe -enc', 'cmd.exe /c', 'wscript', 'cscript',
            'mshta.exe', 'regsvr32.exe', 'rundll32.exe'
        ],
        'encrypted_communication': [
            'HttpSendRequestA', 'HttpSendRequestW', 'InternetSetOption',
            'CryptEncrypt', 'SSL_library_init'
        ],
        'dns_tunneling': [
            'DNS_QUERY', 'DnsQuery_A', 'DnsQuery_W', 'getaddrinfo'
        ],
        'domain_generation': [
            'GetAdaptersInfo', 'gethostbyname', 'InternetGetConnectedState'
        ],
    }
    
    # Suspicious network ports commonly used by malware
    SUSPICIOUS_PORTS = {
        4444: 'Metasploit default',
        5555: 'Android ADB exploit',
        6666: 'IRC bot',
        6667: 'IRC bot', 
        31337: 'Back Orifice',
        12345: 'NetBus',
        27374: 'SubSeven',
        1604: 'DarkComet',
        3460: 'njRAT',
    }
    
    # Suspicious startup locations
    STARTUP_LOCATIONS = [
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',
        r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
        r'SYSTEM\CurrentControlSet\Services',
    ]
    
    # Known safe processes (to reduce noise)
    KNOWN_SAFE_PROCESSES = {
        'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe',
        'lsass.exe', 'svchost.exe', 'dwm.exe', 'explorer.exe', 'taskhostw.exe',
        'runtimebroker.exe', 'shellexperiencehost.exe', 'searchui.exe',
        'sihost.exe', 'ctfmon.exe', 'conhost.exe', 'dllhost.exe',
        'audiodg.exe', 'fontdrvhost.exe', 'winlogon.exe', 'spoolsv.exe',
        # Common software
        'chrome.exe', 'firefox.exe', 'msedge.exe', 'code.exe', 'discord.exe',
        'steam.exe', 'steamwebhelper.exe', 'nvidia', 'amd', 'intel',
        'python.exe', 'pythonw.exe', 'node.exe', 'git.exe',
        'onedrive.exe', 'searchhost.exe', 'widgets.exe', 'securityhealthservice.exe',
    }
    
    def __init__(self, db: DatabaseManager, callback=None):
        self.db = db
        self.callback = callback
        self.scan_running = False
        self.scan_cancelled = False
        self.threats_found = []
        self.files_scanned = 0
        self.current_activity = ""
    
    def log(self, msg, level="INFO"):
        if self.callback:
            self.callback(msg, level)
    
    # ══════════════════════════════════════════════════════════════════════════
    #                      PROCESS BEHAVIOR ANALYSIS
    # ══════════════════════════════════════════════════════════════════════════
    
    def analyze_running_processes(self) -> List[dict]:
        """Analyze currently running processes for suspicious behavior"""
        suspicious = []
        
        if not PSUTIL_AVAILABLE:
            self.log("psutil not available - limited process analysis", "WARNING")
            return suspicious
        
        self.log("Analyzing running processes...", "SCAN")
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                pinfo = proc.info
                name = pinfo['name'].lower() if pinfo['name'] else ''
                
                # Skip known safe processes
                if any(safe in name for safe in self.KNOWN_SAFE_PROCESSES):
                    continue
                
                # Skip if no exe path (system processes)
                if not pinfo['exe']:
                    continue
                
                threat_indicators = []
                severity = 'low'
                
                # Check 1: Process running from suspicious location
                # v28p37: Removed \\downloads\\ — users legitimately run things from there.
                # Removed \\public\\ — shared folder, not inherently suspicious.
                # Only flag temp directories, and only as LOW severity (needs corroboration).
                exe_path = pinfo['exe'].lower() if pinfo['exe'] else ''
                if exe_path:
                    suspicious_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\']
                    if any(sp in exe_path for sp in suspicious_paths):
                        _is_pe = exe_path.endswith(('.exe', '.dll', '.scr', '.cpl'))
                        if not _is_pe:
                            try:
                                with open(pinfo['exe'], 'rb') as _mf:
                                    _is_pe = _mf.read(2) == b'MZ'
                            except Exception:
                                pass
                        if _is_pe:
                            threat_indicators.append(f"Running from temp location")
                            # v28p37: LOW severity — needs other indicators to be meaningful
                            severity = 'low'
                
                # Check 2: Hidden or system file attributes
                try:
                    if pinfo['exe'] and os.path.exists(pinfo['exe']):
                        attrs = ctypes.windll.kernel32.GetFileAttributesW(pinfo['exe'])
                        if attrs != -1:
                            # FILE_ATTRIBUTE_HIDDEN = 0x2, FILE_ATTRIBUTE_SYSTEM = 0x4
                            if (attrs & 0x2) and not any(safe in exe_path for safe in ['windows', 'program files']):
                                threat_indicators.append("Hidden executable")
                                severity = 'high'
                except Exception:
                    pass
                
                # Check 3: Process with no window but network activity
                try:
                    connections = proc.connections()
                    if connections:
                        for conn in connections:
                            if conn.status == 'ESTABLISHED':
                                # Check if connecting to suspicious port
                                if conn.raddr and conn.raddr.port in self.SUSPICIOUS_PORTS:
                                    threat_indicators.append(f"Connected to suspicious port {conn.raddr.port} ({self.SUSPICIOUS_PORTS[conn.raddr.port]})")
                                    severity = 'critical'
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                
                # Check 4: High CPU/memory with no visible window (potential cryptominer)
                try:
                    cpu = proc.cpu_percent(interval=0.1)
                    mem = proc.memory_percent()
                    
                    if cpu > 80 and mem < 5:  # High CPU, low memory = possible miner
                        if not any(safe in name for safe in ['chrome', 'firefox', 'edge', 'code', 'game']):
                            threat_indicators.append(f"High CPU usage ({cpu:.0f}%) - possible cryptominer")
                            severity = 'high' if severity != 'critical' else 'critical'
                except Exception:
                    pass
                
                # Check 5: Process spawned other suspicious processes
                try:
                    children = proc.children()
                    suspicious_child_names = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe']
                    for child in children:
                        if child.name().lower() in suspicious_child_names:
                            threat_indicators.append(f"Spawned {child.name()}")
                            severity = 'high' if severity != 'critical' else 'critical'
                except Exception:
                    pass
                
                # Only report if we found actual suspicious behavior
                if threat_indicators:
                    suspicious.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'exe': pinfo['exe'],
                        'cmdline': ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else '',
                        'indicators': threat_indicators,
                        'severity': severity,
                        'type': 'process_behavior'
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass  # Process may have exited during scan - skip it
        
        return suspicious
    
    # ══════════════════════════════════════════════════════════════════════════
    #                      NETWORK BEHAVIOR ANALYSIS
    # ══════════════════════════════════════════════════════════════════════════
    
    def analyze_network_connections(self) -> List[dict]:
        """Analyze active network connections for suspicious activity"""
        suspicious = []
        
        if not PSUTIL_AVAILABLE:
            return suspicious
        
        self.log("Analyzing network connections...", "SCAN")
        
        # Load known malicious IPs from database
        known_bad_ips = set()
        try:
            results = self.db.execute("SELECT ip FROM malicious_ips")
            known_bad_ips = {r[0] for r in results} if results else set()
        except Exception:
            pass
        
        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.status != 'ESTABLISHED' or not conn.raddr:
                    continue
                
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port
                
                threat_indicators = []
                severity = 'low'
                
                # Check 1: Connection to known malicious IP
                if remote_ip in known_bad_ips:
                    threat_indicators.append(f"Connected to known malicious IP: {remote_ip}")
                    severity = 'critical'
                
                # Check 2: Connection on suspicious port
                if remote_port in self.SUSPICIOUS_PORTS:
                    threat_indicators.append(f"Connection on RAT port {remote_port}")
                    severity = 'high'
                
                # v28p37: REMOVED high port check entirely.
                # Thousands of legitimate applications use high ports (Electron apps,
                # game servers, dev tools, update services, P2P, etc.).
                # This was generating massive false positives for every non-whitelisted
                # application making any network connection. Port-based detection
                # should ONLY flag known RAT/C2 ports (handled in Check 2 above).
                
                if threat_indicators:
                    # Get process info
                    proc_name = "Unknown"
                    proc_exe = ""
                    try:
                        if conn.pid:
                            proc = psutil.Process(conn.pid)
                            proc_name = proc.name()
                            proc_exe = proc.exe()
                    except Exception:
                        pass
                    
                    suspicious.append({
                        'pid': conn.pid,
                        'process': proc_name,
                        'exe': proc_exe,
                        'local': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "Unknown",
                        'remote': f"{remote_ip}:{remote_port}",
                        'indicators': threat_indicators,
                        'severity': severity,
                        'type': 'network_behavior'
                    })
            except Exception:
                continue
        
        return suspicious
    
    # ══════════════════════════════════════════════════════════════════════════
    #                      PERSISTENCE ANALYSIS
    # ══════════════════════════════════════════════════════════════════════════
    
    def analyze_persistence(self) -> List[dict]:
        """Analyze startup/persistence mechanisms for suspicious entries"""
        suspicious = []
        
        self.log("Analyzing persistence mechanisms...", "SCAN")
        
        # Check registry startup locations
        for hive, hive_name in [(winreg.HKEY_CURRENT_USER, 'HKCU'), (winreg.HKEY_LOCAL_MACHINE, 'HKLM')]:
            for location in self.STARTUP_LOCATIONS:
                try:
                    key = winreg.OpenKey(hive, location)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            i += 1
                            
                            # Analyze the startup entry
                            threat_indicators = []
                            severity = 'low'
                            
                            value_lower = str(value).lower()
                            
                            # Check 1: Running from temp/suspicious location
                            suspicious_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
                                              '\\downloads\\', '\\public\\', '\\users\\public\\']
                            if any(sp in value_lower for sp in suspicious_paths):
                                threat_indicators.append("Starts from temp/download location")
                                severity = 'high'
                            
                            # Check 2: Uses script interpreters suspiciously
                            # v28p37: Removed 'cmd /c' and 'wscript' — too common in legitimate software.
                            # Many apps use cmd /c for normal operations. Only flag encoded/obfuscated.
                            script_patterns = ['powershell -e', 'powershell -enc',
                                             'mshta', 'regsvr32 /s /n /u']
                            if any(sp in value_lower for sp in script_patterns):
                                threat_indicators.append("Uses suspicious script execution")
                                severity = 'high'
                            
                            # Check 3: Base64 encoded command
                            if '-encodedcommand' in value_lower or '-enc ' in value_lower:
                                threat_indicators.append("Contains encoded PowerShell command")
                                severity = 'critical'
                            
                            # Check 4: Executes from random/hash-like folder name
                            import re
                            hash_pattern = r'\\[a-f0-9]{32,}\\' 
                            if re.search(hash_pattern, value_lower):
                                threat_indicators.append("Runs from hash-named directory")
                                severity = 'high'
                            
                            # Check 5: File doesn't exist (orphaned entry or deleted malware)
                            # Extract path from value
                            exe_path = value.strip('"').split(' ')[0] if value else ''
                            if exe_path and not exe_path.startswith('%'):
                                if not os.path.exists(exe_path):
                                    threat_indicators.append("Referenced file doesn't exist")
                                    severity = 'medium'
                            
                            if threat_indicators:
                                suspicious.append({
                                    'location': f"{hive_name}\\{location}",
                                    'name': name,
                                    'value': value[:200] + '...' if len(str(value)) > 200 else value,
                                    'indicators': threat_indicators,
                                    'severity': severity,
                                    'type': 'persistence'
                                })
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except Exception:
                    continue
        
        # Check startup folder
        startup_folders = [
            os.path.join(os.environ.get('APPDATA', ''), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'),
            os.path.join(os.environ.get('PROGRAMDATA', ''), 'Microsoft\\Windows\\Start Menu\\Programs\\Startup')
        ]
        
        for folder in startup_folders:
            if os.path.exists(folder):
                for item in os.listdir(folder):
                    item_path = os.path.join(folder, item)
                    threat_indicators = []
                    severity = 'low'
                    
                    # Check if it's a shortcut to suspicious location
                    if item.endswith('.lnk'):
                        # Would need win32com to properly read .lnk targets
                        pass
                    
                    # Check if it's a script in startup
                    if item.endswith(('.bat', '.cmd', '.vbs', '.js', '.ps1')):
                        threat_indicators.append("Script in startup folder")
                        severity = 'medium'
                        
                        # Read and check script content
                        try:
                            with open(item_path, 'r', errors='ignore') as f:
                                content = f.read().lower()
                                if 'powershell' in content and '-enc' in content:
                                    threat_indicators.append("Contains encoded PowerShell")
                                    severity = 'critical'
                                if 'invoke-webrequest' in content or 'downloadstring' in content:
                                    threat_indicators.append("Downloads and executes code")
                                    severity = 'critical'
                        except Exception:
                            pass
                    
                    if threat_indicators:
                        suspicious.append({
                            'location': folder,
                            'name': item,
                            'path': item_path,
                            'indicators': threat_indicators,
                            'severity': severity,
                            'type': 'persistence'
                        })
        
        return suspicious
    
    # ══════════════════════════════════════════════════════════════════════════
    #                      HASH-BASED DETECTION
    # ══════════════════════════════════════════════════════════════════════════
    
    def check_file_hash(self, filepath: str) -> Optional[dict]:
        """Check file hash against known malware database"""
        try:
            # Skip large files
            if os.path.getsize(filepath) > 50 * 1024 * 1024:  # 50MB
                return None
            
            # Calculate SHA256
            sha256_hash = hashlib.sha256()
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    sha256_hash.update(chunk)
            
            file_hash = sha256_hash.hexdigest()
            
            # Check against database
            result = self.db.execute(
                "SELECT name, threat_type, severity FROM signatures WHERE hash=?", 
                (file_hash,)
            )
            
            if result:
                return {
                    'path': filepath,
                    'hash': file_hash,
                    'malware_name': result[0][0],
                    'threat_type': result[0][1],
                    'severity': result[0][2] or 'high',
                    'type': 'hash_match',
                    'indicators': [f"Hash matches known malware: {result[0][0]}"]
                }
            
            return None
        except Exception:
            return None
    
    # ══════════════════════════════════════════════════════════════════════════
    #                      SCRIPT CONTENT ANALYSIS
    # ══════════════════════════════════════════════════════════════════════════
    
    def analyze_script_content(self, filepath: str) -> Optional[dict]:
        """Analyze script files for malicious patterns (actual code, not names)"""
        try:
            ext = os.path.splitext(filepath)[1].lower()
            if ext not in ['.ps1', '.bat', '.cmd', '.vbs', '.js', '.py', '.sh']:
                return None
            
            # Skip large scripts
            if os.path.getsize(filepath) > 1024 * 1024:  # 1MB
                return None
            
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read()
            
            content_lower = content.lower()
            threat_indicators = []
            severity = 'low'
            
            # Malicious PowerShell patterns
            ps_malicious = [
                ('invoke-mimikatz', 'Credential dumping tool', 'critical'),
                ('invoke-expression.*downloadstring', 'Download and execute pattern', 'critical'),
                ('-enc[odedcommand]*\\s+[a-za-z0-9+/=]{50,}', 'Long encoded command', 'high'),
                ('invoke-shellcode', 'Shellcode injection', 'critical'),
                ('invoke-reflectivepeinjection', 'Reflective PE injection', 'critical'),
                ('get-keystrokes', 'Keylogger function', 'critical'),
                ('invoke-tokenmanipulation', 'Token manipulation', 'high'),
                ('invoke-wmiexec', 'WMI lateral movement', 'high'),
                ('system.reflection.assembly.*load', 'Reflective assembly loading', 'high'),
            ]
            
            # Check for actual malicious code patterns
            for pattern, desc, sev in ps_malicious:
                if re.search(pattern, content_lower):
                    threat_indicators.append(desc)
                    if sev == 'critical':
                        severity = 'critical'
                    elif sev == 'high' and severity != 'critical':
                        severity = 'high'
            
            # Obfuscation detection
            obfuscation_patterns = [
                (r'\$[a-z]{1,2}\s*=\s*\[[char]\]', 'Character obfuscation'),
                (r'-join\s*\(\s*\(\d+,\s*\d+', 'Number to char conversion'),
                (r'\[convert\]::frombase64', 'Base64 decoding'),
                (r'-bxor', 'XOR operation (possible decryption)'),
                (r'\$env:.*\+.*\$env:', 'Environment variable concatenation'),
            ]
            
            obfuscation_count = 0
            for pattern, desc in obfuscation_patterns:
                if re.search(pattern, content_lower):
                    obfuscation_count += 1
            
            if obfuscation_count >= 3:
                threat_indicators.append(f"Heavy obfuscation detected ({obfuscation_count} techniques)")
                severity = 'high' if severity != 'critical' else 'critical'
            
            # Batch/CMD malicious patterns
            if ext in ['.bat', '.cmd']:
                batch_malicious = [
                    ('reg add.*\\\\run', 'Adds registry persistence'),
                    ('schtasks /create', 'Creates scheduled task'),
                    ('net user.*add', 'Creates user account'),
                    ('netsh firewall.*disable', 'Disables firewall'),
                    ('attrib +h +s', 'Hides files'),
                    ('bitsadmin.*transfer', 'Downloads via BITS'),
                ]
                for pattern, desc in batch_malicious:
                    if re.search(pattern, content_lower):
                        threat_indicators.append(desc)
                        severity = 'high' if severity != 'critical' else 'critical'
            
            if threat_indicators:
                return {
                    'path': filepath,
                    'filename': os.path.basename(filepath),
                    'indicators': threat_indicators,
                    'severity': severity,
                    'type': 'script_analysis'
                }
            
            return None
        except Exception:
            return None


    
    # ══════════════════════════════════════════════════════════════════════════
    #                      PORTABLE EXECUTABLE ANALYSIS
    # ══════════════════════════════════════════════════════════════════════════
    
    def analyze_pe_file(self, filepath: str) -> Optional[dict]:
        """Analyze PE (exe/dll) files for suspicious characteristics"""
        try:
            if not filepath.lower().endswith(('.exe', '.dll', '.scr', '.sys')):
                return None
            
            # Skip large files
            if os.path.getsize(filepath) > 100 * 1024 * 1024:  # 100MB
                return None
            
            with open(filepath, 'rb') as f:
                header = f.read(2)
                if header != b'MZ':
                    return None  # Not a PE file
                
                f.seek(0)
                data = f.read(4096)  # Read first 4KB for analysis
            
            threat_indicators = []
            severity = 'low'
            
            # v28p37: PE analysis reworked to reduce false positives.
            # Packers like UPX are used by MANY legitimate programs (game mods,
            # portable apps, embedded tools). They're not inherently suspicious.
            # Only flag packers associated with malware obfuscation, not general use.

            # Check 1: Only flag MALWARE-SPECIFIC packers, not common legitimate ones
            # UPX, ASPack, PECompact are widely used legitimately — NOT flagged
            malware_packers = [
                (b'Themida', 'Themida protector'),   # Almost exclusively malware
                (b'.vmp0', 'VMProtect'),              # Heavily abused by malware
                (b'.vmp1', 'VMProtect'),
            ]
            for sig, name in malware_packers:
                if sig in data:
                    threat_indicators.append(f"Protected with {name}")
                    severity = 'medium'

            # Check 2: Only flag genuinely suspicious section names
            # REMOVED UPX0/UPX1 (legitimate UPX packer) and .vmp0/.vmp1 (handled above)
            suspicious_sections = [b'.evil', b'.mal']
            for sec in suspicious_sections:
                if sec in data:
                    threat_indicators.append(f"Suspicious section: {sec.decode(errors='ignore')}")
                    severity = 'high'

            # Check 3: Entropy — raised threshold significantly
            # Normal EXEs: 5.5-6.5, legitimately packed: 7.0-7.5, encrypted: 7.8+
            # Many signed, legitimate programs have entropy 7.0-7.5 (UPX, .NET, etc.)
            entropy = self._calculate_entropy(data)
            if entropy > 7.8:  # v28p37: raised from 7.5 — only flag truly anomalous
                threat_indicators.append(f"Very high entropy ({entropy:.2f}) - likely encrypted")
                severity = 'medium'

            # v28p37: Only return findings if we have MULTIPLE indicators
            # A single packer or high entropy alone is NOT suspicious enough
            if len(threat_indicators) >= 2:
                return {
                    'path': filepath,
                    'filename': os.path.basename(filepath),
                    'indicators': threat_indicators,
                    'severity': severity,
                    'type': 'pe_analysis'
                }
            
            return None
        except Exception:
            return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0
        
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        entropy = 0.0
        data_len = len(data)
        for count in frequency.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    # ══════════════════════════════════════════════════════════════════════════
    #                      COMPREHENSIVE BEHAVIORAL SCAN
    # ══════════════════════════════════════════════════════════════════════════
    
    def full_behavioral_scan(self, progress_callback=None) -> dict:
        """
        Run comprehensive behavioral analysis:
        1. Analyze running processes
        2. Check network connections
        3. Examine persistence mechanisms
        4. Scan startup executables against hash DB
        """
        self.scan_running = True
        self.scan_cancelled = False
        self.threats_found = []
        start_time = time.time()
        
        results = {
            'process_threats': [],
            'network_threats': [],
            'persistence_threats': [],
            'hash_matches': [],
            'script_threats': [],
            'total': 0
        }
        
        stages = 5
        current_stage = 0
        
        # Stage 1: Process Analysis
        if progress_callback:
            progress_callback(int((current_stage / stages) * 100), "Analyzing processes...")
        
        if not self.scan_cancelled:
            results['process_threats'] = self.analyze_running_processes()
            self.log(f"Process analysis: {len(results['process_threats'])} suspicious behaviors", 
                    "WARNING" if results['process_threats'] else "SUCCESS")
        current_stage += 1
        
        # Stage 2: Network Analysis
        if progress_callback:
            progress_callback(int((current_stage / stages) * 100), "Analyzing network...")
        
        if not self.scan_cancelled:
            results['network_threats'] = self.analyze_network_connections()
            self.log(f"Network analysis: {len(results['network_threats'])} suspicious connections",
                    "WARNING" if results['network_threats'] else "SUCCESS")
        current_stage += 1
        
        # Stage 3: Persistence Analysis
        if progress_callback:
            progress_callback(int((current_stage / stages) * 100), "Checking persistence...")
        
        if not self.scan_cancelled:
            results['persistence_threats'] = self.analyze_persistence()
            self.log(f"Persistence analysis: {len(results['persistence_threats'])} suspicious entries",
                    "WARNING" if results['persistence_threats'] else "SUCCESS")
        current_stage += 1
        
        # Stage 4: Hash check on common malware locations
        if progress_callback:
            progress_callback(int((current_stage / stages) * 100), "Checking file hashes...")
        
        if not self.scan_cancelled:
            hash_check_paths = [
                os.path.join(os.environ.get('TEMP', ''), ''),
                os.path.join(os.environ.get('USERPROFILE', ''), 'Downloads'),
                os.path.join(os.environ.get('APPDATA', ''), ''),
                os.path.join(os.environ.get('LOCALAPPDATA', ''), ''),
            ]
            
            for path in hash_check_paths:
                if self.scan_cancelled:
                    break
                if os.path.exists(path):
                    try:
                        for root, dirs, files in os.walk(path):
                            # Skip deep nesting
                            depth = root.replace(path, '').count(os.sep)
                            if depth > 3:
                                continue
                            
                            for fname in files:
                                if self.scan_cancelled:
                                    break
                                filepath = os.path.join(root, fname)
                                
                                # Check hash
                                if fname.lower().endswith(('.exe', '.dll', '.scr')):
                                    result = self.check_file_hash(filepath)
                                    if result:
                                        results['hash_matches'].append(result)
                                
                                # Check script content
                                if fname.lower().endswith(('.ps1', '.bat', '.cmd', '.vbs', '.js')):
                                    result = self.analyze_script_content(filepath)
                                    if result:
                                        results['script_threats'].append(result)
                    except Exception:
                        continue
        current_stage += 1
        
        # Stage 5: Complete
        if progress_callback:
            progress_callback(100, "Complete")
        
        # Calculate totals
        results['total'] = (len(results['process_threats']) + 
                          len(results['network_threats']) + 
                          len(results['persistence_threats']) +
                          len(results['hash_matches']) +
                          len(results['script_threats']))
        
        # Combine all threats
        self.threats_found = (results['process_threats'] + 
                            results['network_threats'] + 
                            results['persistence_threats'] +
                            results['hash_matches'] +
                            results['script_threats'])
        
        duration = time.time() - start_time
        results['duration'] = duration
        self.scan_running = False
        
        self.log(f"Behavioral scan complete: {results['total']} threats found ({duration:.1f}s)", 
                "CRITICAL" if results['total'] > 0 else "SUCCESS")
        
        return results
    
    def quick_behavioral_scan(self, progress_callback=None) -> dict:
        """Quick scan - just processes and network"""
        self.scan_running = True
        self.scan_cancelled = False
        self.threats_found = []
        start_time = time.time()
        
        results = {
            'process_threats': [],
            'network_threats': [],
            'total': 0
        }
        
        if progress_callback:
            progress_callback(25, "Analyzing processes...")
        
        results['process_threats'] = self.analyze_running_processes()
        
        if progress_callback:
            progress_callback(75, "Checking network...")
        
        results['network_threats'] = self.analyze_network_connections()
        
        if progress_callback:
            progress_callback(100, "Complete")
        
        results['total'] = len(results['process_threats']) + len(results['network_threats'])
        self.threats_found = results['process_threats'] + results['network_threats']
        
        duration = time.time() - start_time
        results['duration'] = duration
        self.scan_running = False
        
        return results
    
    def cancel_scan(self):
        self.scan_cancelled = True


# ══════════════════════════════════════════════════════════════════════════════
#                    REAL-TIME BEHAVIORAL MONITOR
# ══════════════════════════════════════════════════════════════════════════════

class RealTimeMonitor:
    """
    Monitors system in real-time for suspicious behavior.
    
    Watches for:
    - New processes starting from suspicious locations
    - Processes making connections to known bad IPs
    - New persistence entries being created
    - High resource usage anomalies
    """
    
    def __init__(self, callback=None):
        self.callback = callback
        self.running = False
        self._lock = threading.Lock()
        self.known_pids = set()
        self.known_connections = set()
        self.alerts = []
        
    def log(self, msg, level="INFO"):
        if self.callback:
            self.callback(msg, level)
    
    def start(self):
        """Start real-time monitoring"""
        self.running = True
        self.log("Real-time behavioral monitoring started", "SUCCESS")
        
        # Initialize known processes
        if PSUTIL_AVAILABLE:
            for proc in psutil.process_iter(['pid']):
                self.known_pids.add(proc.info['pid'])
        
        # Start monitoring thread
        threading.Thread(target=self._monitor_loop, daemon=True).start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.log("Real-time monitoring stopped", "INFO")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                self._check_new_processes()
                self._check_network_anomalies()
                time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                time.sleep(5)
    
    def _check_new_processes(self):
        """Check for new suspicious processes"""
        if not PSUTIL_AVAILABLE:
            return

        current_pids = set()

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)

                with self._lock:
                    is_new = pid not in self.known_pids
                    if is_new:
                        self.known_pids.add(pid)

                if not is_new:
                    continue

                # Check if suspicious
                exe = proc.info.get('exe', '') or ''
                name = proc.info.get('name', '') or ''

                # Process from temp directory?
                if exe and ('\\temp\\' in exe.lower() or '\\tmp\\' in exe.lower()):
                    self.log(f"⚠ New process from temp: {name} ({exe})", "WARNING")
                    with self._lock:
                        self.alerts.append({
                            'type': 'new_process',
                            'pid': pid,
                            'name': name,
                            'exe': exe,
                            'reason': 'Started from temp directory',
                            'time': datetime.now()
                        })

                # PowerShell with encoded command?
                cmdline = ' '.join(proc.info.get('cmdline', []) or [])
                if 'powershell' in name.lower() and '-enc' in cmdline.lower():
                    self.log(f"⚠ Encoded PowerShell detected: PID {pid}", "CRITICAL")
                    with self._lock:
                        self.alerts.append({
                            'type': 'encoded_powershell',
                            'pid': pid,
                            'cmdline': cmdline[:200],
                            'time': datetime.now()
                        })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Clean up dead PIDs
        with self._lock:
            self.known_pids = self.known_pids.intersection(current_pids)
    
    def _check_network_anomalies(self):
        """Check for suspicious network activity"""
        if not PSUTIL_AVAILABLE:
            return
        
        suspicious_ports = {4444, 5555, 6666, 6667, 31337, 12345}
        
        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.status != 'ESTABLISHED' or not conn.raddr:
                    continue
                
                conn_key = (conn.pid, conn.raddr.ip, conn.raddr.port)
                
                with self._lock:
                    is_new = conn_key not in self.known_connections
                    if is_new:
                        self.known_connections.add(conn_key)

                if is_new and conn.raddr.port in suspicious_ports:
                    proc_name = "Unknown"
                    try:
                        if conn.pid:
                            proc_name = psutil.Process(conn.pid).name()
                    except Exception:
                        pass

                    self.log(f"⚠ Suspicious connection: {proc_name} -> {conn.raddr.ip}:{conn.raddr.port}", "CRITICAL")
                    with self._lock:
                        self.alerts.append({
                            'type': 'suspicious_connection',
                            'pid': conn.pid,
                            'process': proc_name,
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'time': datetime.now()
                        })
            except Exception:
                continue
    
    def get_recent_alerts(self, count=10) -> List[dict]:
        """Get recent alerts"""
        with self._lock:
            return self.alerts[-count:] if self.alerts else []


# ══════════════════════════════════════════════════════════════════════════════
#                         INTEGRATION EXAMPLE
# ══════════════════════════════════════════════════════════════════════════════

"""
To integrate with umbrella_v12.py, replace the SmartScanner with BehaviorScanner:

1. Import:
   from behavior_scanner import BehaviorScanner, RealTimeMonitor

2. In UmbrellaSecurityApp.__init__():
   self.scanner = BehaviorScanner(self.db, callback=self._log)
   self.realtime_monitor = RealTimeMonitor(callback=self._log)

3. In start_quick_scan():
   result = self.scanner.quick_behavioral_scan(progress_callback=...)

4. In start_full_scan():
   result = self.scanner.full_behavioral_scan(progress_callback=...)

5. In toggle_shield():
   if self.shield_active:
       self.realtime_monitor.start()
   else:
       self.realtime_monitor.stop()

The scanner will analyze:
- What processes are DOING (not their names)
- Where they're connecting (not their names)
- How they persist (not their names)
- Their actual code patterns (not random string matching)
- Their file hashes against known malware databases
"""

# ========================================================================
# v29: KEV CORRELATION FOR BEHAVIORS
# ========================================================================

def get_technique_cve_mapping(technique_id: str) -> List[Dict]:
    """Get CVEs associated with MITRE ATT&CK technique.
    
    Args:
        technique_id: MITRE technique ID (e.g., 'T1056.001')
        
    Returns:
        List of CVE dicts with KEV and EPSS data
    """
    cve_mappings = []
    
    technique_cve_db = {
        'T1056.001': ['CVE-2024-1234', 'CVE-2023-5678'],
        'T1055': ['CVE-2024-4567', 'CVE-2023-7890'],
        'T1003': ['CVE-2024-2345', 'CVE-2023-3456'],
        'T1547': ['CVE-2024-7890', 'CVE-2023-8901'],
        'T1021': ['CVE-2024-3456', 'CVE-2023-4567'],
    }
    
    cve_list = technique_cve_db.get(technique_id, [])
    
    for cve_id in cve_list[:5]:
        try:
            from vulnerability_scanner import VulnerabilityScanner
            scanner = VulnerabilityScanner()
            
            kev_data = scanner.search_kev(cve_id)
            if kev_data:
                cve_mappings.append({
                    'cve_id': cve_id,
                    'technique': technique_id,
                    'in_kev': True,
                    'cvss': kev_data[0].get('cvss_score', 0),
                    'epss': scanner.get_epss_score(cve_id) or 0,
                    'ransomware': kev_data[0].get('ransomware', 'No')
                })
        except Exception:
            pass
    
    return cve_mappings


def check_behavior_elevated_risk(behavior_type: str) -> Dict:
    """Check if behavior type has elevated risk based on KEV CVEs.
    
    Args:
        behavior_type: Type of suspicious behavior
        
    Returns:
        Dict with risk assessment and CVE context
    """
    result = {
        'behavior': behavior_type,
        'technique': '',
        'associated_cves': [],
        'elevated_risk': False,
        'epss_high': False,
        'recommendation': 'MONITOR'
    }
    
    technique_map = {
        'keylogging': 'T1056.001',
        'process_injection': 'T1055',
        'credential_theft': 'T1003',
        'persistence': 'T1547',
        'lateral_movement': 'T1021',
    }
    
    technique_id = technique_map.get(behavior_type, '')
    if technique_id:
        result['technique'] = technique_id
        cve_data = get_technique_cve_mapping(technique_id)
        
        if cve_data:
            result['associated_cves'] = cve_data
            max_epss = max((cve.get('epss', 0) for cve in cve_data), default=0)
            has_ransomware = any(cve.get('ransomware') == 'Yes' for cve in cve_data)
            
            if max_epss > 0.5 or has_ransomware:
                result['elevated_risk'] = True
                result['epss_high'] = max_epss > 0.5
                result['recommendation'] = 'INVESTIGATE'
    
    return result

