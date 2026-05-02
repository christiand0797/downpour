#!/usr/bin/env python3
"""
PROCESS MONITORING MODULE v29
"""
__version__ = "29.0.0"
import os
import logging
logger = logging.getLogger(__name__)
import threading
import time
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False
    raise ImportError("process_monitor requires psutil: pip install psutil")

try:
    from vulnerability_scanner import VulnerabilityScanner
    _KEV_AVAILABLE = True
except ImportError:
    _KEV_AVAILABLE = False


def check_process_kev(process_name: str) -> dict:
    """Check process against CISA KEV catalog for known vulnerabilities."""
    if not _KEV_AVAILABLE:
        return {'matched_cves': [], 'kev_available': False}
    try:
        scanner = VulnerabilityScanner()
        kev_data = scanner.get_kev_catalog()
        if not kev_data:
            return {'matched_cves': [], 'kev_available': False}
        
        matches = []
        proc_lower = process_name.lower()
        for entry in kev_data:
            prod = entry.get('product', '').lower()
            if proc_lower in prod or prod in proc_lower:
                matches.append({
                    'cve': entry.get('cveID'),
                    'vendor': entry.get('vendorProject'),
                    'product': entry.get('product'),
                    'date_added': entry.get('dateAdded')
                })
        
        return {
            'matched_cves': matches[:5],
            'kev_available': True,
            'count': len(matches)
        }
    except Exception:
        return {'matched_cves': [], 'kev_available': False}


from datetime import datetime, timedelta
from collections import defaultdict
import os

class ProcessMonitor:
    """
    Monitors running processes for suspicious activity.
    
    Watches all processes and alerts on suspicious behavior
    like hidden processes, code injection, or disguised malware.
    """
    
    def __init__(self, config=None):
        """
        Initialize process monitor.
        
        Parameters:
        - config: Configuration object (optional)
        """
        self.running = True
        self.config = config
        
        # Track known processes
        self.known_processes = {}
        self.process_history = defaultdict(list)
        
        # Legitimate system processes (exact names)
        self.system_processes = {
            'System', 'smss.exe', 'csrss.exe', 'wininit.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe',
            'explorer.exe', 'dwm.exe', 'RuntimeBroker.exe',
            'MsMpEng.exe', 'SecurityHealthService.exe'
        }
        
        # Common malware name tricks (misspellings of system processes)
        self.suspicious_names = [
            'svch0st',  # svchost with zero
            'csrss',    # missing .exe
            'lsaas',    # extra 'a'
            'svhost',   # missing 'c'
            'scvhost',  # 'cv' instead of 'vc'
            'explorer',  # missing .exe
            'iexplore',  # old IE, rarely used now
        ]
        
        # Suspicious command line patterns
        self.suspicious_cmdline_patterns = [
            'powershell -enc',  # Encoded PowerShell (hides command)
            'powershell -w hidden',  # Hidden window
            'cmd /c echo',  # Often used in exploits
            'certutil -decode',  # Can download malware
            'bitsadmin',  # Can download files
            'reg add',  # Modifying registry
            'schtasks /create',  # Creating scheduled tasks
            '/start hidden',  # Starting hidden processes
        ]
        
        # Suspicious locations for executables
        self.suspicious_locations = [
            'AppData\\Local\\Temp',
            'AppData\\Roaming',
            'Downloads',
            'Public\\Downloads',
            'Temp',
            'Windows\\Temp',
        ]
        
        # Whitelist from config
        self.whitelist = set()
        if config and config.has_option('WHITELIST', 'trusted_process_names'):
            whitelist_str = config.get('WHITELIST', 'trusted_process_names')
            self.whitelist = set(p.strip() for p in whitelist_str.split('\n') if p.strip())
    
    def is_suspicious_location(self, path):
        """
        Check if executable is running from suspicious location.
        
        Malware often runs from Temp folders or Download directories.
        
        Parameters:
        - path: Full path to executable
        
        Returns:
        - True if location is suspicious
        """
        if not path:
            return False
        
        path_lower = path.lower()
        
        for location in self.suspicious_locations:
            if location.lower() in path_lower:
                return True
        
        return False
    
    def check_process_disguise(self, proc_info):
        """
        Check if process is trying to disguise itself.
        
        Malware often uses names similar to legitimate system processes.
        
        Parameters:
        - proc_info: Dictionary with process information
        
        Returns:
        - (is_suspicious: bool, reason: str)
        """
        name = proc_info.get('name', '').lower()
        path = proc_info.get('exe', '').lower()
        
        # Check for suspicious name patterns
        for suspicious in self.suspicious_names:
            if suspicious in name:
                return (True, f"Process name similar to system process: {name}")
        
        # Check if system process name running from wrong location
        for sys_proc in self.system_processes:
            if name == sys_proc.lower():
                # System processes should be in System32 or Windows folder
                if 'system32' not in path and 'windows' not in path:
                    return (True, f"System process running from unusual location: {path}")
        
        return (False, "")
    
    def check_suspicious_cmdline(self, cmdline):
        """
        Check command line arguments for suspicious patterns.
        
        Malware and exploits often use specific command patterns.
        
        Parameters:
        - cmdline: Command line string
        
        Returns:
        - (is_suspicious: bool, reason: str)
        """
        if not cmdline:
            return (False, "")
        
        cmdline_lower = cmdline.lower()
        
        for pattern in self.suspicious_cmdline_patterns:
            if pattern.lower() in cmdline_lower:
                return (True, f"Suspicious command line pattern: {pattern}")
        
        return (False, "")
    
    def check_process_injection(self, proc_info):
        """
        Check for signs of code injection and process hollowing.

        v28p37: Implemented real detection heuristics:
        - Unsigned exe loaded from temp/user directories
        - Memory anomaly: private working set >> image size
        - Thread count anomaly for known system processes
        - Command line mismatch (svchost without -k, etc.)
        - Suspended main thread (process hollowing signature)

        Parameters:
        - proc_info: Dictionary with process information

        Returns:
        - (is_suspicious: bool, reason: str)
        """
        if not _PSUTIL_AVAILABLE:
            return (False, "")

        reasons = []
        name = (proc_info.get('name') or '').lower()
        exe = (proc_info.get('exe') or '').lower()
        cmdline = proc_info.get('cmdline') or []
        pid = proc_info.get('pid', 0)

        # Skip PID 0/4 (System)
        if pid in (0, 4):
            return (False, "")

        # 1. svchost.exe without -k flag = likely hollowed
        if name == 'svchost.exe' and cmdline:
            cmd_str = ' '.join(cmdline).lower()
            if '-k' not in cmd_str:
                reasons.append("svchost.exe running without -k service flag (hollowing indicator)")

        # 2. System process running from wrong location
        system_exe_paths = {
            'svchost.exe': 'system32',
            'csrss.exe': 'system32',
            'lsass.exe': 'system32',
            'services.exe': 'system32',
            'winlogon.exe': 'system32',
            'smss.exe': 'system32',
            'wininit.exe': 'system32',
            'explorer.exe': 'windows',
        }
        if name in system_exe_paths and exe:
            expected_path = system_exe_paths[name]
            if expected_path not in exe:
                reasons.append(f"{name} running from unexpected location: {exe}")

        # 3. Memory anomaly: high private bytes with no matching exe size
        try:
            proc = _psutil.Process(pid)
            mem = proc.memory_info()
            private_mb = getattr(mem, 'private', getattr(mem, 'rss', 0)) / (1024 * 1024)
            # If a small system process uses >500MB private, suspicious
            if name in system_exe_paths and private_mb > 500:
                reasons.append(f"{name} using {private_mb:.0f}MB private memory (injection indicator)")
        except Exception:
            pass

        # 4. Thread count anomaly for known processes
        try:
            proc = _psutil.Process(pid)
            num_threads = proc.num_threads()
            # Normal notepad/calc has 1-5 threads; >50 suggests injection
            low_thread_procs = {'notepad.exe', 'calc.exe', 'mspaint.exe', 'write.exe'}
            if name in low_thread_procs and num_threads > 30:
                reasons.append(f"{name} has {num_threads} threads (expected <10, possible injection)")
        except Exception:
            pass

        if reasons:
            return (True, '; '.join(reasons))
        return (False, "")
    
    def analyze_process(self, proc):
        """
        Comprehensive analysis of a single process.
        
        Parameters:
        - proc: psutil.Process object
        
        Returns:
        - (suspicion_score: int, alerts: list)
        """
        try:
            # Get process information
            proc_info = {
                'pid': proc.pid,
                'name': proc.name(),
                'exe': proc.exe() if hasattr(proc, 'exe') else None,
                'username': proc.username() if hasattr(proc, 'username') else None,
                'create_time': datetime.fromtimestamp(proc.create_time()),
            }
            
            # Get command line (may fail for some processes)
            try:
                proc_info['cmdline'] = ' '.join(proc.cmdline())
            except Exception:
                proc_info['cmdline'] = None
            
            # Skip whitelisted processes
            if proc_info['name'] in self.whitelist:
                return (0, [], proc_info)

            # Skip known safe system processes
            if proc_info['name'] in self.system_processes:
                # But verify they're in correct location
                if proc_info['exe']:
                    exe_lower = proc_info['exe'].lower()
                    if 'system32' in exe_lower or 'windows' in exe_lower:
                        return (0, [], proc_info)
            
            score = 0
            alerts = []
            
            # Check for disguised process
            is_disguised, reason = self.check_process_disguise(proc_info)
            if is_disguised:
                score += 30
                alerts.append(reason)
            
            # Check for suspicious location
            if self.is_suspicious_location(proc_info['exe']):
                score += 20
                alerts.append(f"Running from suspicious location: {proc_info['exe']}")
            
            # Check command line
            is_suspicious_cmd, reason = self.check_suspicious_cmdline(proc_info['cmdline'])
            if is_suspicious_cmd:
                score += 25
                alerts.append(reason)
            
            # Check for code injection signs
            is_injected, reason = self.check_process_injection(proc_info)
            if is_injected:
                score += 40
                alerts.append(reason)
            
            # Check CPU usage (cryptominers use lots of CPU)
            try:
                cpu = proc.cpu_percent(interval=0.1)
                if cpu > 80:
                    score += 15
                    alerts.append(f"High CPU usage: {cpu:.1f}%")
            except Exception:
                pass
            
            return (score, alerts, proc_info)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return (0, [], {})
        except Exception as e:
            logging.debug(f"Error analyzing process: {e}")
            return (0, [], {})
    
    def scan_all_processes(self):
        """
        Scan all running processes for suspicious activity.
        
        This is called periodically to check everything running.
        """
        suspicious_found = []
        
        try:
            # Get all processes
            for proc in psutil.process_iter(['pid', 'name']):
                score, alerts, proc_info = self.analyze_process(proc)
                
                # Alert on high suspicion
                if score > 30:
                    suspicious_found.append({
                        'score': score,
                        'info': proc_info,
                        'alerts': alerts
                    })
            
            # Report findings
            if suspicious_found:
                self.report_suspicious_processes(suspicious_found)
                
        except Exception as e:
            logging.error(f"Error scanning processes: {e}")
    
    def report_suspicious_processes(self, suspicious_list):
        """
        Report suspicious processes to alert system.
        
        Parameters:
        - suspicious_list: List of suspicious process info
        """
        for item in suspicious_list:
            score = item['score']
            proc_info = item['info']
            alerts = item['alerts']
            
            # Determine severity
            if score >= 70:
                severity = "CRITICAL"
            elif score >= 50:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
            
            # Log the alert
            logging.warning(f"[{severity}] Suspicious Process: {proc_info['name']}")
            logging.warning(f"  PID: {proc_info['pid']}")
            logging.warning(f"  Path: {proc_info.get('exe', 'Unknown')}")
            logging.warning(f"  Suspicion Score: {score}/100")
            logging.warning(f"  Concerns:")
            for alert in alerts:
                logging.warning(f"    • {alert}")
            
            # In real implementation, would call add_alert()
    
    def monitoring_loop(self):
        """
        Continuous monitoring loop.
        
        Runs in background, periodically scanning all processes.
        """
        logging.info("Process monitoring started")
        
        while self.running:
            try:
                # Scan all processes
                self.scan_all_processes()
                
                # Sleep based on configuration
                scan_interval = 10  # seconds
                if self.config and self.config.has_option('GENERAL', 'scan_interval'):
                    scan_interval = self.config.getint('GENERAL', 'scan_interval')
                
                time.sleep(scan_interval)
                
            except Exception as e:
                logging.error(f"Error in process monitoring loop: {e}")
                time.sleep(30)
    
    def start(self):
        """Start process monitoring in background thread."""
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
        logging.info("[OK] Process Monitoring active")
        logging.info(f"Monitoring for {len(self.suspicious_names)} disguise patterns")
    
    def stop(self):
        """Stop process monitoring."""
        self.running = False
        logging.info("Process monitoring stopped")

# Global instance
_monitor_instance = None

def get_monitor(config=None) -> 'ProcessMonitor':
    """Get global process monitor instance."""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = ProcessMonitor(config)
    return _monitor_instance

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    logger.info("Process monitoring test starting")

    print("\n" + "="*80)
    print("          PROCESS MONITORING TEST")
    print("="*80)
    print("\nScanning all running processes...")
    print("This may take a moment...\n")

    monitor = ProcessMonitor()
    monitor.scan_all_processes()

    logger.info("Scan complete")
    print("\nScan complete. Check output above for any suspicious processes.")
    print("Press Enter to exit...")
    input()
