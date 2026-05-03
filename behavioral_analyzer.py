#!/usr/bin/env python3
"""
BEHAVIORAL ANALYSIS MODULE v29
"""
__version__ = "29.0.0"
import os
import logging
import threading
import time
from datetime import datetime, timedelta
from collections import defaultdict
try:
    import psutil
except ImportError:
    raise ImportError("behavioral_analyzer requires psutil")
try:
    import win32api
    import win32con
    import win32process
    import win32security
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False

try:
    from vulnerability_scanner import VulnerabilityScanner
    _KEV_AVAILABLE = True
except ImportError:
    _KEV_AVAILABLE = False

class BehavioralAnalyzer:
    """
    Main class for behavioral analysis of running processes.
    
    Monitors all processes and assigns suspicion scores based on behavior.
    Alerts when processes exhibit malicious patterns.
    """
    
    def __init__(self, config=None):
        """
        Initialize the behavioral analyzer.
        
        Parameters:
        - config: Configuration object (optional)
        """
        self.running = True
        self.config = config
        
        # Track process behavior over time
        self.process_history = defaultdict(lambda: {
            'cpu_usage': [],
            'network_connections': [],
            'file_operations': [],
            'api_calls': [],
            'suspicion_score': 0,
            'first_seen': datetime.now(),
            'alerts_sent': 0
        })
        
        # Suspicious behavior patterns
        self.suspicious_patterns = {
            'rapid_file_modifications': 50,  # Files per minute
            'high_cpu_persistent': 80,  # CPU % for >5 minutes
            'external_connections': 10,  # Connections per minute
            'hidden_process': 100,  # Instant high suspicion
            'privileged_operations': 5,  # Admin operations per minute
        }
        
        # Known good processes (won't be analyzed)
        self.whitelist = [
            'System',
            'svchost.exe',
            'explorer.exe',
            'MsMpEng.exe',  # Windows Defender
            'SecurityHealthService.exe',
            'python.exe',  # Our own process
            'conhost.exe',
            'csrss.exe',
            'lsass.exe',
            'services.exe',
            'smss.exe',
            'wininit.exe',
            'winlogon.exe',
        ]
    
    def get_process_info(self, pid):
        """
        Get detailed information about a process.
        
        Returns:
        - Dictionary with process details (name, path, user, etc.)
        - None if process doesn't exist or can't be accessed
        """
        try:
            proc = psutil.Process(pid)
            
            # Get basic info
            info = {
                'pid': pid,
                'name': proc.name(),
                'exe': proc.exe() if proc.exe() else 'Unknown',
                'username': proc.username() if proc.username() else 'Unknown',
                'create_time': datetime.fromtimestamp(proc.create_time()),
                'status': proc.status(),
            }
            
            # Get resource usage
            try:
                info['cpu_percent'] = proc.cpu_percent(interval=0.1)
                info['memory_mb'] = proc.memory_info().rss / (1024 * 1024)
                info['num_threads'] = proc.num_threads()
            except Exception:
                pass
            
            # Get network connections
            try:
                info['connections'] = len(proc.connections())
            except Exception:
                info['connections'] = 0
            
            return info
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None
        except Exception as e:
            logging.debug(f"Error getting process info for PID {pid}: {e}")
            return None
    
    def detect_keylogger_behavior(self, proc_info):
        """
        Detect keylogger-like behavior patterns.
        
        Keylogger indicators:
        - Hooks keyboard input (monitors for keystrokes)
        - Writes frequently to log files
        - Often has hidden or misleading names
        - May send data over network
        - Low CPU usage but persistent
        
        Returns suspicion score (0-100)
        """
        score = 0
        reasons = []
        
        # Check for suspicious process names
        suspicious_names = ['logger', 'hook', 'key', 'capture', 'monitor']
        name_lower = proc_info.get('name', '').lower()
        
        for suspicious in suspicious_names:
            if suspicious in name_lower:
                score += 20
                reasons.append(f"Suspicious name contains '{suspicious}'")
                break
        
        # Check if process is hidden (no window but not a service)
        # In real implementation, would use Windows API to check
        
        # Check for persistent low CPU usage (typical of keyloggers)
        if proc_info.get('cpu_percent', 0) < 5:
            # Keyloggers typically use very little CPU
            pass
        
        return score, reasons
    
    def detect_ransomware_behavior(self, pid):
        """
        Detect ransomware-like behavior patterns.
        
        Ransomware indicators:
        - Rapidly modifies many files
        - Changes file extensions
        - Deletes shadow copies / backups
        - Creates ransom note files (README.txt, etc.)
        - Encrypts files (high CPU usage for crypto)
        
        Returns suspicion score (0-100)
        """
        score = 0
        reasons = []
        
        history = self.process_history[pid]
        
        # Check for rapid file operations
        file_ops = history.get('file_operations', [])
        recent_file_ops = len(file_ops) if isinstance(file_ops, list) else 0
        if recent_file_ops > self.suspicious_patterns['rapid_file_modifications']:
            score += 40
            reasons.append(f"Rapid file modifications: {recent_file_ops} in last minute")
        
        # Check for file extension changes
        # In real implementation, would monitor file system events
        
        # Check for high CPU usage (encryption is CPU-intensive)
        cpu_usage_list = history.get('cpu_usage', [])
        if isinstance(cpu_usage_list, list) and cpu_usage_list:
            avg_cpu = sum(cpu_usage_list) / len(cpu_usage_list)
            if avg_cpu > 70:
                score += 20
                reasons.append(f"High sustained CPU usage: {avg_cpu:.1f}%")
        
        return score, reasons
    
    def detect_cryptominer_behavior(self, proc_info):
        """
        Detect cryptocurrency mining malware.
        
        Cryptominer indicators:
        - Very high CPU usage (often 90-100%)
        - Persistent over long periods
        - Connects to mining pool servers
        - Often disguised with legitimate-looking names
        - Multiple instances running
        
        Returns suspicion score (0-100)
        """
        score = 0
        reasons = []
        
        cpu = proc_info.get('cpu_percent', 0)
        
        # Check for high CPU usage
        if cpu > self.suspicious_patterns['high_cpu_persistent']:
            score += 30
            reasons.append(f"Very high CPU usage: {cpu:.1f}%")
        
        # Check for network connections to known mining pools
        # Common mining pool ports: 3333, 4444, 5555, 8888
        # In real implementation, would check actual connection details
        
        # Check for suspicious names
        miner_names = ['miner', 'xmr', 'btc', 'crypto', 'coin']
        name_lower = proc_info.get('name', '').lower()
        
        for miner in miner_names:
            if miner in name_lower:
                score += 25
                reasons.append(f"Suspicious name: '{proc_info.get('name')}'")
                break
        
        return score, reasons
    
    def detect_data_exfiltration(self, proc_info):
        """
        Detect programs stealing data.
        
        Data theft indicators:
        - Accesses personal files (Documents, Downloads, etc.)
        - Sends large amounts of data over network
        - Connects to suspicious external IPs
        - Accesses browser data (cookies, passwords, history)
        - Reads credential stores
        
        Returns suspicion score (0-100)
        """
        score = 0
        reasons = []
        
        # Check for many network connections
        connections = proc_info.get('connections', 0)
        if connections > 10:
            score += 15
            reasons.append(f"Many network connections: {connections}")
        
        # In real implementation would check:
        # - File access patterns (reading many documents)
        # - Network traffic volume
        # - Destinations of network connections
        # - Access to browser data directories
        
        return score, reasons
    
    def detect_spyware_behavior(self, proc_info):
        """
        Detect spyware/monitoring software.
        
        Spyware indicators:
        - Takes screenshots
        - Records webcam/microphone
        - Monitors clipboard
        - Tracks browser history
        - Logs application usage
        - Hidden from task manager
        
        Returns suspicion score (0-100)
        """
        score = 0
        reasons = []
        
        # Check for webcam/microphone access
        # In real implementation, would use Windows API to detect device access
        
        # Check for screenshot behavior
        # Would monitor for repeated screen capture API calls
        
        # Check if process is hiding itself
        # Some spyware removes itself from task manager view
        
        return score, reasons
    
    def analyze_process(self, pid):
        """
        Comprehensive analysis of a single process.
        
        Runs all behavioral detection checks and calculates
        total suspicion score.
        
        Returns:
        - total_score: Overall suspicion (0-100)
        - alerts: List of concerning behaviors found
        """
        # Get current process info
        proc_info = self.get_process_info(pid)
        if not proc_info:
            return 0, [], {}

        # Skip whitelisted processes
        if proc_info['name'] in self.whitelist:
            return 0, [], proc_info
        
        # Run all detection methods
        total_score = 0
        all_reasons = []
        
        # Keylogger detection
        score, reasons = self.detect_keylogger_behavior(proc_info)
        total_score += score
        all_reasons.extend(reasons)
        
        # Ransomware detection
        score, reasons = self.detect_ransomware_behavior(pid)
        total_score += score
        all_reasons.extend(reasons)
        
        # Cryptominer detection
        score, reasons = self.detect_cryptominer_behavior(proc_info)
        total_score += score
        all_reasons.extend(reasons)
        
        # Data exfiltration detection
        score, reasons = self.detect_data_exfiltration(proc_info)
        total_score += score
        all_reasons.extend(reasons)
        
        # Spyware detection
        score, reasons = self.detect_spyware_behavior(proc_info)
        total_score += score
        all_reasons.extend(reasons)
        
        # Update process history
        self.process_history[pid]['suspicion_score'] = min(total_score, 100)
        
        return total_score, all_reasons, proc_info
    
    def scan_all_processes(self):
        """
        Scan all running processes for suspicious behavior.
        
        This is called periodically to analyze everything running
        on the system.
        """
        suspicious_found = []
        
        try:
            # Get all running processes
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    pid = proc.info['pid']
                    
                    # Analyze this process
                    result = self.analyze_process(pid)
                    if len(result) == 3:
                        score, reasons, proc_info = result
                    else:
                        score, reasons = result
                        proc_info = {}
                    
                    # Alert on high suspicion scores
                    if score > 40:  # MEDIUM threshold
                        suspicious_found.append({
                            'score': score,
                            'info': proc_info,
                            'reasons': reasons
                        })
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Report findings
            if suspicious_found:
                self.report_suspicious_processes(suspicious_found)
                
        except Exception as e:
            logging.error(f"Error scanning processes: {e}")
    
    def report_suspicious_processes(self, suspicious_list):
        """
        Report suspicious processes to alert system.
        
        Creates alerts for processes with high suspicion scores.
        """
        for item in suspicious_list:
            score = item['score']
            proc_info = item['info']
            reasons = item['reasons']
            
            # Determine severity
            if score >= 80:
                severity = "CRITICAL"
            elif score >= 60:
                severity = "HIGH"
            else:
                severity = "MEDIUM"
            
            # Create alert message
            message = f"Suspicious process detected: {proc_info['name']}"
            details = f"PID: {proc_info['pid']}\n"
            details += f"Path: {proc_info.get('exe', 'Unknown')}\n"
            details += f"Suspicion Score: {score}/100\n"
            details += f"User: {proc_info.get('username', 'Unknown')}\n"
            details += "\nSuspicious Behaviors:\n"
            for reason in reasons:
                details += f"  • {reason}\n"
            
            details += "\nRECOMMENDED ACTION:\n"
            if score >= 80:
                details += "IMMEDIATE: Terminate this process and scan with Windows Defender"
            elif score >= 60:
                details += "Investigate: Research this process online and consider terminating"
            else:
                details += "Monitor: Watch this process for additional suspicious activity"
            
            # Log the alert with context
            logging.warning(f"[{severity}] {message} | PID: {proc_info.get('pid')} | Score: {score}")
            logging.warning(details)
            
            # In real implementation, would call alert_system.add_alert()
    
    def monitoring_loop(self):
        """
        Continuous monitoring loop.
        
        Runs in background, periodically scanning all processes.
        """
        logging.info("Behavioral analysis monitoring started")
        
        while self.running:
            try:
                # Scan all processes
                self.scan_all_processes()
                
                # Clean up old history (keep last 24 hours)
                cutoff_time = datetime.now() - timedelta(hours=24)
                pids_to_remove = []
                
                for pid, history in self.process_history.items():
                    first_seen = history.get('first_seen')
                    if isinstance(first_seen, datetime) and first_seen < cutoff_time:
                        # Check if process still exists
                        if not psutil.pid_exists(pid):
                            pids_to_remove.append(pid)
                
                for pid in pids_to_remove:
                    del self.process_history[pid]
                
                # Sleep based on configuration
                scan_interval = 10  # seconds
                if self.config and self.config.has_option('GENERAL', 'scan_interval'):
                    scan_interval = self.config.getint('GENERAL', 'scan_interval')
                
                time.sleep(scan_interval)
                
            except Exception as e:
                logging.error(f"Error in behavioral monitoring loop: {e}")
                time.sleep(30)
    
    def start(self):
                # Initialize COM for this thread
                try:
                    import pythoncom
                    pythoncom.CoInitialize()
                except ImportError:
                    pass

        """Start behavioral monitoring in background thread."""
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
        logging.info("[OK] Behavioral Analysis System active")
    
    def stop(self):
        """Stop behavioral monitoring."""
        self.running = False
        logging.info("Behavioral analysis stopped")

# Global instance
_analyzer_instance = None

def get_analyzer(config=None) -> 'BehavioralAnalyzer':
    """Get global behavioral analyzer instance."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = BehavioralAnalyzer(config)
    return _analyzer_instance

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*80)
    print("          BEHAVIORAL ANALYSIS TEST")
    print("="*80)
    print("\nScanning all running processes for suspicious behavior...")
    print("This may take a minute...\n")
    
    analyzer = BehavioralAnalyzer()
    analyzer.scan_all_processes()
    
    print("\nScan complete. Check output above for any suspicious processes.")
    print("Press Enter to exit...")
    input()
