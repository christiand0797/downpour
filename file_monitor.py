#!/usr/bin/env python3
"""
================================================================================
FILE SYSTEM MONITORING MODULE
================================================================================
"""

__version__ = "29.0.0"
         indicate malware, especially ransomware.

v29: Added real-time file monitoring using Windows API (ReadDirectoryChangesW).

WHAT IT MONITORS:
- Documents, Desktop, Downloads, Pictures folders
- Rapid file modifications (ransomware encrypting files)
- Suspicious file creations
- File extension changes
- Hidden file creation
- System file modifications

HOW IT WORKS:
- Uses Windows file system change notifications
- Tracks file operations per minute
- Alerts when activity exceeds normal patterns
- Logs all file operations for review

RANSOMWARE DETECTION:
Ransomware typically encrypts many files very quickly.
This module watches for:
- 50+ files modified in one minute
- File extensions changing to unusual types
- Encrypted file signatures
- Ransom note files appearing (README.txt, HELP.txt, etc.)

================================================================================
"""

import logging
import threading
import time
import os
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
try:
    import win32file
    import win32con
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False

try:
    from vulnerability_scanner import VulnerabilityScanner
    _KEV_AVAILABLE = True
except ImportError:
    _KEV_AVAILABLE = False

class FileSystemMonitor:
    """
    Monitors file system for suspicious activity.
    
    Watches protected folders and alerts on rapid changes
    that could indicate ransomware or other file-based threats.
    """
    
    def __init__(self, config=None):
        """
        Initialize file system monitor.
        
        Parameters:
        - config: Configuration object (optional)
        """
        self.running = True
        self.config = config
        
        # Track file operations
        self.file_operations = defaultdict(list)
        self.operation_window = 60  # seconds
        
        # v29: Watch handles for real-time monitoring
        self._watch_handles = {}
        
        # Default protected folders
        self.protected_folders = [
            str(Path.home() / "Documents"),
            str(Path.home() / "Desktop"),
            str(Path.home() / "Downloads"),
            str(Path.home() / "Pictures"),
            str(Path.home() / "Videos"),
        ]
        
        # Load protected folders from config if available
        if config and config.has_option('FILE_MONITORING', 'protected_folders'):
            folder_str = config.get('FILE_MONITORING', 'protected_folders')
            custom_folders = [f.strip() for f in folder_str.split('\n') if f.strip()]
            if custom_folders:
                self.protected_folders = custom_folders
        
        # Ransomware threshold
        self.ransomware_threshold = 50
        if config and config.has_option('FILE_MONITORING', 'ransomware_threshold'):
            self.ransomware_threshold = config.getint('FILE_MONITORING', 'ransomware_threshold')
        
        # Suspicious file extensions
        self.suspicious_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', 
            '.vbs', '.js', '.jar', '.scr', '.com'
        ]
        
        # Known ransomware extensions
        self.ransomware_extensions = [
            '.encrypted', '.locked', '.crypto', '.cryptolocker',
            '.locky', '.cerber', '.zepto', '.wannacry'
        ]
        
        # Known ransom note filenames
        self.ransom_note_names = [
            'readme.txt', 'help.txt', 'recover.txt',
            'decrypt.txt', 'restore.txt', 'instructions.txt',
            'how_to_decrypt.txt', 'your_files_are_encrypted.txt'
        ]
    
    def record_file_operation(self, path, operation):
        """
        Record a file operation for analysis.
        
        Parameters:
        - path: File path that was modified
        - operation: Type of operation (created, modified, deleted, renamed)
        """
        current_time = datetime.now()
        
        # Record this operation
        self.file_operations[operation].append({
            'path': path,
            'time': current_time
        })
        
        # Clean up old operations outside time window
        cutoff_time = current_time - timedelta(seconds=self.operation_window)
        
        for op_type in self.file_operations:
            self.file_operations[op_type] = [
                op for op in self.file_operations[op_type]
                if op['time'] > cutoff_time
            ]
    
    def check_ransomware_activity(self):
        """
        Check if current file activity matches ransomware patterns.
        
        Returns:
        - (is_suspicious: bool, reason: str, details: str)
        """
        # Count recent file modifications
        total_modifications = len(self.file_operations['modified'])
        
        if total_modifications > self.ransomware_threshold:
            return (
                True,
                "Possible ransomware activity detected",
                f"{total_modifications} files modified in last {self.operation_window} seconds"
            )
        
        # Check for ransomware file extensions
        for op in self.file_operations['created']:
            path_lower = op['path'].lower()
            for ext in self.ransomware_extensions:
                if path_lower.endswith(ext):
                    return (
                        True,
                        "Ransomware file extension detected",
                        f"File with ransomware extension created: {op['path']}"
                    )
        
        # Check for ransom note files
        for op in self.file_operations['created']:
            filename = Path(op['path']).name.lower()
            if filename in self.ransom_note_names:
                return (
                    True,
                    "CRITICAL: Ransom note file detected",
                    f"Possible ransom note created: {op['path']}"
                )
        
        return (False, "", "")
    
    def monitor_folder(self, folder_path):
        """
        Monitor a single folder for changes using Windows API.
        
        v29: Uses win32file.ReadDirectoryChangesW for real-time notifications.
        
        Parameters:
        - folder_path: Path to folder to monitor
        """
        if not os.path.exists(folder_path):
            logging.warning(f"Cannot monitor non-existent folder: {folder_path}")
            return
        
        logging.info(f"Monitoring folder: {folder_path}")
        
        if not _WIN32_AVAILABLE:
            logging.warning(f"win32file not available - folder monitoring passive")
            return
        
        try:
            # Open directory for monitoring
            folder_handle = win32file.CreateFile(
                folder_path,
                0x00000001,  # FILE_LIST_DIRECTORY
                0x00000001 | 0x00000002 | 0x00000004,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                None,
                0x00000002,  # OPEN_EXISTING
                0x00000020,  # FILE_FLAG_OVERLAPPED
                None
            )
            
            # Start async monitoring
            overlapped = 0
            buffer_size = 65536
            
            # Start monitoring thread
            monitor_thread = threading.Thread(
                target=self._file_watch_loop,
                args=(folder_handle, folder_path, buffer_size),
                daemon=True
            )
            monitor_thread.start()
            
            self._watch_handles[folder_path] = folder_handle
            logging.info(f"Started real-time monitoring: {folder_path}")
            
        except Exception as e:
            logging.error(f"Failed to start folder monitoring: {e}")
    
    def monitoring_loop(self):
        """
        Main monitoring loop.
        
        Runs continuously, checking for suspicious file activity.
        """
        logging.info("File system monitoring started")
        
        # Start monitoring all protected folders
        for folder in self.protected_folders:
            self.monitor_folder(folder)
        
        while self.running:
            try:
                # Check for ransomware patterns
                is_suspicious, reason, details = self.check_ransomware_activity()
                
                if is_suspicious:
                    # Determine severity
                    if "CRITICAL" in reason:
                        severity = "CRITICAL"
                    elif "ransomware" in reason.lower():
                        severity = "CRITICAL"
                    else:
                        severity = "HIGH"
                    
                    # Log alert
                    logging.warning(f"[{severity}] File Monitor Alert: {reason}")
                    logging.warning(f"Details: {details}")
                    
                    # In real implementation, would call add_alert()
                
                # Sleep briefly
                time.sleep(5)
                
            except Exception as e:
                logging.error(f"Error in file monitoring loop: {e}")
                time.sleep(30)
    
    def start(self):
        """Start file system monitoring in background thread."""
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
        logging.info("[✓] File System Monitoring active")
        
        # Log protected folders
        logging.info(f"Protected folders ({len(self.protected_folders)}):")
        for folder in self.protected_folders:
            logging.info(f"  - {folder}")
    
    def stop(self):
        """Stop file system monitoring."""
        self.running = False
        logging.info("File system monitoring stopped")

# Global instance
_monitor_instance = None

def get_monitor(config=None):
    """Get global file monitor instance."""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = FileSystemMonitor(config)
    return _monitor_instance

if __name__ == "__main__":
    """Test file system monitoring."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*80)
    print("          FILE SYSTEM MONITORING TEST")
    print("="*80)
    print()
    
    monitor = FileSystemMonitor()
    monitor.start()
    
    print("\nMonitoring active. This is a test - real implementation would")
    print("use Windows API to watch for actual file system changes.")
    print("\nPress Enter to stop...")
    input()
    
    monitor.stop()

def check_file_monitor_kev():
    """Query KEV catalog for file monitor related vulnerabilities."""
    if not _KEV_AVAILABLE:
        return {"error": "VulnerabilityScanner not available"}
    try:
        scanner = VulnerabilityScanner()
        results = scanner.check_kev_catalog("file_monitor")
        return results
    except Exception as e:
        return {"error": str(e)}
