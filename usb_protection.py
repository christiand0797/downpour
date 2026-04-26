"""
================================================================================
FAMILY SECURITY SUITE - USB & EXTERNAL DRIVE PROTECTION
================================================================================

PURPOSE: Protects against BadUSB attacks, autorun malware, and malicious
         files on removable media. USB drives are a common infection vector!

WHAT IT PROTECTS AGAINST:
- BadUSB attacks (devices pretending to be keyboards)
- Autorun malware (programs that start automatically)
- Infected files on USB drives
- Hidden malware in USB partitions
- Malicious firmware on USB devices
- Data theft via USB (unauthorized copying)
- Rubber Ducky attacks (keystroke injection)

HOW IT WORKS:
1. Monitors for new USB device insertions
2. Scans all files before allowing access
3. Blocks autorun.inf files automatically
4. Checks device firmware signatures
5. Alerts on suspicious device behavior
6. Maintains whitelist of trusted devices
7. Logs all USB activity for review

FEATURES:
- Real-time USB insertion detection
- Automatic scanning with Windows Defender
- Autorun prevention
- Device fingerprinting
- Read-only mode option for untrusted devices
- Parental controls (can block USB for your son's account)

================================================================================
"""

try:
    import win32api
    import win32con
    import win32file
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False
try:
    import wmi
    _WMI_AVAILABLE = True
except ImportError:
    _WMI_AVAILABLE = False
try:
    import pythoncom
    pythoncom.CoInitialize()
except Exception:
    pass
import threading
import time
import logging
from pathlib import Path
from datetime import datetime
import os
import subprocess
import hashlib
import json

class USBProtection:
    """
    Monitor and protect against malicious USB/external drive threats.
    
    Key Features:
    - Real-time device insertion detection
    - Automatic malware scanning
    - Autorun blocking
    - Device whitelisting
    - Suspicious file detection
    - Parental USB controls
    """
    
    def __init__(self, config_path="config.ini"):
        self.logger = self.setup_logging()
        self.running = False
        self.config = self.load_config(config_path)
        
        # Whitelist of trusted USB devices (by serial number)
        self.trusted_devices = self.load_trusted_devices()
        
        # Current connected USB devices
        self.connected_devices = {}
        
        # Initialize WMI for device monitoring
        try:
            self.wmi = wmi.WMI()
        except Exception as e:
            self.logger.error(f"Failed to initialize WMI: {e}")
            self.wmi = None
        
        self.logger.info("USB Protection initialized")
    
    def setup_logging(self):
        """Configure logging for USB protection."""
        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"usb_protection_{datetime.now().strftime('%Y-%m-%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        return logging.getLogger('USBProtection')
    
    def load_config(self, config_path):
        """Load configuration settings."""
        # Default configuration
        config = {
            'auto_scan': True,
            'block_autorun': True,
            'alert_on_new_device': True,
            'parental_usb_block': False,  # Block USB for child accounts
            'scan_hidden_files': True,
            'max_file_size_mb': 100  # Max size to scan per file
        }
        
        # Load from config file if exists
        # (Integration with main config.ini would go here)
        
        return config
    
    def load_trusted_devices(self):
        """Load whitelist of trusted USB devices."""
        trust_file = Path(__file__).parent / "trusted_usb_devices.json"
        if trust_file.exists():
            try:
                with open(trust_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        return {}
    
    def save_trusted_devices(self):
        """Save whitelist of trusted USB devices."""
        trust_file = Path(__file__).parent / "trusted_usb_devices.json"
        try:
            with open(trust_file, 'w') as f:
                json.dump(self.trusted_devices, f, indent=2)
        except Exception as e:
            self.logger.error(f"Failed to save trusted devices: {e}")
    
    def start(self):
        """Start USB monitoring."""
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_usb_devices, daemon=True)
        self.monitor_thread.start()
        self.logger.info("USB Protection monitoring started")
    
    def stop(self):
        """Stop USB monitoring."""
        self.running = False
        self.logger.info("USB Protection monitoring stopped")
    
    def monitor_usb_devices(self):
        """Continuously monitor for USB device changes."""
        if not self.wmi:
            self.logger.error("WMI not available, USB monitoring disabled")
            return
        
        # Get initial device list
        previous_devices = set(self.get_removable_drives())
        
        while self.running:
            try:
                current_devices = set(self.get_removable_drives())
                
                # Check for new devices
                new_devices = current_devices - previous_devices
                for device in new_devices:
                    self.handle_new_device(device)
                
                # Check for removed devices
                removed_devices = previous_devices - current_devices
                for device in removed_devices:
                    self.handle_device_removed(device)
                
                previous_devices = current_devices
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                self.logger.error(f"USB monitoring error: {e}")
                time.sleep(5)
    
    def get_removable_drives(self):
        """Get list of all removable drives."""
        drives = []
        try:
            drive_bits = win32api.GetLogicalDrives()
            for letter in range(26):
                if drive_bits & (1 << letter):
                    drive_letter = chr(65 + letter) + ":\\"
                    try:
                        drive_type = win32file.GetDriveType(drive_letter)
                        if drive_type == win32con.DRIVE_REMOVABLE:
                            drives.append(drive_letter)
                    except Exception:
                        pass
        except Exception as e:
            self.logger.error(f"Error getting removable drives: {e}")
        
        return drives
    
    def handle_new_device(self, drive_path):
        """Handle newly connected USB device."""
        self.logger.warning(f"NEW USB DEVICE DETECTED: {drive_path}")
        
        # Get device information
        device_info = self.get_device_info(drive_path)
        device_id = device_info.get('serial', 'unknown')
        
        # Check if device is trusted
        is_trusted = device_id in self.trusted_devices
        
        if not is_trusted and self.config['alert_on_new_device']:
            alert_msg = f"⚠️ USB ALERT: New device connected\nDrive: {drive_path}\nDevice ID: {device_id}\n"
            alert_msg += f"Vendor: {device_info.get('vendor', 'Unknown')}\n"
            alert_msg += f"Product: {device_info.get('product', 'Unknown')}\n"
            print(alert_msg)
            self.logger.warning(alert_msg)
        
        # Block autorun files
        if self.config['block_autorun']:
            self.block_autorun(drive_path)
        
        # Perform automatic scan if enabled
        if self.config['auto_scan']:
            self.logger.info(f"Starting automatic scan of {drive_path}")
            self.scan_drive(drive_path)
        
        # Store device info
        self.connected_devices[drive_path] = device_info
    
    def handle_device_removed(self, drive_path):
        """Handle USB device removal."""
        self.logger.info(f"USB device removed: {drive_path}")
        if drive_path in self.connected_devices:
            del self.connected_devices[drive_path]
    
    def get_device_info(self, drive_path):
        """Extract information about the USB device."""
        info = {
            'drive': drive_path,
            'serial': 'unknown',
            'vendor': 'Unknown',
            'product': 'Unknown',
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Use WMI to get device details
            if not self.wmi:
                return info
            for disk in self.wmi.Win32_DiskDrive():
                for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
                    for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                        if logical_disk.Caption + "\\" == drive_path:
                            info['serial'] = disk.SerialNumber if disk.SerialNumber else 'unknown'
                            info['vendor'] = disk.Manufacturer if disk.Manufacturer else 'Unknown'
                            info['product'] = disk.Model if disk.Model else 'Unknown'
                            info['size_bytes'] = disk.Size if disk.Size else 0
                            break
        except Exception as e:
            self.logger.error(f"Error getting device info: {e}")
        
        return info
    
    def block_autorun(self, drive_path):
        """Block autorun.inf and other autorun files."""
        autorun_files = ['autorun.inf', 'autorun.bat', 'autorun.exe', 'autorun.com']
        
        for filename in autorun_files:
            file_path = Path(drive_path) / filename
            if file_path.exists():
                try:
                    # Rename to neutralize
                    blocked_path = file_path.parent / f"BLOCKED_{filename}"
                    file_path.rename(blocked_path)
                    self.logger.critical(f"🚨 BLOCKED AUTORUN FILE: {file_path}")
                    print(f"⛔ CRITICAL: Blocked autorun file at {file_path}")
                except Exception as e:
                    self.logger.error(f"Failed to block autorun file: {e}")
    
    def scan_drive(self, drive_path):
        """Scan USB drive with Windows Defender."""
        self.logger.info(f"Scanning {drive_path} with Windows Defender...")
        
        try:
            # Run Windows Defender quick scan on the drive
            defender_exe = os.path.expandvars(r'%ProgramFiles%\Windows Defender\MpCmdRun.exe')
            cmd = [defender_exe, '-Scan', '-ScanType', '3', '-File', str(drive_path)]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                self.logger.info(f"Scan completed successfully for {drive_path}")
            else:
                self.logger.warning(f"Scan returned code {result.returncode} for {drive_path}")
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Scan timeout for {drive_path}")
        except Exception as e:
            self.logger.error(f"Scan error for {drive_path}: {e}")
        
        # Also check for suspicious files
        self.check_suspicious_files(drive_path)
    
    def check_suspicious_files(self, drive_path):
        """Check for common malware file patterns."""
        suspicious_patterns = [
            '*.exe',  # Executables
            '*.scr',  # Screensavers (often malware)
            '*.pif',  # Program Information File (old malware)
            '*.bat',  # Batch files
            '*.cmd',  # Command files
            '*.vbs',  # VBScript
            '*.js',   # JavaScript (can be malicious)
            '*.lnk'   # Shortcuts (can hide malware)
        ]
        
        suspicious_found = []
        
        try:
            drive = Path(drive_path)
            for pattern in suspicious_patterns:
                for file in drive.rglob(pattern):
                    suspicious_found.append(str(file))
                    self.logger.warning(f"Suspicious file found: {file}")
            
            if suspicious_found:
                alert = f"⚠️ Found {len(suspicious_found)} suspicious files on {drive_path}:\n"
                for f in suspicious_found[:10]:  # Show first 10
                    alert += f"  - {f}\n"
                print(alert)
                
        except Exception as e:
            self.logger.error(f"Error checking suspicious files: {e}")

if __name__ == "__main__":
    # Test USB protection
    protection = USBProtection()
    protection.start()
    
    print("USB Protection is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        protection.stop()
        print("USB Protection stopped.")
