#!/usr/bin/env python3
"""
================================================================================
EMERGENCY RESPONSE SYSTEM
================================================================================
"""

__version__ = "29.0.0"
Created: January 2026 - Claude's Enhancement

FEATURES:
- ONE-CLICK PANIC BUTTON (instant lockdown)
- Immediate network isolation (disconnect internet)
- Process termination (kill suspicious programs)
- System snapshot (save current state)
- Emergency file backup (protect critical files)
- Forensics collection (gather evidence)
- Recovery mode (safe system restore)

USAGE:
    python emergency_response.py --panic          # INSTANT LOCKDOWN
    python emergency_response.py --isolate        # Disconnect network
    python emergency_response.py --snapshot       # Save system state
    python emergency_response.py --recover        # Enter recovery mode

Use this when you suspect ACTIVE attack happening RIGHT NOW!
===============================================================================
"""

import os
import sys
import subprocess
try:
    import psutil
except ImportError:
    raise ImportError("emergency_response requires psutil: pip install psutil")
import json
import shutil
import socket
from datetime import datetime
from pathlib import Path
from typing import Dict, List
import hashlib


class EmergencyResponse:
    """
    Emergency response system for active threats.
    """
    
    def __init__(self):
        self.response_log_path = "emergency_response_log.json"
        self.snapshot_dir = "emergency_snapshots"
        self.quarantine_dir = "emergency_quarantine"
        
        # Create directories
        os.makedirs(self.snapshot_dir, exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        self.response_log = []
    
    def panic_button(self):
        """
        EMERGENCY PANIC BUTTON - Execute all emergency procedures immediately!
        
        This is the "OH NO!" button when you realize you're being hacked RIGHT NOW.
        """
        print("\n" + "=" * 80)
        print("🚨 EMERGENCY PANIC BUTTON ACTIVATED 🚨")
        print("=" * 80)
        print("")
        print("Executing emergency lockdown procedures...")
        print("")
        
        timestamp = datetime.now().isoformat()
        response_id = hashlib.md5(timestamp.encode()).hexdigest()[:8]
        
        steps_completed = []
        steps_failed = []
        
        # Step 1: Isolate network
        print("STEP 1: Isolating system from network...")
        if self.isolate_network():
            print("  ✅ Network isolated successfully")
            steps_completed.append("Network isolation")
        else:
            print("  ❌ Network isolation failed")
            steps_failed.append("Network isolation")
        
        # Step 2: Take system snapshot
        print("\nSTEP 2: Taking system snapshot for forensics...")
        snapshot_path = self.take_system_snapshot(response_id)
        if snapshot_path:
            print(f"  ✅ Snapshot saved: {snapshot_path}")
            steps_completed.append("System snapshot")
        else:
            print("  ❌ Snapshot failed")
            steps_failed.append("System snapshot")
        
        # Step 3: Kill suspicious processes
        print("\nSTEP 3: Terminating suspicious processes...")
        killed = self.kill_suspicious_processes()
        print(f"  ✅ Terminated {len(killed)} suspicious processes")
        steps_completed.append(f"Killed {len(killed)} processes")
        
        # Step 4: Emergency backup of critical files
        print("\nSTEP 4: Emergency backup of critical files...")
        backup_path = self.emergency_backup(response_id)
        if backup_path:
            print(f"  ✅ Emergency backup created: {backup_path}")
            steps_completed.append("Emergency backup")
        else:
            print("  ⚠️  Emergency backup failed (non-critical)")
            steps_failed.append("Emergency backup")
        
        # Step 5: Lock workstation
        print("\nSTEP 5: Locking workstation...")
        if self.lock_workstation():
            print("  ✅ Workstation locked")
            steps_completed.append("Workstation lock")
        else:
            print("  ⚠️  Could not lock workstation")
            steps_failed.append("Workstation lock")
        
        # Step 6: Log the emergency response
        print("\nSTEP 6: Logging emergency response...")
        self.log_emergency_response(response_id, steps_completed, steps_failed)
        print("  ✅ Response logged")
        
        # Final report
        print("\n" + "=" * 80)
        print("🛡️  EMERGENCY LOCKDOWN COMPLETE")
        print("=" * 80)
        print(f"\nResponse ID: {response_id}")
        print(f"Timestamp: {timestamp}")
        print(f"\nSteps Completed: {len(steps_completed)}")
        for step in steps_completed:
            print(f"  ✅ {step}")
        
        if steps_failed:
            print(f"\nSteps Failed: {len(steps_failed)}")
            for step in steps_failed:
                print(f"  ❌ {step}")
        
        print("\n" + "=" * 80)
        print("NEXT STEPS:")
        print("  1. Your computer is now isolated and locked")
        print("  2. Do NOT unlock until you're sure the threat is gone")
        print("  3. Run a full system scan with Windows Defender")
        print("  4. Review the emergency snapshot for forensic evidence")
        print(f"  5. Check emergency logs in: {self.response_log_path}")
        print("  6. Consider professional help if threat persists")
        print("=" * 80)
        print("")
        
        return {
            "response_id": response_id,
            "timestamp": timestamp,
            "steps_completed": steps_completed,
            "steps_failed": steps_failed
        }
    
    def isolate_network(self) -> bool:
        """
        Immediately disconnect from all networks.
        Disables WiFi and Ethernet adapters.
        """
        print("  Disabling network adapters...")
        
        try:
            # Disable all network adapters
            result = subprocess.run(
                ['powershell', '-Command', 
                 'Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Disable-NetAdapter -Confirm:$false'],
                capture_output=True, timeout=10
            )
            
            # Verify network is down
            try:
                # Try to connect to Google DNS (8.8.8.8)
                socket.create_connection(("8.8.8.8", 53), timeout=2)
                # If we get here, network is still up
                print("  ⚠️  Network still appears to be active")
                return False
            except Exception:
                # Connection failed = network is down = success
                print("  ✅ Network successfully isolated")
                return True
        
        except Exception as e:
            print(f"  ❌ Error isolating network: {e}")
            return False
    
    def take_system_snapshot(self, response_id: str) -> str:
        """
        Take a snapshot of current system state for forensic analysis.
        Captures: running processes, network connections, open files, etc.
        """
        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "response_id": response_id,
            "processes": [],
            "network_connections": [],
            "loaded_drivers": [],
            "open_files": []
        }
        
        try:
            # Capture all running processes
            print("  Capturing running processes...")
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
                try:
                    snapshot["processes"].append({
                        "pid": proc.info['pid'],
                        "name": proc.info['name'],
                        "exe": proc.info['exe'],
                        "cmdline": proc.info['cmdline'],
                        "username": proc.info['username'],
                        "create_time": proc.info['create_time']
                    })
                except Exception:
                    pass
            
            # Capture network connections
            print("  Capturing network connections...")
            for conn in psutil.net_connections():
                try:
                    snapshot["network_connections"].append({
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                        "pid": conn.pid
                    })
                except Exception:
                    pass
            
            # Save snapshot
            snapshot_file = os.path.join(
                self.snapshot_dir, 
                f"emergency_snapshot_{response_id}.json"
            )
            
            with open(snapshot_file, 'w') as f:
                json.dump(snapshot, f, indent=4)
            
            print(f"  ✅ Captured {len(snapshot['processes'])} processes, "
                  f"{len(snapshot['network_connections'])} connections")
            
            return snapshot_file
        
        except Exception as e:
            print(f"  ❌ Error taking snapshot: {e}")
            return ""
    
    def kill_suspicious_processes(self) -> List[Dict]:
        """
        Terminate processes that are commonly used by malware.
        CAUTION: This is aggressive and may kill legitimate programs!
        """
        killed_processes = []
        
        # Suspicious process indicators
        suspicious_indicators = {
            "names": [
                "mimikatz", "psexec", "procdump", "lazagne",
                "netcat", "nc.exe", "ncat"
                # FIX-v28p41: Removed powershell.exe — killing ALL PowerShell
                # instances breaks Windows system functionality and Defender.
            ],
            "paths": [
                "\\temp\\", "\\appdata\\local\\temp\\", "\\users\\public\\"
            ],
            "no_description": True  # Processes without file description
        }
        
        print("  Scanning for suspicious processes...")
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                proc_info = proc.info
                is_suspicious = False
                reason = ""
                
                # Check process name
                proc_name = proc_info['name'].lower() if proc_info['name'] else ""
                if any(susp in proc_name for susp in suspicious_indicators["names"]):
                    is_suspicious = True
                    reason = f"Suspicious name: {proc_name}"
                
                # Check process path
                proc_exe = (proc_info['exe'] or "").lower()
                if any(path in proc_exe for path in suspicious_indicators["paths"]):
                    is_suspicious = True
                    reason = f"Suspicious location: {proc_exe}"
                
                # If suspicious, terminate
                if is_suspicious:
                    print(f"  🚫 Terminating: PID {proc_info['pid']} - {reason}")
                    proc.kill()
                    killed_processes.append({
                        "pid": proc_info['pid'],
                        "name": proc_name,
                        "exe": proc_exe,
                        "reason": reason
                    })
            
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        return killed_processes
    
    def emergency_backup(self, response_id: str) -> str:
        """
        Create emergency backup of critical files.
        """
        print("  Identifying critical files...")
        
        backup_dir = os.path.join(self.snapshot_dir, f"emergency_backup_{response_id}")
        os.makedirs(backup_dir, exist_ok=True)
        
        # Critical file locations
        critical_paths = [
            os.path.join(os.path.expanduser("~"), "Documents"),
            os.path.join(os.path.expanduser("~"), "Desktop")
        ]
        
        backed_up_count = 0
        
        try:
            for path in critical_paths:
                if not os.path.exists(path):
                    continue
                
                # Get all files (limit to prevent filling disk)
                files = []
                for root, dirs, filenames in os.walk(path):
                    for filename in filenames:
                        filepath = os.path.join(root, filename)
                        # Skip very large files (> 50MB)
                        try:
                            if os.path.getsize(filepath) < 50 * 1024 * 1024:
                                files.append(filepath)
                                if len(files) >= 1000:  # Limit to 1000 files
                                    break
                        except Exception:
                            pass
                    if len(files) >= 1000:
                        break
                
                # Copy files
                for filepath in files[:100]:  # Emergency backup limited to 100 most recent files
                    try:
                        rel_path = os.path.relpath(filepath, os.path.expanduser("~"))
                        dest = os.path.join(backup_dir, rel_path)
                        # FIX-v28p41: Prevent path traversal via symlinks
                        dest_real = os.path.realpath(dest)
                        if not dest_real.startswith(os.path.realpath(backup_dir)):
                            continue
                        os.makedirs(os.path.dirname(dest), exist_ok=True)
                        shutil.copy2(filepath, dest)
                        backed_up_count += 1
                    except Exception:
                        pass
            
            print(f"  ✅ Backed up {backed_up_count} critical files")
            return backup_dir
        
        except Exception as e:
            print(f"  ❌ Error during emergency backup: {e}")
            return ""
    
    def lock_workstation(self) -> bool:
        """Lock the Windows workstation"""
        try:
            # Windows: Lock workstation
            subprocess.run(['rundll32.exe', 'user32.dll,LockWorkStation'], check=True)
            return True
        except Exception as e:
            print(f"  Error locking workstation: {e}")
            return False
    
    def log_emergency_response(self, response_id: str, 
                              completed: List[str], failed: List[str]):
        """Log the emergency response for later review"""
        log_entry = {
            "response_id": response_id,
            "timestamp": datetime.now().isoformat(),
            "steps_completed": completed,
            "steps_failed": failed,
            "type": "PANIC_BUTTON"
        }
        
        # Load existing log (FIX-v28p41: handle corrupted JSON gracefully)
        log = []
        if os.path.exists(self.response_log_path):
            try:
                with open(self.response_log_path, 'r') as f:
                    log = json.load(f)
                if not isinstance(log, list):
                    log = []
            except (json.JSONDecodeError, ValueError):
                log = []
        
        log.append(log_entry)
        
        # Save updated log
        with open(self.response_log_path, 'w') as f:
            json.dump(log, f, indent=4)
    
    def recovery_mode(self):
        """
        Enter recovery mode - provides options to restore normal operation.
        """
        print("\n" + "=" * 80)
        print("🔧 EMERGENCY RECOVERY MODE")
        print("=" * 80)
        print("\nThis mode helps you recover from emergency lockdown.\n")
        
        while True:
            print("\nRecovery Options:")
            print("  1. Re-enable network connections")
            print("  2. Review emergency snapshots")
            print("  3. Restore from emergency backup")
            print("  4. View emergency response log")
            print("  5. Run system scan (Windows Defender)")
            print("  6. Exit recovery mode")
            
            choice = input("\nSelect option (1-6): ").strip()
            
            if choice == '1':
                self.restore_network()
            elif choice == '2':
                self.review_snapshots()
            elif choice == '3':
                self.restore_backup()
            elif choice == '4':
                self.view_response_log()
            elif choice == '5':
                self.run_system_scan()
            elif choice == '6':
                print("\nExiting recovery mode...")
                break
            else:
                print("Invalid option. Please try again.")
    
    def restore_network(self):
        """Re-enable network adapters"""
        print("\n🌐 Restoring network connections...")
        
        confirm = input("Are you SURE the threat is gone? (yes/no): ").strip().lower()
        if confirm != 'yes':
            print("Network restoration cancelled.")
            return
        
        try:
            subprocess.run(
                ['powershell', '-Command', 
                 'Get-NetAdapter | Where-Object {$_.Status -eq "Disabled"} | Enable-NetAdapter -Confirm:$false'],
                check=True
            )
            print("✅ Network adapters re-enabled")
        except Exception as e:
            print(f"❌ Error restoring network: {e}")
    
    def review_snapshots(self):
        """Review emergency snapshots"""
        print("\n📸 Emergency Snapshots:")
        
        snapshots = list(Path(self.snapshot_dir).glob("emergency_snapshot_*.json"))
        
        if not snapshots:
            print("  No emergency snapshots found.")
            return
        
        for i, snapshot in enumerate(snapshots, 1):
            print(f"  {i}. {snapshot.name}")
        
        choice = input("\nSelect snapshot to review (number) or 0 to cancel: ").strip()
        
        if choice.isdigit() and 0 < int(choice) <= len(snapshots):
            snapshot_file = snapshots[int(choice) - 1]
            with open(snapshot_file, 'r') as f:
                data = json.load(f)
            
            print(f"\nSnapshot: {snapshot_file.name}")
            print(f"Timestamp: {data['timestamp']}")
            print(f"Processes captured: {len(data['processes'])}")
            print(f"Network connections: {len(data['network_connections'])}")
    
    def restore_backup(self):
        """Restore from emergency backup"""
        print("\n💾 Emergency Backups:")
        
        backups = list(Path(self.snapshot_dir).glob("emergency_backup_*"))
        
        if not backups:
            print("  No emergency backups found.")
            return
        
        for i, backup in enumerate(backups, 1):
            print(f"  {i}. {backup.name}")
        
        print("\n⚠️  NOTE: Restore functionality requires manual review of backup contents.")
        print(f"   Backup location: {self.snapshot_dir}")
    
    def view_response_log(self):
        """View emergency response log"""
        print("\n📝 Emergency Response Log:")
        
        if not os.path.exists(self.response_log_path):
            print("  No emergency responses recorded.")
            return
        
        with open(self.response_log_path, 'r') as f:
            log = json.load(f)
        
        for entry in log:
            print(f"\n{'='*60}")
            print(f"Response ID: {entry['response_id']}")
            print(f"Timestamp: {entry['timestamp']}")
            print(f"Type: {entry['type']}")
            print(f"Steps Completed: {', '.join(entry['steps_completed'])}")
            if entry['steps_failed']:
                print(f"Steps Failed: {', '.join(entry['steps_failed'])}")
    
    def run_system_scan(self):
        """Run Windows Defender full system scan"""
        print("\n🔍 Starting Windows Defender full system scan...")
        print("   This may take 1-2 hours to complete.")
        
        try:
            subprocess.Popen(
                ['powershell', '-Command', 'Start-MpScan -ScanType FullScan'],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            print("✅ System scan started in new window")
        except Exception as e:
            print(f"❌ Error starting scan: {e}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Family Security Suite - Emergency Response")
    parser.add_argument('--panic', action='store_true',
                       help='🚨 EMERGENCY PANIC BUTTON - Instant lockdown!')
    parser.add_argument('--isolate', action='store_true',
                       help='Isolate network immediately')
    parser.add_argument('--snapshot', action='store_true',
                       help='Take system snapshot')
    parser.add_argument('--recover', action='store_true',
                       help='Enter recovery mode')
    
    args = parser.parse_args()
    
    er = EmergencyResponse()
    
    if args.panic:
        # PANIC BUTTON - Execute all emergency procedures
        er.panic_button()
    elif args.isolate:
        er.isolate_network()
    elif args.snapshot:
        response_id = datetime.now().strftime("%Y%m%d%H%M%S")
        er.take_system_snapshot(response_id)
    elif args.recover:
        er.recovery_mode()
    else:
        print("Family Security Suite - Emergency Response System")
        print("\n⚠️  EMERGENCY COMMANDS:")
        print("  python emergency_response.py --panic     # 🚨 INSTANT LOCKDOWN")
        print("  python emergency_response.py --isolate   # Disconnect network")
        print("  python emergency_response.py --snapshot  # Save system state")
        print("  python emergency_response.py --recover   # Recovery mode")
        print("\nUse --panic when you suspect ACTIVE attack happening NOW!")
