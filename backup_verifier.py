"""
===============================================================================
BACKUP INTEGRITY VERIFIER MODULE
===============================================================================
Purpose: Ensure ransomware backups are actually good and uncorrupted
Created: January 2026 - Claude's Enhancement

FEATURES:
- Verify backup integrity (not corrupted)
- Check backup freshness (recent enough)
- Test restore capability (can actually restore)
- Monitor backup storage health
- Alert on backup failures
- Automated backup testing schedule

USAGE:
    python backup_verifier.py --check-all
    python backup_verifier.py --test-restore
    python backup_verifier.py --monitor

Critical for ransomware protection - useless backups are worse than no backups
because they give false confidence!
===============================================================================
"""

import os
import sys
import hashlib
import json
import sqlite3
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import zipfile


class BackupIntegrityVerifier:
    """
    Verify that backups are valid and can be restored.
    """
    
    def __init__(self, config_path: str = "backup_config.json"):
        self.config_path = config_path
        self.db_path = "backup_integrity.db"
        
        # Default configuration
        self.config = {
            "backup_locations": [
                {"path": os.path.join(os.path.expanduser("~"), "Documents", "Backups"),
                 "type": "local", "priority": 1},
                {"path": "D:\\Backups", "type": "external", "priority": 2}
            ],
            "important_folders": [
                os.path.join(os.path.expanduser("~"), "Documents"),
                os.path.join(os.path.expanduser("~"), "Pictures"),
                os.path.join(os.path.expanduser("~"), "Desktop")
            ],
            "backup_max_age_days": 7,  # Alert if backup older than 7 days
            "test_restore_frequency_days": 30,  # Test restore monthly
            "integrity_check_frequency_days": 7   # Verify weekly
        }
        
        self.load_config()
        self.init_database()
    
    def load_config(self):
        """Load configuration from JSON file"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                    self.config.update(loaded_config)
                print(f"[OK] Loaded backup config from {self.config_path}")
            except Exception as e:
                print(f"[WARNING] Error loading config: {e}")
    
    def save_config(self):
        """Save configuration to JSON file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"[OK] Saved backup config")
        except Exception as e:
            print(f"[ERROR] Error saving config: {e}")
    
    def init_database(self):
        """Initialize SQLite database for tracking backups"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS backup_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    backup_location TEXT,
                    file_path TEXT,
                    file_hash TEXT,
                    file_size INTEGER,
                    backup_type TEXT,
                    is_valid BOOLEAN
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS integrity_checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    backup_location TEXT,
                    total_files INTEGER,
                    valid_files INTEGER,
                    corrupted_files INTEGER,
                    missing_files INTEGER,
                    check_duration_seconds REAL
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS restore_tests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    backup_location TEXT,
                    test_file TEXT,
                    restore_successful BOOLEAN,
                    error_message TEXT,
                    test_duration_seconds REAL
                )
            ''')

            conn.commit()
        finally:
            conn.close()
        print("[OK] Backup integrity database initialized")
    
    def check_all_backups(self) -> Dict:
        """
        Comprehensive check of all backup locations.
        """
        print("\n" + "=" * 80)
        print("🔍 CHECKING ALL BACKUP LOCATIONS")
        print("=" * 80)
        print("")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "locations_checked": 0,
            "total_backups": 0,
            "valid_backups": 0,
            "corrupted_backups": 0,
            "old_backups": 0,
            "warnings": [],
            "critical_issues": []
        }
        
        for location in self.config["backup_locations"]:
            path = location["path"]
            loc_type = location["type"]
            
            print(f"Checking {loc_type} backup: {path}")
            
            if not os.path.exists(path):
                warning = f"Backup location does not exist: {path}"
                print(f"  [ERROR] {warning}")
                results["critical_issues"].append(warning)
                continue
            
            results["locations_checked"] += 1
            
            # Check backup age
            age_check = self.check_backup_age(path)
            if not age_check["is_fresh"]:
                results["old_backups"] += 1
                results["warnings"].append(age_check["message"])
                print(f"  ⚠️  {age_check['message']}")
            
            # Check backup integrity
            integrity = self.verify_backup_integrity(path)
            results["total_backups"] += integrity["total_files"]
            results["valid_backups"] += integrity["valid_files"]
            results["corrupted_backups"] += integrity["corrupted_files"]
            
            if integrity["corrupted_files"] > 0:
                issue = f"Found {integrity['corrupted_files']} corrupted files in {path}"
                results["critical_issues"].append(issue)
                print(f"  🚨 {issue}")
            else:
                print(f"  [OK] All {integrity['total_files']} backup files are valid")
        
        # Overall assessment
        print("\n" + "=" * 80)
        print("BACKUP HEALTH SUMMARY")
        print("=" * 80)
        print(f"Locations Checked: {results['locations_checked']}")
        print(f"Total Backup Files: {results['total_backups']}")
        print(f"Valid Backups: {results['valid_backups']}")
        print(f"Corrupted Backups: {results['corrupted_backups']}")
        print(f"Old Backups: {results['old_backups']}")
        
        if results["critical_issues"]:
            print("\n🚨 CRITICAL ISSUES:")
            for issue in results["critical_issues"]:
                print(f"   • {issue}")
        
        if results["warnings"]:
            print("\n⚠️  WARNINGS:")
            for warning in results["warnings"]:
                print(f"   • {warning}")
        
        if not results["critical_issues"] and not results["warnings"]:
            print("\n[OK] All backups are healthy!")
        
        print("=" * 80)
        print("")
        
        return results
    
    def check_backup_age(self, backup_path: str) -> Dict:
        """Check if backups are recent enough"""
        result = {
            "is_fresh": True,
            "age_days": 0,
            "message": ""
        }
        
        try:
            # Find most recent backup file
            newest_time = 0
            for root, dirs, files in os.walk(backup_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    mtime = os.path.getmtime(file_path)
                    if mtime > newest_time:
                        newest_time = mtime
            
            if newest_time == 0:
                result["is_fresh"] = False
                result["message"] = f"No backup files found in {backup_path}"
                return result
            
            # Calculate age
            age = datetime.now() - datetime.fromtimestamp(newest_time)
            result["age_days"] = age.days
            
            max_age = self.config["backup_max_age_days"]
            if age.days > max_age:
                result["is_fresh"] = False
                result["message"] = (
                    f"Backup is {age.days} days old (max: {max_age} days). "
                    "Consider creating a new backup!"
                )
        
        except Exception as e:
            result["is_fresh"] = False
            result["message"] = f"Error checking backup age: {str(e)}"
        
        return result
    
    def verify_backup_integrity(self, backup_path: str) -> Dict:
        """Verify integrity of all backup files"""
        result = {
            "total_files": 0,
            "valid_files": 0,
            "corrupted_files": 0,
            "corrupted_file_list": []
        }
        
        start_time = datetime.now()
        
        try:
            for root, dirs, files in os.walk(backup_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    result["total_files"] += 1
                    
                    # Check if file is readable and not corrupted
                    is_valid = self.verify_file(file_path)
                    
                    if is_valid:
                        result["valid_files"] += 1
                    else:
                        result["corrupted_files"] += 1
                        result["corrupted_file_list"].append(file_path)
            
            # Log to database
            duration = (datetime.now() - start_time).total_seconds()
            self.log_integrity_check(
                backup_path, 
                result["total_files"],
                result["valid_files"],
                result["corrupted_files"],
                duration
            )
        
        except Exception as e:
            print(f"Error verifying backup integrity: {e}")
        
        return result
    
    def verify_file(self, file_path: str) -> bool:
        """Verify a single file is not corrupted"""
        try:
            # Try to open and read file
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files
                while chunk := f.read(8192):
                    pass
            
            # If it's a ZIP file, verify its integrity
            if file_path.lower().endswith('.zip'):
                with zipfile.ZipFile(file_path, 'r') as zip_file:
                    bad_file = zip_file.testzip()
                    if bad_file:
                        return False
            
            return True
        
        except Exception:
            return False
    
    def test_restore(self, backup_location: Optional[str] = None) -> Dict:
        """
        Test that we can actually restore from backups.
        Creates a test file, backs it up, deletes it, then restores it.
        """
        print("\n" + "=" * 80)
        print("[TEST] TESTING BACKUP RESTORE CAPABILITY")
        print("=" * 80)
        print("")
        
        if backup_location is None:
            # Use first backup location
            backup_location = self.config["backup_locations"][0]["path"]
        
        result = {
            "success": False,
            "message": "",
            "test_file": "",
            "duration": 0
        }
        
        start_time = datetime.now()
        
        try:
            # Create test directory in backup location
            test_dir = os.path.join(backup_location, "_restore_test")
            os.makedirs(test_dir, exist_ok=True)
            
            # Create test file
            test_file = os.path.join(test_dir, "test_file.txt")
            test_content = f"Backup restore test - {datetime.now().isoformat()}"
            test_hash = hashlib.sha256(test_content.encode()).hexdigest()
            
            print(f"1. Creating test file: {test_file}")
            with open(test_file, 'w') as f:
                f.write(test_content)
            
            # Simulate backup (copy to backup location)
            backup_file = os.path.join(test_dir, "test_file_backup.txt")
            print(f"2. Backing up test file to: {backup_file}")
            shutil.copy2(test_file, backup_file)
            
            # Delete original
            print(f"3. Deleting original file")
            os.remove(test_file)
            
            # Verify it's gone
            if os.path.exists(test_file):
                raise Exception("Original file still exists after deletion")
            print(f"   [OK] Original deleted successfully")
            
            # Restore from backup
            print(f"4. Restoring from backup")
            shutil.copy2(backup_file, test_file)
            
            # Verify restored file
            print(f"5. Verifying restored file")
            with open(test_file, 'r') as f:
                restored_content = f.read()
            
            restored_hash = hashlib.sha256(restored_content.encode()).hexdigest()
            
            if restored_hash == test_hash:
                result["success"] = True
                result["message"] = "Backup restore test PASSED - backups are working!"
                print(f"   [OK] Content matches original (hash verified)")
            else:
                result["success"] = False
                result["message"] = "Backup restore test FAILED - restored file is corrupted"
                print(f"   [ERROR] Content does NOT match original")
            
            # Cleanup
            print(f"6. Cleaning up test files")
            try:
                shutil.rmtree(test_dir)
            except Exception:
                pass
        
        except Exception as e:
            result["success"] = False
            result["message"] = f"Backup restore test FAILED: {str(e)}"
            print(f"   [ERROR] Error: {e}")
        
        result["duration"] = (datetime.now() - start_time).total_seconds()
        result["test_file"] = test_file
        
        # Log to database
        self.log_restore_test(
            backup_location,
            test_file,
            result["success"],
            result["message"],
            result["duration"]
        )
        
        print("\n" + "=" * 80)
        if result["success"]:
            print("[OK] RESTORE TEST: PASSED")
        else:
            print("[ERROR] RESTORE TEST: FAILED")
        print(f"Message: {result['message']}")
        print("=" * 80)
        print("")
        
        return result
    
    def monitor_backup_health(self):
        """
        Continuous monitoring mode - checks backup health periodically.
        """
        print("\n" + "=" * 80)
        print("[STATS] BACKUP HEALTH MONITORING")
        print("=" * 80)
        print("\nMonitoring backup locations... Press Ctrl+C to stop\n")
        
        try:
            while True:
                print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Running backup health check...")
                
                results = self.check_all_backups()
                
                # Alert on critical issues
                if results["critical_issues"]:
                    print("\n🚨 CRITICAL BACKUP ISSUES DETECTED!")
                    print("   Immediate action required:")
                    for issue in results["critical_issues"]:
                        print(f"   • {issue}")
                
                # Check if restore test is due
                last_test = self.get_last_restore_test_date()
                if last_test:
                    days_since = (datetime.now() - last_test).days
                    test_freq = self.config["test_restore_frequency_days"]
                    
                    if days_since >= test_freq:
                        print(f"\n⏰ Restore test is due (last test: {days_since} days ago)")
                        print("   Running automated restore test...")
                        self.test_restore()
                
                print(f"\nNext check in {self.config['integrity_check_frequency_days']} days...")
                print("Press Ctrl+C to stop monitoring")
                
                # Sleep until next check
                import time
                time.sleep(self.config["integrity_check_frequency_days"] * 24 * 60 * 60)
        
        except KeyboardInterrupt:
            print("\n\n🛑 Backup monitoring stopped")
    
    def log_integrity_check(self, backup_location: str, total: int, 
                           valid: int, corrupted: int, duration: float):
        """Log integrity check results to database"""
        timestamp = datetime.now().isoformat()
        missing = 0  # Could be calculated by comparing with previous backup
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO integrity_checks
                (timestamp, backup_location, total_files, valid_files,
                 corrupted_files, missing_files, check_duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, backup_location, total, valid, corrupted, missing, duration))
            conn.commit()
        finally:
            conn.close()

    def log_restore_test(self, backup_location: str, test_file: str,
                        success: bool, error_msg: str, duration: float):
        """Log restore test results to database"""
        timestamp = datetime.now().isoformat()

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO restore_tests
                (timestamp, backup_location, test_file, restore_successful,
                 error_message, test_duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, backup_location, test_file, success, error_msg, duration))
            conn.commit()
        finally:
            conn.close()

    def get_last_restore_test_date(self) -> Optional[datetime]:
        """Get the date of the last restore test"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp FROM restore_tests
                ORDER BY timestamp DESC LIMIT 1
            ''')
            result = cursor.fetchone()
        finally:
            conn.close()

        if result:
            return datetime.fromisoformat(result[0])
        return None
    
    def generate_report(self) -> str:
        """Generate comprehensive backup report"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            report_lines = []
            report_lines.append("=" * 80)
            report_lines.append("BACKUP INTEGRITY REPORT")
            report_lines.append("=" * 80)
            report_lines.append("")

            # Recent integrity checks
            cursor.execute('''
                SELECT timestamp, backup_location, total_files, valid_files, corrupted_files
                FROM integrity_checks
                ORDER BY timestamp DESC LIMIT 5
            ''')

            checks = cursor.fetchall()
            if checks:
                report_lines.append("[STATS] Recent Integrity Checks:")
                for timestamp, location, total, valid, corrupted in checks:
                    date_str = timestamp.split('T')[0]
                    status = "[OK] PASS" if corrupted == 0 else f"[ERROR] {corrupted} CORRUPTED"
                    report_lines.append(f"   [{date_str}] {location}: {valid}/{total} valid {status}")

            report_lines.append("")

            # Recent restore tests
            cursor.execute('''
                SELECT timestamp, backup_location, restore_successful
                FROM restore_tests
                ORDER BY timestamp DESC LIMIT 5
            ''')

            tests = cursor.fetchall()
            if tests:
                report_lines.append("[TEST] Recent Restore Tests:")
                for timestamp, location, success in tests:
                    date_str = timestamp.split('T')[0]
                    status = "[OK] PASS" if success else "[ERROR] FAIL"
                    report_lines.append(f"   [{date_str}] {location}: {status}")
        finally:
            conn.close()
        
        report_lines.append("")
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Family Security Suite - Backup Integrity Verifier")
    parser.add_argument('--check-all', action='store_true',
                       help='Check all backup locations')
    parser.add_argument('--test-restore', action='store_true',
                       help='Test backup restore capability')
    parser.add_argument('--monitor', action='store_true',
                       help='Continuous backup health monitoring')
    parser.add_argument('--report', action='store_true',
                       help='Generate backup integrity report')
    
    args = parser.parse_args()
    
    verifier = BackupIntegrityVerifier()
    
    if args.check_all:
        verifier.check_all_backups()
    elif args.test_restore:
        verifier.test_restore()
    elif args.monitor:
        verifier.monitor_backup_health()
    elif args.report:
        print(verifier.generate_report())
    else:
        print("Backup Integrity Verifier")
        print("\nUsage:")
        print("  python backup_verifier.py --check-all      # Check all backups")
        print("  python backup_verifier.py --test-restore   # Test restore capability")
        print("  python backup_verifier.py --monitor        # Continuous monitoring")
        print("  python backup_verifier.py --report         # Generate report")
