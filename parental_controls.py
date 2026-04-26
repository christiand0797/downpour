"""
===============================================================================
ADVANCED PARENTAL CONTROLS MODULE
===============================================================================
Purpose: Protect your son from inappropriate content and risky behavior online
Created: January 2026 - Claude's Enhancement

FEATURES:
- Website filtering (block inappropriate sites)
- Screen time management (set daily limits)
- Application restrictions (control which apps can run)
- Activity logging (see what your son does online)
- Real-time alerts for risky behavior
- Educational mode (teach safe internet habits)

USAGE:
    python parental_controls.py --setup
    python parental_controls.py --monitor

This module works alongside your existing Family Security Suite to add
comprehensive parental protection specifically for your son's safety.
===============================================================================
"""

import os
import sys
import json
import time
import sqlite3
import hashlib
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import socket
import re
from urllib.parse import urlparse
import ctypes
from typing import Dict, List, Optional, Tuple

# Try importing required modules
try:
    import psutil
    import win32api
    import win32con
    import win32security
    import winreg
except ImportError as e:
    print(f"⚠️  Missing dependency: {e}")
    print("Run: pip install psutil pywin32")
    sys.exit(1)


class ParentalControls:
    """
    Comprehensive parental control system for protecting your son online.
    """
    
    def __init__(self, config_path: str = "parental_config.json"):
        self.config_path = config_path
        self.db_path = "parental_controls.db"
        self.hosts_file = r"C:\Windows\System32\drivers\etc\hosts"
        self.backup_hosts = r"C:\Windows\System32\drivers\etc\hosts.backup"
        
        # Default configuration
        self.config = {
            "enabled": True,
            "child_username": "",  # Windows username for your son
            "screen_time": {
                "enabled": True,
                "weekday_limit_minutes": 120,  # 2 hours on school days
                "weekend_limit_minutes": 240,  # 4 hours on weekends
                "bedtime_start": "21:00",  # 9 PM
                "bedtime_end": "07:00",  # 7 AM
            },
            "web_filtering": {
                "enabled": True,
                "block_categories": [
                    "adult_content",
                    "gambling",
                    "violence",
                    "weapons",
                    "drugs",
                    "hate_speech"
                ],
                "custom_blocked_sites": [],
                "safe_search_enforced": True
            },
            "app_restrictions": {
                "enabled": True,
                "blocked_apps": [],  # List of .exe names to block
                "allowed_apps_only": False,  # If True, only whitelist apps can run
                "allowed_apps": []
            },
            "monitoring": {
                "log_websites": True,
                "log_apps": True,
                "log_searches": True,
                "alert_on_risky_behavior": True
            },
            "educational_mode": {
                "enabled": True,
                "show_blocked_reason": True,
                "teach_safe_habits": True
            }
        }
        
        # Known inappropriate domains (sample - would be much larger in production)
        self.blocked_categories = {
            "adult_content": [
                # Adult content sites blocked
                "pornhub.com", "xvideos.com", "xnxx.com", "redtube.com",
                "onlyfans.com", "chaturbate.com"
            ],
            "gambling": [
                "bet365.com", "888casino.com", "pokerstars.com",
                "draftkings.com", "fanduel.com"
            ],
            "violence": [
                "bestgore.com", "liveleak.com", "documenting reality.com"
            ],
            "weapons": [
                "armslist.com", "gunbroker.com"
            ],
            "drugs": [
                "silk road", "darknet markets"  # Patterns rather than full domains
            ]
        }
        
        self.load_config()
        self.init_database()
    
    def load_config(self):
        """Load configuration from JSON file"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    loaded_config = json.load(f)
                    # Merge with defaults
                    self.config.update(loaded_config)
                print(f"✅ Loaded parental controls config from {self.config_path}")
            except Exception as e:
                print(f"⚠️  Error loading config: {e}")
                print("Using default configuration")
    
    def save_config(self):
        """Save configuration to JSON file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            print(f"✅ Saved parental controls config to {self.config_path}")
        except Exception as e:
            print(f"❌ Error saving config: {e}")
    
    def init_database(self):
        """Initialize SQLite database for activity logging"""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            # Website visits table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS website_visits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    username TEXT,
                    url TEXT,
                    domain TEXT,
                    was_blocked BOOLEAN,
                    block_reason TEXT
                )
            ''')

            # Application usage table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS app_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    username TEXT,
                    app_name TEXT,
                    app_path TEXT,
                    was_blocked BOOLEAN,
                    duration_seconds INTEGER
                )
            ''')

            # Screen time tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS screen_time (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT,
                    username TEXT,
                    total_minutes INTEGER,
                    warnings_shown INTEGER,
                    UNIQUE(date, username)
                )
            ''')

            # Alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    username TEXT,
                    alert_type TEXT,
                    severity TEXT,
                    description TEXT,
                    action_taken TEXT
                )
            ''')

            conn.commit()
        finally:
            conn.close()
        print("✅ Parental controls database initialized")
    
    def setup_web_filtering(self):
        """
        Configure web filtering by modifying Windows hosts file.
        Blocks inappropriate websites at DNS level.
        """
        if not self.config["web_filtering"]["enabled"]:
            print("ℹ️  Web filtering is disabled in config")
            return
        
        print("\n🌐 Setting up web filtering...")
        
        # Check if we have admin rights (required to modify hosts file)
        if not self.is_admin():
            print("❌ Administrator rights required to modify hosts file!")
            print("   Right-click and 'Run as Administrator'")
            return False
        
        # Backup original hosts file
        try:
            if not os.path.exists(self.backup_hosts):
                import shutil
                shutil.copy2(self.hosts_file, self.backup_hosts)
                print(f"✅ Backed up hosts file to {self.backup_hosts}")
        except Exception as e:
            print(f"⚠️  Warning: Could not backup hosts file: {e}")
        
        # Build list of all domains to block
        domains_to_block = set()
        
        # Add domains from blocked categories
        for category in self.config["web_filtering"]["block_categories"]:
            if category in self.blocked_categories:
                domains_to_block.update(self.blocked_categories[category])
        
        # Add custom blocked sites
        domains_to_block.update(self.config["web_filtering"]["custom_blocked_sites"])
        
        # Read existing hosts file
        try:
            with open(self.hosts_file, 'r') as f:
                hosts_content = f.read()
        except Exception as e:
            print(f"❌ Error reading hosts file: {e}")
            return False
        
        # Add our blocking entries
        marker_start = "# === FAMILY SECURITY SUITE - PARENTAL CONTROLS START ===\n"
        marker_end = "# === FAMILY SECURITY SUITE - PARENTAL CONTROLS END ===\n"
        
        # Remove old entries if they exist
        if marker_start in hosts_content:
            start_idx = hosts_content.index(marker_start)
            end_idx = hosts_content.index(marker_end) + len(marker_end)
            hosts_content = hosts_content[:start_idx] + hosts_content[end_idx:]
        
        # Add new entries
        blocking_entries = [marker_start]
        blocking_entries.append(f"# Blocking {len(domains_to_block)} inappropriate domains\n")
        blocking_entries.append(f"# Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        for domain in sorted(domains_to_block):
            # Block both www and non-www versions
            blocking_entries.append(f"127.0.0.1 {domain}\n")
            if not domain.startswith("www."):
                blocking_entries.append(f"127.0.0.1 www.{domain}\n")
        
        blocking_entries.append(marker_end)
        
        # Write updated hosts file
        try:
            with open(self.hosts_file, 'w') as f:
                f.write(hosts_content)
                f.write('\n')
                f.writelines(blocking_entries)
            
            print(f"✅ Web filtering enabled - {len(domains_to_block)} domains blocked")
            
            # Flush DNS cache
            self.flush_dns_cache()
            return True
            
        except Exception as e:
            print(f"❌ Error writing hosts file: {e}")
            return False
    
    def flush_dns_cache(self):
        """Flush Windows DNS cache to apply hosts file changes immediately"""
        try:
            subprocess.run(['ipconfig', '/flushdns'], 
                         capture_output=True, check=True)
            print("✅ DNS cache flushed - blocks active immediately")
        except Exception as e:
            print(f"⚠️  Could not flush DNS cache: {e}")
    
    def monitor_applications(self):
        """
        Monitor running applications and enforce restrictions.
        Block apps that are on the blocklist.
        """
        if not self.config["app_restrictions"]["enabled"]:
            return
        
        blocked_apps = set(self.config["app_restrictions"]["blocked_apps"])
        allowed_apps = set(self.config["app_restrictions"]["allowed_apps"])
        allowed_only = self.config["app_restrictions"]["allowed_apps_only"]
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'exe']):
            try:
                proc_info = proc.info
                proc_name = proc_info['name'].lower()
                proc_exe = proc_info.get('exe', '')
                
                # Check if this is our monitored child's process
                username = proc_info.get('username', '').split('\\')[-1]
                if username != self.config.get("child_username", ""):
                    continue  # Only monitor the specified child user
                
                should_block = False
                block_reason = ""
                
                # Check blocklist
                if proc_name in blocked_apps:
                    should_block = True
                    block_reason = f"App '{proc_name}' is on the blocked list"
                
                # Check allowlist (if enabled)
                elif allowed_only and proc_name not in allowed_apps:
                    should_block = True
                    block_reason = f"App '{proc_name}' is not on the allowed list"
                
                if should_block:
                    print(f"🚫 Blocking app: {proc_name} (PID: {proc_info['pid']})")
                    print(f"   Reason: {block_reason}")
                    
                    # Terminate the process
                    proc.terminate()
                    
                    # Log the event
                    self.log_app_usage(username, proc_name, proc_exe, True)
                    self.create_alert(username, "APP_BLOCKED", "MEDIUM",
                                    block_reason, f"Terminated PID {proc_info['pid']}")
                    
                    # Show educational message to the child
                    if self.config["educational_mode"]["enabled"]:
                        self.show_educational_message(
                            "Application Blocked",
                            f"{proc_name} is blocked for your safety.\n\n"
                            f"Reason: {block_reason}\n\n"
                            "If you believe this is a mistake, please ask your parent."
                        )
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    def check_screen_time(self) -> Tuple[bool, str]:
        """
        Check if screen time limits have been exceeded.
        Returns: (is_exceeded, message)
        """
        if not self.config["screen_time"]["enabled"]:
            return False, ""
        
        # Get today's usage
        today = datetime.now().date().isoformat()
        username = self.config.get("child_username", "")
        
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT total_minutes FROM screen_time
                WHERE date = ? AND username = ?
            ''', (today, username))
            result = cursor.fetchone()
        finally:
            conn.close()
        
        current_minutes = result[0] if result else 0
        
        # Check if it's a weekday or weekend
        is_weekend = datetime.now().weekday() >= 5
        limit_minutes = (self.config["screen_time"]["weekend_limit_minutes"] 
                        if is_weekend 
                        else self.config["screen_time"]["weekday_limit_minutes"])
        
        # Check bedtime
        current_time = datetime.now().strftime("%H:%M")
        bedtime_start = self.config["screen_time"]["bedtime_start"]
        bedtime_end = self.config["screen_time"]["bedtime_end"]
        
        if bedtime_start <= current_time or current_time < bedtime_end:
            return True, f"It's bedtime! Computer access is restricted between {bedtime_start} and {bedtime_end}."
        
        # Check daily limit
        if current_minutes >= limit_minutes:
            return True, f"Screen time limit reached ({current_minutes}/{limit_minutes} minutes used today)"
        
        # Check if getting close to limit (warn at 80%)
        if current_minutes >= limit_minutes * 0.8:
            remaining = limit_minutes - current_minutes
            return False, f"⚠️  Warning: Only {remaining} minutes remaining today!"
        
        return False, ""
    
    def update_screen_time(self, minutes: int = 1):
        """Update screen time counter"""
        today = datetime.now().date().isoformat()
        username = self.config.get("child_username", "")
        
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO screen_time (date, username, total_minutes, warnings_shown)
                VALUES (?, ?, ?, 0)
                ON CONFLICT(date, username) DO UPDATE SET
                total_minutes = total_minutes + ?
            ''', (today, username, minutes, minutes))
            conn.commit()
        finally:
            conn.close()
    
    def log_website_visit(self, username: str, url: str, 
                          was_blocked: bool, block_reason: str = ""):
        """Log website visit to database"""
        domain = urlparse(url).netloc
        timestamp = datetime.now().isoformat()
        
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO website_visits
                (timestamp, username, url, domain, was_blocked, block_reason)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, username, url, domain, was_blocked, block_reason))
            conn.commit()
        finally:
            conn.close()

    def log_app_usage(self, username: str, app_name: str,
                     app_path: str, was_blocked: bool, duration: int = 0):
        """Log application usage to database"""
        timestamp = datetime.now().isoformat()

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO app_usage
                (timestamp, username, app_name, app_path, was_blocked, duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, username, app_name, app_path, was_blocked, duration))
            conn.commit()
        finally:
            conn.close()

    def create_alert(self, username: str, alert_type: str, severity: str,
                    description: str, action_taken: str):
        """Create an alert for parental review"""
        timestamp = datetime.now().isoformat()

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts
                (timestamp, username, alert_type, severity, description, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, username, alert_type, severity, description, action_taken))
            conn.commit()
        finally:
            conn.close()
        
        # Also print to console for real-time monitoring
        print(f"\n🚨 [{severity}] PARENTAL ALERT: {alert_type}")
        print(f"   User: {username}")
        print(f"   {description}")
        print(f"   Action: {action_taken}\n")
    
    def show_educational_message(self, title: str, message: str):
        """
        Show a friendly educational message to the child.
        Uses Windows message box.
        """
        if not self.config["educational_mode"]["show_blocked_reason"]:
            return
        
        try:
            ctypes.windll.user32.MessageBoxW(
                0, message, title, 
                0x40 | 0x0  # MB_ICONINFORMATION | MB_OK
            )
        except Exception as e:
            print(f"Could not show message box: {e}")
    
    def is_admin(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    
    def generate_daily_report(self) -> str:
        """Generate a daily activity report for parent review"""
        today = datetime.now().date().isoformat()
        username = self.config.get("child_username", "")
        
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            report_lines = []
            report_lines.append("=" * 80)
            report_lines.append(f"DAILY PARENTAL CONTROLS REPORT - {today}")
            report_lines.append("=" * 80)
            report_lines.append("")

            # Screen time
            cursor.execute('''
                SELECT total_minutes FROM screen_time
                WHERE date = ? AND username = ?
            ''', (today, username))
            result = cursor.fetchone()
            total_minutes = result[0] if result else 0
            report_lines.append(f"📊 SCREEN TIME: {total_minutes} minutes ({total_minutes/60:.1f} hours)")
            report_lines.append("")

            # Blocked websites
            cursor.execute('''
                SELECT COUNT(*), domain FROM website_visits
                WHERE date(timestamp) = ? AND username = ? AND was_blocked = 1
                GROUP BY domain
                ORDER BY COUNT(*) DESC
                LIMIT 10
            ''', (today, username))
            blocked_sites = cursor.fetchall()

            if blocked_sites:
                report_lines.append(f"🚫 BLOCKED WEBSITES: {len(blocked_sites)} different sites")
                for count, domain in blocked_sites:
                    report_lines.append(f"   • {domain}: {count} attempt(s)")
                report_lines.append("")

            # Blocked applications
            cursor.execute('''
                SELECT COUNT(*), app_name FROM app_usage
                WHERE date(timestamp) = ? AND username = ? AND was_blocked = 1
                GROUP BY app_name
            ''', (today, username))
            blocked_apps = cursor.fetchall()

            if blocked_apps:
                report_lines.append(f"🚫 BLOCKED APPLICATIONS:")
                for count, app_name in blocked_apps:
                    report_lines.append(f"   • {app_name}: {count} attempt(s)")
                report_lines.append("")

            # Alerts
            cursor.execute('''
                SELECT timestamp, alert_type, severity, description
                FROM alerts
                WHERE date(timestamp) = ? AND username = ?
                ORDER BY timestamp DESC
            ''', (today, username))
            alerts = cursor.fetchall()

            if alerts:
                report_lines.append(f"⚠️  ALERTS: {len(alerts)} total")
                for timestamp, alert_type, severity, description in alerts[:10]:
                    time_str = timestamp.split('T')[1][:5]  # HH:MM
                    report_lines.append(f"   [{severity}] {time_str} - {alert_type}: {description}")
                report_lines.append("")
        finally:
            conn.close()
        
        report_lines.append("=" * 80)
        report_lines.append("Review complete logs in parental_controls.db for full details")
        report_lines.append("=" * 80)
        
        return "\n".join(report_lines)
    
    def run_monitoring_loop(self):
        """
        Main monitoring loop.
        Continuously monitors applications, screen time, etc.
        """
        print("\n" + "=" * 80)
        print("🛡️  PARENTAL CONTROLS - MONITORING ACTIVE")
        print("=" * 80)
        print(f"Child User: {self.config.get('child_username', 'NOT SET')}")
        print(f"Web Filtering: {'ENABLED' if self.config['web_filtering']['enabled'] else 'DISABLED'}")
        print(f"App Restrictions: {'ENABLED' if self.config['app_restrictions']['enabled'] else 'DISABLED'}")
        print(f"Screen Time Limits: {'ENABLED' if self.config['screen_time']['enabled'] else 'DISABLED'}")
        print("=" * 80)
        print("\nPress Ctrl+C to stop monitoring\n")
        
        check_interval = 10  # Check every 10 seconds
        minute_counter = 0
        
        try:
            while True:
                # Check screen time limits
                exceeded, message = self.check_screen_time()
                if exceeded:
                    print(f"⏰ {message}")
                    self.show_educational_message("Screen Time Limit", message)
                    # In real implementation, could log out user or block input
                elif message:  # Warning message
                    print(message)
                
                # Monitor applications
                self.monitor_applications()
                
                # Update screen time counter (every minute)
                minute_counter += check_interval
                if minute_counter >= 60:
                    self.update_screen_time(1)
                    minute_counter = 0
                
                time.sleep(check_interval)
                
        except KeyboardInterrupt:
            print("\n\n🛑 Parental controls monitoring stopped")
            print("\nGenerating daily report...")
            print(self.generate_daily_report())


def setup_wizard():
    """Interactive setup wizard for parental controls"""
    print("\n" + "=" * 80)
    print("🧙 PARENTAL CONTROLS SETUP WIZARD")
    print("=" * 80)
    print("\nThis wizard will help you configure parental controls to protect your son.\n")
    
    pc = ParentalControls()
    
    # Get child's username
    print("Step 1: Child's Windows Username")
    print("   (This is the username your son logs in with)")
    username = input("Enter username: ").strip()
    pc.config["child_username"] = username
    
    # Web filtering
    print("\nStep 2: Web Filtering")
    response = input("Enable web filtering to block inappropriate websites? (Y/n): ").strip().lower()
    pc.config["web_filtering"]["enabled"] = response != 'n'
    
    if pc.config["web_filtering"]["enabled"]:
        print("\n   Blocked categories:")
        for category in pc.config["web_filtering"]["block_categories"]:
            print(f"   ✅ {category}")
        
        custom = input("\n   Add custom blocked sites? (y/N): ").strip().lower()
        if custom == 'y':
            print("   Enter sites to block (one per line, blank line to finish):")
            while True:
                site = input("   Site: ").strip()
                if not site:
                    break
                pc.config["web_filtering"]["custom_blocked_sites"].append(site)
    
    # Screen time limits
    print("\nStep 3: Screen Time Limits")
    response = input("Enable screen time limits? (Y/n): ").strip().lower()
    pc.config["screen_time"]["enabled"] = response != 'n'
    
    if pc.config["screen_time"]["enabled"]:
        weekday = input("   Weekday limit (minutes, default 120): ").strip()
        if weekday.isdigit():
            pc.config["screen_time"]["weekday_limit_minutes"] = int(weekday)
        
        weekend = input("   Weekend limit (minutes, default 240): ").strip()
        if weekend.isdigit():
            pc.config["screen_time"]["weekend_limit_minutes"] = int(weekend)
        
        bedtime = input("   Bedtime (HH:MM, default 21:00): ").strip()
        if bedtime:
            pc.config["screen_time"]["bedtime_start"] = bedtime
    
    # App restrictions
    print("\nStep 4: Application Restrictions")
    response = input("Enable application restrictions? (Y/n): ").strip().lower()
    pc.config["app_restrictions"]["enabled"] = response != 'n'
    
    if pc.config["app_restrictions"]["enabled"]:
        print("   Common apps to consider blocking:")
        print("   • torrent clients (utorrent.exe, bittorrent.exe)")
        print("   • remote access tools (teamviewer.exe, anydesk.exe)")
        print("   • hacking tools")
        
        custom = input("\n   Add blocked apps? (y/N): ").strip().lower()
        if custom == 'y':
            print("   Enter app names to block (e.g., utorrent.exe, blank line to finish):")
            while True:
                app = input("   App: ").strip().lower()
                if not app:
                    break
                pc.config["app_restrictions"]["blocked_apps"].append(app)
    
    # Save configuration
    pc.save_config()
    
    print("\n" + "=" * 80)
    print("✅ SETUP COMPLETE")
    print("=" * 80)
    print("\nConfiguration saved to", pc.config_path)
    print("\nNext steps:")
    print("1. Run with administrator rights to enable web filtering:")
    print("   Right-click Command Prompt → 'Run as Administrator'")
    print("   python parental_controls.py --apply-filters")
    print("\n2. Start monitoring:")
    print("   python parental_controls.py --monitor")
    print("\n3. Add to your START_PROTECTION.bat to run automatically")
    print("=" * 80)


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Family Security Suite - Parental Controls")
    parser.add_argument('--setup', action='store_true', 
                       help='Run interactive setup wizard')
    parser.add_argument('--apply-filters', action='store_true',
                       help='Apply web filtering (requires admin)')
    parser.add_argument('--monitor', action='store_true',
                       help='Start monitoring')
    parser.add_argument('--report', action='store_true',
                       help='Generate daily activity report')
    
    args = parser.parse_args()
    
    if args.setup:
        setup_wizard()
    elif args.apply_filters:
        pc = ParentalControls()
        pc.setup_web_filtering()
    elif args.monitor:
        pc = ParentalControls()
        pc.run_monitoring_loop()
    elif args.report:
        pc = ParentalControls()
        print(pc.generate_daily_report())
    else:
        print("Family Security Suite - Parental Controls")
        print("\nUsage:")
        print("  python parental_controls.py --setup          # First-time setup")
        print("  python parental_controls.py --apply-filters  # Apply web filtering (admin)")
        print("  python parental_controls.py --monitor        # Start monitoring")
        print("  python parental_controls.py --report         # Daily activity report")
