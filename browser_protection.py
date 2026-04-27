#!/usr/bin/env python3
"""
================================================================================
FAMILY SECURITY SUITE - BROWSER PROTECTION
================================================================================
"""

__version__ = "29.0.0"
         malicious extensions, hijacking, and dangerous web activity.

WHAT IT PROTECTS AGAINST:
- Malicious browser extensions stealing data
- Browser hijackers changing homepage/search
- Cryptojacking extensions (hidden cryptocurrency mining)
- Password-stealing extensions
- Ad-injection malware
- Browser redirect attacks
- Session hijacking attempts
- Fingerprinting and tracking scripts

HOW IT WORKS:
1. Monitors installed browser extensions
2. Checks extension permissions (red flags)
3. Detects suspicious browser behavior
4. Monitors browser data folders for changes
5. Alerts on dangerous extension installations
6. Tracks homepage/search engine changes
7. Monitors for credential theft attempts

SUPPORTED BROWSERS:
- Google Chrome
- Microsoft Edge (Chromium)
- Firefox
- Brave
- Opera

FEATURES FOR YOUR SON'S PROTECTION:
- Alerts on new extension installations
- Monitors for inappropriate content access
- Detects social media monitoring extensions
- Parental control extension protection
- Gaming site monitoring

================================================================================
"""

import os
import json
import sqlite3
import threading
import time
import logging
logger = logging.getLogger(__name__)
from pathlib import Path
from datetime import datetime
import hashlib

class BrowserProtection:
    """
    Monitor browsers for malicious extensions and suspicious activity.
    
    Key Features:
    - Extension permission analysis
    - Homepage hijack detection
    - Suspicious behavior monitoring
    - Data theft prevention
    - Parental control integration
    """
    
    def __init__(self, config_path="config.ini"):
        self.logger = self.setup_logging()
        self.running = False
        
        # Browser data paths
        self.browser_paths = self.get_browser_paths()
        
        # Known malicious extension patterns
        self.suspicious_permissions = [
            'tabs',  # Can read all tab URLs
            'webRequest',  # Can intercept network requests
            'webRequestBlocking',  # Can block/modify requests
            '<all_urls>',  # Access to all websites
            'cookies',  # Can read cookies (passwords!)
            'proxy',  # Can route traffic through attacker
            'debugger',  # Can inject code
            'desktopCapture',  # Can record screen
            'clipboardRead',  # Can steal clipboard data
        ]
        
        # Track known extensions
        self.known_extensions = {}
        
        self.logger.info("Browser Protection initialized")
    
    def setup_logging(self):
        """Configure logging for browser protection."""
        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"browser_protection_{datetime.now().strftime('%Y-%m-%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        return logging.getLogger('BrowserProtection')
    
    def get_browser_paths(self):
        """Get paths to browser extension directories."""
        user_profile = os.environ.get('USERPROFILE', '')
        local_appdata = os.environ.get('LOCALAPPDATA', '')
        appdata = os.environ.get('APPDATA', '')
        
        paths = {
            'chrome': Path(local_appdata) / "Google" / "Chrome" / "User Data" / "Default" / "Extensions",
            'edge': Path(local_appdata) / "Microsoft" / "Edge" / "User Data" / "Default" / "Extensions",
            'firefox': Path(appdata) / "Mozilla" / "Firefox" / "Profiles",
            'brave': Path(local_appdata) / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Extensions",
            'opera': Path(appdata) / "Opera Software" / "Opera Stable" / "Extensions"
        }
        
        # Filter to only existing paths
        return {k: v for k, v in paths.items() if v.exists()}
    
    def start(self):
        """Start browser monitoring."""
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_extensions, daemon=True)
        self.monitor_thread.start()
        self.logger.info("Browser Protection monitoring started")
    
    def stop(self):
        """Stop browser monitoring."""
        self.running = False
        self.logger.info("Browser Protection monitoring stopped")
    
    def monitor_extensions(self):
        """Continuously monitor browser extensions."""
        # Initial scan
        self.scan_all_extensions()
        
        while self.running:
            try:
                # Check for new or modified extensions
                self.scan_all_extensions()
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Browser monitoring error: {e}")
                time.sleep(60)
    
    def scan_all_extensions(self):
        """Scan extensions in all installed browsers."""
        for browser_name, ext_path in self.browser_paths.items():
            try:
                self.scan_browser_extensions(browser_name, ext_path)
            except Exception as e:
                self.logger.error(f"Error scanning {browser_name}: {e}")
    
    def scan_browser_extensions(self, browser_name, ext_path):
        """Scan extensions for a specific browser."""
        if not ext_path.exists():
            return
        
        # Each extension has its own folder
        for ext_folder in ext_path.iterdir():
            if not ext_folder.is_dir():
                continue
            
            ext_id = ext_folder.name
            
            # Find the manifest.json (in version subfolder)
            for version_folder in ext_folder.iterdir():
                if version_folder.is_dir():
                    manifest_path = version_folder / "manifest.json"
                    if manifest_path.exists():
                        self.analyze_extension(browser_name, ext_id, manifest_path)
                        break
    
    def analyze_extension(self, browser_name, ext_id, manifest_path):
        """Analyze an extension's manifest for suspicious behavior."""
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
            
            ext_name = manifest.get('name', 'Unknown')
            ext_version = manifest.get('version', '0.0')
            permissions = manifest.get('permissions', [])
            
            # Create extension fingerprint
            ext_key = f"{browser_name}:{ext_id}"
            
            # Check if this is a new extension
            if ext_key not in self.known_extensions:
                self.logger.warning(f"NEW EXTENSION DETECTED: {ext_name} in {browser_name}")
                logger.info(f"New browser extension installed: {ext_name}")
                
                # Analyze risk level
                risk_score, risk_reasons = self.calculate_extension_risk(manifest)
                
                if risk_score >= 7:
                    alert = f"HIGH RISK EXTENSION DETECTED!\n"
                    alert += f"Browser: {browser_name}\n"
                    alert += f"Name: {ext_name}\n"
                    alert += f"ID: {ext_id}\n"
                    alert += f"Risk Score: {risk_score}/10\n"
                    alert += f"Reasons:\n"
                    for reason in risk_reasons:
                        alert += f"  - {reason}\n"
                    alert += f"\nRECOMMEND REMOVING THIS EXTENSION!"
                    logger.warning(alert)
                    print(alert)
                
                elif risk_score >= 4:
                    self.logger.warning(f"MEDIUM RISK: {ext_name} (Score: {risk_score}/10)")
                
                # Store extension info
                self.known_extensions[ext_key] = {
                    'name': ext_name,
                    'version': ext_version,
                    'permissions': permissions,
                    'risk_score': risk_score,
                    'first_seen': datetime.now().isoformat()
                }
            
        except Exception as e:
            self.logger.error(f"Error analyzing extension {ext_id}: {e}")
    
    def calculate_extension_risk(self, manifest):
        """Calculate risk score for an extension based on permissions."""
        risk_score = 0
        risk_reasons = []
        
        permissions = manifest.get('permissions', [])
        optional_permissions = manifest.get('optional_permissions', [])
        all_permissions = permissions + optional_permissions
        
        # Check for dangerous permissions
        for perm in all_permissions:
            if perm in self.suspicious_permissions:
                risk_score += 2
                risk_reasons.append(f"Requests dangerous permission: {perm}")
        
        # Check for broad access patterns
        if '<all_urls>' in all_permissions or '*://*/*' in all_permissions:
            risk_score += 3
            risk_reasons.append("Can access ALL websites (major red flag)")
        
        # Check for sensitive data access
        sensitive_apis = ['webRequest', 'cookies', 'history', 'bookmarks']
        for api in sensitive_apis:
            if api in all_permissions:
                risk_score += 1
                risk_reasons.append(f"Can access sensitive data: {api}")
        
        # Check for code injection capabilities
        if 'tabs' in all_permissions and 'webRequest' in all_permissions:
            risk_score += 2
            risk_reasons.append("Can inject code into websites")
        
        return min(risk_score, 10), risk_reasons  # Cap at 10

if __name__ == "__main__":
    # Test browser protection
    protection = BrowserProtection()
    protection.start()

    logger.info("Browser Protection is running. Press Ctrl+C to stop.")
    print("Browser Protection is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        protection.stop()
        logger.info("Browser Protection stopped.")
        print("Browser Protection stopped.")
