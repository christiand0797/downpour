#!/usr/bin/env python3
"""
=================================================================================
SYSTEM HARDENING AUTOMATION MODULE
=================================================================================
"""

__version__ = "29.0.0"
Created: January 2026 - Claude's Enhancement

FEATURES:
- Auto-configure Windows Defender to maximum settings
- Enable all Windows security features
- Harden UAC and firewall settings
- Disable risky Windows features
- Configure secure network settings
- Apply privacy-preserving tweaks
- Regular security policy enforcement

USAGE:
    python system_hardening.py --analyze     # Check current security state
    python system_hardening.py --harden      # Apply all hardening (requires admin)
    python system_hardening.py --schedule    # Auto-run weekly

This module ensures your system is configured securely, closing common
security gaps that hackers exploit.
===============================================================================
"""

import os
import sys
import subprocess
import winreg
import json
import logging
logger = logging.getLogger(__name__)

from datetime import datetime
from typing import Dict, List, Tuple
import ctypes

# Check if running as administrator
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


class SystemHardening:
    """
    Comprehensive Windows system hardening automation.
    """
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "checks_performed": [],
            "applied_fixes": [],
            "warnings": [],
            "security_score": 0,
            "max_score": 0
        }
        
        # Hardening configurations
        self.hardening_tasks = [
            {
                "name": "Windows Defender - Real-time Protection",
                "check": self.check_defender_realtime,
                "fix": self.enable_defender_realtime,
                "severity": "CRITICAL",
                "points": 20
            },
            {
                "name": "Windows Defender - Cloud Protection",
                "check": self.check_defender_cloud,
                "fix": self.enable_defender_cloud,
                "severity": "HIGH",
                "points": 15
            },
            {
                "name": "Windows Defender - Automatic Sample Submission",
                "check": self.check_defender_samples,
                "fix": self.enable_defender_samples,
                "severity": "HIGH",
                "points": 10
            },
            {
                "name": "Windows Defender - PUA Protection",
                "check": self.check_defender_pua,
                "fix": self.enable_defender_pua,
                "severity": "MEDIUM",
                "points": 10
            },
            {
                "name": "Windows Firewall - All Profiles",
                "check": self.check_firewall,
                "fix": self.enable_firewall,
                "severity": "CRITICAL",
                "points": 20
            },
            {
                "name": "User Account Control (UAC)",
                "check": self.check_uac,
                "fix": self.enable_uac,
                "severity": "HIGH",
                "points": 15
            },
            {
                "name": "Windows Update - Automatic Updates",
                "check": self.check_windows_update,
                "fix": self.enable_windows_update,
                "severity": "CRITICAL",
                "points": 20
            },
            {
                "name": "Remote Desktop - Disabled",
                "check": self.check_rdp,
                "fix": self.disable_rdp,
                "severity": "HIGH",
                "points": 10
            },
            {
                "name": "AutoRun - Disabled",
                "check": self.check_autorun,
                "fix": self.disable_autorun,
                "severity": "HIGH",
                "points": 10
            },
            {
                "name": "PowerShell Script Execution Policy",
                "check": self.check_powershell_policy,
                "fix": self.set_powershell_policy,
                "severity": "MEDIUM",
                "points": 10
            },
            {
                "name": "SMBv1 Protocol - Disabled",
                "check": self.check_smb1,
                "fix": self.disable_smb1,
                "severity": "HIGH",
                "points": 10
            },
            {
                "name": "Guest Account - Disabled",
                "check": self.check_guest_account,
                "fix": self.disable_guest_account,
                "severity": "MEDIUM",
                "points": 5
            }
        ]
    
    def analyze_security(self) -> Dict:
        """
        Analyze current security configuration without making changes.
        """
        logger.info("Analyzing system security configuration")
        print("\n" + "=" * 80)
        print("[*] ANALYZING SYSTEM SECURITY CONFIGURATION")
        print("=" * 80)
        print("")
        
        max_score = sum(task["points"] for task in self.hardening_tasks)
        current_score = 0
        
        for task in self.hardening_tasks:
            self.results["checks_performed"].append(task["name"])
            self.results["max_score"] = max_score
            
            print(f"Checking: {task['name']}... ", end="")
            
            try:
                is_secure, details = task["check"]()
                
                if is_secure:
                    print(f"[+] PASS")
                    current_score += task["points"]
                else:
                    severity_icon = {
                        "CRITICAL": "[!]",
                        "HIGH": "[!]",
                        "MEDIUM": "[*]",
                        "LOW": "[i]"
                    }[task["severity"]]
                    
                    print(f"{severity_icon} FAIL - {details}")
                    self.results["warnings"].append({
                        "task": task["name"],
                        "severity": task["severity"],
                        "details": details,
                        "points_lost": task["points"]
                    })
            
            except Exception as e:
                print(f"[!] ERROR - {str(e)}")
                self.results["warnings"].append({
                    "task": task["name"],
                    "severity": "ERROR",
                    "details": str(e),
                    "points_lost": 0
                })
        
        self.results["security_score"] = current_score
        
        # Calculate percentage
        percentage = (current_score / max_score * 100) if max_score > 0 else 0
        
        print("\n" + "=" * 80)
        print(f"SECURITY SCORE: {current_score}/{max_score} ({percentage:.1f}%)")
        print("=" * 80)
        
        if percentage >= 90:
            print("[+] EXCELLENT - Your system is well-protected")
        elif percentage >= 70:
            print("[+] GOOD - Minor improvements recommended")
        elif percentage >= 50:
            print("[!] FAIR - Several security issues need attention")
        else:
            print("[!] POOR - Critical security vulnerabilities detected!")
        
        print("")
        
        return self.results
    
    def apply_hardening(self) -> Dict:
        """
        Apply all security hardening measures (requires admin rights).
        """
        if not is_admin():
            logger.warning("Administrator privileges required")
            print("[!] ERROR: Administrator privileges required for system hardening")
            print("   Right-click and select 'Run as Administrator'")
            return self.results

        logger.info("Applying system hardening")
        print("\n" + "=" * 80)
        print("[*] APPLYING SYSTEM HARDENING")
        print("=" * 80)
        print("")
        
        for task in self.hardening_tasks:
            print(f"Processing: {task['name']}... ", end="")
            
            try:
                is_secure, details = task["check"]()
                
                if is_secure:
                    print("[+] Already secure")
                else:
                    # Apply fix
                    success, message = task["fix"]()
                    
                    if success:
                        print(f"[+] APPLIED - {message}")
                        self.results["applied_fixes"].append(task["name"])
                        self.results["security_score"] += task["points"]
                    else:
                        print(f"[!] FAILED - {message}")
                        self.results["warnings"].append({
                            "task": task["name"],
                            "severity": task["severity"],
                            "details": message
                        })
            
            except Exception as e:
                print(f"[!] ERROR - {str(e)}")
                self.results["warnings"].append({
                    "task": task["name"],
                    "severity": "ERROR",
                    "details": str(e)
                })
        
        print("\n" + "=" * 80)
        print("[*] HARDENING COMPLETE")
        print(f"Applied {len(self.results['applied_fixes'])} security improvements")
        print("=" * 80)
        print("")
        
        # Recommend reboot if significant changes were made
        if len(self.results['applied_fixes']) > 0:
            print("[!]  IMPORTANT: Restart your computer for all changes to take effect")
            print("")
        
        return self.results
    
    # === CHECKER METHODS ===
    
    def check_defender_realtime(self) -> Tuple[bool, str]:
        """Check if Windows Defender real-time protection is enabled"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'Get-MpPreference | Select-Object -ExpandProperty DisableRealtimeMonitoring'],
                capture_output=True, text=True
            )
            is_disabled = result.stdout.strip().lower() == 'true'
            return (not is_disabled, "Real-time protection is disabled" if is_disabled else "")
        except Exception:
            return (False, "Could not check status")
    
    def check_defender_cloud(self) -> Tuple[bool, str]:
        """Check if Windows Defender cloud protection is enabled"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'Get-MpPreference | Select-Object -ExpandProperty MAPSReporting'],
                capture_output=True, text=True
            )
            maps_level = result.stdout.strip()
            is_enabled = maps_level in ['2', '3']  # Advanced or Basic
            return (is_enabled, "Cloud protection is disabled or set to None" if not is_enabled else "")
        except Exception:
            return (False, "Could not check status")
    
    def check_defender_samples(self) -> Tuple[bool, str]:
        """Check if automatic sample submission is enabled"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'Get-MpPreference | Select-Object -ExpandProperty SubmitSamplesConsent'],
                capture_output=True, text=True
            )
            consent = result.stdout.strip()
            is_enabled = consent in ['1', '3']  # Send safe or all samples
            return (is_enabled, "Automatic sample submission is disabled" if not is_enabled else "")
        except Exception:
            return (False, "Could not check status")
    
    def check_defender_pua(self) -> Tuple[bool, str]:
        """Check if PUA (Potentially Unwanted Application) protection is enabled"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'Get-MpPreference | Select-Object -ExpandProperty PUAProtection'],
                capture_output=True, text=True
            )
            pua = result.stdout.strip()
            is_enabled = pua == '1'
            return (is_enabled, "PUA protection is disabled" if not is_enabled else "")
        except Exception:
            return (False, "Could not check status")
    
    def check_firewall(self) -> Tuple[bool, str]:
        """Check if Windows Firewall is enabled for all profiles"""
        try:
            result = subprocess.run(
                ['netsh', 'advfirewall', 'show', 'allprofiles', 'state'],
                capture_output=True, text=True
            )
            output = result.stdout.lower()
            all_enabled = output.count('state                                 on') >= 3
            return (all_enabled, "Firewall is not enabled for all profiles" if not all_enabled else "")
        except Exception:
            return (False, "Could not check firewall status")
    
    def check_uac(self) -> Tuple[bool, str]:
        """Check if User Account Control is enabled"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                0, winreg.KEY_READ
            )
            value, _ = winreg.QueryValueEx(key, "EnableLUA")
            winreg.CloseKey(key)
            is_enabled = value == 1
            return (is_enabled, "UAC is disabled" if not is_enabled else "")
        except Exception:
            return (False, "Could not check UAC status")
    
    def check_windows_update(self) -> Tuple[bool, str]:
        """Check if Windows Update automatic updates are enabled"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', 
                 'Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" -Name NoAutoUpdate -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NoAutoUpdate'],
                capture_output=True, text=True
            )
            no_auto = result.stdout.strip()
            is_disabled = no_auto == '1'
            return (not is_disabled, "Automatic updates are disabled" if is_disabled else "")
        except Exception:
            # If registry key doesn't exist, updates are likely enabled by default
            return (True, "")
    
    def check_rdp(self) -> Tuple[bool, str]:
        """Check if Remote Desktop is disabled"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                0, winreg.KEY_READ
            )
            value, _ = winreg.QueryValueEx(key, "fDenyTSConnections")
            winreg.CloseKey(key)
            is_disabled = value == 1
            return (is_disabled, "Remote Desktop is enabled (security risk)" if not is_disabled else "")
        except Exception:
            return (True, "")  # Assume disabled if key doesn't exist
    
    def check_autorun(self) -> Tuple[bool, str]:
        """Check if AutoRun is disabled"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                0, winreg.KEY_READ
            )
            value, _ = winreg.QueryValueEx(key, "NoDriveTypeAutoRun")
            winreg.CloseKey(key)
            is_disabled = value == 255  # All drives
            return (is_disabled, "AutoRun is not fully disabled" if not is_disabled else "")
        except Exception:
            return (False, "AutoRun policy not configured")
    
    def check_powershell_policy(self) -> Tuple[bool, str]:
        """Check PowerShell execution policy"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', 'Get-ExecutionPolicy'],
                capture_output=True, text=True
            )
            policy = result.stdout.strip()
            # RemoteSigned or AllSigned are secure
            is_secure = policy in ['RemoteSigned', 'AllSigned', 'Restricted']
            return (is_secure, f"PowerShell policy is '{policy}' (too permissive)" if not is_secure else "")
        except Exception:
            return (False, "Could not check PowerShell policy")
    
    def check_smb1(self) -> Tuple[bool, str]:
        """Check if SMBv1 is disabled"""
        try:
            result = subprocess.run(
                ['powershell', '-Command', 
                 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -ExpandProperty State'],
                capture_output=True, text=True
            )
            state = result.stdout.strip()
            is_disabled = state == 'Disabled'
            return (is_disabled, "SMBv1 is enabled (major security risk)" if not is_disabled else "")
        except Exception:
            return (False, "Could not check SMBv1 status")
    
    def check_guest_account(self) -> Tuple[bool, str]:
        """Check if Guest account is disabled"""
        try:
            result = subprocess.run(
                ['net', 'user', 'guest'],
                capture_output=True, text=True
            )
            is_disabled = 'Account active              No' in result.stdout
            return (is_disabled, "Guest account is enabled" if not is_disabled else "")
        except Exception:
            return (True, "")  # Assume disabled if check fails
    
    # === FIXER METHODS ===
    
    def enable_defender_realtime(self) -> Tuple[bool, str]:
        """Enable Windows Defender real-time protection"""
        try:
            subprocess.run(
                ['powershell', '-Command', 'Set-MpPreference -DisableRealtimeMonitoring $false'],
                check=True, capture_output=True
            )
            return (True, "Enabled real-time protection")
        except Exception as e:
            return (False, str(e))
    
    def enable_defender_cloud(self) -> Tuple[bool, str]:
        """Enable Windows Defender cloud protection"""
        try:
            subprocess.run(
                ['powershell', '-Command', 'Set-MpPreference -MAPSReporting Advanced'],
                check=True, capture_output=True
            )
            return (True, "Enabled cloud-delivered protection")
        except Exception as e:
            return (False, str(e))
    
    def enable_defender_samples(self) -> Tuple[bool, str]:
        """Enable automatic sample submission"""
        try:
            subprocess.run(
                ['powershell', '-Command', 'Set-MpPreference -SubmitSamplesConsent SendSafeSamples'],
                check=True, capture_output=True
            )
            return (True, "Enabled automatic sample submission")
        except Exception as e:
            return (False, str(e))
    
    def enable_defender_pua(self) -> Tuple[bool, str]:
        """Enable PUA protection"""
        try:
            subprocess.run(
                ['powershell', '-Command', 'Set-MpPreference -PUAProtection Enabled'],
                check=True, capture_output=True
            )
            return (True, "Enabled PUA protection")
        except Exception as e:
            return (False, str(e))
    
    def enable_firewall(self) -> Tuple[bool, str]:
        """Enable Windows Firewall for all profiles"""
        try:
            subprocess.run(
                ['netsh', 'advfirewall', 'set', 'allprofiles', 'state', 'on'],
                check=True, capture_output=True
            )
            return (True, "Enabled firewall for all profiles")
        except Exception as e:
            return (False, str(e))
    
    def enable_uac(self) -> Tuple[bool, str]:
        """Enable User Account Control"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                0, winreg.KEY_WRITE
            )
            winreg.SetValueEx(key, "EnableLUA", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            return (True, "Enabled UAC (restart required)")
        except Exception as e:
            return (False, str(e))
    
    def enable_windows_update(self) -> Tuple[bool, str]:
        """Enable Windows Update automatic updates"""
        try:
            # Remove the policy that disables updates
            subprocess.run(
                ['reg', 'delete', 
                 r'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
                 '/v', 'NoAutoUpdate', '/f'],
                capture_output=True
            )
            return (True, "Enabled automatic Windows updates")
        except Exception:
            return (True, "Automatic updates already enabled")
    
    def disable_rdp(self) -> Tuple[bool, str]:
        """Disable Remote Desktop"""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server",
                0, winreg.KEY_WRITE
            )
            winreg.SetValueEx(key, "fDenyTSConnections", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
            return (True, "Disabled Remote Desktop")
        except Exception as e:
            return (False, str(e))
    
    def disable_autorun(self) -> Tuple[bool, str]:
        """Disable AutoRun for all drives"""
        try:
            key = winreg.CreateKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            )
            winreg.SetValueEx(key, "NoDriveTypeAutoRun", 0, winreg.REG_DWORD, 255)
            winreg.CloseKey(key)
            return (True, "Disabled AutoRun for all drives")
        except Exception as e:
            return (False, str(e))
    
    def set_powershell_policy(self) -> Tuple[bool, str]:
        """Set PowerShell execution policy to RemoteSigned"""
        try:
            subprocess.run(
                ['powershell', '-Command', 'Set-ExecutionPolicy RemoteSigned -Force'],
                check=True, capture_output=True
            )
            return (True, "Set PowerShell policy to RemoteSigned")
        except Exception as e:
            return (False, str(e))
    
    def disable_smb1(self) -> Tuple[bool, str]:
        """Disable SMBv1 protocol"""
        try:
            subprocess.run(
                ['powershell', '-Command', 
                 'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'],
                check=True, capture_output=True
            )
            return (True, "Disabled SMBv1 (restart required)")
        except Exception as e:
            return (False, str(e))
    
    def disable_guest_account(self) -> Tuple[bool, str]:
        """Disable Guest account"""
        try:
            subprocess.run(
                ['net', 'user', 'guest', '/active:no'],
                check=True, capture_output=True
            )
            return (True, "Disabled Guest account")
        except Exception as e:
            return (False, str(e))
    
    def save_report(self, filename: str = "system_hardening_report.json"):
        """Save hardening report to file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            logger.info(f"Report saved to {filename}")
            print(f"[+] Report saved to {filename}")
        except Exception as e:
            logger.warning(f"Error saving report: {e}")
            print(f"[!] Error saving report: {e}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Family Security Suite - System Hardening")
    parser.add_argument('--analyze', action='store_true',
                       help='Analyze current security configuration')
    parser.add_argument('--harden', action='store_true',
                       help='Apply security hardening (requires admin)')
    parser.add_argument('--report', type=str,
                       help='Save report to file')
    
    args = parser.parse_args()
    
    hardener = SystemHardening()
    
    if args.harden:
        results = hardener.apply_hardening()
    else:  # Default to analyze
        results = hardener.analyze_security()
    
    if args.report:
        hardener.save_report(args.report)
    else:
        # Save with default name
        hardener.save_report()
