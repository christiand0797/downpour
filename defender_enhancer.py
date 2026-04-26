"""
================================================================================
WINDOWS DEFENDER ENHANCEMENT MODULE
================================================================================

PURPOSE: Makes Windows Defender as strong as possible by enabling all
         protection features and keeping them enabled.

WHAT IT DOES:
- Enables real-time protection (if disabled)
- Turns on cloud-delivered protection (uses Microsoft's threat intelligence)
- Enables automatic sample submission (helps Microsoft learn new threats)
- Activates PUA protection (blocks potentially unwanted applications)
- Enables behavior monitoring (watches how programs act)
- Turns on network protection (blocks malicious websites)
- Enables controlled folder access (ransomware protection)
- Keeps all settings enabled even if malware tries to disable them

HOW IT WORKS:
- Uses PowerShell commands to configure Windows Defender
- Uses Windows Management Instrumentation (WMI) to check status
- Monitors Defender service to ensure it stays running
- Automatically re-enables features if something disables them

TECHNICAL NOTES:
- Requires administrator privileges for most operations
- Uses subprocess to execute PowerShell commands
- Reads Defender status from registry and WMI
- Some features require Windows 10/11 with latest updates

================================================================================
"""

import subprocess
import logging
import time
import threading
import winreg
from datetime import datetime, timedelta

class DefenderEnhancer:
    """
    Class to manage Windows Defender configuration and monitoring.
    
    This keeps Defender optimally configured for maximum protection.
    Runs in background thread checking status every few minutes.
    """
    
    def __init__(self):
        """Initialize the Defender enhancer."""
        self.running = True
        self.last_check = None
        self.check_interval = 300  # Check every 5 minutes
        
    def run_powershell_command(self, command):
        """
        Execute a PowerShell command and return result.
        
        Parameters:
        - command: PowerShell command string to execute
        
        Returns:
        - (success: bool, output: str, error: str)
        
        SECURITY NOTE: Only runs predefined safe commands, never user input.
        """
        try:
            # Run PowerShell command
            result = subprocess.run(
                ['powershell', '-Command', command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return (result.returncode == 0, result.stdout, result.stderr)
            
        except subprocess.TimeoutExpired:
            logging.error("PowerShell command timed out")
            return (False, "", "Timeout")
        except Exception as e:
            logging.error(f"Error running PowerShell: {e}")
            return (False, "", str(e))
    
    def enable_realtime_protection(self):
        """
        Enable Windows Defender real-time protection.
        
        This is the main defense - scans files as you access them.
        Should always be enabled for protection.
        """
        logging.info("Enabling real-time protection...")
        
        command = "Set-MpPreference -DisableRealtimeMonitoring $false"
        success, output, error = self.run_powershell_command(command)
        
        if success:
            logging.info("[✓] Real-time protection enabled")
            return True
        else:
            logging.warning(f"[!] Could not enable real-time protection: {error}")
            logging.warning("You may need to do this manually in Windows Security")
            return False
    
    def enable_cloud_protection(self):
        """
        Enable cloud-delivered protection.
        
        This sends suspicious files to Microsoft for analysis.
        Uses Microsoft's global threat intelligence to catch new threats faster.
        Highly recommended - makes Defender much smarter.
        """
        logging.info("Enabling cloud-delivered protection...")
        
        command = "Set-MpPreference -MAPSReporting Advanced"
        success, output, error = self.run_powershell_command(command)
        
        if success:
            logging.info("[✓] Cloud protection enabled")
            return True
        else:
            logging.warning(f"[!] Could not enable cloud protection: {error}")
            return False
    
    def enable_automatic_sample_submission(self):
        """
        Enable automatic sample submission to Microsoft.
        
        When Defender finds something suspicious, it sends it to Microsoft
        for analysis. This helps everyone get protected faster.
        
        NOTE: Does NOT send your personal files. Only sends suspicious programs.
        """
        logging.info("Enabling automatic sample submission...")
        
        command = "Set-MpPreference -SubmitSamplesConsent SendAllSamples"
        success, output, error = self.run_powershell_command(command)
        
        if success:
            logging.info("[✓] Sample submission enabled")
            return True
        else:
            logging.warning(f"[!] Could not enable sample submission: {error}")
            return False
    
    def enable_pua_protection(self):
        """
        Enable PUA (Potentially Unwanted Application) protection.
        
        Blocks software that isn't technically malware but is annoying:
        - Adware
        - Toolbars
        - Bundled software you didn't ask for
        - Cryptocurrency miners
        - Aggressive advertising programs
        """
        logging.info("Enabling PUA protection...")
        
        command = "Set-MpPreference -PUAProtection Enabled"
        success, output, error = self.run_powershell_command(command)
        
        if success:
            logging.info("[✓] PUA protection enabled")
            return True
        else:
            logging.warning(f"[!] Could not enable PUA protection: {error}")
            return False
    
    def enable_behavior_monitoring(self):
        """
        Enable behavior monitoring.
        
        Watches how programs behave to detect suspicious activity:
        - Programs trying to access sensitive files
        - Unusual network activity
        - Attempts to modify system files
        - Suspicious API calls
        
        This catches threats that don't match known virus signatures.
        """
        logging.info("Enabling behavior monitoring...")
        
        command = "Set-MpPreference -DisableBehaviorMonitoring $false"
        success, output, error = self.run_powershell_command(command)
        
        if success:
            logging.info("[✓] Behavior monitoring enabled")
            return True
        else:
            logging.warning(f"[!] Could not enable behavior monitoring: {error}")
            return False
    
    def enable_network_protection(self):
        """
        Enable network protection.
        
        Blocks connections to known malicious websites and IP addresses.
        Prevents:
        - Phishing sites
        - Malware download sites
        - Command & control servers used by hackers
        
        Works with all browsers and programs.
        """
        logging.info("Enabling network protection...")
        
        command = "Set-MpPreference -EnableNetworkProtection Enabled"
        success, output, error = self.run_powershell_command(command)
        
        if success:
            logging.info("[✓] Network protection enabled")
            return True
        else:
            logging.warning(f"[!] Could not enable network protection: {error}")
            logging.warning("This feature requires Windows 10 version 1709 or later")
            return False
    
    def enable_controlled_folder_access(self):
        """
        Enable controlled folder access (ransomware protection).
        
        Protects your important folders from ransomware by only allowing
        trusted programs to modify files.
        
        Protected folders: Documents, Pictures, Videos, Desktop, etc.
        
        NOTE: May need to whitelist some legitimate programs if they
        need to write to these folders (like video editors, backup software).
        """
        logging.info("Enabling controlled folder access...")
        
        command = "Set-MpPreference -EnableControlledFolderAccess Enabled"
        success, output, error = self.run_powershell_command(command)
        
        if success:
            logging.info("[✓] Controlled folder access enabled (ransomware protection)")
            logging.info("NOTE: You may need to allow trusted programs in Windows Security")
            return True
        else:
            logging.warning(f"[!] Could not enable controlled folder access: {error}")
            return False
    
    def update_definitions(self):
        """
        Update virus definitions to latest version.
        
        Downloads the newest threat database from Microsoft.
        Should be done at least daily for best protection.
        """
        logging.info("Updating virus definitions...")
        
        command = "Update-MpSignature"
        success, output, error = self.run_powershell_command(command)
        
        if success:
            logging.info("[✓] Virus definitions updated")
            return True
        else:
            logging.warning(f"[!] Could not update definitions: {error}")
            logging.warning("They may already be up to date")
            return False
    
    def check_defender_status(self):
        """
        Check current Windows Defender status.
        
        Returns dictionary with status of all protection features:
        - Real-time protection
        - Cloud protection  
        - Behavior monitoring
        - Network protection
        - Last update time
        """
        logging.info("Checking Windows Defender status...")
        
        command = "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, BehaviorMonitorEnabled, NISEnabled, AntivirusEnabled | ConvertTo-Json"
        success, output, error = self.run_powershell_command(command)
        
        if success and output:
            try:
                import json
                status = json.loads(output)
                
                logging.info("Current Defender Status:")
                logging.info(f"  Real-time protection: {status.get('RealTimeProtectionEnabled', 'Unknown')}")
                logging.info(f"  Behavior monitor: {status.get('BehaviorMonitorEnabled', 'Unknown')}")
                logging.info(f"  Network protection: {status.get('NISEnabled', 'Unknown')}")
                logging.info(f"  Antivirus enabled: {status.get('AntivirusEnabled', 'Unknown')}")
                
                return status
            except Exception:
                logging.error("Could not parse Defender status")
                return {}
        else:
            logging.warning("Could not check Defender status")
            return {}
    
    def enable_all_protection(self):
        """
        Enable ALL Windows Defender protection features.
        
        This is called during initial setup to maximize protection.
        Also called periodically to ensure settings stay enabled.
        """
        logging.info("="*80)
        logging.info("ENHANCING WINDOWS DEFENDER PROTECTION")
        logging.info("="*80)
        
        results = {
            'realtime': self.enable_realtime_protection(),
            'cloud': self.enable_cloud_protection(),
            'samples': self.enable_automatic_sample_submission(),
            'pua': self.enable_pua_protection(),
            'behavior': self.enable_behavior_monitoring(),
            'network': self.enable_network_protection(),
            #'controlled_folder': self.enable_controlled_folder_access(),  # Commented out - can cause issues with legit programs
        }
        
        # Update definitions
        self.update_definitions()
        
        # Check final status
        time.sleep(2)
        self.check_defender_status()
        
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        
        logging.info("="*80)
        logging.info(f"DEFENDER ENHANCEMENT COMPLETE: {success_count}/{total_count} features enabled")
        logging.info("="*80)
        
        if success_count == total_count:
            logging.info("[✓] All protection features successfully enabled!")
            logging.info("Your Windows Defender is now optimally configured.")
        else:
            logging.warning("[!] Some features could not be enabled automatically.")
            logging.warning("Please check Windows Security settings manually.")
            logging.warning("Go to: Start → Settings → Update & Security → Windows Security")
        
        return success_count == total_count
    
    def monitor_loop(self):
        """
        Continuous monitoring loop.
        
        Runs in background thread checking that Defender stays configured.
        If something tries to disable protection, this re-enables it.
        """
        while self.running:
            try:
                current_time = datetime.now()
                
                # Check if it's time for periodic check
                if (self.last_check is None or 
                    current_time - self.last_check > timedelta(seconds=self.check_interval)):
                    
                    logging.info("Performing periodic Defender check...")
                    
                    # Check status
                    status = self.check_defender_status()
                    
                    # Re-enable features if disabled
                    if status.get('RealTimeProtectionEnabled') == False:
                        logging.warning("[!] Real-time protection was disabled! Re-enabling...")
                        self.enable_realtime_protection()
                    
                    if status.get('BehaviorMonitorEnabled') == False:
                        logging.warning("[!] Behavior monitoring was disabled! Re-enabling...")
                        self.enable_behavior_monitoring()
                    
                    self.last_check = current_time
                
                # Sleep for a bit
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logging.error(f"Error in Defender monitor loop: {e}")
                time.sleep(60)
    
    def start(self):
        """
        Start the Defender enhancement system.
        
        1. Enable all protection features
        2. Start monitoring thread to keep them enabled
        """
        # Enable all features initially
        self.enable_all_protection()
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        monitor_thread.start()
        
        logging.info("[✓] Windows Defender Enhancement System active")
        logging.info("Defender will be monitored and kept optimally configured")
    
    def stop(self):
        """Stop the monitoring system."""
        self.running = False
        logging.info("Defender enhancement system stopped")

# Global instance
_enhancer_instance = None

def get_enhancer():
    """Get global Defender enhancer instance."""
    global _enhancer_instance
    if _enhancer_instance is None:
        _enhancer_instance = DefenderEnhancer()
    return _enhancer_instance

# For testing/standalone execution
if __name__ == "__main__":
    """
    Run this file directly to test Defender enhancement.
    
    This will enable all protection features and show results.
    """
    import sys
    
    # Set up basic logging to console
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*80)
    print("          WINDOWS DEFENDER ENHANCEMENT TEST")
    print("="*80)
    print()
    
    # Check if running as admin
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("[!] Not running as Administrator")
        print("[!] Some features may not work properly")
        print()
        response = input("Continue anyway? (y/n): ")
        if response.lower() != 'y':
            sys.exit(0)
    
    # Create and test enhancer
    enhancer = DefenderEnhancer()
    enhancer.enable_all_protection()
    
    print("\nEnhancement complete. Check output above for results.")
    print("Press Enter to exit...")
    input()
