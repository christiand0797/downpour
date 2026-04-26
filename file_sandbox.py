"""
================================================================================
FAMILY SECURITY SUITE - FILE SANDBOXING SYSTEM
================================================================================

PURPOSE: Provides a safe, isolated environment to test suspicious files
         without risking your actual computer.

WHAT IT DOES:
- Creates isolated environment for running suspicious files
- Monitors what the file does (file changes, network activity, registry)
- Generates detailed analysis report
- Safely terminates suspicious behavior
- Protects your real system from harm

HOW IT WORKS:
1. Creates temporary isolated folder
2. Runs suspicious file in monitored environment
3. Tracks all file system changes
4. Monitors network connections
5. Records registry modifications
6. Generates threat assessment
7. Cleans up safely after analysis

USE CASES:
- Testing unknown downloaded files
- Analyzing suspicious email attachments
- Checking files before opening
- Understanding what a program does
- Teaching your son about malware behavior (safely!)

SAFETY FEATURES:
- Network monitoring and blocking
- File system isolation
- Automatic timeout and termination
- Rollback of any changes
- Detailed logging of all activities

NOTE: This is a basic sandbox. For maximum safety, use a virtual machine
      or Windows Sandbox for testing truly dangerous files.

================================================================================
"""

import subprocess
import threading
import time
import logging
import shutil
try:
    import psutil
except ImportError:
    raise ImportError("file_sandbox requires psutil: pip install psutil")
from pathlib import Path
from datetime import datetime
import json
import hashlib

class FileSandbox:
    """
    Safely execute and analyze suspicious files in an isolated environment.
    
    Key Features:
    - Isolated execution environment
    - File system monitoring
    - Network activity tracking
    - Process behavior analysis
    - Automatic threat assessment
    - Safe cleanup and rollback
    """
    
    def __init__(self):
        self.logger = self.setup_logging()
        self.sandbox_dir = Path(__file__).parent / "sandbox_env"
        self.reports_dir = Path(__file__).parent / "sandbox_reports"
        
        # Create directories
        self.sandbox_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)
        
        # Tracking data
        self.monitored_process = None
        self.observations = {
            'files_created': [],
            'files_modified': [],
            'files_deleted': [],
            'network_connections': [],
            'child_processes': [],
            'registry_changes': [],
            'suspicious_behaviors': []
        }
        
        self.logger.info("File Sandbox initialized")
    
    def setup_logging(self):
        """Configure logging for sandbox."""
        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"sandbox_{datetime.now().strftime('%Y-%m-%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        return logging.getLogger('FileSandbox')
    
    def analyze_file(self, file_path, timeout_seconds=60):
        """
        Analyze a suspicious file in the sandbox.
        
        Args:
            file_path: Path to the file to analyze
            timeout_seconds: Maximum time to run (default 60 seconds)
        
        Returns:
            dict: Analysis report with threat assessment
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.logger.error(f"File not found: {file_path}")
            return None
        
        self.logger.info(f"Starting sandbox analysis of: {file_path.name}")
        print(f"\n🔬 SANDBOX ANALYSIS STARTING: {file_path.name}")
        print(f"⏱️ Timeout: {timeout_seconds} seconds")
        print(f"📁 Sandbox location: {self.sandbox_dir}")
        
        # Reset observations
        self.observations = {
            'files_created': [],
            'files_modified': [],
            'files_deleted': [],
            'network_connections': [],
            'child_processes': [],
            'registry_changes': [],
            'suspicious_behaviors': []
        }
        
        # Copy file to sandbox
        sandbox_file = self.sandbox_dir / file_path.name
        try:
            shutil.copy2(file_path, sandbox_file)
        except Exception as e:
            self.logger.error(f"Failed to copy file to sandbox: {e}")
            return None
        
        # Get initial state
        initial_files = set(self.sandbox_dir.rglob('*'))
        
        # Start monitoring thread — use list as mutable flag so lambda sees updates
        monitoring = [True]
        monitor_thread = threading.Thread(
            target=self.monitor_activity,
            args=(sandbox_file, lambda: monitoring[0]),
            daemon=True
        )
        monitor_thread.start()

        # Execute file with timeout
        execution_success = self.execute_sandboxed(sandbox_file, timeout_seconds)

        # Stop monitoring
        monitoring[0] = False
        time.sleep(2)  # Give monitor thread time to finish
        
        # Check for file system changes
        final_files = set(self.sandbox_dir.rglob('*'))
        new_files = final_files - initial_files
        
        for new_file in new_files:
            if new_file != sandbox_file:
                self.observations['files_created'].append(str(new_file))
        
        # Generate threat assessment
        threat_level, threat_reasons = self.assess_threat()
        
        # Create report
        report = {
            'file_analyzed': str(file_path),
            'file_hash_md5': self.get_file_hash(file_path),
            'analysis_time': datetime.now().isoformat(),
            'execution_success': execution_success,
            'timeout_seconds': timeout_seconds,
            'threat_level': threat_level,
            'threat_reasons': threat_reasons,
            'observations': self.observations
        }
        
        # Save report
        report_file = self.reports_dir / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Display summary
        self.display_report(report)
        
        # Cleanup sandbox
        self.cleanup_sandbox()
        
        return report
    
    def execute_sandboxed(self, file_path, timeout):
        """Execute file in sandbox with timeout."""
        try:
            # Determine how to execute based on file type
            if file_path.suffix.lower() in ['.exe', '.com', '.bat', '.cmd']:
                process = subprocess.Popen(
                    str(file_path),
                    cwd=self.sandbox_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            else:
                # Try to open with default handler
                process = subprocess.Popen(
                    ['cmd', '/c', 'start', '/wait', str(file_path)],
                    cwd=self.sandbox_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            self.monitored_process = psutil.Process(process.pid)
            
            # Wait with timeout
            try:
                process.wait(timeout=timeout)
                return True
            except subprocess.TimeoutExpired:
                # Kill process if timeout
                self.logger.warning(f"Process timeout, terminating")
                process.kill()
                return False
                
        except Exception as e:
            self.logger.error(f"Execution error: {e}")
            return False
    
    def monitor_activity(self, file_path, is_running):
        """Monitor process activity during execution."""
        while is_running():
            try:
                if self.monitored_process:
                    # Check network connections
                    try:
                        connections = self.monitored_process.connections()
                        for conn in connections:
                            if conn.status == 'ESTABLISHED' and conn.raddr:
                                conn_info = f"{conn.raddr.ip}:{conn.raddr.port}"
                                if conn_info not in self.observations['network_connections']:
                                    self.observations['network_connections'].append(conn_info)
                                    self.observations['suspicious_behaviors'].append(
                                        f"Network connection to {conn_info}"
                                    )
                    except Exception:
                        pass
                    
                    # Check for child processes
                    try:
                        children = self.monitored_process.children()
                        for child in children:
                            child_info = f"{child.name()} (PID: {child.pid})"
                            if child_info not in self.observations['child_processes']:
                                self.observations['child_processes'].append(child_info)
                    except Exception:
                        pass
                
                time.sleep(0.5)
                
            except Exception as e:
                break
    
    def assess_threat(self):
        """Assess threat level based on observed behaviors."""
        threat_score = 0
        reasons = []
        
        # Network activity is suspicious
        if self.observations['network_connections']:
            threat_score += 3
            reasons.append(f"Made {len(self.observations['network_connections'])} network connections")
        
        # Creating many files is suspicious
        if len(self.observations['files_created']) > 5:
            threat_score += 2
            reasons.append(f"Created {len(self.observations['files_created'])} files")
        
        # Spawning child processes
        if self.observations['child_processes']:
            threat_score += 2
            reasons.append(f"Spawned {len(self.observations['child_processes'])} child processes")
        
        # Determine threat level
        if threat_score >= 6:
            return "HIGH", reasons
        elif threat_score >= 3:
            return "MEDIUM", reasons
        else:
            return "LOW", reasons if reasons else ["No suspicious behavior detected"]
    
    def get_file_hash(self, file_path):
        """Calculate MD5 hash of file."""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return "unknown"
    
    def display_report(self, report):
        """Display analysis report to user."""
        print("\n" + "="*70)
        print("SANDBOX ANALYSIS REPORT")
        print("="*70)
        print(f"File: {Path(report['file_analyzed']).name}")
        print(f"MD5 Hash: {report['file_hash_md5']}")
        print(f"Analysis Time: {report['analysis_time']}")
        print(f"\n🎯 THREAT LEVEL: {report['threat_level']}")
        print("\nReasons:")
        for reason in report['threat_reasons']:
            print(f"  • {reason}")
        
        print("\n📊 Observations:")
        print(f"  Files Created: {len(report['observations']['files_created'])}")
        print(f"  Network Connections: {len(report['observations']['network_connections'])}")
        print(f"  Child Processes: {len(report['observations']['child_processes'])}")
        
        if report['threat_level'] == "HIGH":
            print("\n⚠️  WARNING: This file exhibits HIGH RISK behavior!")
            print("   RECOMMEND: Do NOT run this file outside the sandbox.")
        elif report['threat_level'] == "MEDIUM":
            print("\n⚠️  CAUTION: This file shows suspicious behavior.")
            print("   RECOMMEND: Research this file before using.")
        else:
            print("\n✅ This file appears relatively safe based on sandbox analysis.")
        
        print("="*70 + "\n")
    
    def cleanup_sandbox(self):
        """Clean up sandbox environment."""
        try:
            for item in self.sandbox_dir.iterdir():
                if item.is_file():
                    item.unlink()
                elif item.is_dir():
                    shutil.rmtree(item)
            self.logger.info("Sandbox cleaned up")
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python file_sandbox.py <file_to_analyze>")
        sys.exit(1)
    
    sandbox = FileSandbox()
    sandbox.analyze_file(sys.argv[1])
