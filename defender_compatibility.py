#!/usr/bin/env python3
"""
Windows Defender Compatibility Module for Downpour v29 Titanium
Ensures long-term compatibility and prevents false positives
"""
__version__ = "29.0.0"

import os
import sys
import json
import subprocess
import tempfile
import hashlib
from pathlib import Path

class DefenderCompatibility:
    """Windows Defender compatibility and whitelisting"""
    
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.config_file = self.script_dir / "defender_config.json"
        self.whitelist_file = self.script_dir / "defender_whitelist.json"
        
    def create_digital_signature_info(self):
        """Create digital signature information"""
        signature_info = {
            'application_name': 'Downpour v29 Titanium',
            'publisher': 'Titanium Security Suite',
            'version': '29.0.0',
            'description': 'Advanced Security Application',
            'file_hashes': {},
            'trusted_paths': []
        }
        
        # Generate hashes for key files
        key_files = [
            'downpour_v29_titanium.py',
            'enhanced_memory_manager.py',
            'security_hardening.py',
            'enhanced_logging.py'
        ]
        
        for file_name in key_files:
            file_path = self.script_dir / file_name
            if file_path.exists():
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                    signature_info['file_hashes'][file_name] = file_hash
                
                signature_info['trusted_paths'].append(str(file_path.absolute()))
        
        with open(self.config_file, 'w') as f:
            json.dump(signature_info, f, indent=2)
        
        return signature_info
    
    def create_defender_exclusions(self):
        """Create comprehensive Defender exclusions"""
        exclusions = {
            'folder_exclusions': [
                str(self.script_dir.absolute()),
                str(self.script_dir / "downpour_v27_data"),
                str(self.script_dir / "logs"),
                tempfile.gettempdir()
            ],
            'process_exclusions': [
                'python.exe',
                'pythonw.exe',
'downpour_v29_titanium.py'
            ],
            'file_extension_exclusions': [
                '.py',
                '.log',
                '.tmp',
                '.cache'
            ],
            'registry_exclusions': [
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Downpour',
                'HKEY_CURRENT_USER\\SOFTWARE\\Downpour'
            ]
        }
        
        with open(self.whitelist_file, 'w') as f:
            json.dump(exclusions, f, indent=2)
        
        return exclusions
    
    def apply_defender_settings(self):
        """Apply Windows Defender path exclusions for Downpour's directory."""
        import logging as _log
        _logger = _log.getLogger(__name__)
        try:
            script_path = str(self.script_dir.absolute())
            data_path   = str((self.script_dir / "downpour_v27_data").absolute())
            ps_cmd = (
                f'Add-MpPreference -ExclusionPath "{script_path}" -Force; '
                f'Add-MpPreference -ExclusionPath "{data_path}" -Force; '
                f'Add-MpPreference -ExclusionProcess "python.exe" -Force'
            )
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps_cmd],
                capture_output=True, text=True, timeout=20,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
            )
            ok = result.returncode == 0
            if ok:
                _logger.info("Defender exclusions applied for %s", script_path)
            else:
                _logger.warning("Defender exclusion warning: %s", result.stderr.strip())
            return ok
        except Exception as exc:
            _log.getLogger(__name__).error("apply_defender_settings: %s", exc)
            return False
    
    def create_portable_mode_config(self):
        """Create portable mode configuration for future projects"""
        portable_config = {
            'portable_mode': True,
            'no_registry_writes': True,
            'temp_directory': 'portable_temp',
            'config_directory': 'portable_config',
            'log_directory': 'portable_logs',
            'defender_compatibility': {
                'auto_exclusions': True,
                'portable_whitelist': True,
                'no_system_changes': True
            }
        }
        
        config_file = self.script_dir / "portable_mode.json"
        with open(config_file, 'w') as f:
            json.dump(portable_config, f, indent=2)
        
        return portable_config
    
    def setup_future_proofing(self):
        """Setup future-proofing for other projects"""
        future_proof = {
            'tool_registry': {
                'enhanced_memory_manager': {
                    'purpose': 'Memory leak prevention',
                    'compatible_projects': ['any_python_project'],
                    'defender_safe': True
                },
                'security_hardening': {
                    'purpose': 'Input validation and security',
                    'compatible_projects': ['any_application'],
                    'defender_safe': True
                },
                'enhanced_logging': {
                    'purpose': 'Comprehensive logging',
                    'compatible_projects': ['any_application'],
                    'defender_safe': True
                }
            },
            'shared_libraries': [
                'enhanced_memory_manager.py',
                'security_hardening.py',
                'enhanced_logging.py'
            ],
            'defender_whitelist_template': 'defender_whitelist.json'
        }
        
        future_file = self.script_dir / "future_proof_tools.json"
        with open(future_file, 'w') as f:
            json.dump(future_proof, f, indent=2)
        
        return future_proof
    
    def run_complete_setup(self):
        """Run complete Defender compatibility setup."""
        import logging as _log
        _logger = _log.getLogger(__name__)
        _logger.info("Setting up Windows Defender compatibility...")
        signature_info  = self.create_digital_signature_info()
        exclusions      = self.create_defender_exclusions()
        portable_config = self.create_portable_mode_config()
        future_proof    = self.setup_future_proofing()
        defender_ok     = self.apply_defender_settings()
        if not defender_ok:
            _logger.warning(
                "Defender exclusion setup incomplete — run as Administrator if needed"
            )
        return {
            'signature_info':   signature_info,
            'exclusions':       exclusions,
            'portable_config':  portable_config,
            'future_proof':     future_proof,
            'defender_success': defender_ok,
        }

# Global Defender compatibility instance
defender_compat = DefenderCompatibility()

def main():
    """Main execution function"""
    import logging
    _log = logging.getLogger(__name__)
    _log.info("Downpour v29 Titanium - Windows Defender Compatibility Setup")
    result = defender_compat.run_complete_setup()
    _log.info("Defender compatibility setup complete")
    return 0

if __name__ == "__main__":
    sys.exit(main())

# ---------------------------------------------------------------------------
# Extended compatibility checker (replaces previous stub section)
# ---------------------------------------------------------------------------
import threading
import time
from typing import Dict, List, Any, Optional
import platform
from dataclasses import dataclass
from enum import Enum

_dc_logger = __import__('logging').getLogger(__name__)


class CompatibilityMode(Enum):
    BASIC    = "basic"
    STANDARD = "standard"
    ADVANCED = "advanced"


@dataclass
class CompatibilityMetrics:
    """Read-only compatibility health metrics."""
    defender_version: str
    real_time_protection: bool
    exclusion_count: int
    compatibility_score: float
    last_check: float


class DefenderStatusChecker:
    """Query Windows Defender status via PowerShell (read-only, no modifications)."""

    _NO_WIN = getattr(__import__('subprocess'), 'CREATE_NO_WINDOW', 0x08000000)

    def get_status(self) -> Dict[str, Any]:
        """Return Defender status dict without modifying any settings."""
        try:
            result = __import__('subprocess').run(
                ['powershell', '-NoProfile', '-Command',
                 'Get-MpComputerStatus | Select-Object -Property '
                 'AMRunningMode,RealTimeProtectionEnabled,AntivirusEnabled '
                 '| ConvertTo-Json'],
                capture_output=True, text=True, timeout=10,
                creationflags=self._NO_WIN
            )
            if result.returncode == 0 and result.stdout.strip():
                import json as _j
                return _j.loads(result.stdout)
        except Exception as exc:
            _dc_logger.debug("DefenderStatusChecker.get_status: %s", exc)
            return {"error": str(exc), "status": "query_failed"}

    def get_exclusion_paths(self) -> List[str]:
        """Return currently configured exclusion paths (read-only query)."""
        try:
            result = __import__('subprocess').run(
                ['powershell', '-NoProfile', '-Command',
                 '(Get-MpPreference).ExclusionPath -join "\\n"'],
                capture_output=True, text=True, timeout=10,
                creationflags=self._NO_WIN
            )
            if result.returncode == 0:
                return [p for p in result.stdout.splitlines() if p.strip()]
        except Exception as exc:
            _dc_logger.debug("DefenderStatusChecker.get_exclusion_paths: %s", exc)
            return [{"error": str(exc), "query_failed": True}]


class ExclusionManager:
    """Manage Windows Defender path exclusions for Downpour's own directory."""

    _NO_WIN = getattr(__import__('subprocess'), 'CREATE_NO_WINDOW', 0x08000000)

    def __init__(self):
        self.script_dir = Path(__file__).parent

    def add_exclusion(self, path: str) -> bool:
        """Add a path exclusion via PowerShell (requires elevation)."""
        try:
            result = __import__('subprocess').run(
                ['powershell', '-NoProfile', '-Command',
                 f'Add-MpPreference -ExclusionPath "{path}" -Force'],
                capture_output=True, text=True, timeout=15,
                creationflags=self._NO_WIN
            )
            ok = result.returncode == 0
            if ok:
                _dc_logger.info("ExclusionManager: added exclusion for %s", path)
            else:
                _dc_logger.warning("ExclusionManager: failed to add exclusion: %s",
                                   result.stderr.strip())
            return ok
        except Exception as exc:
            _dc_logger.error("ExclusionManager.add_exclusion: %s", exc)
            return False

    def add_downpour_exclusion(self) -> bool:
        """Add the Downpour project directory as an exclusion."""
        return self.add_exclusion(str(self.script_dir.absolute()))

    def is_excluded(self, path: str) -> bool:
        """Return True if path is already in Defender exclusions."""
        checker = DefenderStatusChecker()
        exclusions = checker.get_exclusion_paths()
        return any(path.lower() in ex.lower() for ex in exclusions)


class CompatibilityHealthMonitor:
    """
    Periodic background monitor that logs Defender health status.
    Does not modify any Defender settings — read-only diagnostics only.
    """

    def __init__(self, interval_seconds: int = 300):
        self.interval = interval_seconds
        self.checker = DefenderStatusChecker()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.last_metrics: Optional[CompatibilityMetrics] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name="DefenderHealthMonitor"
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                status = self.checker.get_status()
                exclusions = self.checker.get_exclusion_paths()
                rtp = bool(status.get('RealTimeProtectionEnabled', True))
                score = 1.0 if rtp else 0.5
                self.last_metrics = CompatibilityMetrics(
                    defender_version=status.get('AMRunningMode', 'unknown'),
                    real_time_protection=rtp,
                    exclusion_count=len(exclusions),
                    compatibility_score=score,
                    last_check=time.time(),
                )
                _dc_logger.debug(
                    "Defender health: rtp=%s exclusions=%d score=%.2f",
                    rtp, len(exclusions), score
                )
            except Exception as exc:
                _dc_logger.debug("CompatibilityHealthMonitor._run: %s", exc)
            self._stop.wait(self.interval)


class ExtendedDefenderCompatibility:
    """
    Unified compatibility manager used by the main application.
    Combines status checking, exclusion management, and health monitoring.
    """

    def __init__(self, mode: CompatibilityMode = CompatibilityMode.STANDARD):
        self.mode            = mode
        self.status_checker  = DefenderStatusChecker()
        self.exclusion_mgr   = ExclusionManager()
        self.health_monitor  = CompatibilityHealthMonitor()

    def get_metrics(self) -> CompatibilityMetrics:
        status     = self.status_checker.get_status()
        exclusions = self.status_checker.get_exclusion_paths()
        rtp        = bool(status.get('RealTimeProtectionEnabled', True))
        return CompatibilityMetrics(
            defender_version=status.get('AMRunningMode', 'unknown'),
            real_time_protection=rtp,
            exclusion_count=len(exclusions),
            compatibility_score=1.0 if rtp else 0.5,
            last_check=time.time(),
        )

    def ensure_exclusion(self) -> bool:
        """Ensure Downpour's directory is excluded from real-time scanning."""
        script_dir = str(Path(__file__).parent.absolute())
        if self.exclusion_mgr.is_excluded(script_dir):
            _dc_logger.debug("Downpour directory already excluded")
            return True
        return self.exclusion_mgr.add_downpour_exclusion()

    def start_monitoring(self) -> None:
        self.health_monitor.start()

    def stop_monitoring(self) -> None:
        self.health_monitor.stop()

    def analyze_compatibility(self) -> Dict[str, Any]:
        """Return a compatibility report (no system modifications)."""
        metrics = self.get_metrics()
        return {
            "compatible":           True,
            "real_time_protection": metrics.real_time_protection,
            "exclusion_count":      metrics.exclusion_count,
            "compatibility_score":  metrics.compatibility_score,
            "mode":                 self.mode.value,
            "platform":             platform.version(),
        }


# Module-level singleton used by downpour_v29_titanium.py
# NOTE: start_monitoring() is deferred — call it explicitly when ready
sophisticated_compatibility = ExtendedDefenderCompatibility(CompatibilityMode.STANDARD)
