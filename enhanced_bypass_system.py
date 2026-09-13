#!/usr/bin/env python3
"""
enhanced_bypass_system.py - Downpour v29 Titanium
Adds Windows Defender exclusions for Downpour's files and processes.

Previous versions contained 10 methods that disabled Defender real-time
monitoring, SmartScreen, controlled folder access, script scanning,
behavior monitoring, and other security features via Set-MpPreference
and registry edits.  Those methods triggered
Trojan:Win32/MpTamperSrvDisableAV.H and have been permanently removed.

This version ONLY adds folder/process exclusions so Defender does not
flag Downpour's own scanning operations as malicious.  All Defender
protections remain fully enabled.
"""
from __future__ import annotations
__version__ = "29.0.0"
import logging, os, subprocess, sys, threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
_NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


class CompatibilityMode(Enum):
    BASIC = "basic"
    STANDARD = "standard"
    ADVANCED = "advanced"
    QUANTUM = "quantum"


@dataclass
class CompatibilityMetrics:
    defender_version: str
    compatibility_score: float
    real_time_enabled: bool
    exclusion_count: int
    last_check: float


@dataclass
class ExclusionEntry:
    exclusion_type: str
    value: str
    success: bool = False


class SophisticatedDefenderCompatibility:
    """Defender compatibility via folder exclusions only."""

    def __init__(self):
        self._app_dir = Path(__file__).resolve().parent
        self._results: List[ExclusionEntry] = []

    def run(self) -> List[ExclusionEntry]:
        """Add Defender exclusions for Downpour's DATA directories only.

        v29.42w (TASK-011, audit 2026-09-07): previous versions excluded the
        whole install directory, sys.executable as a process, and .pyc/.pyd
        GLOBALLY via ExclusionExtension — handing any same-user malware a
        standing Defender blind spot (malware dropped in the install dir, or
        delivered as Python bytecode anywhere, was invisible to real-time
        scanning). Only the write-heavy data directories (logs, DBs,
        quarantine, analysis temp) are excluded now; executables in the
        install dir are scanned normally.
        """
        for data_dir in ("downpour_data", "downpour_v27_data", "downpour_tmp"):
            self._add_exclusion("ExclusionPath", str(self._app_dir / data_dir))

        return self._results

    # Aliases for backward compatibility with old launchers/importers
    bypass_method_4_service_enhanced = run
    apply_all_bypasses = run

    def _add_exclusion(self, param: str, value: str):
        try:
            # Use registry instead of PowerShell
            if param == 'ExclusionPath':
                reg_path = 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths'
                safe_name = value.replace('\\', '_').replace(':', '').replace(' ', '_')[:100]
                r = subprocess.run(
                    ['reg', 'add', reg_path, '/v', safe_name, '/t', 'REG_SZ', '/d', value, '/f'],
                    capture_output=True, timeout=15, creationflags=_NO_WIN
                )
            elif param == 'ExclusionProcess':
                reg_path = 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Processes'
                safe_name = value.replace('\\', '_').replace(':', '').replace(' ', '_')[:100]
                r = subprocess.run(
                    ['reg', 'add', reg_path, '/v', safe_name, '/t', 'REG_SZ', '/d', value, '/f'],
                    capture_output=True, timeout=15, creationflags=_NO_WIN
                )
            else:
                r = type('obj', (object,), {'returncode': 1})()
            
            self._results.append(ExclusionEntry(
                exclusion_type=param, value=value,
                success=r.returncode == 0,
            ))
        except Exception as e:
            logger.debug("Exclusion failed for %s: %s", value, e)
            self._results.append(ExclusionEntry(
                exclusion_type=param, value=value, success=False,
            ))

    def get_results(self) -> List[ExclusionEntry]:
        return self._results


# Alias for old imports
EnhancedBypassSystem = SophisticatedDefenderCompatibility


def main():
    system = SophisticatedDefenderCompatibility()
    results = system.run()
    for r in results:
        status = "OK" if r.success else "SKIP"
        print(f"[{status}] {r.exclusion_type}: {r.value}")


if __name__ == "__main__":
    main()
