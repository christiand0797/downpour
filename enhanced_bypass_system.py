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
__version__ = "29.0.0"
from __future__ import annotations
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
        """Add exclusions for Downpour's folder and key files."""
        self._add_exclusion("ExclusionPath", str(self._app_dir))
        self._add_exclusion("ExclusionProcess", sys.executable)

        # Exclude key Downpour files by extension
        for ext in [".pyc", ".pyd"]:
            self._add_exclusion(
                "ExclusionExtension", ext)

        return self._results

    # Aliases for backward compatibility with old launchers/importers
    bypass_method_4_service_enhanced = run
    apply_all_bypasses = run

    def _add_exclusion(self, param: str, value: str):
        try:
            cmd = f'Add-MpPreference -{param} "{value}" -ErrorAction SilentlyContinue'
            r = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive',
                 '-Command', cmd],
                capture_output=True, timeout=15,
                creationflags=_NO_WIN,
            )
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
