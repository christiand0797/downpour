#!/usr/bin/env python3
"""
defender_bypass_system.py - Downpour v28 Titanium
Adds Windows Defender folder/process exclusions for Downpour.

Does NOT disable any Defender features.  Previous versions contained
commands that disabled real-time monitoring, SmartScreen, and other
protections — those triggered MpTamperSrvDisableAV and have been
permanently removed.
"""
from __future__ import annotations
import logging, os, subprocess, sys
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)
_NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


class DefenderBypassSystem:
    """Safe Defender compatibility — exclusions only, no disabling."""

    def __init__(self):
        self._app_dir = Path(__file__).resolve().parent

    def run(self) -> List[dict]:
        """Add exclusions and return results."""
        results = []
        # Folder exclusion
        results.append(self._add_exclusion("ExclusionPath", str(self._app_dir)))
        # Python process exclusion
        results.append(self._add_exclusion("ExclusionProcess", sys.executable))
        return results

    def _add_exclusion(self, param: str, value: str) -> dict:
        try:
            cmd = f'Add-MpPreference -{param} "{value}" -ErrorAction SilentlyContinue'
            r = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive',
                 '-Command', cmd],
                capture_output=True, timeout=15,
                creationflags=_NO_WIN,
            )
            return {"type": param, "value": value,
                    "success": r.returncode == 0}
        except Exception as e:
            return {"type": param, "value": value,
                    "success": False, "error": str(e)}


def main():
    system = DefenderBypassSystem()
    for r in system.run():
        status = "OK" if r["success"] else "SKIP"
        print(f'[{status}] {r["type"]}: {r["value"]}')


if __name__ == "__main__":
    main()
