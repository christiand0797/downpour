#!/usr/bin/env python3
"""
adaptive_security_bypass.py - Downpour v29 Titanium
Adds a Windows Defender exclusion for Downpour's own directory so the
scanner is not flagged as malicious.  Does NOT disable any Defender
functionality — real-time protection, cloud protection, tamper
protection, and all other Defender features remain fully enabled.

Previous versions of this file contained Set-MpPreference commands that
disabled Defender monitoring.  Those commands triggered
Trojan:Win32/MpTamperSrvDisableAV.H and have been permanently removed.
"""
from __future__ import annotations
__version__ = "29.0.0"
import logging, os, subprocess, sys
from dataclasses import dataclass, field
from typing import Any, Dict, List

logger = logging.getLogger(__name__)
_NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)


@dataclass
class BypassResult:
    method: str
    success: bool
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)


class AdaptiveSecurityBypass:
    """Add a Defender folder exclusion for Downpour's install directory."""

    def __init__(self):
        self._app_dir = os.path.dirname(os.path.abspath(__file__))
        self._results: List[BypassResult] = []

    def run(self) -> List[BypassResult]:
        """Add exclusion and return results."""
        self._add_folder_exclusion()
        return self._results

    # Alias kept for backwards compatibility with launchers
    comprehensive_security_bypass = run

    def _add_folder_exclusion(self):
        """Add Downpour's folder to Defender's exclusion list."""
        try:
            cmd = (
                f'Add-MpPreference -ExclusionPath "{self._app_dir}" '
                f'-ErrorAction SilentlyContinue'
            )
            r = subprocess.run(
                ['powershell', '-NoProfile', '-NonInteractive',
                 '-Command', cmd],
                capture_output=True, timeout=15,
                creationflags=_NO_WIN,
            )
            ok = r.returncode == 0
            self._results.append(BypassResult(
                method="folder_exclusion",
                success=ok,
                message=f"Added exclusion for {self._app_dir}" if ok
                        else "Could not add exclusion (need Admin)",
            ))
        except Exception as e:
            self._results.append(BypassResult(
                method="folder_exclusion", success=False,
                message=str(e),
            ))

    def get_results(self) -> List[BypassResult]:
        return self._results


def main():
    bypass = AdaptiveSecurityBypass()
    results = bypass.run()
    for r in results:
        status = "OK" if r.success else "SKIP"
        print(f"[{status}] {r.method}: {r.message}")


if __name__ == "__main__":
    main()
