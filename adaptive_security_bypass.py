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

v29-consolidated: delegates to enhanced_bypass_system to avoid code
duplication across three near-identical modules.
"""
from __future__ import annotations
__version__ = "29.0.0"

from enhanced_bypass_system import (
    SophisticatedDefenderCompatibility,
    ExclusionEntry,
)


class AdaptiveSecurityBypass(SophisticatedDefenderCompatibility):
    """Add a Defender folder exclusion for Downpour's install directory.

    Thin wrapper around SophisticatedDefenderCompatibility — preserves
    the original public API (run, comprehensive_security_bypass,
    get_results) while delegating to the canonical implementation.
    """

    # Alias kept for backwards compatibility with launchers
    comprehensive_security_bypass = SophisticatedDefenderCompatibility.run


def main():
    bypass = AdaptiveSecurityBypass()
    results = bypass.run()
    for r in results:
        status = "OK" if r.success else "SKIP"
        print(f"[{status}] {r.exclusion_type}: {r.value}")


if __name__ == "__main__":
    main()
