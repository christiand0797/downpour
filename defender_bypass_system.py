#!/usr/bin/env python3
"""
defender_bypass_system.py - Downpour v29 Titanium
Adds Windows Defender folder/process exclusions for Downpour.

Does NOT disable any Defender features.  Previous versions contained
commands that disabled real-time monitoring, SmartScreen, and other
protections — those triggered MpTamperSrvDisableAV and have been
permanently removed.

v29-consolidated: delegates to enhanced_bypass_system to avoid code
duplication across three near-identical modules.
"""
from __future__ import annotations
__version__ = "29.0.0"

from enhanced_bypass_system import (
    SophisticatedDefenderCompatibility,
    ExclusionEntry,
)


class DefenderBypassSystem(SophisticatedDefenderCompatibility):
    """Safe Defender compatibility — exclusions only, no disabling.

    Thin wrapper around SophisticatedDefenderCompatibility — preserves
    the original public API while delegating to the canonical
    implementation.
    """

    # Alias kept for backwards compatibility with health check
    bypass_method_4_defender_service = SophisticatedDefenderCompatibility.run


def main():
    system = DefenderBypassSystem()
    for r in system.run():
        status = "OK" if r.success else "SKIP"
        print(f"[{status}] {r.exclusion_type}: {r.value}")


if __name__ == "__main__":
    main()
