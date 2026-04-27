#!/usr/bin/env python3
"""
Health check utility for Downpour v29 Titanium.

This script performs a quick health check across core modules, ensuring
basic import sanity, versioning presence, and that key config values are loadable.
It is intended as a quick smoke test for CI, local runs, and sanity checks.
"""

__version__ = "29.0.0"

import importlib
import sys
import platform

MODULES = [
    'config',
    'ai_security_engine',
    'network_monitor',
    'vulnerability_scanner',
    'memory_forensics',
    'threat_feed_aggregator',
    'threat_intelligence_updater',
    'threat_intelligence',
    'enhanced_security_dashboard',
    'enhanced_hardware_integration',
    'parental_controls',
    'backup_verifier',
    'file_scanner',
    'system_cleanup'
]

def main():
    print("Downpour health check v29 (ASCII)")
    print("Platform:", platform.system(), platform.release())
    ok = True
    for name in MODULES:
        try:
            mod = importlib.import_module(name)
            has_version = hasattr(mod, '__version__')
            if has_version:
                ver = getattr(mod, '__version__', 'unknown')
                print(f"[OK] {name}: import ok (v{ver})")
            else:
                print(f"[WARN] {name}: import ok (no __version__)")
        except Exception as e:
            ok = False
            print(f"[FAIL] {name}: {e}")
    print("---")
    if ok:
        print("HEALTH: ALL MODULE IMPORTS OK")
        sys.exit(0)
    else:
        print("HEALTH: SOME MODULES FAILED TO IMPORT. FIX ERRORS ABOVE.")
        sys.exit(1)

if __name__ == '__main__':
    main()
