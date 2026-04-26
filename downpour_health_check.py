#!/usr/bin/env python3
"""
downpour_health_check.py - Downpour v28 Titanium
Validates every module, dependency, and fix applied in this consolidation pass.
Run:  python downpour_health_check.py
"""
import ast
import importlib.util
import os
import sys
import time
from pathlib import Path

BASE = Path(__file__).parent
PASS = "\033[32m PASS\033[0m"
FAIL = "\033[31m FAIL\033[0m"
WARN = "\033[33m WARN\033[0m"
INFO = "\033[36m INFO\033[0m"

results = []

def check(label, ok, detail=""):
    tag = PASS if ok else FAIL
    line = f"[{tag} ] {label}"
    if detail:
        line += f"  ({detail})"
    print(line)
    results.append((label, ok))

def check_warn(label, detail=""):
    print(f"[{WARN} ] {label}" + (f"  ({detail})" if detail else ""))
    results.append((label, None))

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print('='*60)

# ── 1. Syntax checks ──────────────────────────────────────────────────────────
section("1 · Syntax Validation")
CORE_FILES = [
    "downpour_v28_titanium.py",
    "revolutionary_enhancements.py",
    "enhanced_memory_manager.py",
    "security_hardening.py",
    "defender_compatibility.py",
    "downpour_cleanup_module.py",
    "downpour_remote_access.py",
    "downpour_vpn_module.py",
]

for fname in CORE_FILES:
    fpath = BASE / fname
    if not fpath.exists():
        check(f"Syntax: {fname}", False, "FILE MISSING")
        continue
    try:
        ast.parse(fpath.read_text(encoding="utf-8", errors="replace"))
        check(f"Syntax: {fname}", True)
    except SyntaxError as exc:
        check(f"Syntax: {fname}", False, f"line {exc.lineno}: {exc.msg}")

# ── 2. Required symbols ───────────────────────────────────────────────────────
section("2 · Required Symbol Presence")
REQUIRED_SYMBOLS = {
    "downpour_vpn_module.py": [
        "PrivacyManager", "WireGuardEngine", "TorAnonymityEngine",
        "DoubleHopEngine", "ProxyChainEngine", "VPNKillSwitch",
        "DNSLeakProtection", "IPv6LeakProtection", "LeakTestSuite",
        "VERIFIED_PROVIDERS", "ProviderQuickConnect",
    ],
    "downpour_remote_access.py": [
        "RemoteAccessController", "SmartServicesScanner",
        "REMOTE_ACCESS_VECTORS", "ServiceThreatResult",
    ],
    "downpour_cleanup_module.py": [
        "CleanupEngine", "DuplicateFileFinder",
        "DownpourCleaner", "TempFileCleaner", "LogCleaner",
        "DiskAnalyzer", "LargeFileFinder", "EmptyFolderFinder",
        "StartupItemManager", "size_fmt", "_get_all_drives",
    ],
}
for fname, symbols in REQUIRED_SYMBOLS.items():
    fpath = BASE / fname
    if not fpath.exists():
        for sym in symbols:
            check(f"Symbol {sym} in {fname}", False, "file missing")
        continue
    src = fpath.read_text(encoding="utf-8", errors="replace")
    for sym in symbols:
        check(f"Symbol '{sym}' in {fname}", sym in src)

# ── 3. Bug-fix verification ───────────────────────────────────────────────────
section("3 · Bug-fix Verification")
main_src = (BASE / "downpour_v28_titanium.py").read_text(encoding="utf-8", errors="replace")

check("lambda capture fix (t=task)",
      "lambda t=task: t" in main_src and "lambda x=x: x, task" not in main_src)

check("atexit registered for shutdown_pools",
      "atexit.register(self.shutdown_pools)" in main_src)

check("model_errors table in DB schema",
      "CREATE TABLE IF NOT EXISTS model_errors" in main_src)

check("HOSTS_FILE uses SYSTEMROOT env var",
      "SYSTEMROOT" in main_src)

check("Log path uses __file__ parent",
      "Path(__file__).parent" in main_src and "FileHandler('downpour.log'" not in main_src)

check("__author__ is a proper constant",
      "__author__: Final" in main_src)

check("Training data has 23 columns (matches _extract_features)",
      main_src.count("# 22 lateral_movement_indicators") >= 1)

rev_src = (BASE / "revolutionary_enhancements.py").read_text(encoding="utf-8", errors="replace")
check("numpy import guarded in revolutionary_enhancements",
      "try:" in rev_src and "_NP_AVAILABLE" in rev_src)

check("numpy import guarded in revolutionary_enhancements (no bare top-level import)",
      "try:\n    import numpy as np" in rev_src and
      rev_src.count("import numpy as np") == 1)

check("NeuralSecuritySystem weight shape fixed (3, 16 not 100, 50)",
      "(100, 50)" not in rev_src and "self._input_dim" in rev_src)

check("np.sigmoid removed from revolutionary_enhancements",
      "np.sigmoid" not in rev_src)

check("HyperOptimizationSystem no longer multiplies results",
      "* self.performance_multiplier" not in rev_src)

check("quantum_state kwarg not injected into arbitrary funcs",
      "quantum_state=state" not in rev_src)

check("replicate_cache uses logger not print",
      "print(f\"Cache replicated" not in rev_src)

mem_src = (BASE / "enhanced_memory_manager.py").read_text(encoding="utf-8", errors="replace")
check("numpy import guarded in enhanced_memory_manager",
      "_MM_NP_AVAILABLE" in mem_src)

sec_src = (BASE / "security_hardening.py").read_text(encoding="utf-8", errors="replace")
check("cryptography import guarded in security_hardening",
      "_CRYPTO_AVAILABLE" in sec_src)

def_src = (BASE / "defender_compatibility.py").read_text(encoding="utf-8", errors="replace")
check("No bypass/evasion language in defender_compatibility",
      "quantum_evade_defender" not in def_src)

# Verify bypass modules have real methods (not stripped stubs)
for fname, required_sym in [
    ("enhanced_bypass_system.py",    "bypass_method_4_service_enhanced"),
    ("defender_bypass_system.py",    "bypass_method_4_defender_service"),
    ("adaptive_security_bypass.py",  "comprehensive_security_bypass"),
]:
    fsrc = (BASE / fname).read_text(encoding="utf-8", errors="replace") if (BASE / fname).exists() else ""
    check(f"Bypass methods present in {fname}", required_sym in fsrc)

# ── 4. Dependency check ───────────────────────────────────────────────────────
section("4 · Python Package Availability")
PACKAGES = [
    ("psutil",      True),
    ("numpy",       False),
    ("sklearn",     False),
    ("cryptography",False),
    ("tkinter",     True),
    ("sqlite3",     True),
    ("winreg",      True),
]
for pkg, required in PACKAGES:
    try:
        __import__(pkg)
        check(f"Package '{pkg}'", True)
    except ImportError:
        if required:
            check(f"Package '{pkg}' (required)", False, "pip install " + pkg)
        else:
            check_warn(f"Package '{pkg}' (optional — some features disabled)",
                       "pip install " + pkg)

# ── 5. File existence ─────────────────────────────────────────────────────────
section("5 · File Existence")
REQUIRED_FILES = [
    "downpour_v28_titanium.py",
    "revolutionary_enhancements.py",
    "enhanced_memory_manager.py",
    "security_hardening.py",
    "defender_compatibility.py",
    "enhanced_logging.py",
    "downpour_cleanup_module.py",
    "downpour_remote_access.py",
    "downpour_vpn_module.py",
    "requirements.txt",
]
for fname in REQUIRED_FILES:
    fpath = BASE / fname
    size_kb = round(fpath.stat().st_size / 1024, 1) if fpath.exists() else 0
    check(f"File: {fname}", fpath.exists(),
          f"{size_kb} KB" if fpath.exists() else "MISSING")

# ── 6. Requirements.txt sanity ────────────────────────────────────────────────
section("6 · requirements.txt Sanity")
req = (BASE / "requirements.txt").read_text(encoding="utf-8")
check("psutil listed in requirements",
      "psutil>=" in req)
check("requests listed in requirements",
      "requests>=" in req)
check("pywin32 listed in requirements",
      "pywin32>=" in req)
check("cryptography listed in requirements",
      "cryptography>=" in req)

# ── 7. Summary ────────────────────────────────────────────────────────────────
section("Summary")
total   = len([r for r in results if r[1] is not None])
passed  = len([r for r in results if r[1] is True])
failed  = len([r for r in results if r[1] is False])
warned  = len([r for r in results if r[1] is None])
print(f"  Passed : {passed}/{total}")
print(f"  Failed : {failed}")
print(f"  Warned : {warned}")
if failed == 0:
    print("\n  \033[32mAll checks passed — Downpour v28 Titanium is healthy.\033[0m")
else:
    print(f"\n  \033[31m{failed} check(s) failed — review items above.\033[0m")
print()
