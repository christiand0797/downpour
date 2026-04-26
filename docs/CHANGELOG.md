# Downpour v29 Titanium - CHANGELOG
## 2026-03-18 - Phase 28: Full Codebase Bug Audit (45+ fixes across 25 files)

### COMPREHENSIVE AUDIT
- Deep static analysis of all 50 active `.py` files (~55K+ lines total)
- 14 crash fixes in main UI file (USB monitor, firewall tree, gaming labels,
  service/remote access API mismatches, non-existent method calls)
- 4 new classes implemented in downpour_cleanup_module.py (~350 lines):
  DiskAnalyzer, LargeFileFinder, EmptyFolderFinder, StartupItemManager
- Numpy fallback objects fixed (_FakeNP.random, _FakeNP.linalg)
- Import guards added to 17 supporting modules (psutil, requests, win32*,
  magic, yara, pefile, sklearn, numpy, pandas)
- sqlite3 import order fix, UnicodeDecodeError fix, typo fix
- Health check: 74/74 PASS, all 50 files compile clean
- See docs/CHANGELOG_v29.md Phase 28 for full technical details

---

## 2026-03-17 - Comprehensive Stability & Thread-Safety Overhaul

### CRITICAL CRASH FIXES
- **Thread-safe self.after() override**: ALL 260+ self.after() calls across the entire
  44,700-line codebase are now intercepted. Background thread calls get queued to a
  deque and processed by main-thread drain loops at 50ms intervals. This was the #1
  crash cause — Windows Tcl is NOT thread-safe at the C level.
- **Thread-safe self.after_idle() override**: Same protection.
- **_task_scheduler_loop**: Was calling _process_deferred_updates() directly from a
  background thread, executing Tkinter widget operations. Now schedules via self.after().
- **_thread_safe_ui_update**: Was using self.after_idle() (not thread-safe). Changed to
  self.after(0, ...) which goes through the safe override.
- **animate_alerts**: Removed canvas.update() call from background thread.
- **Global crash catchers**: threading.excepthook + sys.excepthook + Tk callback error
  handler + faulthandler for C-level segfaults.

### THREAD-SAFETY (57+ individual fixes)
- ALL background _add_alert() → _queue_alert() conversions
- _init_zeroday_engine callbacks, _rootkit_scan_loop, _run_full_zeroday_scan
- ExtThreatMonitor checks (DNS tunnel, RDP brute, DHCP, data staging, MotW, macros)
- _svc_monitor_loop, _check_iot_devices, _on_kev_refresh
- Mozi botnet, UAC bypass, COM hijacking, rogue DHCP, WinRM detection
- VPN ping progress, PCAP capture, Threat Hunt, Zero Trust Score
- AEGIS L1-L5 startup alerts

### SQL FIXES
- Fixed 5 column/placeholder mismatches in worm_events INSERT statements
  (4 instances of 5-col/4-val, 1 instance of 7-col/6-val)

### LOGIC IMPROVEMENTS
- DNS tunnel entropy thresholds: 3.5→3.8 (long label), 4.8→4.5 (high entropy)
- DNS tunnel min label length: 30→40 chars
- DNS tunnel PowerShell timeout: 20→25s + returncode guard
- _feed_refresh_loop: winfo_exists guard + hasattr checks
- _hw_loop: guard against missing widgets during early startup
- _drain_alert_queue: per-alert try/except + TclError handling + self-heal
- mainloop restart: 20→50 retries + TclError catch + event flush
- monitor_removable_media: pythoncom.CoInitialize() for WMI thread
- Version string: v26 → v27

### LAUNCHER
- Full UAC auto-elevation
- Automatic dependency installation
- Windows Defender exclusion bypass
- Kimwolf/Mozi C2 IP firewall rules
- Stale cache cleanup
- faulthandler enabled via -X faulthandler
- Stderr capture to dp_stderr.txt
- crash_fault.log display on exit
- Comprehensive status banner

### DOCUMENTATION
- README.md with quick start, architecture, troubleshooting
- CHANGELOG.md with detailed change history
- DONE.md tracking all completed fixes
- TODO.md tracking remaining items
