# TODO LIST - Downpour v29 Titanium
# Updated: 2026-04-04 (after 42 patch phases, 550+ fixes)
# Status: LAUNCH READY — Phase 42 bug fixes + progress bar + settings enhancement

---

## COMPLETED (this session — Phases 1-27, 230+ fixes)

All critical bugs fixed, all launch-blocking issues resolved.
Full codebase audit completed (50 active .py files, ~55K lines scanned).
See DONE.md for full list of completed items by phase.

### Key achievements:
- [x] GUI freeze fix (setswitchinterval, staggered startup, alert flood control)
- [x] Rain engine overhaul (zero-alloc, 12fps, pre-allocated pools)
- [x] Performance gauge fix (font cache, bg fill, tab name check)
- [x] Tab bar (compact names, scroll arrows, settings button)
- [x] Hardware utilization (multiprocessing, removed forced sleeps, ABOVE_NORMAL)
- [x] Feed management (13 dead feeds removed, per-feed logging, IOC expiration)
- [x] Crash fixes (SmartServicesScanner, RemoteAccessController)
- [x] Code quality (105->3 bare excepts, dead code archived, v27->v29)
- [x] File organization (104+ files archived, renamed to v29)
- [x] Re-enabled features (MITRE tagging, alarm sounds via executor)
- [x] Manual-only intel downloads (no more auto-download on startup)
- [x] Multiprocessing for 12-core CPU utilization during parsing
- [x] **Phase 27: Full codebase audit** — 120+ bugs across 27 files:
  - [x] 14 crash fixes in main UI (USB monitor, firewall tree, gaming labels, service/remote access API mismatches)
  - [x] 4 missing classes implemented (DiskAnalyzer, LargeFileFinder, EmptyFolderFinder, StartupItemManager)
  - [x] Numpy fallback objects fixed (_FakeNP.random, _FakeNP.linalg)
  - [x] Import guards on 17 supporting modules (psutil, requests, win32*, magic, yara, pefile, sklearn, numpy, pandas)
  - [x] sqlite3 import order fix in threat_feed_aggregator.py
  - [x] UnicodeDecodeError fix in neural_decrypt
  - [x] Health check 74/74 PASS, all 50 .py files compile clean

---

## REMAINING TODO (Future Sessions)

### HIGH PRIORITY
- [ ] **GPU utilization** — gpu_executor pool exists (50% cores) but no CUDA workloads.
      RTX 3050 sits idle. Would need cupy/tensorflow for ML detection on GPU.
- [x] **Startup progress bar** — ~~Replace static "Initializing..." with real progress.~~
      **DONE in Phase 42** — ttk.Progressbar with per-tab updates + percentage label
- [ ] **Feed health dashboard UI tab** — DB table `feed_status` has data, needs UI.

### MEDIUM PRIORITY
- [x] ~~**Settings menu enhancement**~~ — **Partially DONE in Phase 42**
      Rain intensity slider (existed), worker count slider (new), export/import config (new).
      Remaining: theme selection.
- [ ] **Sophisticated false positive system** — DB-backed auto-suppression instead
      of hardcoded whitelists. Track alert frequency, auto-suppress after N clean.
- [ ] **Tab overlap on small windows** — Scroll arrows help but Notebook still wraps.
      Consider custom horizontal scroll canvas instead of native tabs.
- [ ] **Per-feed timeout tuning** — Some feeds take 2+ min. Add slow feeds queue.
- [ ] **Feed auto-retry with exponential backoff** — Currently just skips on fail.
- [ ] **Re-enable _maybe_send_alert_email()** via _io_executor.submit().
- [ ] **Merge SecureThreatIntelligenceDownloader** dead code (bypassed with if False).
- [ ] **Merge EXTRA_FEEDS into main FEEDS dict** — Two separate feed dicts is confusing.
- [x] ~~Dead CTk code section~~ — **Removed in Phase 41** (~3400 lines deleted)

### LOW PRIORITY
- [ ] Add unit tests for thread-safety mechanisms
- [ ] System tray minimize support (pystray)
- [ ] Dark mode detection for Windows 11 integration
- [ ] Export-to-PDF for security reports
- [ ] Feed source categories in UI (abuse.ch, phishing, C2, etc.)
- [ ] Consider async I/O (aiohttp) instead of ThreadPoolExecutor for feeds
- [ ] `gpu_detector_fix.py` module referenced by enhanced_security_dashboard.py doesn't exist
      (import is guarded with try/except so not a crash, but feature is missing)

### NETWORK SECURITY
- [ ] **IoT devices 192.168.4.23 / 192.168.4.40** — Real ESP8266 and Gaoshengda
      devices flagged by Kimwolf. Need firmware update or VLAN isolation.

---

## KNOWN LIMITATIONS (Cannot Fix Without Major Rewrite)

1. **Python GIL** — Phase 25 added ProcessPoolExecutor for parsing (multi-core).
   But other CPU work (psutil, regex scans) still contends on main thread.
   Remaining GIL freezes are 2-12s during monitoring loop activations.

2. **Tkinter single-threaded** — ALL widget updates must happen on main thread.
   Background threads queue work via self.after() / _pending_alerts.

3. **45K-line single file** — Monolithic architecture makes changes risky.
   Ideally split into modules but that's a major refactor.

4. **Rain canvas Tk limitation** — coords() calls on 120+ items at 12fps costs
   ~5ms per frame. Inherent to Tk's canvas implementation.

---
*Updated 2026-03-18 after 41 v29 patch phases. 540+ total fixes. LAUNCH READY.*
