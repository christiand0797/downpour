# Changelog v29.42 Titanium

## Performance & Telemetry Enhancements
* **GPU Power & Clock Gauges:** Added real-time GPU power draw and clock speed monitoring gauges to the Performance tab.
* **Network Packets Tracking:** Added real-time tracking for network packets per second.
* **TCP State Breakdown:** Added new gauges for tracking specific TCP states (TIME_WAIT, CLOSE_WAIT, SYN_SENT).
* **Load Average Improvement:** The Windows load average metric now uses an exponential moving average (EMA) for smoother and more accurate long-term trend analysis.
* **Gauge Rendering Optimization:** Implemented performance optimizations for gauge rendering, skipping updates for gauges that have not changed value, significantly reducing GUI overhead.
* **Perf Sweep Single-Flight + Cached Status:** `HardwareMonitor._fetch` now coalesces concurrent callers via a `Future` single-flight and caches `process_iter(['status'])` to a 10s snapshot; `open_files` uses `num_handles()` (~6× cheaper). Sweep cut from ~9s to ~3s, unlocking true live cadence for the 129+ gauges.

## Bug Fixes & Stability
* **Native Crash Hardened (0xc0000005 in _psutil_windows.pyd):** psutil keeps global mutable state (`_pmap`, `_LOWEST_PID`, shared C buffers in `net_connections`/`cpu_percent`) with no module lock — concurrent calls from hw-monitor (1-3s), Perf executor fetch, heartbeat (60s) and scan workers corrupted the C buffers at the 60-min feed update. Added process-wide `_PSUTIL_LOCK` (RLock) wrapping 19 psutil system-wide functions at module import (`process_iter` generator holds lock for whole iteration). 12-thread hammer + single-flight verified, 93/93 tests.
* **DNS Latency Fix:** Fixed DNS latency measurement by ensuring it tracks real hostname resolution times rather than cached or dummy values (now throttled to 30s, `dns.google` via `getaddrinfo`).
* **Process Monitor Fix:** Resolved false positives in `process_monitor.py`.
* **Hardware Integration Crash:** Fixed a crash bug in `enhanced_hardware_integration.py` related to missing WMI/NVML telemetry.
* **CPU Percent Blocking:** Fixed blocking issues in `process_monitor` and `hardware_monitor` where `cpu_percent()` calls would hang the thread.
* **Performance gauge label visibility fix (v29.42a):** Canvas height adjustment.
* **Feed-health change-detection cache (v29.41k5g):** Reduces Tcl calls.
* **WAL database reader/writer connection split (v29.41k5f):** Prevents main-thread stalls.
* **DNS live monitor seen-set dedup (v29.41k5e):** Stops duplicate row/alarm spam.
* **HTTPS-first upgrades & live Country column (v29.41k5b-d):** Enhancements to Network tab and intel fetches.
* **Nested-parallelism deadlock fix (v29.41k5):** n_jobs=1 post-fit fixes joblib thread explosion.
* **Test count inconsistency fix:** 93/93 not 92+.

## Documentation & Repository Maintenance
* **.gitignore Cleanup:** Cleaned up `.gitignore` and added rules for `downpour_copy.log` and standard cache directories.
* **README Updates:** Updated README badges (v29.42 Titanium, 92+ passing tests) and documented new Performance tab metrics and gauge count (129+ unique live gauges).
* **Module Map:** Created `docs/MODULE_MAP.md` documenting the 40+ supporting architecture modules.
