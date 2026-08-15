# Downpour v29.40 - Titanium Edition Release Notes

## Release Date: 2026-08-14

## Overview
v29.40 fixes the Python 3.13+ startup crash and completes the live real-time
Performance tab data pipeline. Every gauge now draws from real telemetry:
~15 file/behavior anomaly gauges were silently stuck at 0 because the code
referenced variables that were never defined, and several gauge pairs were so
duplicated that one of each pair could never update.

---

## Critical Fixes

### 1. Boot crash on Python 3.13+
`AttributeError: module 'logging' has no attribute 'handlers'` at startup line
114. Python 3.13+ no longer auto-binds the `logging.handlers` submodule as an
attribute — the app now imports it explicitly
(`import logging.handlers as _crash_handlers`).

### 2. Alpha-Python wheel breakage (`PIL._imaging uses unknown slot ID 85`)
The bundled `.venv` was created on **Python 3.15.0a6 (an alpha)** whose C ABI
differs between milestones — binary wheels for Pillow (and friends) crash at
import. The virtualenv is now rebuilt on the repo's documented stable
**Python 3.12.10**. `find_latest_python()` also now skips alpha/beta/rc builds.

### 3. Live Performance data — silent-zero gauges fixed
`HardwareMonitor._fetch` referenced `fm` (file monitor) and `bs` (behavior
scanner) that were never defined. Every tick those blocks threw a quiet
`NameError`, so **15 real-time gauges always read 0**:
- File: MOD/H, CREATE/H, DELETE/H, SUS CREATE/H, RANSOM/H
- Behavior: KEYLOG/H, SCREEN/H, INJECT/H (behavior), CRED/H, PERSIST/H,
  EVASION/H, EXFIL/H (behavior), LATERAL/H (behavior)

Both are now lazily constructed and cached on the monitor, so they reflect the
single live instances used by the rest of the app.

### 4. Swap / page-fault rates could NameError
The memory-fragmentation block borrowed the disk-IO block's local `dt` — if
that block had failed first, the whole memory block silently died. It now owns
its own timestamped delta.

### 5. Removed dead crash-landmine
`_update_hw_ui()`'s `except` handler referenced undefined
`pct`/`score`/`max_score`/`color` (masking real exceptions with a NameError).
Unreachable `_start_hw_thread` (read a never-set `_hw_ms`) removed.

---

## Performance & Live-Data Enhancements

- **Perf loop in-flight guard**: `_perf_loop` could pile up executor
  submissions on slow ticks — now skipped-and-rearmed instead.
- **Adaptive interval honored**: the loop now uses
  `_adaptive_prf_ms` (from `HardwareProfiler.adapt_to_load`) so the app
  throttles gauge redraws under CPU/RAM pressure instead of thrashing.
- **10s "show real values" safety timer** (`_force_perf_ui`) is finally
  scheduled from `_auto_start` (was defined, never scheduled → gauges could
  sit on "..." forever).
- **Gauge grid refined**: same-key duplicates (DISK QUEUE, FILE THREATS/H,
  EXFIL/H) removed so every canvas is owned by a unique stat key — now
  **129 unique live gauges**; added UPTIME; renamed FEED ERR TOTAL to
  disambiguate from row 23 FEED ERRORS.

---

## Compatibility & Reliability

- `requirements.txt`: dropped EOL `netifaces` (no Python 3.12 wheel, unused);
  documented `setuptools` (supplies the `distutils` shim GPUtil needs on 3.12).
- `LAUNCH_V29_TITANIUM.bat`: Python 3.14 added to discovery; still rejects
  non-final releases.
- AEGIS layer alert wiring now tolerates missing optional layers.

---

## Testing
- 10 new regression guards (`TestV2940Reliability`) covering the crash fix,
  the live-anomaly bindings, the perf loop guards, gauge-key uniqueness, and
  stable-Python selection — **60/60 tests pass**.
- `py_compile` clean; `HardwareMonitor._fetch` headless round-trip verified.