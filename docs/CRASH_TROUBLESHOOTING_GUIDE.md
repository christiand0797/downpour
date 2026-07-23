# Downpour v29 Titanium — Crash Troubleshooting Guide

## Most Common Crashes (from live logs)

---

### 1. `AttributeError: '_tkinter.tkapp' has no attribute '_alert_queue'`

**File:** `tk_callback_errors.txt`  
**Root cause:** `_add_alert()` called via `self.after()` before `_init_state()` finishes initializing `_alert_queue`  
**Status:** ✅ Fixed in v29 — `hasattr` guard added  
**Workaround (if still seeing it):** Upgrade to v29 from GitHub

---

### 2. `AttributeError: '_tkinter.tkapp' has no attribute '_alerted_dedup'`

**Root cause:** Same as above — `_queue_alert()` called pre-init  
**Status:** ✅ Fixed in v29 — `hasattr` guard added

---

### 3. `0x800401f0 CO_E_NOTINITIALIZED` (flood in crash_fault.log)

**Root cause:** Windows COM (WMI, shell objects) requires `CoInitializeEx()` on every thread. ThreadPoolExecutor workers didn't initialize COM.  
**Status:** ✅ Fixed in v29 — `initializer=_com_thread_init` on all 3 thread pools  
**Workaround (if still seeing it):** Upgrade launcher + main file from GitHub

---

### 4. `TclError: Item Microsoft Store already exists`

**Location:** `_fw_apply_filter()` in Firewall tab  
**Root cause:** Treeview not cleared before re-populating  
**Status:** ✅ Fixed in v29 — `tree.delete(*tree.get_children())` added at top of filter method

---

### 5. `ImportError: cannot import name 'DiskAnalyzer' from 'downpour_cleanup_module'`

**Root cause:** Local `downpour_cleanup_module.py` is an older version missing `DiskAnalyzer` class  
**Fix:** Download latest `downpour_cleanup_module.py` from GitHub  
**Status:** ✅ Correct version in repo

---

### 6. sklearn warning flood in dp_stderr.txt

```
UserWarning: ...sklearn.utils.parallel.delayed...
```

**Root cause:** sklearn's internal joblib dispatching emits warnings on every fit/predict  
**Status:** ✅ Fixed in v29 — `warnings.filterwarnings()` block at module top

---

### 7. GitHub push rejected: `GH013: Repository rule violations`

**Root cause:** GitHub token was hardcoded in `DO_PUSH_NOW.bat` / `DO_PUSH_NOW.vbs`  
**Status:** ✅ Fixed — both files now prompt for token at runtime, never store it  
**If you see this:** Revoke the leaked token at https://github.com/settings/tokens then re-run push

---

## Collecting Crash Info

After a crash, share these files:
1. `crash_fault.log` — C-level / faulthandler trace
2. `dp_stderr.txt` — Python stderr (last session)
3. `tk_callback_errors.txt` — Tkinter after() callback exceptions

The launcher (`LAUNCH_V29_TITANIUM.bat`) automatically prints the last 20 lines of each on exit.

---

## Log File Locations

| File | Purpose |
|------|---------|
| `crash_fault.log` | C-level crashes (faulthandler) |
| `dp_stderr.txt` | Python stderr |
| `tk_callback_errors.txt` | Tkinter widget callback exceptions |
| `push_log.txt` | Git push output log |
| `downpour_data/` | Threat intelligence database |
| `downpour_tmp/` | Session temp files (auto-cleaned on launch) |
