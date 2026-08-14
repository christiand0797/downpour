# Downpour v29 Titanium — Enhancement Worklog

## Branch: main

# Downpour v29 Titanium — Enhancement Worklog

## Branch: main

## Session 2026-08-13l — v29.32: live DNS Overview panel
- ✅ **Bug found**: `_dns_refresh_overview` had zero callers — its build
  comment said "now called from _auto_start()" but that kickoff was removed
  during FIX-v28p38 loop cleanup. The DNS Overview info panel + threat score
  never updated after first paint.
- ✅ **Fix**: restored `after(4000, self._dns_refresh_overview)` one-shot and
  added `_dns_overview_loop` (60s throttle) — refreshes only while the DNS
  tab is visible, with an in-flight busy guard (set in `_dns_refresh_overview`
  before the fetch thread starts, cleared on the `after(0)` UI postback) plus
  a 180s stuck-fetch safety reset. Uses `_orig_after` for the reschedule,
  matching the perf loop.
- ✅ Tests: `TestDnsOverviewLiveV2932` (4 cases) — caller exists, loop wired
  into auto_start, loop never raises on a bare instance, busy guard raised.
  Full suite 46/46 pass; py_compile OK; pushed `62117b3..13b3f90`.

## Session 2026-08-13k — v29.31: tooltips for the last bare buttons

## Session 2026-08-13l — v29.30b follow-up: hasattr() recursion fix on bare instances
- ✅ **Bug**: the v29.30b warm-history pre-pass used `hasattr(self, '_perf_history')`
  guard clauses. On a bare `object.__new__(downpour)` test instance (no Tk
  runtime), `hasattr()` for a *missing* attribute recurses via
  `Misc.__getattr__ → self.tk` → RecursionError — silently swallowed by the
  blanket `except`, so the pre-pass never ran and the new
  `TestWarmPerfHistoryV2930b` tests (6) all failed.
- ✅ **Fix**: the four lazy-init guards now use `'<attr>' not in self.__dict__`
  membership (no `__getattr__` involved) — strictly more robust, identical
  behavior on real Tk instances. Also patched the concurrent session's
  `test_winfo_exists_false_returns_early` which asserted with `hasattr()`.
- ✅ Result: 42/42 tests pass, py_compile OK, AST 750 methods / 0 dupes,
  pushed to GitHub.

## Branch: main

## Session 2026-08-13k — v29.31: tooltips for the last bare buttons
- ✅ Scanned every `tk.Button(` assignment in the main file (script-based
  tooltip-gap audit). Most flagged sites already bind `_tooltip`; the real
  stragglers were 9 named buttons: Rain toggle, Storm cycle, Settings gear,
  Widget toggle, tab-strip ◀/▶ scroll arrows, CVE "Apply Mitigation for This
  CVE", TPM/BitLocker bypass toggle, and the DNS Live Monitor start/stop.
- ✅ All 9 now have `_tooltip(...)` bindings with short action/state
  explanations. `py_compile` OK; 31/31 unit tests pass.

## Session 2026-08-13k — v29.30b: warm Performance history (gauges never idle)
- ✅ **Gap**: `_update_perf_ui` early-returned whenever the Perf tab wasn't
  visible, so sparkline history and ▲/▼ deltas only accumulated while you
  watched — opening the tab always started from an empty, flat history and
  the adaptive DISK/NET rate ceilings began cold at 0.
- ✅ **Fix**: a cheap warm-history pre-pass now runs *before* the
  tab-visibility guard — every `_perf_gauge_meta` key's value is appended to
  its 30-point deque and per-key deltas computed every tick regardless of
  tab. The visible loop only redraws canvases, reading the warm history
  (removed the old duplicate/triple appends so history has one source).
- ✅ Bonus: adaptive ceilings now learn from background traffic, so DISK/NET
  needles are already scaled correctly when the tab is opened.
- ✅ Verified `py_compile` OK; 31/31 unit tests pass.

## Session 2026-08-13j — v29.30: inline browser-extension security scan
- ✅ **Gap**: `browser_protection.py` (a defensive orphan module: extension
  manifest risk scoring + browser KEV matching) was never wired into the v29
  app; `manifest.json` / `extension_risk` had zero hits in the main file.
  The v29 Threats tab had no browser-extensions surface at all.
- ✅ **Wiring decision (Phase 5)**: rather than importing the standalone
  module (which owns its own `logging.basicConfig`, spawns a daemon thread,
  and depends on `VulnerabilityScanner` + `pythoncom`), consolidated the
  capability inline as `_scan_browser_extensions` / `_browser_cve_check` /
  `_browser_ext_dir` — reusing the already-running `CisaKevEngine` singleton
  for browser→KEV matching instead of a second KEV copy.
- ✅ Scan covers Chrome, Edge, Brave, Firefox (profiles), Opera, Vivaldi, Arc;
  Chromium-family walks `{User Data}/{Profile}/Extensions/{id}/{ver}/manifest.json`,
  Firefox scans profile `extensions` dirs. Risk score = unique suspicious
  permissions ×25 (tabs, webRequest, <all_urls>, cookies, proxy, debugger,
  desktopCapture, clipboardRead, nativeMessaging, management, downloads.open,
  history…), +15 for unnamed/empty-name extensions, capped at 100.
- ✅ Runs on `_io_executor` (never blocks main thread); `_queue_alert` +
  `after(0)` postback; summary via `messagebox.showinfo`. Rate-limited alerts
  auto-apply (`_queue_alert` global 2/s cap). No new runtime deps.
- ✅ Wired into Threats toolbar: `🌐 Browser Scan` button with tooltip.
- ✅ **Declined**: `advanced_device_profiler.py` is evasion/anti-security
  tooling (bypass-capability analysis, adaptation strategies for covert ops)
  — explicitly NOT wired in, consistent with Phase 5 rule "do NOT strengthen
  bypass/evasion orphans".
- ✅ New tests: `TestBrowserScanV2930` (5 tests, 36 total). 36/36 pass,
  py_compile OK, AST 750 methods / 0 dupes, full-project audit clean.

## Branch: main

## Session 2026-08-13i — v29.29: risk-confirmation gates on destructive actions
- ✅ **Gap**: the Threat Action Panel (right-click alert response) ran kill/
  block/suspend/root-cause with ZERO confirmation — one click on the wrong
  row force-killed a process tree or firewall-blocked IPs. Threats tab
  `_threats_kill_selected` also `taskkill /F` without asking.
- ✅ **`_confirm_risk(title, message, action, icon)`** — centralized risk
  gate: always `askyesno` first, runs `action` ONLY on confirmation,
  returns bool. Headless/test-safe: if the dialog can't be shown it returns
  False and refuses the destructive action.
- ✅ Wired into Threat Action Panel (Block All IPs / Kill PIDs / Quarantine /
  Suspend / Root Cause) and Threats tab Kill Selected (with per-alert
  preview + unsaved-work warning).
- ✅ New tests: `TestRiskConfirmation` (3 tests, 31 total). 31/31 pass,
  py_compile OK, AST OK.

## Branch: main

## Session 2026-08-13h — v29.28: Performance tab overhaul (layout + live data)
- ✅ **Bug (the "black box covering half of them")**: `_draw_gauge` drew the
  gauge label at y=`size+18` but `_draw_sparkline` renders a dark fill box at
  `size+14..size+29` and is drawn AFTER the gauge — the box covered the label
  on every gauge. Label now renders at `size+8` (its own reserved band above
  the sparkline strip).
- ✅ **Adaptive gauge ceilings**: DISK/NET rate gauges shipped with static
  ceilings (7000 MB/s, 102400 KB/s) so needles stayed pinned at 0 for any
  realistic traffic. Now `_rate_keys` derive a dynamic ceiling from observed
  history (`ceil(peak*1.4/100)*100`), updated in `_perf_gauge_meta` so both
  needle and sparkline scale together. Gauge never flickers between frames.
- ✅ **GPU column in perf process table**: same `_gpu_proc_map` attribution as
  the Processes tab (VRAM MB when readable) — 12 rows now shown.
- ✅ **Live network + disk tables**: new "LIVE NETWORK INTERFACES" (per-NIC
  send/recv KB/s + link speed, UP/DOWN color) and "DISK PARTITIONS" (used%
  with warn/full coloring) treeviews fed from existing `nic_stats` /
  `disk_partitions` stats — real-time, no new deps.
- ✅ **Bug**: `_perf_scroll_canvas.bind_all('<MouseWheel>')` hijacked wheel
  scroll for ALL tabs after the perf tab was built. Now checks
  `winfo_containing()` so only hovers over the perf grid scroll it.
- ✅ **Tooltips**: Refresh Now / Pause/Resume / Export CSV header buttons.
- ✅ New tests: `TestPerfTabV2928` (5 tests, 28 total). Verified: 28/28 pass,
  py_compile OK, AST OK.

## Branch: main

## Session 2026-08-13g — v29.27: perf-loop live kickoff + Threat Web Stack deep-links
- ✅ **Bug**: the Performance tab was written with an interval slider, pause/
  resume and adaptive `self.after()` rescheduling, but the any initial
  `after(2000, self._perf_loop)` kickoff was commented out — the loop only
  ever called *itself* recursively, so the entire "live" Performance tab
  never updated after first paint (gauges stuck on `...` and pills at 0).
  Suspicion confirmed by grepping every `_perf_loop` reference: zero
  external trigger existed.
- ✅ `_auto_start` now schedules `self.after(2000, self._perf_loop)` — it's
  read-only telemetry (no side effects), so it runs live from launch like
  the alert drainer, instead of being gated behind the Engine Control Panel.
- ✅ **Threat Web Stack** button in Intel tab + `_intel_threat_web_links()` /
  `_intel_threat_web_stack()` — keyless browser deep-links for the OSINT4ALL
  curated threat-intel sources that expose no unkeyed JSON API: Cisco Talos,
  Hybrid Analysis, PhishTank, ANY.RUN, Joe Sandbox. IOC percent-encoded.
- ✅ New tests: `tests/test_thread_safety.py::TestThreatWebStack` (5 new
  tests, 23 total). Verified: 23/23 pass, py_compile OK, project AST 0
  failures.

## Branch: main

## Session 2026-08-13f — v29.26: Windows 11 immersive dark title bar
- ✅ **Gap**: "dark mode detection for Windows 11" TODO — the app is dark but
  the native title bar used system light chrome.
- ✅ **`_apply_dark_titlebar()`** — sets DWMWA_USE_IMMERSIVE_DARK_MODE (attr
  20 Win11 / 19 Win10 fallback) on the real top-level HWND (`GetParent` of
  `winfo_id`), and reads `AppsUseLightTheme` registry → `_system_dark_theme`.
  All ctypes, fully wrapped, never raises.
- ✅ Called at loading reveal + after final title set.
- ✅ Live-verified: DwmSetWindowAttribute rc=0 on a real window (both attrs);
  current machine reads dark theme (AppsUseLightTheme=0).
- ✅ 2 new unit tests (18 total). py_compile OK; main file **741 methods /
  0 dupes**; project AST **0 failures**.

## Branch: main

## Session 2026-08-13e — v29.25: first unit tests + FP fingerprint fix
- ✅ **Gap**: TODO item "Unit tests for thread-safety mechanisms (none exist)"
  finally started. `tests/test_thread_safety.py` (pytest): 16 tests for
  `_fp_fingerprint`, `_fp_is_suppressed`, `_queue_alert` suppression +
  rate limit, and the executor `after(0)` post-back pattern.
- ✅ Uses `object.__new__(downpour)` so pure logic runs without a full Tk
  app. `Python312\python.exe -m pytest tests -q` → 16 passed.
- ✅ **Bug caught + fixed**: `_fp_fingerprint('... 45.88.48.238 :443')` did
  NOT equal `_fp_fingerprint('... 45.88.48.238')` — the port became a
  trailing `*N*` token, so an IP:port FP confirmation couldn't suppress the
  bare-IP alert (and vice-versa). Added an IP[:port] unit regex
  `\b\d{1,3}(\.\d{1,3}){3}(?:\s*:\s*\d{1,5})?\b` → `*IP*` before the generic
  port strip. The docstring claimed this collapsed; the tests proved it
  didn't. (This is exactly why the "no tests" item existed.)
- ✅ Verified: 16/16 pass; py_compile OK; main file **740 methods / 0 dupes**;
  project AST **0 failures**.

## Branch: main

## Session 2026-08-13d — v29.24: GPUDetector module shipped
- ✅ **Bug**: `enhanced_security_dashboard.py` imports `gpu_detector_fix`
  (`from gpu_detector_fix import GPUDetector`) but the module never existed —
  guarded import silently degraded GPU info in that dashboard forever.
- ✅ Created **`gpu_detector_fix.py`**: `GPUDetector.get_gpu_info()` returning
  the exact dict schema the dashboard reads (`available/name/usage/
  memory_used/memory_total/memory_percent/temperature/fan_speed/power_draw/
  clock_speed/memory_clock/driver_version/gpu_count/multi_gpu`).
- ✅ Layered detection: NVML (nvidia_ml_py → pynvml) → nvidia-smi CLI →
  GPUtil → WMI. All paths wrapped; always returns a dict, never raises.
- ✅ Live-verified: RTX 3050 via NVML (33%, 557/8192MB, 38C); dashboard
  AST parses and imports GPUDetector cleanly. Project AST **0 failures**.
- ✅ README: added feature rows for tray, perf-tab, PDF export, GPU
  attribution, keyless infra OSINT.

## Branch: main

## Session 2026-08-13c — v29.23: per-process GPU attribution
- ✅ **Gap**: GPU gauges worked (NVML) but the Processes tab had no per-process
  GPU visibility — couldn't tell which PIDs were GPU-accelerated.
- ✅ `_proc_loop` background scan now runs `nvidia-smi --query-compute-apps=
  pid,used_memory --format=csv,noheader,nounits` (timeout 8s, CREATE_NO_WINDOW)
  and caches `self._gpu_proc_map` on the executor thread.
- ✅ `_update_proc_ui` adds a **GPU** column (VRAM in MB when readable, else
  `[GPU]` marker) — new col in the `cols`/`widths` tuples, diff-based update
  untouched.
- ✅ `_show_proc_detail` shows the GPU line in the detail panel.
- ✅ Live-verified: 14 GPU processes detected on the RTX 3050; `[N/A]` VRAM
  fallback (non-admin) exercised; `_sort_proc_tree` uses column-name API so
  the new col sorts fine.
- ✅ Dependency: uses the bundled `nvidia-smi` CLI — no new Python packages.
- ✅ Verified: py_compile OK; main file **740 methods / 0 dupes**; project AST
  **0 failures**.

## Branch: main

## Session 2026-08-13b — v29.22: real PDF export for security reports
- ✅ **Bug**: `_export_compliance_pdf` was a stub — it just showed a messagebox
  telling the user to save a .txt and use a PDF printer.
- ✅ **Bug**: `_run_nsa_security_report` pushed results only to the alerts
  panel and then discarded them — the full assessment was never persisted.
- ✅ **`_export_pdf_report(title, subtitle, headers, rows, notes)`** — generic
  reportlab PDF writer. Save dialog on main thread, build on `_executor`.
  Teal-on-dark styled: wrapped Paragraph cells, dark header row, PASS/FAIL
  row shading, timestamp, optional notes bullets.
- ✅ **`_export_compliance_pdf`** — now dumps the live compliance tree into a
  real PDF (with failing/warning count note); guards empty-tree with a
  "run Full Audit first" hint.
- ✅ **`_save_nsa_report_pdf(report, critical, grade)`** — executor-side PDF
  writer for the NSA assessment; auto-writes to
  `~/Documents/DownpourReports/downpour_nsa_report_<ts>.pdf` and shows a
  completion dialog. `_run_nsa_security_report` calls it after the summary.
- ✅ Dependency: reportlab verified installed + live-built a valid `%PDF-1.4`
  file with the exact table/style code used. No new installs.
- ✅ Verified: py_compile OK; main file **740 methods / 0 dupes**; project AST
  **0 failures**.

## Branch: main

## Session 2026-08-13a — v29.21: Performance tab live controls + keyless infra OSINT
- ✅ Checkpointed the uncommitted sprint (perf controls + 3 keyless OSINT
  lookups) as v29.21.
- ✅ **Performance tab**: `_toggle_perf_pause` (pause/resume monitoring without
  losing state), `_on_interval_change` (2-30s slider, applies live to adaptive
  intervals), `_draw_sparkline` (real sparklines on perf canvases, re-rendered
  on interval change).
- ✅ **`_osint_ipinfo_lookup`** — keyless IPinfo.io ASN/geo/anycast/bogon
  attribution. Live-verified: `8.8.8.8` → `AS15169 Google LLC / US`.
- ✅ **`_osint_bgpview_lookup`** — keyless BGPView BGP routing graph for IPs and
  ASNs. NOTE: `api.bgpview.io` DNS fails on this network (possibly blocked);
  verified the code's web-page fallback path handles it.
- ✅ **`_osint_hacktarget_lookup`** — keyless HackerTarget multi-recon
  (reverse-IP, GeoIP, DNS, ASN). Live-verified both endpoints.
- ✅ **Bug fixed**: all 6 HackerTarget URLs used `api.hacktarget.com` (no `er`) —
  nonexistent host, DNS-fail. Corrected to `api.hackertarget.com` /
  `hackertarget.com`. Caught by live-testing each endpoint before commit.
- ✅ All three OSINT lookups wired into Network tab, Intel tab, DNS Advanced
  Tools via `_executor` + `after(0)` post-back.
- ✅ Verified: py_compile OK; main file **738 methods / 0 dupes**; project AST
  **0 failures**; keyless endpoints live-tested.

## Branch: main

## Session 2026-08-12g — v29.20: system tray icon (restore path)
- ✅ **Bug**: `minimize_to_tray` config + `_on_close`'s `withdraw()` existed,
  but NO tray icon was ever created — closing the window hid the app with no
  way to restore it (the TODO's "tray never shipped" item).
- ✅ **`_setup_tray_icon()`** — builds a pystray `Icon` (PIL-drawn 64x64
  shield) with Show / Minimize / Exit menu actions, `run_detached()` so it
  owns its own thread and never blocks the Tk loop. Wired into `_auto_start`
  at 8s. Guards on `PYSTRAY_AVAILABLE` + already-running.
- ✅ **`_tray_restore()`** — main-thread deiconify/lift/focus (with brief
  topmost flash so it appears above other windows).
- ✅ **`_tray_toggle()`** — hide/show toggle for the menu item.
- ✅ **`_on_close`** — now fires a `[TRAY]` alert on minimize so the user
  knows where the app went.
- ✅ **`_shutdown`** — stops `_tray_icon` before tearing down Tk.
- ✅ Verified: pystray API surface live-checked (`run_detached`/`stop`/menu/
  PIL icon all OK); py_compile OK; main file **733 methods / 0 dupes**;
  project AST **0 failures**.

## Branch: main

## Session 2026-08-12f — v29.19: OSINT multi-lookup email classification fix
- ✅ **Bug**: `_osint_multi_lookup` had no email branch — emails fell into the
  domain `else`, producing broken links (`dom = ioc.split('/')[0]` →
  `test@example.com`).
- ✅ Added `is_email` detection (before IP/hash/domain) with an email source
  stack: HIBP account, Hudson Rock email, EmailRep.io, DeHashed, Hunter.io,
  VT domain-of-domain, crt.sh, Google. Removed the now-redundant
  unconditional HIBP breach link (folded into domain branch).
- ✅ Verified classification with 8 cases (IP/hash/email/domain/URL/all pass),
  and removed a leftover duplicated `elif is_hash` block my first edit
  created (AST caught it, compile + audit clean after).
- ✅ Verified: py_compile OK; main file **730 methods / 0 dupes**; project
  AST **0 failures**.

## Branch: main

## Session 2026-08-12e — v29.18: slow-feed result-timeout tuning
- ✅ Investigated the `fut.result(timeout=30)` in `update_all`: empirically
  confirmed with a 60s-slow feed test that `as_completed` only yields
  finished futures, so the 30s timeout never fired and MITRE CTI (48MB)
  already counted as OK. The old 30s was therefore misleading AND a latent
  bug — any refactor to a plain `futures` loop would have falsely failed
  every slow feed.
- ✅ Raised to `timeout=150` with a documented budget comment (3x15s download
  attempts + backoff + 120s multiprocess parse = worst case) so it's
  defense-in-depth, not a slow-feed killer.
- ✅ Verified: py_compile OK; main file **730 methods / 0 dupes**; project
  AST **0 failures**.

## Branch: main

## Session 2026-08-12d — v29.17: feed fetch retry with backoff
- ✅ `_fetch_feed` upgraded from 2 immediate attempts to **3 attempts with
  backoff** `(0s, 2s, 6s)` — transient timeouts / 5xx / flaky certs recover
  instead of the feed being marked failed for the whole cycle. Last-attempt
  errors still recorded in `self._feed_errors` → `feed_status`.
- ✅ Cross-checked the periodic path: `_intel_auto_loop` re-runs `update_all`
  when due (default 6h) and checks every 10 min, so a feed that fails the
  3-attempt backoff still retries on the next scheduled cycle.
- ✅ Verified: py_compile OK; main file **730 methods / 0 dupes**; project
  AST **0 failures**.

## Branch: main

## Session 2026-08-12c — v29.16: DB-backed false-positive auto-suppression
- ✅ **`fp_suppressions` table** (fingerprint PK, confirmed, suppressed,
  first_seen, last_seen, sample_msg) in the DB schema DDL.
- ✅ **`_fp_fingerprint(msg)`** — normalizes an alert into a stable key:
  bracket category kept, body lowercased, ports/IPs→`*N*`, hashes→`*H*`,
  whitespace collapsed, trimmed to 64 chars. Verified collisions: same
  IP+port → same key, distinct ports → distinct keys, hashes stable.
- ✅ **`_fp_load_cache()` / `_fp_cache_update()`** — loads `fp_suppressions`
  into an in-memory dict on the executor at startup (6s in `_auto_start`);
  `_queue_alert` hot path only does a dict lookup, no DB on main thread.
- ✅ **`_fp_is_suppressed(msg)`** in `_queue_alert` — drops known-FP alerts
  before they reach the UI.
- ✅ **`_fp_confirm(msg)`** — persists a Mark-FP confirmation (executor
  write); auto-suppresses at `_FP_SUPPRESS_THRESHOLD = 3` confirms, fires a
  `[FP] Auto-suppressed` alert, keeps `first_seen` via COALESCE. Verified in
  isolation: confirms 1-2 no-op, 3rd flips suppressed=True, 4th dropped.
- ✅ **`_threats_mark_fp`** now calls `_fp_confirm` (persisted, not just an
  in-memory status flip).
- ✅ **`_threats_fp_manager`** modal — lists active suppressions (fingerprint
  + confirm count), `Re-arm Selected` (`_fp_unsuppress`), `Clear All`
  (`_fp_clear_all`), both executor writes. New `🤫 FP Blocklist` button in
  the Threats tab toolbar.
- ✅ Verified: py_compile OK; main file **730 methods / 0 dupes**; project
  AST **0 failures**.

## Branch: main

## Session 2026-08-12b — v29.15: Feed health dashboard in Intel tab
- ✅ **`_refresh_feed_health()`** — async reader: `intel.get_feed_status()`
  (`feed_status` table: feed_name / last_update / records_added / error)
  runs on `self._executor`, rows marshaled back via `after(0)`.
- ✅ **`_apply_feed_health(rows)`** — main-thread updater colors the Intel-tab
  feed Status column (which sat on "Pending" forever despite real DB data):
  `[OK] N IOCs - hh:mm` (keeps darkweb/clearnet/gov/community tag),
  `[FAIL] err` (red `feed_err` over-ride), `[STALE]` >3 days (yellow
  `feed_stale`), `[PENDING]` when feed_status has no row. Also sets the
  `_intel_status` summary label to `ok / failed / tracked` counts.
- ✅ Wired: `_feed_refresh_loop` periodic, `_update_intel_now` post-update,
  and a one-shot first paint in `_auto_start` (5s). Adds `feed_err`/
  `feed_stale` tag configs + `_intel_feed_stale_days = 3` in `_build_intel_tab`.
- ✅ Verified: py_compile OK; main file **720 methods / 0 dupes**; project AST
  **0 failures**.

## Branch: main

## Session 2026-08-12a — v29.14: main-thread DB freeze cleanup (v31p2)
- ✅ **Freeze fix round 2**: audited every `count_intel()` / `SELECT COUNT(*)`
  call site for main-thread risk. Eliminated 5+ remaining main-thread DB blocks:
  - New shared helper `_refresh_ioc_count_display()` — runs `db.count_intel()`
    on `self._executor`, posts the label update back via `self.after(0, ...)`,
    with `hasattr`/membership guards so it is safe from both main-thread
    loops and background threads.
  - `_update_network_ui` (30s loop) — was calling `count_intel()` inline on main.
  - `_auto_start` — one-shot `count_intel()` on main at startup.
  - `_feed_refresh_loop` — replaced the per-loop inline executor closure with
    the shared helper (dedupe).
  - `_update_intel_now` — posted `count_intel()` to main in its after(0) lambda.
  - `_aegis_fetch_extra_feeds` — same main-thread after(0) pattern.
  - `_refresh_aegis_stats` (15s AEGIS loop) — both `SELECT COUNT(*) FROM
    aegis_events` and the 10-row `ORDER BY id DESC LIMIT 10` were on main.
    Wired `_aegis_fetch_events` (executor) → `_apply_aegis_events` (main).
- ✅ Audit results: main file now **718 methods / 0 dupes**; py_compile OK;
  project-wide AST **0 failures** (removed stray `zz_dbaudit.py`,
  `zz_health.py` BOM-broken temp scripts).

## Branch: main

## Session 2026-08-11m — v29.13: Hudson Rock infostealer lookup + freeze fix (v31p1)
- ✅ `_osint_hudsonrock_lookup(ioc)` — keyless Hudson Rock **Cavalier** API
  (sidebar source: OSINT4ALL "OSINT for Cybersecurity" — Exposure & breach
  context). Dispatch: email → `search-by-email`, domain → `search-by-domain`.
  Renders affected-machine count, corporate/user creds exposed, most-recent
  compromise date, AV present on infected machines, employee/user/third-party
  split + compromised login URLs for domains. Fires `[BREACH]` alert signal.
- ✅ `_osint_hudsonrock_show(text, ioc)` — display + open cavalier.hudsonrock.com
- ✅ Buttons: `Hudson Rock` in Intel tab Threat Response row; `[BREACH]
  Infostealer Check` in DNS Advanced Tools (via `_dns_adv_hudsonrock` wrapper);
  `Hudson Rock` added to `_osint_multi_lookup` domain deep-link stack.
- ✅ **Freeze fix**: `_refresh_status_pills` ran `SELECT COUNT(*) FROM threats`
  on the *main thread* every 10s — with `db._lock` already held by background
  bulk-insert threads this blocks the UI (same documented root cause as the
  earlier `_feed_refresh_loop` fix). Moved the count to `self._executor` +
  `self.after(0, _apply_threat_pill)`. Status pills now non-blocking.
- ✅ Verified live: email-with-hits, clean domain (`total=0`), real exposure
  domain (tesla.com → 29,630 creds), no-hit email (`stealers=[]`).
- ✅ Project: 0 AST failures; main file 715 methods / 0 dupes; py_compile OK.
- ✅ Committed previously-untracked `ultimate_threat_intel/__init__.py`
  (live runtime for threat_feed_aggregator: ThreatDatabase schema + registry)
  — it was showing as untracked despite being imported at runtime.

## Branch: enhance/all-mods-v29 (historical; now committed on main)

## Completed (Phases 1-2)
- ✅ Removed 2249 illegal `: Any` annotations (token-stream CRLF-safe rewriter)
- ✅ Fixed 6 global/nonlocal annotation conflicts
- ✅ Implemented RemoteAccessController.disable_vector / enable_vector / disable_all_remote_access (@staticmethod)
- ✅ Repointed THREAT FEEDS gauge from broken ultimate_threat_intel stub to working threat_feed_aggregator
- ✅ Added `_make_button()` shared helper + tooltips to: Scanner, Processes, Network, Hardening, AEGIS, Intel, Firewalls, Threats detail panel

## Session 2026-08-11k — DNS tab inline urlscan.io search (v29.12)
- ✅ `_dns_adv_urlscan()` — reuses keyless `_osint_urlscan_search` on the DNS domain field; empty-domain guard
- ✅ Live github.com domain search verified

## Session 2026-08-11j — Keyless inline AlienVault OTX lookup (v29.11)
- ✅ `_osint_otx_lookup(ioc)` — OTX general endpoint, keyless; IP/domain/hostname/URL/file dispatch
- ✅ ASN/geo/reputation/pulse-count/pulse-names + community false-positive notice
- ✅ Live keyless 8.8.8.8 verified; fixed urllib.parse quote bug

## Session 2026-08-11i — Inline ThreatFox IOC search (v29.10)
- ✅ `_osint_threatfox_lookup(ioc)` — ThreatFox API (search_hash / search_ioc exact-match), same abuse.ch Auth-Key
- ✅ Renders malware family/threat type/confidence/Malpedia per hit; no-result dialog
- ✅ Verified both dispatches + keyless fallback; abuse.ch slice complete (MalwareBazaar + URLhaus + ThreatFox)

## Session 2026-08-11h — Inline URLhaus lookup (v29.9)
- ✅ `_osint_urlhaus_lookup(ioc)` — URLhaus API dispatch (hash→payload/, URL→url/, IP/domain→host/), reuses abuse.ch Auth-Key
- ✅ Blacklist state (Surbl + Spamhaus DBL labels), VT ratio, payload drops, recent malware URLs
- ✅ Verified hash/URL/host paths + keyless fallbacks

## Session 2026-08-11g — Inline MalwareBazaar hash lookup (v29.8)
- ✅ `_osint_malwarebazaar_lookup(ioc)` — POST get_info (MD5/SHA1/SHA256), free Auth-Key header; signature/file/type/timestamps/tags/vendor-intel
- ✅ Live probe: endpoint now 401 without Auth-Key → added Settings key field + keyless page fallback
- ✅ Verified hit/not-found/non-hash/keyless paths

## Session 2026-08-11f — Inline Netlas.io host lookup (v29.7)
- ✅ `_osint_netlas_lookup(ioc)` — Netlas host API (Bearer key): IP (ASN/netblock/org/geo/PTR/ports/software) + domain (WHOIS/related domains/NS/MX/ports)
- ✅ `netlas_key` Settings field; `Netlas` button in Intel Threat Response row
- ✅ Verified IP + domain paths, keyless fallback, empty input

## Session 2026-08-11e — Inline Censys host-view lookup (v29.6)
- ✅ `_osint_censys_lookup(ioc)` — Censys Search API v2 host view (API ID + Secret basic auth): ports/services, TLS cert subject/issuer, ASN/geo/DNS; keyless → public page
- ✅ Settings: `censys_api_id` + `censys_secret` masked fields (replaces dead `censys_enabled` boolean)
- ✅ `Censys` button in Intel Threat Response row; `_osint_censys_show()` Tk callback
- ✅ Keyed path verified via mocked v2 response; keyless path opens host page

## Session 2026-08-11d — Keyless urlscan.io public search (v29.5)
- ✅ `_osint_urlscan_search(ioc)` — no-key urlscan.io public search: IP → `ip:`, URL → `page.url:`, else `domain:`; verdicts+scores surfaced, index page opened
- ✅ `is:` operator 403s keyless on this network → switched to `ip:` (live-verified)
- ✅ `urlscan Search` button in Intel Threat Response row; `_urlscan_search_show()` Tk callback

## Session 2026-08-11c — MISP import firewall-block option (v29.4)
- ✅ `_intel_import_misp()` prompts to firewall-block imported IPs (askyesno) — `Downpour_MISP_<ip>` netsh inbound rules, cap 250 (`_MISP_BLOCK_IMPORT_CAP`), blocked/failed/skipped tally
- ✅ Decline path = no firewall work; import unaffected; accept/decline verified via fake netsh harness

## Session 2026-08-11b — MISP/STIX indicator sharing (v29.3)
- ✅ `_intel_import_misp()` — imports MISP event JSON / STIX 2.0 bundle / plain IOC text into titanium.db intel tables (source `MISP-Import:<file>`)
- ✅ `_misp_extract_iocs()` recursive parser (Event/Attribute/objects/response containers, dedupe, generic fallback)
- ✅ MISP type hints incl. `filename|sha256` composite; STIX indicator.pattern + ipv4-addr/domain-name/url/file SCO; multi-label domain classifier
- ✅ `_intel_export_misp()` — exports malicious_ips/domains/urls/hashes as MISP-format JSON event (uuid/info/date/Attribute with type/category/to_ids/comment)
- ✅ Buttons `[MISP] Import IOCs` + `[MISP] Export Event` in Intel Threat Response row
- ✅ Round-trip verified vs temp DB (import→store→export), no duplicates; `py_compile` OK
- ✅ `docs/TODO_v30_DDoS.md` — all 6 DDoS checklist items marked complete

## Session 2026-08-11 — Email-auth DNS check + DNS allowlist bug fix (v29.2)
- ✅ `_dns_adv_email_security()` SPF/DMARC/DKIM check in DNS Advanced Tools (DNS-only, no key)
- ✅ SPF verdict regex handles `-all`/`~all`/`+all`/missing; DMARC `p=` tag regex fixes `sp=reject` false-positive; DKIM multi-selector probe (google/selector1/etc.)
- ✅ **FIXED latent bug**: `_DNS_SAFE_CMD_RE` had a literal backspace byte (`\x08`) instead of `\b`, making every `_dns_run_cmd()` return `[BLOCKED]` — whole DNS tab tooling was silently dead; now `\b`, all 7 call patterns verified
- ✅ Live-verified: google.com (SPF `~all` WARN / DMARC `p=reject` OK / DKIM google selector OK), github.com (DMARC `p=quarantine; sp=reject` now correctly WARN)
- ✅ `_txt_for()` extracts quoted TXT values via regex (nslookup puts value on a separate line from `text =`)

## Session 2026-08-10 — DDoS v30 bootstrap + OSINT4ALL indicator stack (v29.1)
- ✅ Fixed duplicate/conflicting DDoS blocklist persistence (v29 flat dict vs v30 wrapper) — all blocks now land in one JSON store
- ✅ `_ddos_load_blocklist` now backward-compatible + actually removes expired firewall rules on load
- ✅ Wired v30 DDoS Shield UI buttons (Shield / Rate Monitor / Block All / Export / Purge) + startup restore in `_start_loops`
- ✅ OSINT4ALL stack: multi-lookup deep-links (VT/AbuseIPDB/Talos/GreyNoise/Shodan/Censys/OTX/urlscan/HA/MalwareBazaar/SecurityTrails/DNSlytics)
- ✅ Inline AbuseIPDB + Shodan + **Pulsedive** + **ONYPHE** lookups (free API keys; web-page fallback when keyless)
- ✅ HIBP **Pwned Passwords** k-anonymity check (no key) — live-verified vs real API (`password` → 52M hits)
- ✅ GeoIP proxy/hosting flags; Settings → OSINT API Keys (4 fields); extended multi-lookup with Pulsedive/ONYPHE/ANY.RUN/Joe Sandbox/URLhaus/HIBP
- ✅ **DNS tab**: crt.sh CT subdomain discovery (retry + Certspotter fallback, live-verified), Domain OSINT Stack deep-link (14 infra sources incl. Wayback/Archive.today/ViewDNS/DNSDumpster/MXToolbox/Wappalyzer/BuiltWith/Netlas/ZoomEye/FullHunt)
- ✅ **Intel tab**: EmailRep.io inline email reputation (key configurable, page fallback) + GCHQ CyberChef decode with pre-loaded value; Settings → 5 OSINT API key fields
- ✅ **Session 4**: GreyNoise Community noise-vs-targeted triage (Network tab, keyed), Wayback Machine availability check (no-key, no-history = phishing flag), urlscan.io one-click scan submit (Intel tab, keyed); Settings → 7 OSINT API key fields
- ✅ Verified: py_compile + module import + functional tests all pass under Python 3.12

## Phase 3 — Tooltip conversion (in progress)
Remaining button blocks needing tooltips (NO _tooltip / _make_button yet):
- Emergency tab: big panic button (24337), actions loop (24377) — 9 buttons
- Parental tab: 3 buttons (24306, 24309, 24312)
- Ransomware tab: 5 main buttons loop (24473), 3 dir buttons (24532, 24535, 24538)
- Memory tab: 5 buttons loop (24720)
- CVE tab: 7 buttons loop (26037)
- VPN tab: local btn() wrapper (27652) — 9 buttons total (action bar + filter bar)
- Settings tab: revert (27352), bypass (27378), save/export/import (27411-27419), test email (27457), zero trust (27518-27533) — 10 buttons
- Hunt tab: HUNT/STOP (29321, 29329), actions loop (29397) — 10 buttons
- Sandbox tab: browse (30633), detonate/static/clear (30658-30664) — 4 buttons
- Remote Access tab: 4 buttons loop (38837)
- Duplicates cleanup sub-tab: local _btn (40177) — 3 buttons
- Large Files cleanup sub-tab: local _btn (40659) — 2 buttons
- Empty Folders cleanup sub-tab: browse (40891), local _btn (40898) — 3 buttons
- Disk Usage cleanup sub-tab: browse (41328), local _btn (41335) — 2 buttons
- Security Cleanup sub-tab: 7 buttons loop (~41531)
- WiFi tab: 4 buttons loop (42591)
- Timeline tab: 4 main (42898-42907), 4 quick filter + 1 all (42936-42942)
- IoT tab: 7 buttons loop (44436)
- USB tab: 6 buttons loop (43209), remove/save whitelist (43273, 43277)

## Phase 4 — Performance tab overhaul (HIGH PRIORITY)
- "no black box covering half of them" → fix canvas/gauge layout bug
- working gauges (live stats, animated)
- top-N process table, history sparklines
- refresh interval control, freeze/pause, export CSV
- 10x better

## Phase 4b — Modernize GUI
- Keep rain + crescent moon theme
- Add risk warning popups for destructive actions

## Phase 5 — Consolidate orphan modules
- threat_detection_engine, advanced_threat_analyzer, ml_behavioral_analyzer, behavioral_analyzer, behavior_scanner, threat_intelligence (none imported)
- Wire useful ones in; do NOT strengthen bypass/evasion orphans
- Fix broken threat databases

## Phase 6 — Cleanup
- Delete _*.py throwaway scripts + .bak + _illegal_any.json
- .gitignore: add *.pyi, .mypy_cache/, _mypy_*.txt, pyrightconfig.json, stub dirs
- requirements.txt: ensure ALL deps present (torch, scipy, etc) — no optional skips

## Phase 7 — Docs
- README.md: fix 27 tabs (not 24), 104 YARA, real feed count, real FIM count
- docs/README.md, docs/LAUNCHER_GUIDE.md fixes
- docs/AI_Integration.md (0 bytes) — write it
- docs/MODULE_MAP.md — create
- docs/CHANGELOG.md update

## Phase 8 — Verify + push
- py_compile all 58+ modules + main file
- Commit on enhance/all-mods-v29
- git push to origin

## Session 2026-07-10 — Pyright type-fix blitz (1,147→0 errors)
- **Root cause of 806 tkinter None errors**: Removed dead `except ImportError: tk = None` block
- **~180 import None errors**: Annotated ALL `= None` in try/except ImportError blocks with `: Any` (GPUtil, wmi, sklearn, torch, cryptography, requests, pystray, colorama, etc.)
- **~15 instance var None errors**: Added `: Any` to `self._conn`, `self._scaler`, `self._iso_forest`, `self._rf_classifier`, `self._neural_net`, `self.security_auditor`, `self.cleanup_engine`, `self.dup_finder`, `self._iot_scanner`
- **3 runtime bugs fixed**: Missing `url` arg in `_fetch_feed()`, wrong `command_line` kwarg in `_report_apt_detection()`, wrong arg count in `_update_proc_ui()`
- **~15 Optional type signatures**: Fixed function defaults (`str = None` → `Optional[str] = None`)
- **20 redeclaration warnings fixed**: Removed redundant parameter re-annotations
- **1 unused expression fixed**: `getattr(x, None) and x.stop()` → proper `if` guard
- **Config fixes**: `reportRedeclaration` → `"warning"`, retained `reportAttributeAccessIssue: false`
- **stub fixes**: `apply_revolutionary_enhancements(target: Any = None)` in `revolutionary_enhancements/__init__.pyi`
- **Result**: 0 pyright errors, 102 warnings (all `reportUnusedVariable`), app launches clean to mainloop
- **Blocked**: Pillow/matplotlib/scikit-learn/yara-python can't be built — no C compiler + no cp315 wheels yet (Python 3.15.0a6)
