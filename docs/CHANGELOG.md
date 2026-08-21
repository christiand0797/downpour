# Downpour v29 Titanium — Changelog

## v29.42a - Perf gauge visibility — black box no longer covers label
- `c = Canvas(cell, width=SIZE, height=SIZE+60)` (was +52); label at
  `size+10` (was +8) and sparkline strip at `size+30..size+46` (was
  +26..+42). Gap label→strip 8px → 20px so the dark `#06080f` strip no
  longer visually touches the label. Test `test_gauge_label_not_under_
  sparkline` updated to accept `size+10`/`size+30`.

## v29.41k5h - psutil native crash hardened + Perf sweep single-flight
- Native crash `0xc0000005` in `_psutil_windows.pyd` (k9 smoke at 60 min):
  psutil keeps global mutable state with no lock; concurrent `process_iter`,
  `net_connections`, `cpu_percent` from hw-monitor (1-3s), Perf executor
  fetch, heartbeat (60s) and scan workers corrupted the C buffers.
- Global `_PSUTIL_LOCK` (RLock) now wraps 19 psutil system-wide functions at
  module import via attribute patching (`process_iter` generator wrapper holds
  the lock for the whole iteration). Every `import psutil` hits the locked
  wrappers. Per-Process instance methods already have their own lock.
- `HardwareMonitor._fetch` single-flight: concurrent callers share one Future;
  `get_stats`/`_fetch`/`Refresh Now` no longer run duplicate 3-9s sweeps.
- Sweep itself trimmed: `open_files` uses `num_handles()` (~6× cheaper than
  `open_files()` enumeration, 0.9s→0.15s per 100 pids) and `process_iter`
  status snapshot cached to 10s (was twice per fetch, ~1.9s). DNS latency
  already throttled to 30s. 92/92 tests (12-thread concurrent psutil hammer
  + single-flight coalescing verified).

## v29.41k5g - Feed-health refresh: zero Tcl calls for unchanged rows
- After the DB read/writer split, the remaining 1.6-2.4s FREEZEs came from
  `_apply_feed_health`: every periodic Intel-tab refresh re-issued per-row
  `tree.item('tags')` + `tree.set` + `tree.item(tags=)` — a few hundred Tcl
  round-trips even when no feed status changed, GIL-starving the Tk client
  under the writer/training storm.
- Now a `_feed_health_rendered` cache stores the last-rendered
  `(value, tags, base_tag)` per row; unchanged rows skip the tree entirely
  (base tag reused from cache, so no read either); iids that vanish from the
  tree are pruned from the cache. 92/92 tests.

## v29.41k5f - DB reader/writer split: reads never block behind bulk writers
- `Database` used one RLock across the single WAL connection — main-thread
  SELECTs stalled behind background bulk `executemany()` batches (the
  startup/intel FREEZE warnings, 1.5-5s).
- New dedicated reader connection (`_read_conn`/`_read_lock`): pure reads
  route there and never wait for writers; WAL guarantees a consistent
  snapshot. Writers unchanged. Stress-tested: 50 reads in 0.005s while a
  writer ran continuous 200-row batch inserts. 91/91 tests.

## v29.41k5e - DNS live-monitor dedup: no more duplicate rows or alarm spam
- `_dns_monitor_loop` reads the full DNS client cache snapshot every 3s and
  was re-inserting every entry each cycle (duplicate rows, endless Queries
  ratchet, same-threat re-alert every poll).
- Seen-set of `(domain,data,type)` keys now gates inserts/counts/alerts;
  count label reads `Queries: n`; Clear resets the seen-set. 90/90 tests.

## v29.41k5d - VPN Mirror-2 fetch HTTPS-first + full egress audit
- Audited all 38 `urllib.request.urlopen` call sites: 37 HTTPS or
  user-configurable; one plain-HTTP-only left — VPN tab Mirror-2 source
  (`lab.mahidol.ac.th`).
- `_vpn_load_servers()` now prefers `https://` for every source and falls
  back to `http://` only on failure; `raw` defaults to `''` so dead sources
  degrade to logged skips (no NameError). 89/89 tests.

## v29.41k5c - Intel feed fetches: HTTPS-first with HTTP fallback
- `_fetch_feed()` no longer hard-locks a `_HTTP_OK` host set (`sysctl.org`,
  `data.phishtank.com`, `pgl.yoyo.org`, `someonewhocares.org`) to plain
  `http://` forever, and no longer skips a feed when its HTTPS fetch fails.
- All feeds are fetched over HTTPS first (permissive SSL context still used
  for the expired/self-signed-cert hosts, which complete the handshake);
  plain-HTTP is only a terminal fallback. `_HTTP_OK` removed.
- Same pattern as the `_ip_api_get` geo helper from v29.41k5b — privacy
  first, resilience second. 88/88 tests.

## v29.41k5b - Network tab Country column made live + unified HTTPS-first geo helper
- The Network tab's Country column was hard-coded blank forever (no lookup ever
  ran). Now resolves live: `_geo_cache` + `_async_geo(ip)` do a keyless
  ip-api.com country lookup on the executor for public IPs; private IPs stay
  blank (rate-limit hygiene) and failures degrade to `--` without blocking.
- New shared `_ip_api_get(self, ip, fields, timeout)` helper — HTTPS-first,
  plain-HTTP fallback (free JSON endpoint is HTTP-only), uniform UA, returns
  `{}` on total failure. All five geo call sites unified on it: live Country
  column, Intel-tab GeoIP, alert-action GeoIP, Net-tab Geo-Locate,
  alert-feed `_geolocate_one`. Four previously used plain-HTTP only.
- 87/87 tests (added geo regression guards). Smoke: threads stable 67–80, ZERO
  scan-worker/joblib wedges, 17 transient ≤2s FREEZE warnings (DB-write
  contention only).

## v29.41k5 - scan-worker/joblib thread explosion fixed + Perf-tab live-data restore

### Critical: scan-worker/joblib nested-parallelism deadlock (thread/memory runaway)
- Root cause: sklearn 1.9.0 + joblib 1.5.3 deadlock inside joblib's `_retrieve`
  whenever `predict_proba()` / `decision_function()` were called from inside a
  `ThreadPoolExecutor` worker (the `scan-worker` pool in `scan_all()`). Every
  60s `_proc_loop` leaked a fresh 9-worker pool stuck forever — observed
  176 → 341 threads in ~50 min, RSS crawling toward 2.56GB.
- Fitted sklearn estimators now force `n_jobs = 1` post-fit (single-sample
  inference gains nothing from n_jobs > 1) so nested joblib dispatch can never
  fire from inside a pool worker.
- `scan_all()` split into `_scan_all_locked()` with a `_scan_in_progress`
  overlap guard (returns `[]` while a scan is draining) and explicit
  `pool.shutdown(wait=False, cancel_futures=True)`; `as_completed(futures,
  timeout=90)` abandons wedged workers so `_proc_loop` can never stack pools.

### Perf tab: live data restored to real cadence
- The `open_files` walk (verified ~8.5s for 500 pids on Windows) ran on EVERY
  fetch tick, strangling the whole 1-3s refresh to ~14s. Now sampled every 15s
  (300-pid cap, cached in between) — non-sampling ticks drop to ~3s.
- Top-processes table gained live per-process RSS MB, disk I/O rate (KB/s) and
  active connection count — enrichment is bounded to the top-20 CPU consumers
  via one shared `net_connections` walk (O(top-N), not O(all procs)).
- Columns now: pid / name / cpu% / mem% / rssMB / rd / wr / conns / gpu / status.

### Stability
- winfo_exists Tcl-safety: `_tk_alive` flag + `_winfo_ok()` helper across all
  16 worker-thread `winfo_exists()` sites; `_shutdown()` clears the flag first.
- Verified: smoke thread count stable at 67–80 (was climbing 176→341), ALIVE
  cadence clean, fetch cadence restored. 84/84 tests.

## v29.36 - 60-Second History Timeline Chart, Performance Threshold Alerts, Alert Rate Meter

### Performance Tab: 60-Second History Timeline
- Added a dedicated `tk.Canvas`-based rolling time-series chart below the disk partition table
- Shows CPU%, RAM%, GPU%, and combined NET KB/s (scaled 0–100) over the last 60 samples
- Color-coded lines with latest-value dots and text labels on the rightmost point
- Per-pixel grid lines at 25%/50%/75%; X-axis shows elapsed sample count and "now" marker
- `_draw_perf_timeline(s)` new method — calls self-initialize if deques don't exist yet
- Timeline storage: 4 × `collections.deque(maxlen=60)` for cpu/ram/gpu/net history

### Performance Threshold Alert Engine
- New `_perf_check_thresholds(s)` method — runs on EVERY stats update regardless of which tab is visible
- Fires `_queue_alert()` when: CPU>90%, RAM>90%, CPU temp>85°C, GPU temp>85°C, Disk>95%, Swap>80%
- 120-second cooldown per alert key prevents spam during sustained high-load events
- Spike detection: fires instantly if CPU jumps >40% in a single sample AND ends above 60%
- Spike cooldown: 30 seconds
- All thresholds/cooldowns configurable via dict constant `_THRESH`

### Status Bar Alert Rate Meter
- New `⚡ N/min` label in the status bar tracking alerts fired in the last 60 seconds
- Color-coded: dim (0–2/min), orange (3–9/min), red (10+/min)
- `_update_alert_rate_meter()` reschedules itself every 15s via `_orig_after`
- `_queue_alert()` now appends a timestamp to `self._alert_timestamps` for rate tracking
- Wired into `_auto_start()` with a 15s initial delay

### Tests
- New `TestPerfThresholdAlertsV2936` class (5 tests):
  - `test_method_exists` — verifies both new methods exist in source
  - `test_never_raises_on_bare_instance` — no crash on empty or full stats dict
  - `test_cooldown_prevents_duplicate_alerts` — only 1 cpu_high alert in rapid-fire calls
  - `test_spike_detection_fires` — 60-point jump triggers spike alert
  - `test_draw_timeline_never_raises` — canvas draw safe on bare instance
- All 55+ tests pass; py_compile OK

---

## v29.35 - Complete Tooltip Sweep + WiFi/IoT/USB/Timeline Tab Enhancements

### Phase 3 Tooltip Sweep (Final)
- Audited WiFi, IoT, USB, Timeline, VPN, Settings, Hunt, and Sandbox tabs
- All 113+ buttons now have `_tooltip()` hover help — 0 bare buttons remain in any tab
- Confirmed all tabs use 4-tuple `(text, cmd, color, tip)` pattern in action lists
- Fix: test `TestTabIndicatorV2934b::test_indicator_created_before_tab_change_binding`
  — search string updated from bare `<<NotebookTabChanged>>` to `self.nb.bind('<<NotebookTabChanged>>'`
  to skip the comment occurrence at line ~1499 and match the actual binding call
- 50/50 unit tests pass; py_compile OK; 1720 methods

### WiFi Security Analyzer (new tab)
- Real-time `netsh wlan` scanner populating SSID/BSSID/Signal/Auth/Cipher/Band/Score/Evil-Twin columns
- Evil-twin detection: flags all SSIDs with more than one BSSID entry
- Security scoring: WPA3=100, WPA2=75, WPA=45, WEP=10, Open=0
- Color coding: green ≥70, orange ≥40, red <40; evil-twin rows magenta
- Per-network security analysis panel (findings list: protocol weaknesses, TKIP deprecation)
- Show Saved Passwords: decrypts Wi-Fi profiles via `netsh wlan show profile key=clear`
- DNS Leak Test: resolves test domains + runs `nslookup` to expose split-tunnel leaks
- Export to CSV; status bar shows network count + weak/evil-twin counts

### IoT Device Discovery (new tab)
- Ping-sweep of local subnet using `subprocess.run ping -n 1 -w 200`
- ARP table lookup via `arp -a` for MAC address and vendor resolution
- Mozi/Kimwolf botnet signature check via `iot_scanner.IoTDeviceScanner`
- Port fingerprinting via TCP connect probes on common IoT ports
- Per-device block via `netsh advfirewall firewall add rule`
- Per-device unblock matching on rule name
- Risk column: CRITICAL/HIGH/MEDIUM/LOW based on open ports and known-bad vendor strings
- Real-time progress label + status indicator pill

### USB Guard (new tab)
- Live device enumeration via `wmic path Win32_USBHub get` and `Win32_USBControllerDevice`
- Windows USB history from registry `HKLM\SYSTEM\CurrentControlSet\Enum\USB`
- Per-device whitelist with persistent JSON save to `downpour_data/usb_whitelist.json`
- Auto-block toggle: monitors USB insertion events via WMI `__InstanceCreationEvent`
- Alert log panel showing all insertion/removal events with timestamps
- Right-click context menu: whitelist / block / copy device ID
- Sort by column, tag coloring (whitelisted=green, blocked=red, unknown=orange)

### Security Event Timeline (new tab)
- Windows Security event log via `Get-WinEvent` PowerShell (up to 2000 events)
- 28-event-ID map including: 4624/4625 logon, 4688 process create, 4697/7045 service install,
  4720 account create, 4698/4702 scheduled task, 4728/4732 group membership
- Attack pattern detection: brute force (≥5 failed logins per user), lateral movement
  (explicit-credential logon count > 3), persistence (service/task install, account creation)
- Quick-filter radio buttons per event ID; "All Events" clears filter
- Column sort (click header); severity tag coloring: critical=red, warning=orange, info=blue
- Export to self-contained HTML report with dark theme
- Detail pane shows full event message on selection

---

## v29.34 - Full Tooltip Sweep (All Main Tabs)

- Gap audit: counted 122 `tk.Button` creations vs 72 `_tooltip` calls — 50 bare buttons
- Added tooltips to: PANIC, ECP engine buttons, HUNT, packet-capture bar (Start/Stop/Check Rogue DHCP),
  intel feed management (Add/Fetch/Remove/Import/Statistics), Scanner header (Run Full Scan/Fix All/Zero-Days),
  DNS monitor (Clear/Export Log), DNS cache (View/Flush/Scan/Export), DNS blocklist (Block/Unblock/Import/Export),
  DNSSEC (Validate/Audit), poison/system-domain/router-DNS checks, firewall Load Events,
  GreyNoise lookup + Unblock Selected, fingerprint Re-arm/Clear All, hardening Rollback Selected
- Tooltip count: 72 → 113; remaining 14 bare are self-explanatory Close/Cancel/❌ in modal dialogs
- 46/46 unit tests pass; py_compile OK; 751 methods / 0 dupes

---

## v29.33 - Tooltips across every DNS sub-tab


- Upgraded the 5 DNS button-factory helpers (qbtn / srv_btn / hbtn /
  enc_btn / tbtn) to accept a tip= and bind the hover tooltip; added
  per-button help text to ~30 DNS buttons: Overview quick-actions,
  Servers (apply/show/reset/latency/leak), Hosts (load/save/block/
  import/hijack-scan/backup/restore), DoH (Win11/Cloudflare/Google/test),
  Advanced tools column (14 lookups), Security-tests column (7) and
  Repair/Harden column (7), plus the secure-provider loader.
- 46/46 unit tests pass; py_compile OK.

## v29.32 - Live DNS Overview panel (throttled auto-refresh)

- Found via call-site audit: _dns_refresh_overview (the DNS Overview info
  panel + threat score) had ZERO callers -- the kickoff promised in its
  build comment ("called from _auto_start") had been removed during loop
  cleanup, so the panel stayed stale / "Click Refresh to scan" forever.
- Restored the one-shot refresh at startup (after 4s) and added
  _dns_overview_loop: a throttled 60s auto-refresh that only fires while the
  DNS tab is visible, never overlaps an in-flight fetch (busy guard with a
  180s stuck-fetch safety reset), and keeps the threat score + detail line
  live. Read-only telemetry, consistent with the v29.27/v29.28 live-loop
  rationale.
- 4 new unit tests (46 total), 46/46 pass; py_compile OK.

## v29.31 - Tooltips for the last bare buttons

- Added hover tooltips to the 9 remaining tk.Button widgets that had none:
  Rain, Storm, Settings gear, Widget toggle, tab-strip scroll arrows (both),
  CVE "Apply Mitigation" button, TPM/BitLocker bypass toggle, and the DNS
  Live Monitor start/stop button.
- Verified py_compile OK; 31/31 unit tests pass.

## v29.30b - Warm Performance History (gauges never idle)

- _update_perf_ui now runs a cheap warm-history pre-pass BEFORE the
  tab-visibility guard: every gauge value is appended to its 30-point
  history deque and per-gauge up/down deltas are computed even while the
  Perf tab is hidden.
- Result: sparkline rings are already populated and delta markers meaningful
  the instant the Perf tab is opened; adaptive DISK/NET ceilings also learn
  from background traffic instead of starting cold at 0.
- Removed the duplicate/triple history appends in the visible loop (single
  source of truth = the pre-pass).
- Verified py_compile OK; 31/31 unit tests pass.

## v29.30a - Inline Browser-Extension Security Scan (Threats toolbar)

- browser_protection.py (defensive orphan) wired inline as
  _scan_browser_extensions / _browser_cve_check / _browser_ext_dir,
  reusing the running CisaKevEngine singleton for browser->KEV matching.
- Scans Chrome, Edge, Brave, Firefox, Opera, Vivaldi, Arc manifests; risk
  score = suspicious permissions x25 + anonymity penalty, capped at 100.
- Runs on the IO executor, posts back via after(0) + _queue_alert; new
  Browser Scan button on the Threats toolbar with tooltip.
- 5 new tests (36 total), 36/36 pass, AST 750 methods / 0 dupes.

## v29.29 - Risk-Confirmation Gates on Destructive Actions

- Kill / block / suspend / quarantine actions now require an explicit
  confirm dialog before executing, consistent with the perf-tab process
  kill flow.

## v29.28 - Performance Tab Overhaul

- Fixed label/sparkline overlap ("black box over half the gauges").
- Adaptive rate-gauge ceilings for DISK/NET so needles track real traffic.
- GPU + network + disk live tables, scoped mousewheel, live detail row
  (RAM / Disk / CPU temp / Net totals / last-updated) and delta markers.
- Perf live kickoff at startup (dead perf tab fix, v29.27) + status-bar
  telemetry ticker (CPU/RAM/DISK/NET, color-coded).

## v29.27 - Perf live kickoff + Threat Web Stack deep-links

- Performance telemetry loops auto-start from launch (read-only, no side
  effects); threat web-stack rows deep-link to open ports / processes.

## v29.26 Titanium — Windows 11 Immersive Dark Title Bar + Theme Detection

Session goal: clear the "dark mode detection for Windows 11" TODO. Downpour
is inherently dark-themed; on Windows 11 the native title bar defaulted to
the system light chrome, which looked broken against the void-black UI.

- **`_apply_dark_titlebar()`** — new helper that
  - sets `DWMWA_USE_IMMERSIVE_DARK_MODE` on the real top-level HWND (attr 20
    on Win11, falling back to attr 19 on Win10; found via `GetParent` of
    `winfo_id`, the same pattern verified live), and
  - reads `AppsUseLightTheme` from
    `HKCU\...\Themes\Personalize` and stores `self._system_dark_theme` so a
    future settings toggle can follow the system theme.
  - Pure ctypes, every step wrapped, never raises.
- Called twice: at the loading-screen reveal and again after the final title
  is set (defensive if the window handle changes).
- Live-verified: `DwmSetWindowAttribute` returns rc=0 (success) on a real
  top-level window for both attrs; the registry read reports the current
  machine is in dark theme (`AppsUseLightTheme=0`).
- 2 new unit tests added (18 total): the method is callable on a bare
  instance without raising, and the Win11/Win10 attr-fallback loop is
  present.
- Verified: `py_compile` OK; all 18 tests pass; project-wide AST 0 failures.
  Invariant: main `downpour` class **741 methods, 0 duplicate method names**.

## v29.25 Titanium — First Unit Tests + FP-Fingerprint Normalization Fix

Session goal: start closing the "no unit tests exist" TODO item with a
pytest suite for the thread-safety/FP-suppression mechanisms — and it
immediately paid off by catching a real bug.

- **`tests/test_thread_safety.py`** (new): 16 tests covering
  - `_fp_fingerprint` normalization (category capture, port/hash/timestamp
    normalization, category distinctness, garbage-safety),
  - `_fp_is_suppressed` hot path (memory-only, never touches DB),
  - `_queue_alert` suppression + rate limiting (max 2/sec),
  - the executor-post-back pattern (background threads marshal UI updates
    through `self.after(0, ...)` and guard `RuntimeError` during shutdown).
- Uses `object.__new__(downpour)` to exercise pure logic without a full Tk
  app (no display needed). Run with
  `Python312\python.exe -m pytest tests -q`.
- **Bug fixed (found by the tests)**: `_fp_fingerprint` did NOT actually
  collapse `'45.88.48.238'` and `'45.88.48.238 :443'` to one key — the port
  survived as a trailing `*N*` token, so a confirmed FP on an IP:port pair
  wouldn't suppress the bare-IP alert. Added an explicit IP[:port] unit
  regex (`\b\d{1,3}(\.\d{1,3}){3}(?:\s*:\s*\d{1,5})?\b` → `*IP*`) that runs
  before the generic port normalization.
- Verified: all 16 tests pass; `py_compile` OK; project-wide AST 0 failures.
  Invariant: main `downpour` class **740 methods, 0 duplicate method names**.

## v29.24 Titanium — GPUDetector Module Shipped (fixes missing import)

Session goal: resolve the long-standing TODO item where
`enhanced_security_dashboard.py` imported `gpu_detector_fix` but the module
never existed — the import was guarded so it silently degraded, disabling GPU
info in the dashboard forever.

- **`gpu_detector_fix.py`** (new module): `GPUDetector.get_gpu_info()` returns
  the exact dict schema the dashboard consumes (`name/usage/memory_used/
  memory_total/memory_percent/temperature/fan_speed/power_draw/clock_speed/
  memory_clock/driver_version/available/gpu_count/multi_gpu`).
- Layered detection, first success wins: NVML (via `nvidia_ml_py`, with
  `pynvml` fallback) → `nvidia-smi` CLI → GPUtil → WMI. Every path wrapped;
  runtime failures degrade to `available: False` and can never raise into the
  importer.
- Self-test CLI included (`python gpu_detector_fix.py`).
- Live-verified on the RTX 3050: `available=True`, `NVIDIA GeForce RTX 3050`,
  33% usage, 557/8192 MB VRAM, 38 degC via NVML; dashboard imports +
  instantiates cleanly. Project-wide AST still 0 failures across all files.

## v29.23 Titanium — Per-Process GPU Attribution in Processes Tab

Session goal: make the GPU actually show up in live process monitoring. The
GPU *monitoring* gauges already worked (NVML), but the Processes tab had no
idea which PIDs were running on the GPU — the `gpu_executor` TODO noted the
RTX 3050 being "idle" with no per-process visibility.

- **`_proc_loop`** now probes `nvidia-smi --query-compute-apps=pid,used_memory`
  on the background scan thread (never the main thread) and caches the result
  in `self._gpu_proc_map`.
- **`_update_proc_ui`** appends a **GPU** column to every process row: shows
  `NNNMB` VRAM when permissions allow, else `[GPU]` — so you can instantly see
  which processes are GPU-accelerated vs CPU-only.
- **`_show_proc_detail`** shows the GPU line (`NNNMB VRAM` / `[GPU active]` /
  `not on GPU`) in the right-hand detail panel.
- Verified live: `nvidia-smi --query-compute-apps` returns 14 GPU processes on
  this RTX 3050 box; the exact parse code (csv, noheader, nounits, fallback
  for `[N/A]` VRAM under non-admin) exercised and works. Column added with
  minwidth + sort via the existing `_sort_proc_tree` column-name API so
  nothing positionally breaks.
- Dependency: uses the NVIDIA driver's bundled `nvidia-smi` CLI — no new
  Python packages.
- Verified: `py_compile` OK; project-wide AST 0 failures. Invariant: main
  `downpour` class **740 methods, 0 duplicate method names**.

## v29.22 Titanium — Real PDF Export for Security Reports

Session goal: fix the fake "PDF export" (a stub messagebox) and the
alert-only NSA assessment (results were pushed to alerts and then discarded)
by shipping genuine reportlab PDF exports.

- **`_export_pdf_report()`** — generic reportlab PDF writer: save dialog on
  the main thread, PDF build on the executor (never blocks the event loop).
  Teal-on-dark styled document with title, subtitle + timestamp, a wrapped
  table (Paragraph cells) with dark header row, PASS/FAIL row shading, and
  an optional notes list. Verified live: builds a valid `%PDF-1.4` file.
- **`_export_compliance_pdf()`** — replaced the stub messagebox with a real
  export: reads the current compliance audit results tree, computes a
  failing/warning summary note, and renders it via `_export_pdf_report`.
  Guarded with a "run Full Audit first" hint when the tree is empty.
- **`_run_nsa_security_report()`** — the NSA-style assessment previously only
  queued alerts and lost the details. Now persists the full result set to
  `~/Documents/DownpourReports/downpour_nsa_report_<ts>.pdf` automatically
  after the assessment completes (graceful error logged via error_logger if
  the build fails).
- **`_save_nsa_report_pdf()`** — executor-side PDF writer for the assessment:
  three-column Status/Check/Detail table with `[OK]`/`[FAIL]` icons, grade +
  pass/critical summary line, teal title block, and a completion messagebox.
- Dependency note: reportlab is installed on Python 3.12 — no new installs.
- Verified: `py_compile` OK; live reportlab build test produced a valid PDF;
  project-wide AST 0 failures. Invariant: main `downpour` class **740 methods,
  0 duplicate method names**.

## v29.21 Titanium — Performance Tab Live Controls + Keyless Infra OSINT

Session goal: turn the Performance tab into a live, interactive monitoring
surface and add keyless infrastructure-recon OSINT lookups that complement the
abuse-scoring services already integrated.

- **Performance tab live controls**:
  - **`_toggle_perf_pause()`** — Pause/Resume button freezes all HW/per-process
    monitoring loops without destroying state (the "live data" gap).
  - **`_on_interval_change()`** — a slider lets the user pick refresh interval
    (2–30 s) instead of being locked to the fixed default; applies live to the
    adaptive intervals.
  - **`_draw_sparkline()`** — real sparklines now drawn on the perf canvases
    (CPU/GPU/mem gauges) instead of empty widgets; adaptive interval changes
    re-render them.
- **New keyless OSINT infrastructure lookups** (no API key required):
  - **`_osint_ipinfo_lookup()`** — IPinfo.io Lite ASN/org/country/city/
    hostname/anycast/bogon attribution (live-verified: `8.8.8.8` →
    `AS15169 Google LLC / US`).
  - **`_osint_bgpview_lookup()`** — BGPView.io BGP routing graph for IPs (RIR
    allocation, announced prefixes, upstream ASNs) or ASNs (name, peers,
    country). Graceful web-page fallback when the API is unreachable (the API
    host's DNS is currently blocked on this network — fallback path exercised).
  - **`_osint_hacktarget_lookup()`** — HackerTarget multi-recon: reverse-IP +
    GeoIP for IPs, DNS records + reverse-IP cohosting for domains, ASN lookup
    for ASNs (live-verified both endpoints return data). Rate-limited 50/day —
    bounded result sets.
  - All three wired into Network tab, Intel tab, and DNS Advanced Tools with
    `_executor` + `after(0)` post-back (never blocks the event loop).
- **Bug fixed**: all HackerTarget URLs used `api.hacktarget.com` (missing the
  `er`) — that host does not exist and DNS-fails; corrected to the
  live-working `api.hackertarget.com` / `hackertarget.com` across all 6
  references. Discovered by live-testing each new endpoint before wiring.
- Verified: each keyless endpoint live-tested on Python 3.12; `py_compile` OK;
  project-wide AST 0 failures. Invariant: main `downpour` class **738 methods,
  0 duplicate method names**.

## v29.20 Titanium — System Tray Icon

Session goal: ship the system-tray minimize/restore feature the config always
promised. The `minimize_to_tray` setting and `_on_close()`'s `withdraw()`
existed, but **no tray icon was ever created** — closing the window just hid
the app with no way to bring it back.

- **`_setup_tray_icon()`** — creates a pystray `Icon` (PIL-drawn 64×64
  shield in the app's teal-on-void palette) with `Show Downpour` /
  `Minimize / Hide` / `Exit Downpour` menu actions. Runs via
  `run_detached()` so the icon owns its own thread and never blocks the Tk
  main loop. Wired into `_auto_start` (8 s) behind `PYSTRAY_AVAILABLE` and
  an already-running guard.
- **`_tray_restore()`** — main-thread deiconify/lift/focus_force with a
  brief `-topmost` flash so the window appears above other apps.
- **`_tray_toggle()`** — hide/show toggle backing the menu item.
- **`_on_close`** — now emits a `[TRAY]` alert telling the user the app
  minimized rather than exiting silently.
- **`_shutdown`** — stops the tray icon before tearing down Tk.
- Verified: the installed pystray API surface (`Icon.run_detached`,
  `Icon.stop`, `MenuItem`, PIL image construction) live-checked on Python
  3.12; `py_compile` OK; project-wide AST 0 failures. Invariant: main
  `downpour` class **733 methods, 0 duplicate method names**.

## v29.19 Titanium — OSINT Multi-Lookup Email Classification Fix

Session goal: fix the OSINT4ALL multi-lookup dispatcher's indicator-type
detection so emails are handled (they were silently producing broken deep
links by being routed through the domain branch).

- **`_osint_multi_lookup`**: added `is_email` detection (checked before
  IP/hash/domain) with a purpose-built email source stack — Have I Been
  Pwned account, Hudson Rock (Cavalier) email, EmailRep.io, DeHashed,
  Hunter.io, plus domain-of-email cross-checks (VirusTotal, crt.sh) and a
  Google search. The unconditional HIBP breach link was folded into the
  domain branch since it is now part of the email stack too.
- Classification verified against 8 representative inputs (IPv4, SHA1,
  SHA256, email, bare domain, full URL, plain text) — all dispatch to the
  correct branch.
- A stray duplicate `elif is_hash` block introduced during the first edit was
  caught by the AST duplicate-method/syntax audit and removed.
- Invariant: main `downpour` class **730 methods, 0 duplicate method names**;
  `py_compile` OK; project-wide AST 0 failures.

## v29.18 Titanium — Slow-Feed Result-Timeout Tuning

Session goal: verify and fix the per-feed result timeout so slow-but-healthy
feeds (MITRE CTI is 48 MB) are never misreported as failed.

- Empirically tested the `fut.result(timeout=30)` under `as_completed` with a
  60 s-slow feed: `as_completed` only yields finished futures, so the 30 s
  timeout was a no-op for in-flight feeds — they completed at 60 s and were
  counted OK. This also means the 30 s value was a **latent bug**: a future
  refactor to a plain `futures` loop would have instantly failed every slow
  feed.
- Raised the budget to **`timeout=150`** with a documented worst-case
  derivation (3 × 15 s download attempts + backoff + 120 s multiprocess parse)
  so it functions as genuine defense-in-depth without becoming a
  slow-feed killer.
- Invariant: main `downpour` class **730 methods, 0 duplicate method names**;
  `py_compile` OK; project-wide AST 0 failures.

## v29.17 Titanium — Feed Fetch Retry with Backoff

Session goal: stop marking feeds as failed on a single transient network
error. The old code retried twice *immediately* with no delay, which meant a
flaky feed (timeout, 5xx, expired cert) got skipped for the whole cycle.

- **`_fetch_feed`**: 3 attempts with backoff `(0s, 2s, 6s)` — attempt 1 is
  immediate (unchanged behavior), then 2s and 6s sleeps so transient
  failures recover. Last-attempt errors still flow into `self._feed_errors`
  → `feed_status` so the Feed Health column (v29.15) reports them.
- Periodic path confirmed: `_intel_auto_loop` (checks every 10 min) re-runs
  `update_all` when the 6h interval is due, so feeds that exhaust all 3
  attempts retry on the next scheduled cycle anyway.
- Invariant: main `downpour` class **730 methods, 0 duplicate method names**;
  `py_compile` OK; project-wide AST 0 failures.

## v29.16 Titanium — DB-Backed False-Positive Auto-Suppression

Session goal: replace the ephemeral "Mark FP" (which only flipped an in-memory
status and re-fired every session) with a persisted, DB-backed suppression
that auto-suppresses repeated nuisance alerts after N confirmed-clean cycles.

- **`fp_suppressions` table** — `fingerprint TEXT PK`, `confirmed`,
  `suppressed`, `first_seen`, `last_seen`, `sample_msg`.
- **`_fp_fingerprint(msg)`** — stable alert key: category bracket + normalized
  body (ports/IPs → `*N*`, hashes → `*H*`, collapsed whitespace). Same
  nuisance alert across sessions collapses to one key.
- **Hot path stays DB-free**: `_fp_load_cache()` populates an in-memory dict
  on the executor at startup; `_queue_alert` only does a dict lookup via
  `_fp_is_suppressed(msg)` before a known-FP alert reaches the UI. No
  main-thread DB work (consistent with the v29.14 freeze rule).
- **Auto-suppress**: `_fp_confirm(msg)` persists each Mark-FP (executor
  write, `first_seen` preserved via COALESCE) and flips `suppressed` once
  `confirmed >= _FP_SUPPRESS_THRESHOLD` (3). Fires a green `[FP] Auto-suppressed`
  alert so the operator sees the drop.
- **`_threats_mark_fp`** now calls `_fp_confirm` — FP status is persisted
  across sessions instead of vanishing at exit.
- **`_threats_fp_manager`** — modal blocklist UI: lists active suppressions
  (fingerprint + confirm count), `Re-arm Selected` (`_fp_unsuppress`),
  `Clear All` (`_fp_clear_all`). New `🤫 FP Blocklist` button in the Threats
  tab toolbar.
- Invariant: main `downpour` class **730 methods, 0 duplicate method names**;
  `py_compile` OK; project-wide AST 0 failures.

## v29.15 Titanium — Feed Health Dashboard (Intel Tab)

Session goal: surface the `feed_status` DB data (written by
`ThreatIntelEngine.update_all`) in the UI — the Intel-tab feed Status column
had stayed on "Pending" forever even though last-update / records-added /
error data was already in the database.

- **`_refresh_feed_health()`** — executor-based reader; calls
  `intel.get_feed_status()` off the main thread (same `db._lock` rule as the
  v29.14 cleanup) and marshals rows back via `after(0)`.
- **`_apply_feed_health(rows)`** — main-thread renderer:
  - `[OK] 12,345 IOCs - MM-DD HH:MM` — keeps the dark-web/clearnet/gov/community
    category tag for row color.
  - `[FAIL] <error>` — red `feed_err` tag over-rides the category color so
    broken feeds stand out.
  - `[STALE] 1,234 IOCs - MM-DD HH:MM` — yellow `feed_stale` tag when the last
    update is older than `_intel_feed_stale_days` (default 3).
  - `[PENDING] not updated yet` — feed exists but `feed_status` has no row.
  - Updates the `_intel_status` label with a live `ok / failed / tracked`
    summary.
- **Wiring**: `_feed_refresh_loop` (periodic, 30s), `_update_intel_now`
  (immediately after a manual feed refresh), and a one-shot first paint in
  `_auto_start` (5s).
- New tag setups `feed_err` / `feed_stale` + `_intel_feed_stale_days = 3`
  registered in `_build_intel_tab`.
- Invariant: main `downpour` class **720 methods, 0 duplicate method names**;
  `py_compile` OK; project-wide AST 0 failures.

## v29.14 Titanium — Main-Thread DB Freeze Cleanup (round 2)

Session goal: eliminate the remaining main-thread DB-blocking call sites so no
`db._lock`-held query can stall the UI, and centralize the IOC-count pattern
into a single shared helper.

### Shared helper: `_refresh_ioc_count_display()`
Runs `db.count_intel()` on `self._executor` and posts the label update back
via `self.after(0, ...)`, with `hasattr(self, '_stat_labels')` +
`'iocs' in self._stat_labels` guards so it is safe to call from both
main-thread loops and background threads. Replaces 5 duplicated inline
closures with one reviewed implementation.

### Off-main-thread audit — fixed call sites
- **`_update_network_ui`** (Network tab, 30 s loop): `count_intel()` was called
  inline on the main thread every refresh — now delegated to the helper.
- **`_auto_start`**: one-shot startup `count_intel()` on main — now schedules
  `_refresh_ioc_count_display()` after 500 ms.
- **`_feed_refresh_loop`**: the per-loop inline executor closure was moved to
  the shared helper (pure dedupe, same behavior).
- **`_update_intel_now`**: `count_intel()` was posted into a main-thread
  `after(0)` lambda — now the helper runs the count off-thread.
- **`_aegis_fetch_extra_feeds`**: same main-thread `after(0)` pattern — routed
  through the helper.
- **`_refresh_aegis_stats`** (AEGIS tab, 15 s loop): the two `aegis_events`
  queries (`SELECT COUNT(*)` and `ORDER BY id DESC LIMIT 10`) ran on the main
  thread. Split into `_aegis_fetch_events` (executor, queries + marshals rows
  back) → `_apply_aegis_events` (main thread, renders count + log + FIX-C2 trim).

### Invariant re-verified
- Main `downpour` class: **718 methods, 0 duplicate method names**.
- `py_compile` OK; project-wide AST walk: **0 failures** (also removed two
  BOM-corrupted leftover `zz_dbaudit.py` / `zz_health.py` audit temp files).

## v29.13 Titanium — Hudson Rock Infostealer Lookup + Status-Pill Freeze Fix

Session goal: add the last OSINT4ALL "Exposure and breach context" source
(Hudson Rock Cavalier, keyless free OSINT endpoints) as an inline lookup, and
fix a main-thread DB-block freeze in the status bar.

### Inline Hudson Rock Cavalier infostealer lookup (keyless)
- **`_osint_hudsonrock_lookup(ioc)`** — Cavalier public API (no API key):
  - **Email** → `search-by-email`: affected-machine count, corporate + user
    credentials exposed, most-recent compromise date, antivirus present on the
    infected machines, and the first 5 matched machines (date + OS).
  - **Domain** → `search-by-domain`: compromised-credential total with the
    employee/user/third-party split, compromised login URLs, last user +
    employee compromise dates.
  - Fires a `[BREACH]` alert into the live stream (RED when exposure is found,
    GREEN when clean) so credential-exposure signals surface in the dashboard.
  - Runs on `self._executor`; failures open cavalier.hudsonrock.com.
- **`_osint_hudsonrock_show(text, ioc)`** — Tk callback (established pattern).
- **UI wiring**:
  - Intel tab Threat Response row: `Hudson Rock` button (email/domain dispatch).
  - DNS Advanced Tools: `[BREACH] Infostealer Check` via `_dns_adv_hudsonrock`
    (domain field, mirrors the urlscan cross-integration).
  - `_osint_multi_lookup` domain deep-link stack: added `Hudson Rock`.
- Verified live: email-with-hits (test@example.com), clean domain (`total=0`),
  real exposure (tesla.com → 29,630 creds / 548 employees / 774 third-parties),
  no-hit email (`stealers=[]`), and domain input-validation (`domain=not a
  domain` → rejected before any network call).

### Freeze fix — status-bar pill DB query moved off main thread
- **Root cause**: `_refresh_status_pills()` ran
  `SELECT COUNT(*) FROM threats WHERE status='active'` on the **main thread**
  every 10s. `db.execute()` acquires `db._lock`, which background threads also
  hold during bulk IOC inserts — so the UI could block for many seconds. This
  is the exact freeze mechanism already fixed for `_feed_refresh_loop`/`count_intel`.
- **Fix**: the count now runs on `self._executor`, posting the result via
  `self.after(0, ...)` to a small main-thread updater `_apply_threat_pill(count)`
  that owns all `_sb_threats` + rain-label writes. Pills refresh on the same
  10s cadence but never block the event loop.

### Housekeeping
- **Committed `ultimate_threat_intel/__init__.py`** (was untracked despite being
  runtime reality): `threat_feed_aggregator.py` imports `ThreatFeedRegistry` /
  `ThreatDatabase` / `get_database()` from it and the main app references it at
  line 17165. The `.pyi` sibling stays gitignored (`*.pyi` rule).

### Verification
- `py_compile` clean; main file 715 methods / **0 duplicate method names**;
  full-project AST audit **0 failures**; all new call sites wired (grep).

## v29.12 Titanium — DNS Tab: Inline urlscan.io Domain Search

Session goal: cross-integrate the keyless urlscan.io public-search capability
into the DNS tab, where domain-context OSINT deep-links already live.

### DNS tab urlscan.io search
- **`_dns_adv_urlscan()`** — DNS Tools button `[WEB] urlscan.io Search` feeds
  the DNS domain field into the existing keyless `_osint_urlscan_search`
  (domain: search expr, renders recent public scans with MALICIOUS/score
  flags, index total, opens the urlscan.io search page).
- Guards empty domain with an inline notice.
- Verified: delegation + empty-guard via mock, live keyless `github.com`
  search end-to-end, `py_compile` + integrity OK.

## v29.11 Titanium — Keyless Inline AlienVault OTX Indicator Lookup

Session goal: add an inline lookup for AlienVault OTX — the highest-profile
OSINT4ALL threat-intel source still stuck as a deep-link — without requiring an
API key (the OTX `general` summary endpoint is public).

### Inline OTX indicator lookup
- **`_osint_otx_lookup(ioc)`** — OTX `indicators/<section>/<ioc>/general`
  endpoint, keyless:
  - IOC-type dispatch: IPv4 / domain / hostname / URL / file (by regex).
  - Summary fields: ASN, country + code, city, numeric reputation (neutral /
    suspicious / positive), OTX pulse count + up to 3 pulse names with tags,
    and a "community-flagged false positive" notice when `validation` lists
    one.
  - Runs on `self._executor`; failures open the matching OTX indicator page
    (IPv4/hostname/domain/file sections resolved per IOC type).
- **`_osint_otx_show(text, ioc)`** — Tk callback (established pattern).
- **UI**: `AlienVault OTX` button added to Intel tab Threat Response row.
- Verified: IP/domain/URL/file dispatches vs mocked responses, live keyless
  8.8.8.8 lookup, failure→web fallback, `py_compile` + integrity OK.
- Fixed mid-session: `urllib.request` has no `.parse` attribute — quote the
  IOC with an explicit `urllib.parse` import.

## v29.10 Titanium — Inline ThreatFox IOC Search

Session goal: complete the abuse.ch trio by adding an inline search for
ThreatFox IOCs (MalwareBazaar + URLhaus added in v29.8/v29.9).

### Inline ThreatFox API search
- **`_osint_threatfox_lookup(ioc)`** — ThreatFox API (POST JSON with the same
  abuse.ch Auth-Key already configured for MalwareBazaar/URLhaus):
  - **Hash** → `search_hash`; **everything else (IP/domain/URL)** →
    `search_ioc` with `exact_match: True`.
  - Renders up to 8 hits: malware family (printable + malpedia ID), threat
    type, confidence level, exact IOC + port (when it differs), truncated
    first-seen and the Malpedia deep-link.
  - `no_result` → clean "no exactly-matching IOC known" dialog.
  - Keyless mode opens `threatfox.abuse.ch/browse.php?search=<ioc>`.
  - Runs on `self._executor`; failure degrades to the browse page.
- **`_osint_threatfox_show(text, ioc)`** — Tk callback (established pattern).
- **UI**: `ThreatFox` button added to Intel tab Threat Response row, closing
  the abuse.ch slice (MalwareBazaar / URLhaus / ThreatFox all inline).
- Verified: search_ioc dispatch (query + exact_match), search_hash dispatch,
  multi-hit rendering, no-result dialog, keyless fallback, `py_compile` +
  integrity OK.

## v29.9 Titanium — Inline URLhaus Lookup (Host/URL/Hash Dispatch)

Session goal: add an inline lookup for URLhaus (the sibling abuse.ch service
to MalwareBazaar) covering domain, URL and hash IOCs in one dispatch method.

### Inline URLhaus API lookup
- **`_osint_urlhaus_lookup(ioc)`** — URLhaus API dispatch on IOC type, reusing
  the abuse.ch Auth-Key already configured for MalwareBazaar
  (auth.abuse.ch issues one key for all abuse.ch services):
  - **MD5/SHA256** → `/v1/payload/`: signature/family, file type + size,
    first-seen, VirusTotal detection ratio, and observed malware URLs.
  - **URL** → `/v1/url/`: online status, host, blacklist state (Surbl +
    Spamhaus DBL with the specific abuse-type label), tags, payload drops.
  - **IP/domain** → `/v1/host/`: URL count, first-seen, blacklist state,
    recent malware URLs with threat labels.
  - Keyless mode opens `urlhaus.abuse.ch` (browse.php for hashes, /host/ for
    hosts/URLs) instead of failing.
  - Runs on `self._executor`; failure degrades to the public page.
- **`_osint_urlhaus_show(text, ioc)`** — Tk callback (established pattern).
- **UI**: `URLhaus` button added to Intel tab Threat Response row next to
  `MalwareBazaar`.
- Verified: hash/URL/host `_do` paths vs mocked responses with the real API
  field names, keyless fallbacks, `py_compile` + integrity OK.

## v29.8 Titanium — Inline MalwareBazaar Hash Lookup

Session goal: give hash IOCs their first inline lookup (previously hashes only
had deep-links to VirusTotal/Hybrid/MalwareBazaar).

### Inline MalwareBazaar get_info lookup
- **`_osint_malwarebazaar_lookup(ioc)`** — abuse.ch MalwareBazaar community API
  (POST form-data `query=get_info&hash=<md5|sha1|sha256>`, free Auth-Key from
  auth.abuse.ch, required since the API moved to header auth):
  - Returns malware signature/family, file name + size, MIME type, first/last
    seen timestamps, tags and per-vendor intel detection counts.
  - Hash format gate (32/40/64 hex) before calling; `hash_not_found` → clean
    "not known to MalwareBazaar" dialog (not an error).
  - Keyless mode opens `bazaar.abuse.ch/sample/<hash>/` instead of failing.
  - Runs on `self._executor`; failure degrades to the public sample page.
- **`_osint_malwarebazaar_show(text, ioc)`** — Tk callback (Censys/Netlas pattern).
- **Settings**: `malwarebazaar_key` masked field added to OSINT API Keys.
- **UI**: `MalwareBazaar` button added to Intel tab Threat Response row.
- Verified: hit path (signature/file/tags/vendor intel), not-found dialog,
  non-hash input gate, keyless fallback, `py_compile` + integrity OK.
- Note: live probe confirmed the endpoint now returns 401 without an Auth-Key
  header (keyless `get_info` is no longer accepted).

## v29.7 Titanium — Inline Netlas.io Host Lookup

Session goal: add the last deep-link-only attack-surface service from the
OSINT4ALL stack — Netlas.io (free tier: 50 API requests/day).

### Inline Netlas host API lookup
- **`_osint_netlas_lookup(ioc)`** — Netlas host API (`app.netlas.io/api/host/<ip|domain>/`,
  Bearer auth) for both IP and domain IOCs:
  - **IP**: ASN + netblock, org, geo, PTR, related domains, open ports,
    software fingerprints (with tag names / fullnames).
  - **Domain**: WHOIS registrant, related domains, NS + MX records, open ports.
  - Keyless mode opens `app.netlas.io/host/<ioc>/` instead of failing.
  - Runs on `self._executor`; failure degrades to the public host page.
- **`_osint_netlas_show(text, ioc)`** — Tk callback matching the Censys pattern.
- **Settings**: `netlas_key` masked field added to OSINT API Keys.
- **UI**: `Netlas` button added to Intel tab Threat Response row (Netlas was
  previously only a domain deep-link in the multi-lookup stack).
- Verified: IP + domain `_do` bodies vs mocked v2 responses, keyless fallback,
  empty-input handling, `py_compile` + integrity OK.

## v29.6 Titanium — Inline Censys Host-View Lookup

Session goal: close the last gap in the OSINT4ALL attack-surface stack — Censys
was only a web-page deep-link despite the `censys_enabled` config flag.

### Inline Censys Search API v2 host view
- **`_osint_censys_lookup(ioc)`** — free Censys Search API v2 (API ID + Secret,
  HTTP basic auth, 250 queries/mo free tier):
  - Returns the host's last-scan timestamp, ASN + BGP prefix, geo, DNS names,
    and up to 8 open services with port/transport/service name plus TLS leaf
    cert subject + issuer.
  - Keyless mode opens `search.censys.io/hosts/<ip>` instead of failing.
  - Runs on `self._executor`; network failure degrades to the public host page.
- **`_osint_censys_show(text, ioc)`** — Tk callback for the result dialog +
  page open (matches the urlscan-search pattern).
- **Settings**: `censys_api_id` + `censys_secret` masked fields added to OSINT
  API Keys (previously only the dead `censys_enabled` boolean existed).
- **UI**: `Censys` button added to Intel tab Threat Response row (Censys already
  present in the multi-lookup deep-link stack).
- Verified: keyed path renders services/ASN/TLS via mocked v2 response;
  keyless path opens the host page; `py_compile` + integrity OK.

## v29.5 Titanium — Keyless urlscan.io Public-Search Lookup

Session goal: add a credential-free urlscan.io indicator triage path to the
OSINT4ALL stack (the keyed submit already covers evidence preservation).

### Inline keyless urlscan.io search
- **`_osint_urlscan_search(ioc)`** — queries the public urlscan.io search index
  (no API key) for the most recent public scans touching the indicator and
  surfaces verdicts + scores in a messagebox, then opens the matching index page:
  - IP → `ip:<addr>`; URL → `page.url:"..."`; otherwise `domain:<host>`.
  - Renders up to 8 recent results with `[MALICIOUS]`/`score=` flags, page
    domain/IP and scan time, plus the index `total`.
  - `is:` operator dropped in favor of `ip:` — urlscan returns 403 on `is:`
    without credentials from this network.
  - Runs on `self._executor`; network failure falls back to opening the public
    search site.
- **`_urlscan_search_show(text, page)`** — small Tk callback that shows the
  result dialog and opens the page (separated so the executor callback stays
  single-purpose).
- **UI**: `urlscan Search` button added to Intel tab Threat Response row next to
  the existing `urlscan Submit`.
- Verified live: `domain:example.com`, `ip:1.1.1.1`, and `page.url:"https://..."`
  variants all return results; expr builder + `py_compile` + integrity OK.

## v29.4 Titanium — MISP Import Firewall-Block Option

Session goal: make MISP-imported indicators immediately actionable.

### Optional inbound firewall blocking of imported IPs
- `_intel_import_misp()` now prompts after a successful import with
  `messagebox.askyesno` — "Block imported IPs via Windows Firewall?".
  - Accepting creates `Downpour_MISP_<ip>` inbound block rules via
    `netsh advfirewall firewall add rule`, capped at `_MISP_BLOCK_IMPORT_CAP`
    (250) per import for safety.
  - Result label reports blocked/failed/skipped tallies; failures degrade to
    an orange status instead of aborting the import.
  - Declining skips firewall work entirely (indicator import still completes).
- Verified: accept path issues exactly one netsh rule per IP, decline path issues
  zero; import tally + block tally both reported; `py_compile` + integrity OK.

## v29.3 Titanium — MISP/STIX Indicator Sharing (import + export)

Session goal: add the OSINT4ALL open-source pick for indicator exchange — MISP
(Malware Information Sharing Platform) — as a first-class Intel tab workflow.

### MISP / STIX indicator import
- **`_intel_import_misp()`** — file dialog (`.json`/`.txt`/`.csv`/`.ioc`) ingests
  indicators into the same `titanium.db` tables the intel tab reads:
  - **MISP event JSON** — walks `Event.Attribute[]`, honoring type hints
    (`ip-src`/`ip-dst`, `domain`/`hostname`, `url`, `sha256`/`sha1`/`md5`,
    `filename|sha256` composite → hash before the `|`).
  - **STIX 2.0 bundles** — `indicator.pattern` (ipv4-addr/domain-name/url
    `value = '...'` and `file:hashes.'SHA-256'`), plus `ipv4-addr`,
    `domain-name`, `url`, `file.hashes` SCO objects.
  - **Plain IOC text** — one per line, hosts-file (`0.0.0.0 dom`) and CSV aware.
  - Stores via the same `INSERT OR IGNORE` batching `_store_iocs()` uses, with
    `MISP-Import:<filename>` source tag; result tallies IPs/Domains/URLs/Hashes.
- **`_misp_extract_iocs(obj, out)`** — recursive parser; descends `Event`,
  `Attribute`, `objects`, `response` containers with dedupe, falls back to a
  generic dict scan only when no known container present.
- **`_misp_classify_value(val)`** — type classifier (ip/domain/url/hash);
  domain regex upgraded to accept **multi-label domains** (subdomains).

### MISP event export
- **`_intel_export_misp()`** — dumps current `malicious_ips/domains/urls/hashes`
  tables as a MISP-format JSON event (`Event.uuid/info/date/Attribute[]` with
  proper `type`, `category`, `to_ids`, source `comment`), ready to share with a
  peer MISP instance or SOC. Hash lengths auto-map to `sha256`/`sha1`/`md5`.

### UI + verification
- Two buttons added to Intel tab Threat Response row: `[MISP] Import IOCs`,
  `[MISP] Export Event`.
- Verified: MISP event + STIX bundle extraction (no duplicates), plain-text +
  hosts-format import, import→DB→export round-trip against a temp DB, `py_compile`
  OK, module import + 11-method integrity OK.

## v29.2 Titanium — Email-Auth DNS Check + DNS Allowlist Bug Fix

Session goal: add a DNS-only SPF/DMARC/DKIM email-authentication check to the
DNS Advanced Tools, and fix a latent shell-allowlist regex bug found while
verifying it.

### DNS Advanced Tools — new `[EMAIL] SPF/DMARC/DKIM` check
- **`_dns_adv_email_security()`** runs three passive `nslookup -type=TXT`
  queries (DNS-only, no API key) and renders plain-language verdicts:
  - **SPF** — `v=spf1` trailing `all` mechanism parsed with a tag regex:
    `-all` hardfail = OK (green), `~all` softfail = WARN (orange),
    `+all` open = HIGH (red), missing `all` = WARN, no record = HIGH.
  - **DMARC** — queries `_dmarc.<domain>` and extracts the **main `p=` policy
    tag only** (regex `(?:^|;)\s*p=([a-z]+)`), so `p=quarantine; sp=reject`
    no longer false-positives as `p=reject`. `p=reject` = OK, `p=quarantine` =
    WARN, `p=none` = HIGH, missing = HIGH.
  - **DKIM** — multi-selector probe (`default`, `google`, `selector1`,
    `selector2`, `s1`, `s2`, `k1`, `dkim`), reports which selector holds the
    `v=DKIM1; k=rsa; p=` key; cross-selector miss degrades to WARN.
  - Detail lines show the raw record; a closing line tallies HIGH-risk gaps.
  - Live-verified: google.com → SPF `~all` WARN / DMARC `p=reject` OK / DKIM
    (google selector) OK; github.com → DMARC `p=quarantine; sp=reject` now
    correctly reported WARN (not reject).
- **`_dns_adv_email_security` wired** into the DNS Advanced Tools column as a
  `_tbtn` between crt.sh and the Domain OSINT Stack.

### Bug fix — DNS command allowlist regex rejected every command
- `_DNS_SAFE_CMD_RE` at the allowlist guard contained a **literal backspace
  byte** (`\x08`) instead of `\b` word boundary after the command alternation,
  so `^(nslookup|ipconfig|netsh|powershell|Get-DnsClient)<BACKSPACE>` matched
  nothing — every `_dns_run_cmd()` call returned `[BLOCKED: command not in DNS
  allowlist]`, silently breaking the whole DNS tab's nslookup / ipconfig /
  netsh / powershell tooling. Replaced with `\b`; all 7 existing call patterns
  (nslookup, -type=dnskey, ipconfig /flushdns, netsh winsock/int ip reset,
  powershell -Command Get-DnsClient*) verified to pass, shell-metachar strip
  still enforced first.

## v29.1 Titanium — OSINT4ALL Indicator-Triage + DDoS v30 Bootstrap

Session goal: leverage the OSINT4ALL curated OSINT resource directory
(threat-intelligence / indicator-triage and breach-exposure toolkits) to expand
Downpour's indicator investigation depth, and finish the v30 DDoS persistence
bootstrap that was only half-wired.

### DDoS v30 — persistence bootstrap completed + critical conflict fixed
- **Fixed duplicate/conflicting blocklist methods.** Two parallel DDoS
  blocklist stores existed: a v29-era flat `{ip: meta}` on-disk format
  (`_ddos_block_metadata`) and the v30 `_ddos_blocked_ips` + `_ddos_blocklist_meta`
  wrapper. Because the v30 `_ddos_load/save_blocklist` were defined later in the
  class body they silently shadowed the v29 ones — so `_ddos_record_block` wrote
  into `_ddos_block_metadata` which was **never persisted**. Consolidated to a
  single v30 store:
  - `_ddos_record_block()` now calls `_ddos_init_state()` and writes into
    `_ddos_blocked_ips` + `_ddos_blocklist_meta`, then persists. Every auto-block
    (legacy packet-capture path OR v30 shield engine) lands in the same file.
  - `_ddos_unblock_ip()` now prunes `_ddos_blocklist_meta` too (was only removing
    the un-persisted v29 dict).
  - `_ddos_load_blocklist()` gained **backward compatibility** with the old flat
    dict format, and now **actually removes expired firewall rules** on load
    instead of just dropping them from memory.
- **v30 DDoS Shield UI was dead code** — the 4 shield/rate-monitor handlers were
  defined but never attached to any button. Wired into the Network tab action bar:
  `DDoS Shield`, `Rate Monitor`, `Block All Flooders`, `Export DDoS Report`,
  `Purge DDoS Blocks` (all via `_make_button` with tooltips).
- **Blocklist now restores on startup.** `_start_loops()` calls `_ddos_init_state()`
  so persisted blocks survive a restart and expired entries self-heal at launch.

### OSINT4ALL integration — indicator triage + breach/exposure stack
- **OSINT Stack deep-link** button (Network tab + right-click menu + Intel tab):
  opens the selected IP/hash/domain across the OSINT4ALL-curated indicator stack —
  VirusTotal, AbuseIPDB, Cisco Talos, GreyNoise, Shodan, Censys, urlscan.io,
  AlienVault OTX, Hybrid Analysis, MalwareBazaar, SecurityTrails, DNSlytics.
  Extended this session with **Pulsedive**, **ONYPHE**, **ANY.RUN**, **Joe Sandbox**,
  **URLhaus** host lookups, and a Have I Been Pwned breach listing.
- **AbuseIPDB inline reputation** — live `api/v2/check` with the user's free API
  key (Settings → OSINT API Keys); falls back to opening the AbuseIPDB page
  when no key is set. Shows confidence score, report count, usage type, ISP.
- **Shodan inline host lookup** — API-key based (`shodan/host/{ip}`): open ports,
  CVEs, OS, hostnames; graceful web-page fallback without a key.
- **Pulsedive inline enrichment** (NEW) — `pulsedive.com/api/info.php` with the
  free API key returns threat label, risk, references and linked properties for
  IP/domain/URL/hash IOCs; keyless mode opens the public indicator page.
- **ONYPHE passive attack-surface** (NEW) — `api.onyphe.io/v2/search` with the
  free API key returns passive dataleak/port/hostname records; keyless fallback
  opens the ONYPHE search page. Wired to Network action bar + right-click menu
  + Intel tab.
- **HIBP Pwned Passwords check** (NEW) — k-anonymity hash-range lookup against
  `api.pwnedpasswords.com` needs **no API key**: only the first 5 hex chars of
  SHA-1(password) leave the machine. Verdict popup + HIGH alarm + alert email
  when a password is found in public breach corpora. Live-verified against the
  real HIBP API this session (`password` → 52,372,427 hits). Added as a
  `🔑 Password Breach Check` button beside Dark Web Leak Check.
- **GeoIP enrichment** — ip-api now reports `proxy` / `hosting` flags (VPN/datacenter
  signals) alongside country/ISP/AS.
- **Settings** gained an OSINT API Keys section (AbuseIPDB + Shodan + Pulsedive
  + ONYPHE), stored in the `[osint]` config section.

### DNS tab — OSINT4ALL infrastructure stack (Session 2)
- **crt.sh certificate-transparency subdomain discovery** (NEW) — passive CT-log
  lookup pulls historical hostnames/SAN entries for a domain with zero network
  touch on the target. Free, no API key. Includes 3-attempt retry for crt.sh's
  flaky backend + **Certspotter free CT API fallback** (live-verified this session:
  3 hostnames for example.com). On total failure, opens the crt.sh web page.
- **Domain OSINT Stack deep-link** (NEW) — one button opens the domain across the
  full OSINT4ALL infrastructure stack: crt.sh, Wayback Machine, Archive.today,
  ViewDNS.info, DNSDumpster, MXToolbox, SecurityTrails, DNSlytics, urlscan.io,
  Wappalyzer, BuiltWith, Netlas.io, ZoomEye, FullHunt.
- `_osint_multi_lookup` domain branch extended with crt.sh, ViewDNS, MXToolbox,
  Wappalyzer, Netlas.io deep-links alongside the existing reputation sources.

### Intel tab — EmailRep + CyberChef (Session 3)
- **EmailRep.io email reputation** (NEW) — inline risk signal for an email address
  (reputation, suspicious flag, deliverability, breach associations) via the free
  EmailRep.io API key (Settings → OSINT API Keys). Keyless/rate-limited calls fall
  back to opening the EmailRep.io page. Validates the input is a real email first.
- **GCHQ CyberChef decode** (NEW) — one button opens CyberChef with the current
  Intel check-box value pre-loaded (base64url input) for safe offline decoding of
  indicators, encodings, and extracted strings.
- Settings → OSINT API Keys now has 5 fields (AbuseIPDB, Shodan, Pulsedive,
  ONYPHE, EmailRep).

### Intel/Network tabs — GreyNoise + Wayback + urlscan submit (Session 4)
- **Wayback Machine availability check** (NEW, no key) — `archive.org/wayback/available`
  finds the most recent archived snapshot of a URL/domain (proof of historical page
  state) and flags **no-history pages** as a common one-shot phishing indicator.
  Live-verified against the real API this session.
- **GreyNoise Community triage** (NEW) — free API key (Settings → OSINT API Keys)
  separates routine internet background noise (scanners, bots) and RIOT benign
  infrastructure from hosts that actually warrant attention. Keyless mode opens
  the GreyNoise viz page. Wired into the Network action bar + right-click menu.
- **urlscan.io scan submit** (NEW) — free API key submits a URL for a public
  render + network-trace scan (evidence preservation), then opens the result
  page. Keyless mode opens the urlscan search. Wired into the Intel tab.
- Settings → OSINT API Keys now has 7 fields (AbuseIPDB, Shodan, Pulsedive,
  ONYPHE, EmailRep, GreyNoise, urlscan.io).

### Verification
- `py_compile` clean; module imports cleanly under Python 3.12.
- Blocklist round-trip, restart-restore, and legacy-format import all tested
  against the real `downpour` class methods (all pass).

---

## v29 Titanium — Session 2 (Threat Hunt Engine + Live Feed Fixes)

### New Module: `threat_hunt_engine.py`
Built on techniques from the Anthropic Cybersecurity Skills library, wired live into the Dashboard via two new buttons:

| Button | What it does |
|---|---|
| 🍯 **Deploy Canaries** | Drops hidden honeytoken files in Desktop/Documents/Downloads/Pictures. Any deletion or modification triggers an instant CRITICAL alert — the fastest available ransomware tripwire (T1486), no ML/entropy baseline needed. |
| 🔎 **Run Threat Hunt** | On-demand scan across 4 techniques: LOLBAS abuse, registry Run-key persistence, canary integrity, and BYOVD (vulnerable driver) detection. |

Also wired **automatically** (no button needed) into the live process monitor loop:
- Every process scan cycle now checks running processes against a 15-binary LOLBAS watch-list (certutil, mshta, regsvr32, wmic, etc.), each mapped to its MITRE technique ID. Deduplicated per PID+name so it doesn't spam the same alert every cycle; capped at 2,000 tracked entries to prevent unbounded memory growth.

### Detection Capabilities Added
- **LOLBAS abuse detection** (T1218 family) — 15 living-off-the-land binaries with malicious-flag pattern matching
- **Registry persistence hunting** (T1547.001) — flags autorun entries pointing to non-standard locations
- **Scheduled task / WMI subscription / startup folder persistence hunters** (T1053.005, T1546.003, T1547.001)
- **BYOVD detection** (T1068/T1562.001) — 13 known-vulnerable-but-legitimately-signed drivers (RTCore64, dbutil_2_3, Zemana, TrueSight, WinRing0x64, etc.) that ransomware crews use to blind EDR/AV at the kernel level before encrypting — verified against **458 live drivers on the actual dev machine via WMI, 0 false positives**
- **Sigma rule export** — any finding can be exported as a portable `.yml` Sigma detection rule for external SIEMs (Splunk/Elastic/Sentinel)

### Threat Intelligence — Researched July 2026, Added to `mega_threat_signatures.py`
New ransomware families based on live web research into the current threat landscape:
- **Qilin** — most active RaaS 2025-26, buys stolen VPN creds from initial-access brokers
- **RansomHub**, **DragonForce**, **LockBit5** (resurfaced Sept 2025, targets critical infrastructure)
- **The Gentlemen** — most active group Q2 2026 (300 victims), packaged intrusion kit
- **Deadlock** — blockchain-hosted C2 (no blockable domains/IPs), BYOVD EDR-killer, directly motivated the new BYOVD detector above
- **NightSpire**, **Scattered LAPSUS$ Hunters** cartel (LockBit+Qilin+DragonForce alliance)

### Critical Bugs Found & Fixed (via direct testing against real system/network — not assumed)

| # | Bug | How it was found | Fix |
|---|-----|---|-----|
| 1 | `_run_threat_hunt` naming collision | AST duplicate-method scan after adding new method | Renamed new method to `_run_proactive_hunt`; original Threat Hunter tab search feature preserved (642 methods, 0 duplicates confirmed) |
| 2 | `detect_zero_day_threats()` / `_analyze_process_anomalies()` was **dead code** — zero callers anywhere | Traced the call chain before wiring LOLBAS into it | Abandoned that path; wired LOLBAS into the actually-live `_proc_loop()`/`do_scan()` instead |
| 3 | Registry persistence hunter had a **100% false-negative rate** on real autorun entries | Tested against actual live HKCU/HKLM Run keys on dev machine — found 0/4 correctly classified before the fix | Registry values are quoted (`"C:\...\app.exe" /ARGS`); `.startswith()` checks were silently defeated by the leading `"`. Strip quotes before matching. Also expanded suspicious-path list to include `\appdata\roaming\` |
| 4 | Ransomware canary integrity check flagged **100% of files as tampered**, even untouched ones | Ran a 6-case smoke test before shipping | Windows text-mode file writes silently convert `\n`→`\r\n`, breaking the hash comparison. Fixed by writing/hashing raw bytes instead |
| 5 | `fetch_cisa_kev_catalog()` used a **404ing URL** (`.../catalog.csv` instead of the real JSON feed) | Live test returned only 1 stale cached entry instead of the real ~1,650-entry catalog | Corrected to `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| 6 | Same function then **hung indefinitely** even with the correct URL | Isolated via raw `requests` test vs native PowerShell `Invoke-WebRequest` — confirmed CISA's WAF silently blocks (not 403s — just never responds to) the default `python-requests` User-Agent | Added a browser-like `User-Agent` header |
| 7 | **Root cause of the "hang"**: the function made **one synchronous NVD API call per KEV entry** (1,650+), with no rate-limit handling — NVD allows ~5 req/30s unauthenticated, so this would have taken hours and likely gotten the caller's IP blocked | Read the full function body after fix #6 still hung | Capped CVSS enrichment to a 15-call / 12-second budget; remaining entries keep default severity (still fully usable for KEV listing and patch-priority purposes) |

**Final verification:** `fetch_cisa_kev_catalog()` now completes in **1.36 seconds**, returns all **1,651 real KEV entries**, and correctly surfaces `CVE-2026-56155` and `CVE-2026-56164` (both confirmed present in the live CISA feed via direct research this session).

### Full-Project Audit
- 58 Python files scanned (AST parse), **0 syntax errors, 0 failures**
- Main file: 642 methods in the `downpour` class, **0 duplicate method names**
- 3 `shell=True` command-injection surfaces found and eliminated (converted to `shlex.split()` + `shell=False`)

---

## v29 Titanium — Session 1

### Critical Bug Fixes (from live crash logs)

| Bug | Source | Fix |
|-----|--------|-----|
| `AttributeError: '_tkinter.tkapp' has no attribute '_alert_queue'` | `tk_callback_errors.txt` line 33087 | Added `hasattr(self, '_alert_queue')` guard in `_add_alert` — called via `after()` before `_init_state` completes |
| `AttributeError: '_tkinter.tkapp' has no attribute '_alerted_dedup'` | `tk_callback_errors.txt` line 33165 | Added `hasattr(self, '_alerted_dedup')` guard in `_queue_alert` |
| `AttributeError: '_tkinter.tkapp' has no attribute '_usb_monitor_active'` | `tk_callback_errors.txt` | `while self._usb_monitor_active` → `while getattr(self, '_usb_monitor_active', False)` |
| `TclError: Item X already exists` (Firewall tab) | `tk_callback_errors.txt` | `_fw_apply_filter` now clears treeview before re-populating |
| `ImportError: cannot import name 'DiskAnalyzer'` | `tk_callback_errors.txt` | `downpour_cleanup_module.py` now includes `DiskAnalyzer` class |
| `AttributeError: RemediationAction has no attribute 'action'` | `tk_callback_errors.txt` | `a.action` → `a.action_type` + `a.description` |
| `0x800401f0 CO_E_NOTINITIALIZED` (×100+ per session) | `crash_fault.log` | All 3 `ThreadPoolExecutor` pools now use `initializer=_com_thread_init` which calls `CoInitializeEx(0)` on every worker thread |
| sklearn `parallel.delayed` warnings flooding `dp_stderr.txt` | `dp_stderr.txt` | Global `warnings.filterwarnings()` block added at module top |
| Stray `)` in `LAUNCH_V29_TITANIUM.bat` pynvml block | Launcher | Removed — was causing batch parse error |
| GitHub push blocked (`GH013: secret detected`) | `push_log.txt` | `DO_PUSH_NOW.bat` and `DO_PUSH_NOW.vbs` now prompt for token instead of hardcoding it |

### New Features

#### UI Power Buttons
- **Dashboard**: `REMEDIATE ALL`, `Kill Suspicious`, `IR Report`, `Isolate Host`, `Fix ALL Hardening`
- **Threats tab**: `Remediate All`, `Quarantine Selected`, `Auto-Remediate toggle`, Threat Detail Panel, MITRE column, Risk Score header, HTML report, Intel Lookup
- **Network tab**: `Block ALL C2`, `Kill C2 Procs`, `Whitelist IP`, `Export CSV`
- **Processes tab**: `Kill ALL Suspicious`, `Quarantine ALL`, `Export CSV`, `Scan EXE`
- **Emergency tab**: `Quarantine ALL`, `Wipe Temp/Cache`, `Full IR Report`

#### Detection Improvements
- YARA rules: 25 → 45 (LockBit, BlackCat, Clop, RedLine, Raccoon, Metasploit, Empire, AsyncRAT, NjRAT, QuasarRAT, DCSync, Kerberoasting, BloodHound, PlugX, Gh0stRAT, XMRig, GuLoader, Themida)
- Behavioral cmdline heuristics: 8 → 40+ patterns
- MITRE ATT&CK: 45 → 85+ techniques with multi-keyword confidence scoring
- FIM: 6 → 35 critical system files with on-disk baseline drift detection (`fim_baseline.json`)
- Threat Detail Panel: split-pane showing full description, MITRE tag, status, quick-action buttons

#### Hardening
- All `shell=True` subprocess calls eliminated — converted to `shlex.split()` list form
- All 190 subprocess calls have explicit `timeout=` values
- Monitor watchdog (`_monitor_watchdog`) restarts stalled background loops every 30s
- All 8 monitor threads respect `_stop_event` for clean shutdown
- Result queue capped at 256 entries (was unbounded memory leak)
- Performance monitor: rolling cap of 100 entries per metric type

### Launcher (LAUNCH_V29_TITANIUM.bat)

**New vs v28 (LAUNCH_DOWNPOUR.bat):**
- `AttackSurfaceReductionOnlyExclusions` added — ASR is a separate subsystem from `ExclusionPath` (v28 bug: only set `ExclusionPath`, ASR rules still fired)
- ASR rule `3b576869` disabled during pip installs, restored to AuditMode after
- `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` prevents ASR trigger on Chromium download
- `--only-binary :all:` pip installs first to avoid meson/ninja ASR trigger
- Log rotation: keeps last 3 of `crash_fault.log`, `dp_stderr.txt`, `tk_callback_errors.txt`
- Free RAM check with warning if below 2 GB
- Python 3.10–3.13 discovery
- Expanded C2 block list: Kimwolf, BadBox2, Mozi, AISURU, CobaltStrike
- `downpour_v29_titanium.py` targeted explicitly (not v28)
- Stray `)` syntax bug fixed

---

## v28 Titanium

See `docs/CHANGELOG_v28.md`

### New Features

#### UI Power Buttons
- **Dashboard**: `REMEDIATE ALL`, `Kill Suspicious`, `IR Report`, `Isolate Host`, `Fix ALL Hardening`
- **Threats tab**: `Remediate All`, `Quarantine Selected`, `Auto-Remediate toggle`, Threat Detail Panel, MITRE column, Risk Score header, HTML report, Intel Lookup
- **Network tab**: `Block ALL C2`, `Kill C2 Procs`, `Whitelist IP`, `Export CSV`
- **Processes tab**: `Kill ALL Suspicious`, `Quarantine ALL`, `Export CSV`, `Scan EXE`
- **Emergency tab**: `Quarantine ALL`, `Wipe Temp/Cache`, `Full IR Report`

#### Detection Improvements
- YARA rules: 25 → 45 (LockBit, BlackCat, Clop, RedLine, Raccoon, Metasploit, Empire, AsyncRAT, NjRAT, QuasarRAT, DCSync, Kerberoasting, BloodHound, PlugX, Gh0stRAT, XMRig, GuLoader, Themida)
- Behavioral cmdline heuristics: 8 → 40+ patterns
- MITRE ATT&CK: 45 → 85+ techniques with multi-keyword confidence scoring
- FIM: 6 → 35 critical system files with on-disk baseline drift detection (`fim_baseline.json`)
- Threat Detail Panel: split-pane showing full description, MITRE tag, status, quick-action buttons

#### Hardening
- All `shell=True` subprocess calls eliminated — converted to `shlex.split()` list form
- All 190 subprocess calls have explicit `timeout=` values
- Monitor watchdog (`_monitor_watchdog`) restarts stalled background loops every 30s
- All 8 monitor threads respect `_stop_event` for clean shutdown
- Result queue capped at 256 entries (was unbounded memory leak)
- Performance monitor: rolling cap of 100 entries per metric type

### Launcher (LAUNCH_V29_TITANIUM.bat)

**New vs v28 (LAUNCH_DOWNPOUR.bat):**
- `AttackSurfaceReductionOnlyExclusions` added — ASR is a separate subsystem from `ExclusionPath` (v28 bug: only set `ExclusionPath`, ASR rules still fired)
- ASR rule `3b576869` disabled during pip installs, restored to AuditMode after
- `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` prevents ASR trigger on Chromium download
- `--only-binary :all:` pip installs first to avoid meson/ninja ASR trigger
- Log rotation: keeps last 3 of `crash_fault.log`, `dp_stderr.txt`, `tk_callback_errors.txt`
- Free RAM check with warning if below 2 GB
- Python 3.10–3.13 discovery
- Expanded C2 block list: Kimwolf, BadBox2, Mozi, AISURU, CobaltStrike
- `downpour_v29_titanium.py` targeted explicitly (not v28)
- Stray `)` syntax bug fixed

---

## v28 Titanium

See `docs/CHANGELOG_v28.md`
