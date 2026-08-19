# Downpour v29 Titanium — Enhancement Worklog

## Branch: main

## Session 2026-08-19e — v29.41k5e: DNS live-monitor dedup (kill duplicate rows + alarm spam)
- ✅ `_dns_monitor_loop` polls the Windows DNS client cache — a full snapshot —
  every 3s. It re-inserted ALL cached entries each cycle: identical rows
  accumulated forever, the `Queries` counter ratcheted endlessly, and the same
  threatening domain re-fired `[R] BLOCKLIST HIT` / DGA alerts on EVERY poll.
- ✅ FIX (FIX-v29.41k5e): introduced a seen-set of `(domain,data,rtype)` keys
  (`self._dns_mon_seen`, lazily init on the monitor thread). Only genuinely
  new cache entries insert rows, bump `q_count`/`t_count`, or alert. Count
  label changed from `Cache entries:` (was factually wrong — it counted
  processed snapshot rows, not cached entries) to `Queries:`. `_dns_clear_
  monitor` resets the seen-set so an explicit Clear re-captures the current
  state instead of staying dark.
- ✅ Regression test (source-level assertions for dedup guard + reset). 90/90
  tests. Smoke PID 13756 stable through the edit.

## Session 2026-08-19d — v29.41k5d: VPN Mirror-2 fetch HTTPS-first + full egress HTTPS audit
- ✅ Completed an audit of every `urllib.request.urlopen` call site (38
  found). All but one were already HTTPS or user-configurable (DoH template,
  OSINT download URLs). The one remaining plain-HTTP-only egress was the VPN
  tab's Mirror-2 server-list source (`http://lab.mahidol.ac.th/vpngate/api/
  iphone/`).
- ✅ FIX (FIX-v29.41k5d): `_vpn_load_servers` now builds an HTTPS-first
  candidate list per source — `https://` promoted from `http://`, original
  `http://` retained as terminal fallback. `raw` initialised to `''` so a
  dead source degrades to a logged/skipped source instead of an unbound
  NameError; both parsers (vpngate_csv, protonvpn_json, generic_json) handle
  empty input gracefully within their existing try/except.
- ✅ Regression test asserting the https-first promotion block. 89/89 tests.
- ✅ Smoke PID 13756 stable through all edits (threads 23, RSS ~161MB).

## Session 2026-08-19c — v29.41k5c: intel feed fetches HTTPS-first with HTTP fallback
- ✅ Audit of network egress found the same ip-api-style HTTPS gap in
  `_fetch_feed`: a `_HTTP_OK` host set (`sysctl.org`, `data.phishtank.com`,
  `pgl.yoyo.org`, `someonewhocares.org`) was hard-locked to plain `http://`
  forever, and any feed whose HTTPS attempt failed was skipped entirely for
  the whole cycle (no fallback).
- ✅ FIX (FIX-v29.41k5c): every feed now builds an HTTPS-first candidate list
  (`https://` promoted from `http://`) with the original `http://` kept as the
  final fallback. The permissive SSL context (for expired/self-signed cert
  hosts) still completes a TLS handshake, so exempt hosts now go HTTPS too.
  `_HTTP_OK` deleted; backoff (0/2/6s) retained per candidate.
- ✅ Regression test: `_fetch_feed` invoked with an `http://` feed URL must
  open `https://` first and succeed in a single call (fake urlopen context
  manager needed `__enter__`/`__exit__` for the `with` block). 88/88 tests.
- ✅ Smoke PID 13756 still stable (threads 23, RSS ~161MB) while models train
  in the background; no joblib/scan-worker wedges.

## Session 2026-08-19b — v29.41k5b: Network tab Country column made live + all 5 geo call sites unified on HTTPS-first helper
- ✅ Audit found the Network tab's Country column was hard-coded `''` forever
  (every row showed a blank country; no lookup ever ran). Real live-data gap.
- ✅ FIX (FIX-v29.41k5b):
  - Added `_geo_cache` dict + `_async_geo(ip)` (async ip-api.com countryCode
    lookup on the executor). Country cells now resolve live for public IPs;
    private IPs (192.168.*, 10.*, 172.*, 127.*, 169.254.*, fe80::, ::1) stay
    blank to keep the free ip-api rate limit clean; failures/misses degrade to
    `--` and never block or raise.
  - Added shared `_ip_api_get(self, ip, fields, timeout)` helper: HTTPS-first
    for privacy, plain-HTTP fallback (the free JSON endpoint is HTTP-only),
    uniform `downpour/29` UA, returns `{}` on total failure.
  - Routed ALL FIVE geo call sites through `_ip_api_get`: live Country column
    (`_async_geo`), Intel-tab GeoIP (`_intel_geoip`), alert-action GeoIP
    (`_alert_action_geoip`), Net-tab Geo-Locate (`_geolocate_ip`),
    alert-feed `_geolocate_one`. Four of them were previously plain-HTTP only
    (which the free tier silently rejects) — they now get the HTTPS-first +
    fallback too. `grep http://ip-api` = 0 matches now.
- ✅ Verified: `py_compile` OK; **87/87 tests** (added geo regression tests:
  `_async_geo` failure marks `--`; `_ip_api_get` is HTTPS-first with `{}`
  on total failure). Smoke PID threads stable 67–80; 17 transient FREEZE
  warnings over 40 min (all DB-write contention, ≤2s), ZERO scan-worker /
  joblib events.

## Session 2026-08-19a — v29.41k5: scan-worker/joblib thread explosion + Perf-tab live-data restore
- ✅ Root cause of the smoke-test thread/memory runaway: **ThreadPoolExecutor
  ("scan-worker") + sklearn 1.9.0 + joblib 1.5.3 nested-parallelism deadlock**.
  Every 60s `_proc_loop` → `scan_all()` → each worker's
  `predict_proba()`/`decision_function()` deadlocked in joblib's `_retrieve`
  (nested joblib dispatch from inside a pool worker). The `with`-block
  `shutdown(wait=True)` never returned and `_proc_loop` rescheduled
  unconditionally → pools piled up: threads 176 → 229 → 296 → **341** in
  ~50 min, 64+ workers permanently wedged in
  `joblib.parallel._retrieve` → `analyze_process_sklearn`, RSS crawled
  2.4→2.56GB. Prior session (PID 1668) was unaffected only because models
  weren't trained yet (`_models_trained` False → early return).
- ✅ Fixes in `downpour_v29_titanium.py`:
  - Post-fit `self._iso_forest.n_jobs = 1` + `self._rf_classifier.n_jobs = 1`
    (FIX-v29.41k5) — single-sample inference gains nothing from n_jobs>1, and
    the nested joblib dispatch can no longer fire.
  - `scan_all()` split into `_scan_all_locked()` with a `_scan_in_progress`
    overlap guard (returns `[]` while a scan is draining) and explicit
    `pool.shutdown(wait=False, cancel_futures=True)`; `as_completed(futures,
    timeout=90)` abandons wedged workers so `_proc_loop` can never stack pools.
- ✅ Perf-tab live-data restore (FIX-v29.41k5): the ~8.5s `open_files` walk ran
  on EVERY fetch tick (verified: `open_files 500 pids` = 8.5s; full `_fetch` =
  ~14s) — so the whole Perf tab effectively refreshed ~1×/14s despite the 1-3s
  loop. Now sampled every 15s (bounded at 300 pids, cached in between).
  top-procs rows gained live `rss_mb`, `disk_rd_kbs`, `disk_wr_kbs` and `conns`
  (one shared `net_connections` walk filtered to the top-20 candidate PIDs —
  enrichment is O(top-N), not O(all procs)). Treeview columns:
  pid/name/cpu%/mem%/rssMB/rd/wr/conns/gpu/status.
- ✅ winfo_exists Tcl-safety (uncommitted from prior session, folded in):
  `_tk_alive` flag + `_winfo_ok()` helper replacing all 16 worker-thread
  `winfo_exists()` calls; `_shutdown()` clears the flag first.
- ✅ Verified: smoke PID threads stable at 67–80 (was climbing 176→341); ALIVE
  cadence clean; fetch cadence restored (non-open_files ticks ~3s).
  `py_compile` OK; **84/84 tests** (added TestV2941K5ScanWorkerFix +
  TestV2941K5PerfTabLive regression guards).

## Session 2026-08-18a — v29.41k4: parse-pool child isolation kills the phantom main-process memory leak
- ✅ Root cause: the main-process "leak" (97–116 MB/min reports, RSS ratcheting
  to 1.27GB mid-wave) was **not** an accumulator in the app — it was
  **ProcessPoolExecutor children monitoring themselves**. Under Windows `spawn`,
  every parse worker re-imports `downpour_v29_titanium.py`, which imports the
  `enhanced_memory_manager` singleton (L169) and starts **tracemalloc + a
  monitor thread in each child**, logging the worker's own memory view into the
  shared `downpour.log` (166MB at `text.splitlines()`, 183MB at
  `connection.py:251`, 42–71MB decode/gzip buffers). tracemalloc-tracing every
  parse allocation slowed the children, so the parent pool queue backed up with
  large pickled payloads → parent RSS ratcheted and reports looked like a real
  leak.
- ✅ Fix (in `enhanced_memory_manager.py`):
  - `_is_spawn_child()` detects non-main processes (`current_process().name`
    not MainProcess/SpawnMainProcess); children neutralize the singleton
    (`enabled=False`) + `tracemalloc.stop()`. Workers are `SpawnProcess-1/2`.
  - Leak growth now computed from **this process's own RSS**
    (`psutil.Process(os.getpid()).memory_info().rss`, new `rss_bytes` field)
    instead of system-wide `used_bytes` (which counted other apps and caused
    false 87–110 MB/min alarms).
  - Leak report surfaces `top allocations:` (first 6 tracemalloc sites) and
    `top types:` (top 10 gc type counts); gc counts captured BEFORE the
    tracemalloc snapshot so the report's own Traceback/Statistic objects don't
    pollute the histogram.
  - Fixed `NameError: interval` in the monitor loop — it silently slept 60s
    per iteration; now 15s (HIGH pressure) / 30s. Leak detection every 10
    snapshots.
- ✅ Verified with 8 memprobes + 15 leak-test sessions: main PID 1668 RSS flat
  at **660–665MB across a full 10-min staggered wave cycle** (probe 8,
  00:41–00:51), waves spike ~1.27GB then release to baseline; only ONE clean
  report in the 08-18 session (00:36, 5.13 MB/min — post-wave transient), zero
  since. Pre-fix reports (16–116 MB/min) discarded as child-contaminated.
- ✅ 75/75 tests; `py_compile` OK.

## Session 2026-08-17a — v29.41k3: boot-storm freezes eliminated via intel dedupe + bounded workers
- ✅ Root cause: the 9.3–53.8s boot freezes (main thread parked in trivial
  `tk.call('configure'...)` / `after` for seconds) were a **boot-window CPU/IO
  storm**, not intel logic alone: freezes began before the intel DB init, and
  the first boot had 0 `feed_status` writes yet still froze. Two concurrent
  updaters both re-downloaded the same OSINT feeds (URLhaus/Feodo/SSLBL/
  ThreatFox/Bazaar/Spamhaus ...): the legacy `_scheduled_feed_update`
  (`ThreatIntelligenceManager.update_all_feeds`) and the new `_intel_auto_loop`
  (`ThreatIntelEngine.update_staggered`).
- ✅ Fixes (all in `downpour_v29_titanium.py`):
  - Intel auto-update flipped to default ON (`'auto_update': 'true'`,
    6h interval) so the staggered engine owns feed refreshes.
  - `_scheduled_feed_update` **stands down** when auto-update is enabled
    (re-arms hourly; only falls back to legacy `update_all_feeds` when
    auto-update is off).
  - `update_staggered` parses on ONE shared `ProcessPoolExecutor(max_workers=2)`
    (`_get_shared_parse_pool` ~L11873, created lazily, reused across all waves)
    with 120s future timeouts + in-process fallback — no per-call
    `ProcessPoolExecutor(max(4, cpu-2))` fork storm.
  - `AIEnhancedThreatDetector._train_models_background` defers the first fit
    ~60s (daemon-thread sleep) and caps `n_jobs` to 2 — IsolationForest/RF
    full `n_jobs=-1` was flooding every core during boot.
- ✅ Diagnostics that got us there: `_freeze_sampler` snapshots other-thread
  top frames too (`_freeze_diag_othr`); `_freeze_check` prints
  `<other threads during block:>`. Sampled other-threads during blocks were
  sklearn fits, `pathlib.stat`/`read_text`, subprocess readers, watchdog
  observers, feed DB writes — all concurrent at boot.
- ✅ Verified: fresh boot smoke test (`2026-08-17 20:45` session) ran the full
  build, auto-start, staggered feed waves (feed_status rows written live at
  20:48–20:49, e.g. easylist 5,845 / firehol_l2 16,490 / fanboy_annoyance
  25,725 IOCs) with **zero FREEZE events** and responsive mainloop
  (`[ALIVE]` every 10s, `pending_after` draining to 0). 75/75 tests.

## Session 2026-08-16a1 — v29.41k: main-thread freeze elimination (rain + net UI)
- ✅ Root-caused recurring 1.5–28.5s GUI freezes with a background
  `freeze-sampler` daemon thread (120ms samples of the main-thread stack via
  `sys._current_frames()`, 3s dominant-location vote) + per-section `_fmark`
  timing inside the animation loop. Two real culprits dominated:
  1. **Rain canvas** `ImmersiveRainCanvas._animate`: frames cost 1–4.4s in the
     loaded app vs 2.8ms standalone (each Tk `coords()` ≈ 4–90ms under
     software-render/load). The old 10fps `after(100)` loop stole whole
     seconds whenever anything else ran concurrently.
  2. **`_update_network_ui`** ran on the main thread every 5s and rebuilt
     hundreds of Treeview rows via `_net_tree.item()` roundtrips sampled as
     6–21.5s freezes — even while the rain was hard-frozen.
- ✅ Rain fixes (all in `downpour_v29_titanium.py`):
  - Fg/stipple/outline/fill itemconfig caching (skip redundant Tk reconfigs).
  - Splash/streak pool resets limited to previously-used slots
    (`_splash_last_used`, `_streak_last_used`) — killed the 50/70 pointless
    off-screen reset coords per frame.
  - Adaptive degradation: `_load_ema` (0.7/0.3) of frame cost drives
    `_anim_allowed` backoff 100→1200ms; when >150ms the cosmetic layers
    (splashes/fog/puddles/mist/lightning/**stars**) are skipped.
  - Rotating drop stride `_update_drops(dt_scale, stride, degraded)` — only
    1/N drops touched per frame, slice rotates so every drop still animates;
    stride also scales linearly with EMA (`1 + ema/150`, capped 40) so a
    pathological 3.6s frame degrades to ~3 coords().
  - Hard freeze hysteresis: frame >700ms or EMA>600 → `_anim_frozen` (static
    sky ~25s, ticks at 500ms); resume seeds `_anim_allowed=1200` and
    **EMA=6000** with a 12-frame `_anim_probe_ticks` window (max stride,
    freeze suppressed) so recovery ramps up gracefully instead of re-freezing
    the instant full speed returns.
  - Degrade path purges `_splashes/`_streaks` residue each frame (spawned in
    `_update_drops` but never aged out when `_update_splashes` is skipped) —
    had grown to `splashes=156 streaks=253` → 844ms wipe-out frame on resume.
- ✅ Net UI fix: `_update_network_ui` now hard-skips when the Network tab is
  off-screen (`winfo_viewable()==0`) and diffs a **rotating 60-row slice**
  per pass instead of the whole tree — a 300-row refresh is spread over ~5
  passes so it can never stall one frame.
- ✅ Result (fresh run ~13 min, launched 04:47): **zero FREEZE logs** in the
  first 8 min, then only 3 minor 1.5–1.8s hiccups from a `_drain_alert_queue`
  reschedule + one mist frame mid-probe vs. previous runs' 2–26.7s freezes
  every few seconds. Steady state is now nominal.
- ✅ `pytest.ini` added (testpaths=tests; norecursedirs=_ARCHIVE
  /_legacy_launchers/downpour_tmp/.venv) — bare `pytest` used to recurse into
  legacy `_ARCHIVE` GUI/feed tests and die; now 75/75 clean.
- ✅ 75/75 tests; boot smoke clean.

## Session 2026-08-16a2 — v29.41k2: kill residual 1.5–21.4s freezes (idle backoff + coords-cost degradation)
- ✅ Tally of the 3 residual 1.5–3s freezes from session a1 (`_day_tally2.txt`,
  1210 freezes/7h) showed the freeze-checker now catches mostly **periodic
  drain-loop backlog**: three separate sub-200ms main-thread loops
  (`_early_drain` @200ms, `_drain_alert_queue` @150ms, `_schedule_ui_updates`
  @150ms) with `_pending_after` drained redundantly by two of them. On a
  loaded box each Tk call costs 4–90ms, so constant-wakeup drains built an
  accumulated Tcl backlog that tripped the 1.5s check even with rain fixed.
- ✅ **Idle backoff** on all three drains: `_early_drain` and
  `_drain_alert_queue` re-arm at **1s when nothing was queued** (150–200ms
  only when they actually drained work); `_schedule_ui_updates` re-arms at
  500ms idle / 150ms busy. `_did_work` flags added to each. (~5× fewer
  main-thread wakeups in steady state.)
- ✅ Root-caused the still-periodic **9.9–21.4s freezes**: the rain stride
  keyed off the *frame-cost* EMA, which oscillates — cheap probe frames decay
  the EMA to ~83, the linear stride term collapses to 1, and a full 120-drop
  frame at ~80ms/coords = a 10s main-thread block, freeze, probe, repeat.
- ✅ **Coords-cost self-regulation** (decoupled from frame EMA):
  - `_update_drops` times its actual `coords()` calls and keeps a
    `_coords_cost_ema` (0.7/0.3, updated only when ≥5 calls sampled).
  - `_animate` computes the drop stride from a hard **~50ms coords budget**:
    `stride = ceil(n_drops / floor(50ms / per-coords-cost))`, capped 80, so a
    80ms/coords box touches ~2 drops/frame regardless of EMA state.
  - `_degrade` is now ALSO true whenever `_coords_cost_ema >= 8` — cosmetic
    layers (stars/splash/fog/mist/lightning) stay off while canvas ops are
    intrinsically expensive, so they can't run a multi-second frame the moment
    the frame EMA falls back to 100ms. Seeded `_coords_cost_ema = 8.0` at init.
- ✅ Result (fresh run 20:10:33, observed ~6 min): **zero FREEZE logs**, no
  RAIN freeze/resume cycling at all, CPU ~34% idle-ish, alerts flowing. Prior
  run of the same commit: 9.9–21.4s freezes every ~30–60s.
- ✅ 75/75 tests; boot smoke clean.

## Session 2026-08-14b9 — v29.41j: wire 4 more dead Perf gauges to live `_ti_ref`
- ✅ Systematic gauge audit (130 gauge keys vs `_fetch` writes) confirmed every
  key is written — but a second audit of `self._*` reads found 4 more never-
  assigned attrs feeding gauges: `_file_threats_last_hour` (FILE THREATS/H),
  `_malware_detected_total` (MALWARE DETECTED), `_phishing_urls_total`
  (PHISHING URLS), `_suspicious_dns_total` (SUSPICIOUS DNS). All four now read
  the live cached `ThreatIntelligenceManager` (`_file_threats_hour`,
  `_total_malware_hashes`, `_total_phishing_urls`, `_total_suspicious_dns`).
  The wired-key regression suite is the same-class guarantee.
- ✅ 75/75 tests; clean boot smoke; pushed `fc9fb9b`.

## Session 2026-08-14b8 — v29.41i: wire 4 dead Perf-tab gauges to real counters
- ✅ Gauge audit found 4 more stuck-at-zero gauges: SEC EVENTS / OSINT
  LOOKUPS / OSINT TODAY / OSINT CACHE were read in `_fetch` via `getattr(self,
  '_x', 0)` but written NOWHERE. Wired:
  - SEC EVENTS → `_queue_alert` increments `_security_events_today` (daily
    reset via `_events_counter_day`).
  - OSINT total/today/cache → new `_bump_osint_lookup(cache_hit)` helper,
    called from `check_ip` (distinguishes cache hit/miss), `check_url`,
    `check_hash`; daily reset via `_osint_day`.
- ✅ 74/74 tests (new regression test); pushed `db8042e`.

## Session 2026-08-14b7 — v29.41h: vuln-scanner None-crash trio + CEV DB timeout
- ✅ Log audit surfaced two recurring crash signatures (last seen Aug 11, 102
  hits each): `detect_exploit_attempts` bug — `proc.info.get('cmdline',
  [])` can be `None` (psutil sets attr to None on AccessDenied for the attr
  list in process_iter), so `' '.join(None)` → "can only join an iterable".
  Fixed with `proc_info.get('cmdline') or []`. `check_privilege_escalations`
  — `proc_info.get('username', '')` also can be None → `.endswith` on None.
  Fixed with `(proc_info.get('username') or '')`.
- ✅ `get_cev_score` (read every fetch tick) opened each connection with the
  5s default timeout; long feed-writer transactions → "database is locked"
  (351 hits). Bumped to `timeout=30`.
- ✅ 73/73 tests (2 new regression tests); pushed `1e8b21b`.

## Session 2026-08-14b6 — v29.41g: feed updates off the Tk main thread
- ✅ `_scheduled_feed_update` called `ti.update_all_feeds()` directly in the
  `after` callback — URLhaus `csv_recent` full-dump per-row inserts froze the
  GUI for minutes (observed: 4+ min blocked). Both `_scheduled_feed_update` and
  `_scheduled_feed_health_check` now spawn `threading.Thread(daemon=True)`
  workers; the hourly/30-min reschedule stays on the main thread via `self.after`
  and feed-alert queuing is marshaled back with `self.after(0, ...)`.
- ✅ Validated during live ingest: GUI mainloop stays ALIVE + responsive
  (alerts/pending_after counters ticking) the entire time URLhaus is ingesting.
- ✅ 72/72 tests; pushed `6b1e271`.
- ℹ️ URLhaus ingest itself remains slow (~minutes) — per-row `add_malicious_url`
  DB insert, pre-existing. Now non-blocking, so acceptable.

## Session 2026-08-14b5 — v29.41f: missing `_record_feed_history` + VS DB-init cache
- ✅ **Real bug found via boot smoke**: every OSINT feed update (threatfox/
  urlhaus/phishtank/malwarebazaar) crashed with `'ThreatIntelligenceManager'
  object has no attribute '_record_feed_history'` — `_feed_history` dict was
  initialized in `__init__` but the `_record_feed_history` method was never
  written. Feed updates failed silently every launch; only visible in
  `downpour.log`. Added the method (appends (ts, ioc_count), capped at
  `_max_history_points=100`). ThreatFox now updates `[OK]` in ~3s.
- ✅ **Second DB-init-per-tick offender**: the CVE gauges block also did
  `VulnerabilityScanner()` fresh every fetch tick → `[OK] Vulnerability scanner
  database initialized` logged ~every 15s. Cached once as `_vs_ref` on the
  monitor (same pattern as `_ti_ref` in v29.41e). Post-fix: DB init appears
  only once at startup.
- ✅ 71/71 tests; clean boot confirmed (2 VS inits total, zero feed errors);
  pushed `d3f0a16`.
- ℹ️ Known: `_scheduled_feed_update` runs `update_all_feeds()` on the Tk main
  thread; URLhaus full-dump insert can block the GUI for minutes. Pre-existing,
  not addressed in this session.

## Session 2026-08-14b4 — v29.41d/e: net/process anomaly gauges live + TI cache
- ✅ **v29.41d**: net anomaly gauges (PORT SCAN/H, EXFIL/H, DNS TUN/H,
  LATERAL/H) now served by a *throttled* (10s) live `net_monitor.
  analyze_connections()` classification — port_scan/data_exfil/dns_tunneling/
  connection_flood alert types map to the gauges, `_nm_alert_map` reused
  between ticks so the full psutil connection walk doesn't run every 1-3s.
  Process anomaly gauges (INJECT/H, DISGUISE/H, SUS LOC/H, SUS CMD/H,
  HIGH CPU/H) classify the live scanned process list (`_PKEY` keyword map).
  EXFIL/H is the NET gauge — behavior's exfil counter uses setdefault; the
  heatmap `c2_servers_total` reads from live beaconing alerts too. Caught a
  real ordering bug headless: behavior block overwrote net exfil — fixed via
  setdefault precedence. 25 live-gauge assertions pass on a fake app.
- ✅ **v29.41e**: `ThreatIntelligenceManager` does DB init in `__init__` and
  was constructed fresh 2× per fetch tick — now cached once as `_ti_ref` on
  the monitor (both file-threat + OSINT feed blocks share it).
- ✅ 69/69 tests; boot smoke → zero stderr; pushed `db9c00a`.

## Session 2026-08-14b3 — v29.41c: behavior gauges → live [BEHAVIOR] findings
- ✅ **Last orphan-gauge group**: KEYLOG/SCREEN/INJECT/CRED/PERSIST/EVASION/
  EXFIL/LATERAL-H read `behavior_scanner.BehaviorScanner(db=None)` — a module
  the app never starts (it even documents wiring into a different app). Static
  0 forever.
- ✅ **Fix**: when the `_app` backref exists, the eight behavior gauges now
  classify `[BEHAVIOR]` keyed findings from the app's LIVE scanned process
  list (`_processes` → `scan_all()` → `risk_reasons`, refreshed continuously
  by `_proc_loop`). Live path only writes when ≥1 behavior found; otherwise
  the orphan fallback still satisfies the keys (never NameErrors).
- ✅ 65/65 tests pass; boot smoke 50s → zero stderr; pushed `b553e04`.
- ✅ All three orphan-monitor gauge groups (file, proc/net threats, behavior)
  are now wired to genuine live app data.

## Session 2026-08-14b2 — v29.41b: PROC/NET THREAT gauges → live app data
- ✅ **Same orphan-module class of bug**: NET THREATS / PROC THREATS read
  `network_monitor` / `process_monitor` singletons that are never `.start()`ed
  anywhere in the app — static 0 regardless of what the app is doing.
- ✅ **Fix**: with the `_app` backref present, PROC THREATS counts suspicious
  from the app's LIVE `_processes` list (refreshed continuously by
  `_proc_loop` → `scanner.scan_all()`), and NET THREATS runs the app's live
  `net_monitor.analyze_connections()` for alert count. Without a backref
  (headless tests) it falls back to the orphan singletons. `nm`/`pm` local
  refs stay always-bound so the finer-grained anomaly gauges below never
  NameError on the live path.
- ✅ 64/64 tests pass; boot smoke 50s → zero stderr; pushed `090b250`.
- ⏳ Next: the 8 behavior gauges (KEYLOG/SCREEN/INJECT/CRED/PERSIST/EVASION/
  LATERAL/H) still read the orphan `behavior_scanner` module.

## Session 2026-08-14b — v29.41: file gauges bound to the LIVE RansomwareDetector
- ✅ **Follow-up on v29.40c**: the `fm` fix bound the *orphan* `file_monitor`
  module (`get_monitor()`), but that module is never `.start()`ed anywhere in
  the app — its counters (`_file_modifications_hour`, etc.) could never move,
  so MOD/H, CREATE/H, DELETE/H, SUS CREATE/H, RANSOM/H would stay 0 forever.
- ✅ **Fix**: `HardwareMonitor._fetch` now prefers the app's LIVE
  `RansomwareDetector` — `self.hw._app = self` backref wired in the app
  constructor, and the file gauges compute real per-hour counts from
  `ransomware._file_changes` deque (watchdog-fed; created/suspicious-extension/
  ransomware-note classification inline via KnownThreats lists). Falls back to
  the old orphan binding only when no app backref exists (headless tests).
- ✅ Verified headless with a fake app + deque: mod/create/delete/sus/ransom
  all counted correctly; fallback path returns 0 without raising. Full suite
  63/63 pass; boot smoke test 45s → zero stderr. Pushed `26a0177`.

## Session 2026-08-14a — v29.40c: boot crash fix + live Performance data pipeline
- ✅ **CRITICAL boot regression**: `downpour_v29_titanium.py` exited code 1 at
  line 114 with `AttributeError: module 'logging' has no attribute 'handlers'`.
  Python 3.13+ dropped the implicit `logging.handlers` attribute binding; the
  explicit `import logging.handlers as _crash_handlers` now loads it.
- ✅ **Env root-cause**: repo `.venv` was built on Python 3.15.0a6 (an alpha —
  no binary wheels). Pillow imported with `SystemError: PIL._imaging uses
  unknown slot ID 85`. Rebuilt `.venv` on the repo's documented
  `C:\Users\purpl\AppData\Local\Programs\Python\Python312\python.exe`
  (all 20 deps install; netifaces dropped — EOL with no py3.12 wheel and zero
  usage in the codebase). Added setuptools (provides the `distutils` shim GPUtil
  still needs on 3.12). Full GUI now boots GUI clean (zero stderr).
- ✅ **Live-data pipeline fixes** (Performance tab): `_fetch` referenced
  `fm`/`bs` that were never defined → ~15 file/behavior anomaly gauges silently
  NameError-zeroed every tick. Both are now lazily bound and cached on the
  monitor (`_file_monitor_ref` / `_behavior_scanner_ref`). Swap/page-fault rate
  block borrowed the disk block's local `dt` (NameError on some machines) —
  now owns its own `_dt_m`. `_force_perf_ui` 10s safety timer was defined but
  never scheduled — wired into `_auto_start`.
- ✅ **Perf-loop hardening**: `_perf_loop` could stack executor submissions on a
  slow tick — added `_perf_inflight` guard. It now also honors
  `_adaptive_prf_ms` (HardwareProfiler.adapt_to_load) so under CPU/RAM pressure
  the throttle actually engages.
- ✅ **Dead-landmine removal**: `_update_hw_ui`'s except-block referenced
  undefined `pct`/`score`/`max_score`/`color` (masked real errors with a
  NameError). `_start_hw_thread` read a never-set `_hw_ms`. Both removed.
- ✅ **Interpreter selection**: `find_latest_python()` unconditionally preferred
  the newest Python (→ 3.15.0a6, breaking wheels). It now skips alpha/beta/rc
  (`releaselevel == 'final'`) and parses `py --list` correctly.
- ✅ **Launcher**: added Python 3.14 discovery paths + replaced eol-only
  `netifaces`/`pynvml` notes in requirements prose.
- ✅ **Gauge refinement**: GAUGES table had same-key duplicates (DISK QUEUE,
  FILE THREATS/H, EXFIL/H) where only one of the pair of canvases ever updated;
  plus cross-key visual dupes (DISK READ/WRITE, MEM FRAG, PAGE FAULTS, FEED
  ERRORS). Deduplicated → 129 unique live gauges; added UPTIME.
- ✅ **AEGIS guard**: alert wiring now uses `getattr(..., None)` so a missing
  optional layer can't blow up the startup callback chain.
- ✅ Tests: +10 regression guards (`TestV2940Reliability`) → 60/60 pass,
  py_compile OK, `_fetch` headless round-trip verified (no NameError; anomaly
  keys bound; swap/page-fault/disk rates live). Pushed `c526c10..22cf5c5`.

## Session 2026-08-13n — v29.34: Phase 3 tooltip sweep across all main tabs
- ℹ️. **Gap**: Phase 3 audit counted 122 `tk.Button` creations vs only 72
  `_tooltip` calls — 55 bare buttons across the main (non-DNS) tabs had no
  hover help. Factory loops and dialog Close/Cancel buttons were the
  legitimate leftovers; everything actionable still needed a tip.
- ℹ️. **Added tooltips (41 buttons)**: PANIC, all 6 ECP engine buttons +
  START ALL ENGINES, 4 triage buttons, Privacy Mode + Score, global HUNT,
  packet-capture bar (Start Capture/Stop/Check Rogue DHCP), intel feed
  management (Add Feed/Fetch Now/Remove Selected/Import from File/Feed
  Statistics), Scanner header (RUN FULL SCAN/FIX ALL/Check Zero-Days),
  DNS monitor (Clear/Export Log), DNS cache (View/Flush/Scan/Export), DNS
  blocklist (Block/Unblock/Import/Export), DNSSEC (Validate/Full Audit),
  poison/system-domain/router-DNS checks, firewall Load Events, GreyNoise
  lookup + Unblock Selected, fingerprint Re-arm/Clear All, hardening
  Rollback Selected.
- ℹ️. Named every button in a `_xxx_btn: Any` var instead of `.pack()`/`.grid()`
  on a throwaway so `self._tooltip()` can attach cleanly.
- ℹ️. Tooltip calls 72 → 113; remaining 14 bare are self-explanatory dialog
  Close/Cancel/❌ and factory loops (labels already describe action, and the
  `_btn` factory at 44635 already supports `tip=`).
- ℹ️. 46/46 tests pass; py_compile OK; 751 methods / 0 dupes; pushed
  `c505cdf..ba41d9c`.

## Session 2026-08-13m — v29.33: tooltips across all DNS sub-tabs
- ✅ **Gap**: the DNS tabs' button-factory helpers (`_qbtn`, `_srv_btn`,
  `_hbtn`, `_enc_btn`, `_tbtn`) had no tooltip support at all, so ~30 DNS
  buttons showed no hover help. The generic `_btn` helpers used elsewhere
  already took `tip=` (positional) — the DNS ones were the stragglers.
- ✅ **Fix**: added `tip=None` + `self._tooltip(btn, tip)` to all five DNS
  helpers, and wrote per-button help for the Overview quick-actions, Servers
  (apply/show/reset/latency/leak), Hosts editor actions, DoH enablers, the
  14-button Advanced tools column, 7-button Security-tests column, 7-button
  Repair/Harden column, and the secure-provider "Load ->" button.
- ✅ Also kept every created button reference in a named var (no more
  `.pack()`/`.grid()` on a throwaway) so tooltips attach cleanly.
- ✅ 46/46 tests pass; py_compile OK; pushed `1e2b193..e165e69`.

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
- ✅ Scanned every `tk.Button(` assignment in the main file (script-based
  tooltip-gap audit). Most flagged sites already bind `_tooltip`; the real
  stragglers were 9 named buttons: Rain toggle, Storm cycle, Settings gear,
  Widget toggle, tab-strip ◀/▶ scroll arrows, CVE "Apply Mitigation for This
  CVE", TPM/BitLocker bypass toggle, and the DNS Live Monitor start/stop.
- ✅ All 9 now have `_tooltip(...)` bindings with short action/state
  explanations. `py_compile` OK; 31/31 unit tests pass.

## Session 2026-08-13k2 — v29.30b follow-up: hasattr() recursion fix on bare instances
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

## Session 2026-08-13x — v29.35: fix failing test + Phase 3 tooltip sweep (WiFi/IoT/USB/Timeline/VPN/Settings/Hunt/Sandbox)
- ✅ Fixed failing test TestTabIndicatorV2934b::test_indicator_created_before_tab_change_binding by searching for the exact binding string rather than a bare event name that matched a comment.
- ✅ Verified Phase 3 tooltip sweep for WiFi, IoT, USB, Timeline, VPN, Settings, Hunt, and Sandbox tabs (tooltips were already correctly populated).
- ✅ Tests: 50 pass (1720 methods)
