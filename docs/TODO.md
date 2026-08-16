# TODO / Current State — Downpour v29 Titanium
# Last verified: 2026-08-14 (v29.40c, boot-crash fix + live Performance data)

**READ THIS FIRST if you are a new agent picking up this project.**
This file was badly stale (dated April 2026) until this rewrite. `_WORKLOG.md`
in the repo root has the detailed, dated session-by-session log — that is the
authoritative history. This file is the current-state snapshot + what's left.

---

## Verified Current State (as of this rewrite)

- `downpour_v29_titanium.py`: ~52,780 lines, 1313 methods across classes
  (751 in the main `downpour` class), **0 duplicate method names** (verify with
  the AST script below before and after any edit session — this has caught real
  bugs multiple times)
- `gpu_detector_fix.py` shipped in v29.24 (was a dangling import in
  `enhanced_security_dashboard.py`).
- `tests/test_thread_safety.py` added in v29.25 — pytest cases covering the
  FP-suppression flow, `_queue_alert` rate limit, and the executor post-back
  pattern. Run: `Python312\python.exe -m pytest tests -q`. (18 tests as of
  v29.26 with the dark-titlebar cases; **31 tests as of v29.29** — added
  `TestPerfTabV2928` gauge/sparkline/ceiling cases, `TestThreatWebStack` intel
  deep-link builder cases, and `TestRiskConfirmation` `_confirm_risk` cases;
  **46 tests as of v29.34** — added `TestBrowserScanV2930` (5) and
  `TestWarmPerfHistoryV2930b` (6) plus DNS cases; **60 tests as of v29.40** —
  added `TestV2940Reliability` (10) covering the boot-crash fix, live
  anomaly-gauge bindings, perf-loop guards, gauge-key uniqueness, and
  stable-Python selection.)
- Full project: 58 Python files, 0 syntax errors
- **Main-thread DB-freeze rule (v29.14)**: every `self.db.*` / `count_intel()`
  reached from a main-thread `after()` loop or a one-shot startup callback must
  run on `self._executor` with results marshaled back via `self.after(0, ...)`.
  The shared helper `_refresh_ioc_count_display()` centralizes the IOC-count
  pattern; `_aegis_fetch_events` → `_apply_aegis_events` covers the AEGIS
  event log. grep for `count_intel` and `SELECT COUNT(*)` before editing a
  periodic loop. Background threads may still call `self.db.*` directly.
- **Python 3.12 is the correct interpreter.** Do NOT use whatever `python` on
  PATH resolves to without checking — this machine's default was Python
  3.15.0a6 (an alpha build) for a long time, which has NO compiled wheels for
  matplotlib/Pillow/pystray/netifaces/scipy and no C compiler to build from
  source. The repo `.venv` was rebuilt on 3.12.10 in v29.40 after the alpha
  venv crashed with `PIL._imaging uses unknown slot ID 85`. Use
  `C:\Users\purpl\AppData\Local\Programs\Python\Python312\python.exe`
  explicitly. All 20 dependencies install cleanly on 3.12. The launcher
  (`LAUNCH_V29_TITANIUM.bat`) already rejects non-final Python releases.
- GitHub: `github.com/christiand0797/downpour`, single branch `main`
  (27 stale branches were pruned in an earlier session — keep it that way,
  don't create new long-lived branches, commit straight to `main`)

## Standard Verification Workflow (do this before AND after every edit session)

```powershell
# 1. Compile check the file(s) you touched
& 'C:\Users\purpl\AppData\Local\Programs\Python\Python312\python.exe' -m py_compile downpour_v29_titanium.py

# 2. AST duplicate-method check (catches silent method-shadowing bugs)
#    Write this to a temp .py file and run it — has caught real collisions:
python -c "
import ast
with open('downpour_v29_titanium.py', encoding='utf-8', errors='replace') as f:
    tree = ast.parse(f.read())
for node in ast.walk(tree):
    if isinstance(node, ast.ClassDef) and node.name == 'downpour':
        names = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        dupes = {n for n in names if names.count(n) > 1}
        print(f'{len(names)} methods, {len(dupes)} duplicates:', dupes or 'none')
"

# 3. Full-project audit (all 58 files)
#    Walk the repo, ast.parse() every .py file, print failures only.

# 4. If wiring a new module/feature, VERIFY IT'S ACTUALLY CALLED, not just
#    imported/instantiated. This codebase has repeatedly had well-built
#    modules that were never wired into any live code path — found and fixed
#    this pattern at least 5 times (VulnerabilityScanner, threat_intelligence.py,
#    detect_zero_day_threats(), a KIMWOLF_C2_IPS import that was never
#    referenced, and more). grep for the function/method name across the
#    whole file — if it only appears in its own def line, it's dead.
```

## PowerShell / Desktop Commander gotchas (save yourself the debugging time)

- Inline PowerShell with complex quoting (nested `"`, `$`) is unreliable via
  Desktop Commander — write a `.ps1` script file first, then
  `powershell -NoProfile -ExecutionPolicy Bypass -File "path.ps1"`.
- For anything that might hang (network requests, large downloads): wrap in
  `Start-Job` with `Wait-Job -Timeout N`, then `Receive-Job`/`Stop-Job`.
  Several "hangs" turned out to just be slow real downloads (MITRE CTI feed
  is 48MB) — not infinite loops. Give it a real timeout budget, don't assume.
- git commit messages with embedded quotes: write to a `.txt` file and use
  `git commit -F file.txt`, not inline `-m "..."` with a PowerShell here-string.
- Clean up temp scripts after each session (`zz_*.ps1`, `zz_*.py`, `_test_*`,
  `_check_*` etc.) — they accumulate fast and clutter `git status`.

---

## HIGH PRIORITY — Real, Verified Gaps

- [ ] **GPU ML workloads** — gpu_executor pool exists (50% cores reserved) but
      no CUDA ML workloads run on it. Would need cupy/tensorflow wiring (both
      NOT installed; only CPU `torch 2.10.0+cpu`). PARTIAL v29.23: per-process
      GPU attribution added — the Processes tab now shows which PIDs run on
      the GPU (via `nvidia-smi --query-compute-apps`, VRAM MB or `[GPU]` marker
      when non-admin) and `_show_proc_detail` reports it. GPU *monitoring*
      (util/temp/mem gauges) has worked since v28 via NVML. What remains is
      actually *running compute* on the GPU, which requires the CUDA toolchain.
- [x] **Feed health dashboard UI tab** — `feed_status` DB table has real data
      (from the OSINT/threat-feed work), no UI surfaces it yet. FIXED v29.15:
      Intel-tab feed Status column now shows `[OK]`/`[FAIL]`/`[STALE]`/
      `[PENDING]` with color tags via `_refresh_feed_health` (executor) +
      `_apply_feed_health` (main).
- [x] **Sophisticated false-positive suppression** — currently hardcoded
      whitelists in places; a DB-backed auto-suppression (track alert
      frequency per indicator, auto-suppress after N confirmed-clean cycles)
      would reduce alert fatigue. FIXED v29.16: `fp_suppressions` table +
      `_fp_fingerprint` normalization + `_fp_confirm` (auto-suppress at 3
      confirms) + `_fp_is_suppressed` in the `_queue_alert` hot path +
      `_threats_fp_manager` blocklist UI (re-arm / clear). Mark-FP is now
      persisted across sessions.
- [x] **Main-thread DB freeze in status pills** — FIXED v29.13: the 10s
      `_refresh_status_pills` threat-count query ran on the main thread and
      could block on `db._lock` held by background bulk inserts. Now runs on
      `self._executor` + `_apply_threat_pill`. Same class of fix as the
      earlier `_feed_refresh_loop`/`count_intel` fix — when you find another
      `self.db.execute(...)` call inside an `after()` loop on the main thread,
      apply the same executor pattern.
- [x] **`docs/TODO_v30_DDoS.md`** — spot-checked directly against the code
      (not just the checklist file): all 10 named handler methods
      (`_ddos_init_state`, `_ddos_analyze_connections`, `_ddos_classify`,
      `_ddos_load_blocklist`, `_ddos_save_blocklist`, `_ddos_reputation`,
      `_ddos_shield`, `_ddos_rate_monitor_ui`, `_ddos_block_all_flooders`,
      `_ddos_export_report`) genuinely exist. Confirmed complete, not
      aspirational.

## v29.27–v29.29 Session (2026-08-13) — Performance tab + hardening

- [x] **Performance tab live loop fixed** — `_perf_loop` had zero external
      trigger (its kickoff `after()` was commented out), so the tab was a dead
      UI shell. v29.27 wired `_auto_start` → `after(2000, self._perf_loop)`.
- [x] **Perf gauges: label no longer covered by sparkline** — label was drawn
      at `size+18` which sat inside the sparkline strip's `size+14..size+29`
      band (rendered as a filled "black box"). v29.28 moved label to `size+8`.
- [x] **Adaptive gauge ceilings for rate gauges** — DISK/NET rate gauges
      previously used static max (7000 MB/s / 102400 KB/s) so the needle sat
      at ~0 for real traffic. v29.28 derives `dyn_max = ceil(peak*1.4/100)*100`
      from each gauge's history and stores it back into `_perf_gauge_meta` so
      needle + sparkline scale together.
- [x] **Perf waterfall: GPU column** — per-process table now shows GPU
      attribution via `_gpu_proc_map` (NVML compute-apps).
- [x] **Perf tab: live tables** — new "LIVE NETWORK INTERFACES" and "DISK
      PARTITIONS" treeviews fed from HardwareMonitor public stats.
- [x] **Mousewheel scoping fix** — `bind_all('<MouseWheel>')` was hijacking
      every widget's scroll; v29.28 guards with `winfo_containing()`.
- [x] **Intel tab "Threat Web Stack"** — keyless browser deep-links to Cisco
      Talos, Hybrid Analysis, PhishTank, ANY.RUN, Joe Sandbox (from OSINT4ALL
      triage stack mining).
- [x] **`_confirm_risk()` gates** — v29.29 adds a shared confirmation helper
      (always `askyesno`, headless-safe, returns `bool`) now wired into Threat
      Action Panel (Block All IPs / Kill PIDs / Quarantine / Suspend / Root
      Cause) and Threats-tab Kill Selected.
- [x] **Tooltip sweep** — Intel Threat Response row (31 buttons) + Dashboard
      quick-actions row now show tooltips (`_resp_tips` pattern + hand2).
- [x] **Browser-extension security scan (v29.30)** — inflated a defensive
      orphan (`browser_protection.py`) inline into the Threats toolbar:
      `_scan_browser_extensions` reads every installed-browser extension
      `manifest.json` and risk-scores permissions (tabs/webRequest/cookies/
      debugger/clipboardRead/…), `_browser_cve_check` matches installed
      browsers against the existing `CisaKevEngine` singleton. Runs on
      `_io_executor` with `_queue_alert` + after(0) postback. DECLINED: the
      `advanced_device_profiler.py` orphan (evasion/bypass-capability toolkit)
      is deliberately left unwired.

## OSINT4ALL Research — Status

Mined start.me/p/L1rEYQ/osint4all (mirrored at osint4all.com) across
multiple sessions. Summary for future agents so this doesn't get re-done:

- [x] **Threat Intelligence and Indicator Triage Stack** collection —
      comprehensively mined. This is the direct source of the 18+ inline
      OSINT lookups added in v29.1–v29.12 (VirusTotal, AbuseIPDB, Shodan,
      Censys, Netlas, GreyNoise, Pulsedive, ONYPHE, urlscan.io, ThreatFox,
      URLhaus, AlienVault OTX, MalwareBazaar, EmailRep.io, HIBP Pwned
      Passwords, crt.sh, Wayback Machine, CyberChef).
- [x] **Hudson Rock Cavalier** (exposure/breach context, osint4all.com
      "OSINT for Cybersecurity" guide) — added in **v29.13** as a keyless
      inline lookup (email + domain dispatch). This was the last actionable
      gap in the OSINT4ALL cybersecurity use-case page; the remaining listed
      tools there (Shodan/Censys/Netlas, urlscan/VT/OTX, CyberChef/MISP,
      HIBP/EmailRep) are all already integrated.
- [x] **Infrastructure attribution (IP/ASN routing)** — v29.21 added three
      keyless lookups: `_osint_ipinfo_lookup` (IPinfo.io ASN/geo/anycast/
      bogon), `_osint_bgpview_lookup` (BGPView.io routing graph for IP + ASN),
      `_osint_hacktarget_lookup` (HackerTarget reverse-IP/GeoIP/DNS/ASN).
      These fill the "routing/ASN attribution" lens the OSINT4ALL
      Shodan-vs-Censys-vs-SecurityTrails guide frames as distinct from the
      abuse-scoring tools. NOTE: `api.bgpview.io` DNS is blocked on this
      network — the BGPView button exercises its web-page fallback here.
- [x] **Mitaka** (browser-extension indicator pivoting) — reviewed; it is a
      Chrome/Firefox extension, not an API/web service, so there is no
      programmatic surface to integrate. Not a fit — don't re-evaluate.
- [x] **Domain/DNS/Web Infrastructure** tools — also already covered.
      DNSDumpster, MXToolbox, DNSlytics, ViewDNS.info, SecurityTrails are
      all part of the existing "Domain OSINT Stack" deep-link (14 infra
      sources per `_WORKLOG.md`, alongside Wappalyzer/BuiltWith/ZoomEye/
      FullHunt/Archive.today).
- [ ] Not yet done, low priority: OSINT4ALL's "Shodan vs Censys vs
      SecurityTrails" comparison guide frames these as 3 *different*
      reconnaissance jobs (exposed services / cert pivots / DNS history)
      rather than interchangeable options. Worth reading before doing the
      "consolidate 18+ lookup buttons into one dispatcher" item below —
      naive consolidation could blur genuinely different use cases.
- [x] The other OSINT4ALL collections (breach/exposure research for
      companies, journalist verification workflows, corporate due-diligence,
      geolocation) are NOT relevant — evaluated and confirmed out of scope,
      see "Content Judgment Calls" section below. No further mining of this
      resource is expected to yield new value for this codebase.

## MEDIUM PRIORITY

- [ ] **Tab overlap on small windows** — PARTIAL v29.37: found the root
      cause — `self.minsize(1024, 650)` in `_build_ui` was silently
      overriding the adaptive hardware-profile minsize computed earlier in
      init, and 1024px isn't enough horizontal room for ~24+ notebook tabs.
      Raised to `minsize(1280, 700)` — below even the smallest common laptop
      resolution (1366x768) — which reduces wrapping on real displays. This
      is a floor-raise, NOT the full fix: `ttk.Notebook` has no native
      horizontal-scroll for its tab strip, so wrapping can still occur on a
      genuinely tiny/unusual window. The real fix is replacing the native
      tab strip with a custom scrollable canvas widget — left undone
      because it can't be visually verified without live-rendering the GUI
      (no screenshot/render capability in this environment). If picking
      this up: verify by actually launching the app and resizing the
      window, not just by reading the code.
- [x] **Per-feed timeout tuning** — RESOLVED v29.18: feeds already run in
      parallel (ThreadPoolExecutor + as_completed), so slow feeds (MITRE CTI
      is 48MB) don't block faster ones; the result timeout was empirically
      confirmed never to fire for in-flight feeds and was raised to 150s
      (matches the worst-case download+parse budget) as defense-in-depth.
      The "slow feeds queue" idea turned out to be unnecessary — parallelism
      already handles it. Checkbox fixed for consistency with the body text.
- [x] **Feed auto-retry with backoff** — DONE v29.17: `_fetch_feed` now
      retries 3x with (0s, 2s, 6s) backoff (verified present in code this
      session — `_BACKOFF: Any = (0, 2, 6)`); `_intel_auto_loop` still
      re-runs failed feeds on the next scheduled cycle (checks every 10 min).
      Checkbox was left unchecked despite the body text already saying DONE
      — fixed for consistency.
- [x] Consider consolidating the OSINT lookup buttons (VT/AbuseIPDB/Shodan/
      Censys/Netlas/GreyNoise/Pulsedive/ONYPHE/urlscan/ThreatFox/URLhaus/OTX/
      MalwareBazaar/EmailRep/HIBP/crt.sh/Wayback/CyberChef/HudsonRock — that's
      19+ separate inline lookups added across v29.1–v29.13) into a single
      "Lookup Everywhere" dispatcher that opens the relevant subset based on
      indicator type, rather than one button per service. Getting unwieldy.
      DONE v29.19: `_osint_multi_lookup` is that dispatcher and now
      classifies email/IP/hash/domain correctly (email branch was the missing
      piece — emails previously fell through to the domain branch and broke).
      Single-service buttons intentionally kept for keyless inline lookups;
      "OSINT Stack" button on Intel tab + network tab is the consolidated path.

## LOW PRIORITY

- [ ] Unit tests for thread-safety mechanisms (none exist — all verification
      so far has been manual compile + AST + live functional testing)
      PARTIAL v29.25: `tests/test_thread_safety.py` (pytest) added with 16
      tests for `_fp_fingerprint`/`_fp_is_suppressed`/`_queue_alert`
      suppression + rate limit, and the executor `after(0)` post-back
      pattern. Immediately caught a real bug: IP:port fingerprints did NOT
      collapse (fixed with an IP[:port] unit regex). Uses
      `object.__new__(downpour)` so no display needed. Extend coverage to
      other hot paths as new logic lands.
- [x] System tray minimize support — pystray IS installed and working on
      Python 3.12, but no tray icon code is wired into the running app
      (a `downpour_tray.py`-style module was drafted in an early session but
      never actually shipped to this machine — check if it's worth reviving
      or just building fresh, since a lot has changed since then). DONE
      v29.20: `_setup_tray_icon` / `_tray_restore` / `_tray_toggle` wired
      into `_auto_start`; `_on_close` now alerts + minimizes; `_shutdown`
      stops the icon. Fixes the real bug where `minimize_to_tray` withdrew
      the window with no way to restore it.
- [x] Dark mode detection for Windows 11 integration — DONE v29.26:
      `_apply_dark_titlebar()` sets DWMWA_USE_IMMERSIVE_DARK_MODE (attr 20
      Win11 / 19 Win10) on the real top-level HWND and stores
      `_system_dark_theme` from the `AppsUseLightTheme` registry value.
      Live-verified rc=0 on a real window. Called at loading reveal + after
      final title set.
- [x] Export-to-PDF for security reports — DONE v29.22: `_export_pdf_report`
      is a generic reportlab writer (save dialog + executor build). The
      compliance "Export PDF Report" stub now dumps the real audit tree, and
      the NSA Full Assessment auto-persists to
      `~/Documents/DownpourReports/downpour_nsa_report_<ts>.pdf` instead of
      only firing alerts. reportlab verified installed + live-tested.
- [x] `gpu_detector_fix.py` referenced by `enhanced_security_dashboard.py`
      didn't exist — import was guarded so not a crash, just a missing
      optional feature. FIXED v29.24: shipped `gpu_detector_fix.py` with a
      `GPUDetector.get_gpu_info()` matching the dashboard's expected schema
      (NVML → nvidia-smi CLI → GPUtil → WMI layered fallback; always returns
      a dict, never raises). Live-verified returning real RTX 3050 stats.

## Known Limitations (architectural, not "TODO" — document, don't chase)

1. **Python GIL** — background threads still contend with the main thread on
   CPU-bound work (psutil polling, regex scans). Expect occasional 2-12s UI
   pauses during heavy monitoring-loop activations. The known main-thread
   blocking-DB freezes have been fixed (status pills v29.13, feed loop earlier);
   any *new* `self.db.execute()` inside a main-thread `after()` loop should be
   moved to the executor the same way.
2. **Tkinter is single-threaded** — all widget updates must happen on the
   main thread via `self.after()` / `_pending_alerts`. Never touch a widget
   directly from a background/executor thread.
3. **~49K-line single file** — monolithic. Changes are riskier than they'd be
   in a properly modularized codebase. This is why the AST duplicate-method
   check matters so much — normal code review can't catch a silent shadow in
   a file this size.
4. **Rain canvas** — Tk's `coords()` on 100+ canvas items per frame has an
   inherent per-frame cost; this is a Tk limitation, not a bug to fix.

## Content Judgment Calls Made (for consistency — don't re-litigate these)

Two externally-suggested GitHub/web resources were evaluated and declined as
not a fit for this codebase's mission:
- `Panniantong/Agent-Reach` — social-media scraping CLI for AI agents, unrelated
- `fmhy.net` — free-streaming/VPN/piracy-adjacent aggregator wiki, unrelated

`OSINT4ALL` (start.me/p/L1rEYQ/osint4all, mirrored at osint4all.com) WAS
genuinely useful — its "Threat Intelligence and Indicator Triage Stack"
collection is the source of most of the v29.1–v29.12 inline OSINT lookups
listed above. If revisiting it, the other collections (breach/exposure for
companies, journalist verification, geolocation) are NOT relevant — they're
oriented at investigators researching people/companies, not endpoint security.
