# TODO / Current State — Downpour v29 Titanium
# Last verified: 2026-08-11 (multiple agents/sessions, see docs/CHANGELOG.md + _WORKLOG.md for full history)

**READ THIS FIRST if you are a new agent picking up this project.**
This file was badly stale (dated April 2026) until this rewrite. `_WORKLOG.md`
in the repo root has the detailed, dated session-by-session log — that is the
authoritative history. This file is the current-state snapshot + what's left.

---

## Verified Current State (as of this rewrite)

- `downpour_v29_titanium.py`: ~45,900 lines, 711 methods in the main `downpour`
  class, **0 duplicate method names** (verify with the AST script below before
  and after any edit session — this has caught real bugs multiple times)
- Full project: 58 Python files, 0 syntax errors
- **Python 3.12 is the correct interpreter.** Do NOT use whatever `python` on
  PATH resolves to without checking — this machine's default was Python
  3.15.0a6 (an alpha build) for a long time, which has NO compiled wheels for
  matplotlib/Pillow/pystray/netifaces/scipy and no C compiler to build from
  source. Use `C:\Users\purpl\AppData\Local\Programs\Python\Python312\python.exe`
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

- [ ] **GPU utilization** — gpu_executor pool exists (50% cores reserved) but
      no CUDA workloads actually run on it. RTX 3050 sits idle. Would need
      cupy/tensorflow wiring for ML-based detection to actually use it.
- [ ] **Feed health dashboard UI tab** — `feed_status` DB table has real data
      (from the OSINT/threat-feed work), no UI surfaces it yet.
- [ ] **Sophisticated false-positive suppression** — currently hardcoded
      whitelists in places; a DB-backed auto-suppression (track alert
      frequency per indicator, auto-suppress after N confirmed-clean cycles)
      would reduce alert fatigue.
- [ ] **`docs/TODO_v30_DDoS.md`** — per `_WORKLOG.md` all 6 checklist items
      are marked complete. Spot-check this file's checkboxes match reality
      before trusting it; it may itself need a final "done" pass.

## MEDIUM PRIORITY

- [ ] **Tab overlap on small windows** — Notebook still wraps on narrow
      windows despite scroll arrows. A custom horizontal-scroll canvas would
      fix this properly.
- [ ] **Per-feed timeout tuning** — some feeds (MITRE CTI is 48MB) take a
      while; consider a "slow feeds" queue so they don't block faster ones.
- [ ] **Feed auto-retry with backoff** — currently just skips on failure.
- [ ] Consider consolidating the OSINT lookup buttons (VT/AbuseIPDB/Shodan/
      Censys/Netlas/GreyNoise/Pulsedive/ONYPHE/urlscan/ThreatFox/URLhaus/OTX/
      MalwareBazaar/EmailRep/HIBP/crt.sh/Wayback/CyberChef — that's 18+
      separate inline lookups added across v29.1–v29.12) into a single
      "Lookup Everywhere" dispatcher that opens the relevant subset based on
      indicator type, rather than one button per service. Getting unwieldy.

## LOW PRIORITY

- [ ] Unit tests for thread-safety mechanisms (none exist — all verification
      so far has been manual compile + AST + live functional testing)
- [ ] System tray minimize support — pystray IS installed and working on
      Python 3.12, but no tray icon code is wired into the running app
      (a `downpour_tray.py`-style module was drafted in an early session but
      never actually shipped to this machine — check if it's worth reviving
      or just building fresh, since a lot has changed since then)
- [ ] Dark mode detection for Windows 11 integration
- [ ] Export-to-PDF for security reports
- [ ] `gpu_detector_fix.py` referenced by `enhanced_security_dashboard.py`
      doesn't exist — import is guarded so not a crash, just a missing
      optional feature

## Known Limitations (architectural, not "TODO" — document, don't chase)

1. **Python GIL** — background threads still contend with the main thread on
   CPU-bound work (psutil polling, regex scans). Expect occasional 2-12s UI
   pauses during heavy monitoring-loop activations.
2. **Tkinter is single-threaded** — all widget updates must happen on the
   main thread via `self.after()` / `_pending_alerts`. Never touch a widget
   directly from a background/executor thread.
3. **~46K-line single file** — monolithic. Changes are riskier than they'd be
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
