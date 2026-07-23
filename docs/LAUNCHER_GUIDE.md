# Downpour v29 Titanium — Launcher Guide

## Which Launcher to Use

| File | Version | Use |
|------|---------|-----|
| `LAUNCH_V29_TITANIUM.bat` | **v29** | ✅ Use this one |
| `LAUNCH_DOWNPOUR.bat` | v28 | Kept as backup — launches old `downpour_v28_titanium.py` |

---

## LAUNCH_V29_TITANIUM.bat — What It Does

### Step-by-Step

1. **UAC Elevation** — Self-re-launches as Administrator if not already elevated
2. **Environment** — Sets UTF-8, disables Python bytecode writing, sets `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1`
3. **Target verification** — Confirms `downpour_v29_titanium.py` exists
4. **Python discovery** — Checks 3.10, 3.11, 3.12, 3.13 across common install paths + PATH
5. **pip upgrade** — Silently upgrades pip
6. **Dependency install** — Binary wheels first (`--only-binary :all:`), falls back to source
7. **pynvml removal** — Removes deprecated pynvml if installed (conflicts with nvidia-ml-py)
8. **Defender exclusions**:
   - `ExclusionPath` — real-time protection bypass for app folder + Python
   - `AttackSurfaceReductionOnlyExclusions` — **separate ASR subsystem** (v28 bug: this was missing)
   - ASR rule `3b576869` disabled during install, restored to AuditMode after
9. **Firewall rules** — Blocks known C2 IPs: Kimwolf, BadBox2, Mozi, AISURU, CobaltStrike
10. **Log rotation** — Keeps last 3 of: `crash_fault.log`, `dp_stderr.txt`, `tk_callback_errors.txt`
11. **RAM check** — Warns if less than 2 GB free
12. **Status banner** — Prints all pre-flight results
13. **Launch** — `python -X utf8 -X faulthandler downpour_v29_titanium.py`
14. **Exit handler** — On non-zero exit: prints crash trace + last 20 stderr + last 10 tk callback errors

---

## Key Fixes vs v28 Launcher

### Bug: ASR rule 3b576869 still firing despite ExclusionPath
**Problem:** `ExclusionPath` only covers real-time protection.  
`AttackSurfaceReductionOnlyExclusions` is a **separate subsystem** that must be set independently.  
Without it, ASR rule `3b576869` ("Block executable files based on prevalence, age, trusted list") fires on:
- New pip-installed executables in temp folders
- Playwright Chromium download
- meson/ninja build system tools

**Fix in v29:** `Add-MpPreference -AttackSurfaceReductionOnlyExclusions` added for both the app folder and Python executable.

### Bug: Stray `)` syntax error
Previous version had:
```bat
)    ← this extra paren caused batch parse error
)    ← and this is the end of the if block
```
Fixed in v29.

### Bug: Pip installs trigger ASR
`meson` and `ninja` (required by some packages with C extensions) spawn temp executables that ASR blocks.  
**Fix:** `--only-binary :all:` installs binary wheels — no compiler invocation.

---

## C2 IP Block Rules

The launcher applies these Windows Firewall rules on every launch:

| Rule Name | Threat | Direction |
|-----------|--------|-----------|
| `DOWNPOUR_C2_KIMWOLF` | Kimwolf C2 servers | Outbound + Inbound |
| `DOWNPOUR_C2_BADBOX2` | BadBox2 botnet C2 | Outbound |
| `DOWNPOUR_C2_MOZI` | Mozi P2P botnet | Outbound |
| `DOWNPOUR_C2_AISURU` | AISURU botnet | Outbound |
| `DOWNPOUR_C2_COBALT` | CobaltStrike team servers | Outbound |

Rules are deleted and recreated fresh on each launch to pick up any IP updates.

---

## Troubleshooting

**"Python 3.10+ not found"** → Install from https://www.python.org/downloads/ — tick "Add to PATH"

**App crashes immediately** → Check `crash_fault.log` and `dp_stderr.txt` — the launcher prints these on exit

**Defender keeps killing the app** → Run launcher once as Admin, then add folder to Defender exclusions manually via Windows Security UI

**Low RAM warning** → Close browser tabs / other apps. App needs ~500MB minimum, 1-2 GB for full scan.
