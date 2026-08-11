# Downpour v29 Titanium — Changelog

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
