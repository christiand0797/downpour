# ⛈ Downpour — Advanced Personal Security Suite

> **Work in progress** — Personal antivirus, anti-malware, anti-RAT, and comprehensive Windows threat-defense platform built in Python with a full Tkinter GUI.

<p align="center">
  <img src="https://img.shields.io/badge/version-v29.42%20Titanium-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078d7?style=for-the-badge&logo=windows" />
  <img src="https://img.shields.io/badge/python-3.12%20recommended-yellow?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/status-active%20WIP-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/YARA%20rules-104-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/threat%20feeds-34%2B-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/MITRE%20techniques-85%2B-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/tabs-27-teal?style=for-the-badge" />
  <img src="https://img.shields.io/badge/tests-93%2B%20passing-brightgreen?style=for-the-badge" />
</p>

---

## What is Downpour?

Downpour is a personal, all-in-one Windows security suite — written entirely in Python — that covers every attack surface a modern threat actor might exploit. It runs as a standalone GUI application with 27 tabs, live threat gauges, an animated rain overlay that intensifies with threat level, and one-click remediation for everything it detects.

---

## Quick Start

```bat
:: Run as Administrator for full features
LAUNCH_V29_TITANIUM.bat
```

> The launcher handles: UAC elevation, Python discovery, dependency install, Defender/ASR exclusions, C2 firewall rules, log rotation, and RAM check — all automatically.

---

## Features

| Domain | What Downpour Does |
|--------|--------------------|
| 🦠 **Antivirus / Antimalware** | 104 YARA rules, SHA-256 hash IOC lookup, entropy-based packer detection |
| 🐀 **Anti-RAT / Anti-C2** | Kimwolf/Botnet detector, 34 threat feeds, named-pipe C2 detection |
| 🔴 **ONE-CLICK REMEDIATE ALL** | Kill processes, block IPs, quarantine files, remove persistence in one click |
| 🔥 **Firewall Manager** | netsh advfirewall integration, Block ALL C2 IPs in one click |
| 🌐 **Network Monitor** | Live connection map, IP reputation, bandwidth graph, ARP spoof detection |
| 🧬 **Process Monitor** | Kill ALL suspicious, Quarantine ALL, real-time injection detection |
| 📁 **File Integrity Monitor** | 6 critical Windows processes, SHA-256 integrity checks |
| 🔑 **Credential Guard** | LSASS dump detection, HVCI/PPL/VBS status, Kerberoasting alerts |
| 🛡️ **Windows Hardening** | 40+ DISA-STIG checks, Fix ALL Hardening in one click |
| 📡 **DNS Security** | DoH provider switcher, DNS rebind detection, canary monitoring |
| 📊 **IR Report** | One-click full HTML Incident Response report |
| 🕵️ **MITRE ATT&CK** | 85+ technique tags auto-applied to every alert |
| 🚨 **AEGIS 5-Layer Defense** | Physical, TCP, Ingest, NLP, Memory — concurrent threat correlation |
| 🤖 **Auto-Remediate** | Toggle ON: auto-remediates CRITICAL threats on arrival |
| 🍯 **Ransomware Canaries** | Honeytoken files with instant tripwire on delete/modify (T1486) |
| 🎯 **Proactive Threat Hunt** | On-demand: LOLBAS abuse, registry persistence, BYOVD (vulnerable driver), canary check |
| 🛡️ **BYOVD Detection** | Catches EDR-killer drivers (RTCore64, dbutil_2_3, TrueSight, etc.) used by ransomware to blind AV/EDR before encrypting |
| 📋 **Live CISA KEV Feed** | Dynamically updated actively-exploited-CVE catalog, rate-limit-safe NVD CVSS enrichment |
| 📤 **Sigma Rule Export** | Any finding exports as a portable `.yml` rule for Splunk/Elastic/Sentinel |
| 🌐 **OSINT4ALL Indicator Stack** | One-click deep-links for any IP/hash/domain → VirusTotal, AbuseIPDB, Talos, GreyNoise, Shodan, Censys, OTX, Pulsedive, ONYPHE, urlscan.io + more |
| 🔎 **Inline Reputation Lookups** | AbuseIPDB, Shodan, Pulsedive, ONYPHE, EmailRep, GreyNoise via free API keys (web-page fallback when keyless); Settings → OSINT API Keys |
| 🗄️ **Evidence Preservation** | Wayback Machine availability check (no-key, flags no-history phishing pages) + urlscan.io one-click scan submit |
| 🔬 **CyberChef Decode** | One-click pre-loaded GCHQ CyberChef for safe offline IOC/encoding decoding from the Intel tab |
| 🔎 **urlscan.io Search** | Keyless public-search triage (IP/domain/URL → recent scans + verdicts) alongside the keyed scan-submit |
| 🌐 **Censys Host View** | Inline Censys Search API v2 (API ID + Secret): open ports/services, TLS cert subject/issuer, ASN/geo/DNS names |
| 🛰️ **Netlas Host Lookup** | Inline Netlas host API (free tier): ASN/netblock, geo, WHOIS, related domains, NS/MX + open ports/software |
| 🦠 **MalwareBazaar Hash** | Inline abuse.ch hash triage (free Auth-Key): signature/family, file info, first/last seen, tags, vendor detections |
| 🚨 **URLhaus Lookup** | Inline URLhaus dispatch (host/URL/hash): blacklist state (Surbl + Spamhaus DBL), VT ratio, payload drops, malware URLs |
| 🎯 **ThreatFox Search** | Inline ThreatFox IOC search (exact match): malware family, threat type, confidence, Malpedia links |
| 🛡️ **AlienVault OTX** | Keyless inline OTX indicator summary: ASN/geo, reputation, pulse count + names, false-positive notices |
| 🕵️ **Hudson Rock Cavalier** | Keyless infostealer-exposure check (email/domain): affected machines, exposed corporate+user creds, compromise dates, AV on infected, employee/third-party split |
| 📡 **DNS urlscan Search** | DNS Tools cross-integration: inline keyless urlscan.io public search for the domain field |
| 🤝 **MISP/STIX Sharing** | Import MISP event JSON / STIX 2.0 bundles / plain IOC lists into the intel DB (optional firewall-block of imported IPs); export the local indicator set as a MISP-format JSON event for SOC/peer sharing |
| 🌍 **Domain Investigation** | crt.sh certificate-transparency subdomain discovery (Certspotter fallback), Domain OSINT Stack deep-links (ViewDNS/DNSDumpster/MXToolbox/Wappalyzer/Netlas/ZoomEye/FullHunt + archives), email-security SPF/DMARC/DKIM DNS check |
| 🔑 **Pwned Passwords Check** | HIBP k-anonymity hash-range lookup (no API key — only 5 SHA-1 chars sent); alerts if a password appears in breach corpora |
| 🛡️ **DDoS Shield v30** | Auto-block flooders, rate monitor, block-all, export report, purge — persistent 24h-TTL blocklist restored at startup |
| 🧭 **Keyless Infra OSINT** | IPinfo.io ASN/geo/anycast/bogon, BGPView BGP routing graph (IP + ASN), HackerTarget reverse-IP/GeoIP/DNS/ASN recon — no API keys (v29.21) |
| ⚡ **Live Performance Tab** | Pause/resume monitoring, 2-30s interval slider, 28 sparkline gauges, per-core bars, top-CPU process table, live health score (v29.21) |
| ⚡ **Perf tab v29.28 overhaul** | Gauge label/sparkline overlap fixed, adaptive DISK/NET rate ceilings (needles readable on real traffic), GPU column in the top-process table, live NIC + disk-partition tables, scoped mousewheel |
| 🔄 **Warm perf history** | Gauges keep sampling + sparkline history/deltas and adaptive ceilings keep learning even while the Perf tab is hidden (v29.30b) |
| 📄 **PDF Report Export** | Compliance audit + NSA-style assessment export to real PDFs (reportlab); NSA report auto-persists to Documents/DownpourReports (v29.22) |
| 🎮 **Per-Process GPU Attribution** | Processes tab shows which PIDs run on the GPU (nvidia-smi compute-apps) with VRAM when readable (v29.23) |
| 🌐 **Browser-extension scan** | One-click scan of all installed browsers' extensions for risky manifest permissions (tabs/cookies/webRequest/debugger/clipboardRead/…) + matches browsers against the live CISA KEV catalog (v29.30) |
| 🛡️ **Risk-confirmation gates** | Destructive actions (kill process / block IP / quarantine / suspend / root-cause) now always ask before executing (v29.29) |
| 🌓 **Windows 11 dark title bar** | Immersive dark mode applied to the real top-level HWND + system-theme detection (v29.26) |
| 🌐 **Live DNS Overview** | DNS tab overview panel + threat score auto-refresh (60s throttled, busy-guard protected) (v29.32) |
| 💬 **Tooltips everywhere** | Every button in the Threats, Dashboard, Intel, DNS, WiFi, IoT, USB, Timeline, VPN, Hunt, Sandbox, Settings, and all remaining tabs now has hover help (v29.31–v29.35) |
| 🖥️ **System Tray** | pystray minimize-to-tray with Show/Hide/Exit menu (v29.20) |
| 🌧️ **Rain Overlay** | Animated rain that intensifies with threat level |
| 📶 **WiFi Security Analyzer** | Real-time WiFi network scanner with SSID/BSSID/signal/auth/cipher/band, evil-twin detection, security scoring (WPA3=100/WPA2=75/WEP=10/Open=0), saved password reveal, DNS leak test (v29.35) |
| 📱 **IoT Device Discovery** | Ping-sweep subnet scanner with MAC/vendor lookup, Mozi/Kimwolf botnet signature check, per-device block/unblock via netsh firewall rules, risk coloring (Critical/High/Medium/Low) (v29.35) |
| 🔌 **USB Guard** | Live USB device enumeration, Windows registry history scan, per-device whitelist with persistent save, alert log, monitor toggle with OS event hooks (v29.35) |
| 🕐 **Security Event Timeline** | Windows Security event log viewer (up to 2000 events), MITRE-aligned attack pattern detection (brute force / lateral movement / persistence), HTML export, quick-filter buttons per event ID (v29.35) |
| 📊 **60-Second History Chart** | Rolling sparkline timeline canvas in the Performance tab showing CPU%, RAM%, GPU%, and combined NET KB/s over the last 60 samples in real-time (v29.36) |
| 🚨 **Perf Threshold Alerts** | Auto-fires alerts into the main feed when CPU>90%, RAM>90%, CPU temp>85°C, GPU temp>85°C, Disk>95%, Swap>80% — with 120s cooldown to prevent spam; also detects CPU spikes >40% in one sample (v29.36) |
| ⚡ **Alert Rate Meter** | Status bar badge showing how many alerts fired in the last 60 seconds (⚡ N/min) with color coding: green→orange→red (v29.36) |
| 📊 **v29.42 New Features** | GPU Power Draw & Clock Speed monitoring, Real DNS latency measurement, Network packets/sec tracking, TCP state breakdown (TIME_WAIT, CLOSE_WAIT, SYN_SENT), Improved Windows load average with exponential moving average, and performance-optimized gauge rendering. Now features 129+ unique live gauges on the Performance tab (v29.42) |

---

## Installation

```bat
git clone https://github.com/christiand0797/downpour.git
cd downpour
LAUNCH_V29_TITANIUM.bat
```

The launcher installs all dependencies automatically on first run.

---

## Project Structure

```
downpour/
├── downpour_v29_titanium.py      ← Main application (51,800+ lines, 1,720+ methods)
├── LAUNCH_V29_TITANIUM.bat       ← v29 launcher (use this)
├── LAUNCH_DOWNPOUR.bat           ← v28 launcher (kept as backup)
├── requirements.txt
├── docs/
│   ├── CHANGELOG.md
│   ├── CRASH_TROUBLESHOOTING_GUIDE.md
│   ├── LAUNCHER_GUIDE.md
│   └── ...
├── yara_rules/                   ← YARA rule files
└── 40+ supporting modules        ← See table below
```

### Supporting Modules

| Module | Purpose |
|--------|---------|
| `advanced_threat_remediation.py` | 5-phase threat remediation engine |
| `ai_security_engine.py` | ML-powered anomaly detection + KEV correlation |
| `mega_threat_signatures.py` | 750+ malware family signature database |
| `memory_forensics.py` | Memory dump analysis, process injection detection |
| `kimwolf_botnet_detector.py` | Kimwolf/Botnet detector with 150+ IOCs |
| `ml_behavioral_analyzer.py` | Behavioral baseline + anomaly scoring |
| `ransomware_detector.py` | Entropy monitoring, shadow copy watch, canary files |
| `threat_intelligence.py` | Legacy 11-source threat-intelligence downloader (not wired into the main app) |
| `threat_intelligence_updater.py` | KEV/EPSS/CVE live update engine |
| `network_monitor.py` | Live connection analysis |
| `file_scanner.py` | YARA + hash scan engine |
| `usb_protection.py` | USB device monitoring and blocking |
| `browser_protection.py` | Extension audit, history analysis — **consolidated inline into the main app v29.30** (`_scan_browser_extensions`), kept as standalone reference |
| `advanced_device_profiler.py` | Device/privilege profiler — **declined for wiring** (evasion/bypass-capability oriented); not part of the shipped feature set |
| `vulnerability_scanner.py` | CVE-aligned vulnerability assessment |
| `system_hardening.py` | DISA-STIG automated hardening |
| `emergency_response.py` | Incident response automation |
| `email_security.py` | Phishing/malware email detection |
| `iot_scanner.py` | IoT device fingerprinting, Mozi/Kimwolf detection |
| + 22 more | See full file listing |

---

## YARA Rules (104)

Detects: **Mimikatz, CobaltStrike, Metasploit, Empire, PoshC2, AsyncRAT, NjRAT, QuasarRAT, LockBit, BlackCat, Clop, RedLine, Raccoon, DCSync, Kerberoasting, BloodHound, PlugX, Gh0stRAT, XMRig, GuLoader, Themida** and 20+ more.

---

## Configured Threat Feed Sources (34)

| Category | Count | Examples |
|----------|-------|---------|
| abuse.ch malware / C2 / hash feeds | 8 | URLhaus, Feodo Tracker, MalwareBazaar, ThreatFox, SSLBL |
| Spamhaus blocklists | 2 | DROP, EDROP |
| Phishing intelligence | 4 | PhishTank, OpenPhish, Phishing Army |
| Malware analysis | 3 | Malpedia, MalShare, VirusShare |
| C2 tracking | 2 | Malware Traffic Analysis, Fox-IT Cobalt Strike |
| DNS security | 3 | HaGeZi, StevenBlack, AdGuard DNS |
| IP reputation | 5 | AbuseIPDB, Binary Defense, CINS, Blocklist.de |
| YARA rule sources | 2 | Yara-Rules, Malpedia |
| CVE / exploit data | 3 | CISA KEV, NVD, ExploitDB |
| MISP community sources | 2 | CIRCL MISP, MISP Project |

---

## System Requirements

- **OS**: Windows 10 / 11 (64-bit)
- **Python**: 3.12 recommended. **Avoid 3.15 / pre-release builds** — verified this session that matplotlib, Pillow, pystray, netifaces, and scipy have no compiled wheels for 3.15 alpha and fail to build with no C compiler present. Python 3.12 installs all 20 dependencies cleanly.
- **RAM**: 4 GB minimum, 8 GB recommended
- **Privileges**: Administrator (for Defender exclusions, firewall rules, network isolation)
- **GPU**: Optional (NVIDIA — enables accelerated scans)

---

## Changelog

See [`docs/CHANGELOG.md`](docs/CHANGELOG.md) for full details.

**v29.42f**: GPU `GPUTIL` fallback now tried even when `NVML` present but `gpu_percent==0` (headless / no GPU) — previously `elif` never fired, gauges stayed `0` instead of `N/A`/GPUTIL. WMI `MSAcpi_ThermalZoneTemperature` duplicate `except` and broken cache write-back fixed (30s throttle now actually caches). 93/93 tests.

**v29.42e**: WMI `MSAcpi_ThermalZoneTemperature` COM call (~300 ms) throttled to 30s with `psutil.sensors_temperatures()` fast-path first, cache write-back fixed. Warm fetch stays ~1.3s. 93/93 tests.

**v29.42d**: Hardened silent `except: pass` that hid the `0xc0000005` crash — `HwMonitor` bg loop (`17392`) and `IntelFeedHealth` loader (`38733`) now `error_logger.log` instead of swallowing, so `Pending` status and `0%` gauges are traceable. 93/93 tests.

**v29.42c**: Pruned 12 dead/non-IOC feed sources that bloated `titanium.db` and wasted 48 MB parallel fetch budget every tick: `disconnect_track/mal/ad` (3 tracking lists), `hagezi_pro/tif/ultimate/multi` (4 adblock, 300-700k domains each), `easylist/easyprivacy/fanboy_annoyance` (3 adblock), plus `malshare`/`virusshare` API endpoints (always 403 anon). Kept one DNS blocklist (`hagezi_light`) for DNS security. `Malware Patrol` and `C2IntelFeeds` already present as keyless replacements. 93/93 tests.

**v29.42b**: Merged 4× unthrottled full-system walks that defeated live cadence: `process_count/thread_count` (2 walks every 1-3s → 10s cache), `disk_partitions` (recomputed every tick, cache write-back missing → 60s cache), `net_connections` (3 walks per tick → single per-tick `_get_net_conns()` cache), WMI thermal (~300 ms COM every tick → 30s throttle + `sensors_temperatures()` fast path). Warm fetch `2.16s → 1.32s`. 93/93 tests.

**v29.42a**: Fixed the Perf tab "black box covers parts of the gauges" — the dark sparkline strip (`#06080f` at `size+26..+42`) sat only ~8 px below the gauge label (`size+8`), so the strip visually touched the label. Canvas raised to `SIZE+60` (was +52), label to `size+10`, strip to `size+30..+46` (20 px gap, 14 px bottom margin). 93/93 tests.

**v29.41k5h**: Fixed the **native crash** (`0xc0000005` in `_psutil_windows.pyd`, k9 smoke at 60 min) — psutil keeps global mutable state (`_pmap` in `process_iter`, `_LOWEST_PID`, shared C buffers in `net_connections`/`cpu_percent`) with no module lock, so concurrent calls from the hw-monitor thread, Perf-tab executor fetch, heartbeat timer and scan workers corrupted the C buffers. Added a process-wide `_PSUTIL_LOCK` (RLock) wrapping 19 psutil system-wide functions (`process_iter`, `pids`, `net_connections`, `cpu_percent`, `cpu_times`, `virtual_memory`, …) via module attribute patching, so every `import psutil` in the app hits the locked wrappers (generators hold the lock for the whole iteration). `HardwareMonitor._fetch` also gained **single-flight** coalescing: concurrent callers (bg thread vs Refresh Now) now share one sweep instead of running duplicate 3-9 s sweeps. Perf sweep itself cut from ~9 s to ~3 s: `open_files` now uses `num_handles()` (~6× cheaper) and `process_iter(['status'])` is cached to a 10 s snapshot (was 2× per tick). 93/93 tests.

**v29.41k5g**: Squashed the post-k5f FREEZE class. With DB reads off the writer lock, the remaining 1.6-2.4s main-thread blocks were `_apply_feed_health` re-issuing per-row `tree.item('tags')`/`tree.set`/`tree.item(tags=)` Tcl round-trips on *every* periodic Intel-tab refresh — a few hundred Tcl calls even when nothing changed, GIL-starving the Tk client under the writer/training storm. The refresh now renders **change-detection** via a `_feed_health_rendered` cache: rows whose `(value, tags)` are unchanged issue **zero** Tcl calls (base tag is reused from the cache), and stale iids are pruned when rows disappear. 92/92 tests.

**v29.41k5f**: Killed the main-thread DB-read stalls (the startup/intel FREEZE warnings). The single persistent WAL connection was locked with one global RLock held by BOTH readers and writers — so a main-thread `SELECT count(*)` blocked behind every background bulk `executemany` (fsync-bound BEGIN/COMMIT batches). `Database` now keeps a dedicated **reader connection** (`_read_conn`, own `_read_lock`): pure reads route there and never wait for writers; WAL guarantees a consistent snapshot per read. Writers keep the original connection/lock untouched. Verified: 50 reads in 0.005s *total* while a writer hammered 200-row batch inserts continuously. 91/91 tests.

**v29.41k5e**: Fixed the DNS live-monitor's duplicate-row/alarm-spam bug. The DNS client cache is a full snapshot, so the 3s poll re-returned every cached entry each cycle — identical rows inserted forever, `Queries` count ratcheted endlessly, and the same threatening domain re-fired its alert on every poll. Now a seen-set of `(domain,data,type)` keys skips already-observed entries (only genuinely new DNS activity inserts/counts/alerts), the live-monitor count label reads `Queries: n` instead of `Cache entries: n`, and Clear resets the seen-set so the view re-captures. 90/90 tests.

**v29.41k5d**: Full audit of every `urllib.request.urlopen` call site — the VPN tab's Mirror-2 server-list fetch (`lab.mahidol.ac.th`) was the last plain-HTTP-only egress; it now tries `https://` first and falls back to `http://` only on failure. All remaining 30+ fetch sites verified HTTPS or user-configured. 89/89 tests.

**v29.41k5c**: Intel feed fetches are now HTTPS-first with a plain-HTTP fallback. `_fetch_feed` previously hard-locked a small set of hosts (`sysctl.org`, `data.phishtank.com`, `pgl.yoyo.org`, `someonewhocares.org`) to plain `http://` forever (via `_HTTP_OK`) and skipped any feed whose HTTPS fetch failed outright. Every feed now tries HTTPS first (permissive SSL context for the expired/self-signed-cert hosts, which still complete the handshake), and falls back to `http://` only if HTTPS fails — same pattern as the geo helper. `_HTTP_OK` removed. 88/88 tests.

**v29.41k5b**: Made the Network tab's Country column live for the first time (it was hard-coded empty forever) — async keyless ip-api.com lookups populate it for public IPs while private IPs stay blank, defaulting to `--` on failure. Added a single shared HTTPS-first/HTTP-fallback `_ip_api_get` helper and routed all five geo call sites through it (live Country column, Intel tab GeoIP, alert-ac-tion GeoIP, Net tab Geo-Locate, alert-feed `_geolocate_one`); previously four of them were plain-HTT-P only (free tier is HTTP-only). 87/87 tests.

**v29.41k5**: Killed the scan-worker/joblib thread explosion. sklearn 1.9.0 + joblib 1.5.3 deadlock inside joblib's `_retrieve` whenever `predict_proba`/`decision_function` were called from inside a `ThreadPoolExecutor` worker — every 60s `scan_all()` leaked a fresh 9-worker pool stuck forever (observed **176 → 341 threads in ~50 min**, RSS crawling toward 2.56GB). Fitted estimators now force `n_jobs = 1` post-fit (single-sample inference gains nothing from nested joblib); `scan_all()` got an overlap guard (`_scan_in_progress`, never starts while a scan is draining) and abandons wedged pools (`as_completed(futures, timeout=90)` + `shutdown(wait=False, cancel_futures=True)`) so `_proc_loop` can never pile pools up again. Perf tab now runs on genuinely live data too: the ~8.5s `open_files` walk is sampled every 15s instead of every tick (fetch cadence restored from ~14s to ~3s), and the top-processes table gained live **RSS MB, per-process disk I/O KB/s, and active connection count** columns. Also made all 16 worker-thread `winfo_exists()` sites Tcl-safe (`_tk_alive` flag + `_winfo_ok()` helper). 86/86 tests.

**v29.41k4**: Fixed the phantom main-process memory leak. Parse-pool worker children (ProcessPoolExecutor under Windows `spawn`) were importing the memory-manager singleton and running their OWN tracemalloc + monitor threads, flooding the log with the worker's memory view (166–183MB parse/gzip buffers) and slowing the children so the parent pool queue backed up — RSS appeared to ratchet and leak reports fired every 2–5 min (16–116 MB/min). Workers now self-identify (`_is_spawn_child`) and neutralize tracing/monitoring. Leak detection also now measures **this process's own RSS** instead of system-wide `used_bytes` (which counted other apps and caused false 87–110 MB/min alarms), logs top allocation sites + gc type counts, and the monitor loop no longer sleeps the undefined `interval` (60s instead of 15/30s). Verified: main PID RSS flat at ~660–665MB across a full 10-min staggered wave cycle, waves spike then release to baseline, zero leak reports post-fix. 75/75 tests.

**v29.41k3**: Eliminated the boot-time startup freezes caused by a CPU/IO storm that starved the Tcl interpreter lock (9.3–53.8s blocks at boot). Root cause: intel auto-update (**now enabled by default**) running the legacy feed updater AND the new staggered engine simultaneously — both downloaded the same OSINT feeds; plus heavy in-thread sklearn fits and per-call process pools. The legacy `_scheduled_feed_update` now stands down when auto-update is on; `update_staggered` parses on ONE shared 2-worker process pool with 120s timeouts; sklearn model training defers ~60s and caps `n_jobs` at 2. Verified: zero FREEZE logs across a full boot + staggered feed run (feed_status rows written live, mainloop responsive). 75/75 tests.

**v29.41k**: Eliminated the recurring main-thread GUI freezes (1.5–28.5s). Rain canvas got full adaptive degradation — EMA backoff, rotating drop stride (linear in measured frame cost), cosmetic-layer gating, itemconfig caching, and a hard-freeze hysteresis that holds a static sky under load then resumes at peak back-off with a probe window. The Network tab's diff-based Treeview refresh was the other major blocker (6–21.5s sampled) — it now hard-skips off-screen and diffs a rotating 60-row slice per pass. Zero FREEZE logs in a 13-min steady-state run (was 2–26.7s every few seconds). 75/75 tests.

**v29.41k2**: Killed the residual 1.5–21.4s freezes that returned under sustained load. The three sub-200ms periodic drain loops (`_early_drain`, `_drain_alert_queue`, `_schedule_ui_updates`) now use idle backoff (1s/500ms idle vs 150–200ms busy) so they stop stacking Tcl backlog. The rain drop stride is now derived from the **measured per-coords() call cost** against a ~50ms/frame budget (not the oscillating frame EMA), and cosmetic layers stay gated off whenever canvas ops are intrinsically expensive — both self-regulate, so no more 10s frames or freeze/resume cycling. Zero FREEZE logs over a 6-min steady-state run at ~34% CPU. 75/75 tests.

**v29.41j**: Wired 4 more dead Performance-tab gauges (MALWARE DETECTED / PHISHING URLS / SUSPICIOUS DNS / FILE THREATS) to the live threat-intel manager — they read never-assigned attributes and were stuck at 0. 75/75 tests.

**v29.41i**: Wired the last dead Perf-tab gauges — SEC EVENTS now increments in the alert queue, and OSINT LOOKUPS/TODAY/CACHE increment from live IP/URL/hash lookups (all four were read-only, stuck at 0 forever). 74/74 tests.

**v29.41h**: Fixed two vulnerability-scanner scan crashes (psutil cmdline/username can be `None` → join/endswith crashes) and gave the per-tick CEV reader a 30s DB timeout (was "database is locked" during long feed writes). 73/73 tests.

**v29.41g**: Scheduled OSINT feed updates and feed-health checks now run in daemon threads — previously `update_all_feeds()` (URLhaus csv_recent ingest) ran on the Tk main thread and froze the GUI for minutes.

**v29.41f**: Fixed every OSINT feed update crashing (`_record_feed_history` method was missing; threatfox/urlhaus/phishtank/malwarebazaar all failed silently). Cached `VulnerabilityScanner` on the monitor — its DB init ran fresh every fetch tick (~every 15s logged), now once at startup. 71/71 tests.

**v29.41e**: Cached `ThreatIntelligenceManager` on the monitor (DB init in `__init__` was run 3× per fetch tick).

**v29.41d**: Net anomaly gauges (PORT SCAN/EXFIL/DNS TUN/LATERAL) served by throttled live `net_monitor` alert classification; process anomaly gauges classify the live scan; EXFIL/H now the net gauge with setdefault precedence; `c2_servers_total` live.

**v29.41c**: Completed the Performance-tab live-data pipeline: file gauges now read the live `RansomwareDetector` deques, PROC/NET THREAT gauges read live scanned processes + connection alerts, and all 8 behavior gauges classify `[BEHAVIOR]` findings from the continuous scan loop — the orphan `file_monitor`/`network_monitor`/`process_monitor`/`behavior_scanner` modules (never started anywhere) no longer leave 23 gauges stuck at zero.

**v29.41b**: PROC/NET THREAT gauges read the app's live process list + `net_monitor` alerts instead of never-started orphan modules; `nm`/`pm` stay bound for the finer anomaly gauges.

**v29.41**: File gauges on the Performance tab now read from the app's live `RansomwareDetector` per-hour file-change counts (the previously-wired `file_monitor` module was never started, so MOD/CREATE/DELETE/SUS-CREATE/RANSOM gauges could never move). `HardwareMonitor` gets an app backref, graceful fallback retained, 3 new regression tests.

**v29.40** (latest): Fixed the Python 3.13+ boot crash (`logging.handlers` import) and the alpha-Python wheel breakage. Completed the live Performance data pipeline — ~15 file/behavior anomaly gauges were silently stuck at 0 (undefined variable refs), swap/page-fault rates now live, perf-loop in-flight guard + adaptive interval honored, 10s safety timer finally scheduled, gauge grid deduplicated to 129 unique live gauges. 10 new regression tests (60/60 passing).

**v29.36**: 60-second CPU/RAM/GPU/NET history timeline chart, performance threshold auto-alerts (CPU/RAM/Temp/Disk spike detection with 120s cooldown), alert rate meter in the status bar (⚡ N/min), 5 new passing tests.

**v29.35**: Completed Phase 3 tooltip sweep — all 113 buttons across every tab now have hover help. Added WiFi Security Analyzer, IoT Device Discovery, USB Guard, and Security Event Timeline tabs with full functionality.

**v29.34**: Full tooltip sweep across Threats, Dashboard, Scanner, DNS, Firewall, Hardening, Processes, Hunt, and remaining tabs (41 buttons covered in one session).

**v29.33**: Tooltip support added to all 5 DNS button-factory helpers (~30 DNS buttons), complete per-button help text for all DNS sub-tabs.

**v29.32**: Live DNS Overview panel now auto-refreshes (60s throttle, busy-guard, 180s stuck-fetch reset).

**v29.28–v29.31**: Gauge label/sparkline overlap fix, adaptive DISK/NET ceilings, GPU column in process table, live NIC + partition tables, warm history sampling, scoped mousewheel.

**v29 highlights:** 10 critical bug fixes from live crash logs, one-click Remediate All, 104 YARA rules, 85+ MITRE techniques, six-file FIM integrity checks, COM crash eliminated, auto-remediate toggle, threat detail panel, IR report generator, proactive threat hunt engine (LOLBAS/persistence/BYOVD/canaries), and a live CISA KEV feed with rate-limit-safe enrichment.
Personal project, work in progress. Not a replacement for enterprise security software. Some features make real system changes (firewall rules, registry edits, Defender exclusions). Use at your own risk.

---

## Author

**Christian** — [@christiand0797](https://github.com/christiand0797)

*Built because sometimes you just want to know exactly what's running on your machine.*
