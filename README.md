# ⛈ Downpour — Advanced Personal Security Suite

> **Work in progress** — Personal antivirus, anti-malware, anti-RAT, and comprehensive Windows threat-defense platform built in Python with a full Tkinter GUI.

<p align="center">
  <img src="https://img.shields.io/badge/version-v29.36%20Titanium-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078d7?style=for-the-badge&logo=windows" />
  <img src="https://img.shields.io/badge/python-3.12%20recommended-yellow?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/status-active%20WIP-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/YARA%20rules-104-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/threat%20feeds-34%2B-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/MITRE%20techniques-85%2B-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/tabs-27-teal?style=for-the-badge" />
  <img src="https://img.shields.io/badge/tests-60%2B%20passing-brightgreen?style=for-the-badge" />
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
