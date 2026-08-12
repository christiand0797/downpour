# ⛈ Downpour — Advanced Personal Security Suite

> **Work in progress** — Personal antivirus, anti-malware, anti-RAT, and comprehensive Windows threat-defense platform built in Python with a full Tkinter GUI.

<p align="center">
  <img src="https://img.shields.io/badge/version-v29%20Titanium-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078d7?style=for-the-badge&logo=windows" />
  <img src="https://img.shields.io/badge/python-3.12%20recommended-yellow?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/status-active%20WIP-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/YARA%20rules-104-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/threat%20feeds-34%2B-orange?style=for-the-badge" />
  <img src="https://img.shields.io/badge/MITRE%20techniques-81-purple?style=for-the-badge" />
  <img src="https://img.shields.io/badge/tabs-27-teal?style=for-the-badge" />
</p>

---

## What is Downpour?

Downpour is a personal, all-in-one Windows security suite — written entirely in Python — that covers every attack surface a modern threat actor might exploit. It runs as a standalone GUI application with 24 tabs, live threat gauges, an animated rain overlay that intensifies with threat level, and one-click remediation for everything it detects.

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
| 📁 **File Integrity Monitor** | 35 critical system files, SHA-256 baseline drift detection |
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
| 📋 **Live CISA KEV Feed** | 1,650+ actively-exploited CVEs, rate-limit-safe NVD CVSS enrichment |
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
| 📡 **DNS urlscan Search** | DNS Tools cross-integration: inline keyless urlscan.io public search for the domain field |
| 🤝 **MISP/STIX Sharing** | Import MISP event JSON / STIX 2.0 bundles / plain IOC lists into the intel DB (optional firewall-block of imported IPs); export the local indicator set as a MISP-format JSON event for SOC/peer sharing |
| 🌍 **Domain Investigation** | crt.sh certificate-transparency subdomain discovery (Certspotter fallback), Domain OSINT Stack deep-links (ViewDNS/DNSDumpster/MXToolbox/Wappalyzer/Netlas/ZoomEye/FullHunt + archives), email-security SPF/DMARC/DKIM DNS check |
| 🔑 **Pwned Passwords Check** | HIBP k-anonymity hash-range lookup (no API key — only 5 SHA-1 chars sent); alerts if a password appears in breach corpora |
| 🛡️ **DDoS Shield v30** | Auto-block flooders, rate monitor, block-all, export report, purge — persistent 24h-TTL blocklist restored at startup |
| 🌧️ **Rain Overlay** | Animated rain that intensifies with threat level |

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
├── downpour_v29_titanium.py      ← Main application (44,900+ lines)
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
| `threat_intelligence.py` | 289-feed threat intel aggregator |
| `threat_intelligence_updater.py` | KEV/EPSS/CVE live update engine |
| `network_monitor.py` | Live connection analysis |
| `file_scanner.py` | YARA + hash scan engine |
| `usb_protection.py` | USB device monitoring and blocking |
| `browser_protection.py` | Extension audit, history analysis |
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

## Threat Feeds (34)

| Category | Count | Examples |
|----------|-------|---------|
| IP Reputation | ~80 | Blocklist.de, FireHOL, IPSUM, Emerging Threats |
| Domain Blocklists | ~90 | Hagezi, StevenBlack, OISD, AdGuard |
| C2 Tracking | ~20 | Feodo, Bambenek, C2IntelFeeds, Blackbook |
| URL Feeds | ~15 | URLhaus, OpenPhish, PhishTank |
| Malware Hashes | ~10 | MalwareBazaar, YARAify |
| CVE / Exploit | ~10 | CISA KEV, ExploitDB, MITRE ATT&CK |
| Ransomware | ~5 | Maltrail, RansomWatch |
| DNS Security | ~15 | Hagezi (5 tiers), NoTrack |

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

**v29 highlights:** 10 critical bug fixes from live crash logs, one-click Remediate All, 45+ YARA rules, 85+ MITRE techniques, 35-file FIM with drift detection, COM crash eliminated, auto-remediate toggle, threat detail panel, IR report generator, proactive threat hunt engine (LOLBAS/persistence/BYOVD/canaries), live CISA KEV feed (1,650+ CVEs, rate-limit-safe).

---

## ⚠️ Disclaimer

Personal project, work in progress. Not a replacement for enterprise security software. Some features make real system changes (firewall rules, registry edits, Defender exclusions). Use at your own risk.

---

## Author

**Christian** — [@christiand0797](https://github.com/christiand0797)

*Built because sometimes you just want to know exactly what's running on your machine.*
