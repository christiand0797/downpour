# ⛈ Downpour — Advanced Personal Security Suite

> **Downpour v29 Titanium** — Personal antivirus, anti-malware, anti-RAT, and comprehensive Windows threat-defense platform built in Python.

<p align="center">
  <img src="https://img.shields.io/badge/version-v29%20Titanium-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/platform-Windows%2010%2F11-0078d7?style=for-the-badge&logo=windows" />
  <img src="https://img.shields.io/badge/python-3.12%2B-yellow?style=for-the-badge&logo=python" />
  <img src="https://img.shields.io/badge/status-active%20WIP-brightgreen?style=for-the-badge" />
  <img src="https://img.shields.io/badge/YARA%20rules-45%2B-red?style=for-the-badge" />
  <img src="https://img.shields.io/badge/threat%20feeds-289%2B-orange?style=for-the-badge" />
</p>

---

## What is Downpour?

Downpour is a personal, all-in-one Windows security suite — written entirely in Python with a Tkinter/CTk GUI — that covers every attack surface a modern threat actor might exploit.

| Domain | What Downpour Does |
|--------|--------------------|
| 🦠 **Antivirus / Antimalware** | 45+ YARA rules, SHA-256 hash IOC lookup, entropy-based packer detection, magic-byte mismatch flagging |
| 🐀 **Anti-RAT / Anti-C2** | Kimwolf/Botnet detector, C2 feed matching (Feodo, Bambenek, Blackbook, C2IntelFeeds), named-pipe C2 |
| 🔴 **Remediate All** | One-click: kill processes, block IPs, quarantine files, remove persistence — for ALL active threats |
| 🔥 **Firewall Manager** | netsh advfirewall integration, rule creation/deletion, Block ALL C2 in one click |
| 🌐 **Network Monitor** | Live connection map, IP reputation, bandwidth graph, ARP spoof detection, geo-location |
| 🧬 **Process Monitor** | Kill ALL suspicious, Quarantine ALL, Export CSV, real-time injection detection |
| 📁 **File Integrity Monitor** | 35+ critical system files, SHA-256 baseline drift detection, streaming hash |
| 🔑 **Credential Guard** | LSASS dump detection, HVCI/PPL/VBS status, Kerberoasting alerts |
| 🛡️ **Windows Hardening** | 40+ DISA-STIG checks, Fix ALL Hardening in one click |
| 📡 **DNS Security** | DoH provider switcher, DNS rebind detection, canary monitoring, poison detection |
| 🖥️ **Hardware Monitor** | CPU/RAM/GPU/Disk gauges, threat-reactive rain overlay |
| 🔌 **USB Guard** | New device alerting, auto-disable untrusted devices |
| 📶 **WiFi Analyzer** | SSID scan, evil-twin detection heuristics |
| 📅 **Security Event Timeline** | Windows Event Log correlation (4624/4625/4688/5156) |
| 🕵️ **MITRE ATT&CK Mapping** | 85+ technique tags auto-applied to every alert |
| 🚨 **AEGIS 5-Layer Defense** | Physical, TCP, Ingest, NLP, Memory — concurrent threat correlation |
| 📊 **IR Report** | One-click full HTML Incident Response report |
| 🌧️ **Rain Overlay** | Animated rain that intensifies with threat level |

---

## v29 Titanium - Bug Fixes

- **FIX**: All v28 references → v29 (title/banner/loading screens)
- **FIX**: RemediationAction.action → .action_type + .description  
- **FIX**: USB monitor crash on window close (winfo_exists check)
- **FIX**: Firewall duplicate item prevention (_fw_filtering flag)
- **FIX**: nvidia-ml-py import (removed deprecated pynvml)
- **FIX**: sklearn warnings silenced
- **FIX**: COM init on ThreadPoolExecutor threads
- **Performance**: 24fps rain animation with delta-time compensation
- **Performance**: Pre-allocated canvas items (no alloc/dealloc during render)

---

## Quick Start

```bat
:: Run as Administrator for full features
LAUNCH_V29_TITANIUM.bat
```

---

## Architecture

```
downpour_v29_titanium.py          ← Main application (45,600+ lines)
├── Project AEGIS                 ← 5-layer concurrent defense engine
├── 289 Threat Intel Feeds        ← IP/domain/hash/URL/C2/CVE
├── 45+ YARA Rules                ← LockBit, BlackCat, Mimikatz, Metasploit...
├── MITRE ATT&CK Engine           ← 85+ technique auto-tagging
├── Kimwolf Botnet Detector       ← Mozi, Mirai, BadBox2 + 150 IOCs
├── FIM Engine                    ← 35+ critical file baseline monitoring
├── Rain Overlay                  ← Threat-reactive animated background
└── 24 UI Tabs                    ← Lazy-loaded, thread-safe
```

### Supporting Modules (18 total)

| Module | Purpose |
|--------|---------|
| `advanced_threat_remediation.py` | 5-phase threat remediation engine |
| `ai_security_engine.py` | ML-powered anomaly detection |
| `mega_threat_signatures.py` | 10,000+ IOC signature database |
| `memory_forensics.py` | Memory dump analysis and process injection detection |
| `kimwolf_botnet_detector.py` | Kimwolf/Botnet family detector with 150+ IOCs |
| `ml_behavioral_analyzer.py` | Behavioral baseline + anomaly scoring |
| `ransomware_detector.py` | Entropy monitoring, shadow copy watch, canary files |
| `threat_intelligence.py` | 289-feed threat intel aggregator |
| `network_monitor.py` | Live connection analysis |
| `file_scanner.py` | YARA + hash scan engine |
| `usb_protection.py` | USB device monitoring and blocking |
| `browser_protection.py` | Browser extension audit, history analysis |
| `vulnerability_scanner.py` | CVE-aligned vulnerability assessment |
| `system_hardening.py` | DISA-STIG automated hardening |
| `emergency_response.py` | Incident response automation |
| `enhanced_logging.py` | Structured security event logging |
| `email_security.py` | Phishing/malware email detection |
| `iot_scanner.py` | IoT device fingerprinting and Mozi/Kimwolf detection |

---

## Threat Intelligence Feeds (289+)

| Category | Count | Sources |
|----------|-------|---------|
| IP Reputation | ~80 | Blocklist.de, FireHOL, IPSUM, Emerging Threats, CINSscore |
| Domain Blocklists | ~90 | Hagezi, StevenBlack, OISD, AdGuard, PhishingArmy |
| C2 Tracking | ~20 | Feodo, Bambenek, C2IntelFeeds, ThreatView, Blackbook |
| URL Feeds | ~15 | URLhaus, OpenPhish, PhishTank |
| Malware Hashes | ~10 | MalwareBazaar, YARAify |
| CVE / Exploit | ~10 | CISA KEV, ExploitDB, MITRE ATT&CK |
| Ransomware | ~5 | Maltrail, RansomWatch |
| DNS Security | ~15 | Hagezi (5 tiers), NoTrack, AdGuard DNS |
| Privacy / Ads | ~15 | EasyList, EasyPrivacy, Fanboy |
| Tor / VPN / Proxy | ~10 | Tor Project, X4BNet, TheSpeedX |

---

## YARA Rules (45+)

Detects: Mimikatz, CobaltStrike, Metasploit, Empire, AsyncRAT, NjRAT, QuasarRAT, LockBit, BlackCat, Clop ransomware, RedLine, Raccoon infostealers, DCSync, Kerberoasting, BloodHound, PlugX, Gh0stRAT, XMRig cryptominer, GuLoader, Themida packer, and 20+ more.

---

## System Requirements

- **OS**: Windows 10 / 11 (64-bit)
- **Python**: 3.12+
- **Privileges**: Administrator (for Defender exclusions, firewall rules, network isolation)
- **RAM**: 8 GB recommended (4 GB minimum)
- **CPU**: 4+ cores recommended

---

## Installation

```bat
git clone https://github.com/christiand0797/downpour.git
cd downpour
pip install -r requirements.txt --break-system-packages
LAUNCH_DOWNPOUR.bat
```

---

## Changelog

### v29 Titanium (Current)
- **CRASH FIX**: `0x800401f0 CO_E_NOTINITIALIZED` — all 3 ThreadPoolExecutors now init COM on every worker thread
- **CRASH FIX**: `RemediationAction.action` AttributeError → `.description` + `.action_type`
- **SPAM FIX**: sklearn warning flood silenced
- **ONE-CLICK REMEDIATE ALL**: Kill, quarantine, block, clean all active threats in one button
- **Dashboard power buttons**: Remediate All, Kill Suspicious, IR Report, Isolate Host, Fix ALL Hardening
- **Network power buttons**: Block ALL C2, Kill C2 Procs, Whitelist IP, Export CSV
- **Process power buttons**: Kill ALL Suspicious, Quarantine ALL, Export CSV, Scan EXE
- **Emergency power buttons**: Quarantine ALL, Wipe Temp/Cache, Full IR Report
- **Threat Detail Panel**: Split-pane with full description, MITRE tag, quick-action buttons
- **Auto-Remediate toggle**: Auto-remediates CRITICAL threats on arrival
- **YARA rules**: 25 → 45 (LockBit, BlackCat, Clop, RedLine, Raccoon, Metasploit, AsyncRAT, NjRAT, DCSync, Kerberoasting, BloodHound...)
- **Behavioral heuristics**: 8 → 40+ cmdline patterns
- **MITRE ATT&CK**: 45 → 85+ techniques with multi-keyword scoring
- **FIM**: 6 → 35 critical system files with baseline drift detection
- **All `shell=True` eliminated** — command injection hardened
- **190 subprocess calls** — all have explicit `timeout=` values

---

## ⚠️ Disclaimer

Personal project, work in progress. Not a replacement for enterprise security software. Some features require Administrator privileges and make real system changes. Use at your own risk.

---

## Author

**Christian** — [@christiand0797](https://github.com/christiand0797)

*Built because sometimes you just want to know exactly what's running on your machine.*
