# Downpour v29 Titanium — Module Map

> Last updated: 2026-08-14 (v29.40)

## Architecture Overview

```
downpour_v29_titanium.py (52,600+ lines)
├── Core Application (class downpour(tk.Tk))
│   ├── __init__: Window setup, theme, state initialization
│   ├── _build_ui: 27-tab notebook, status bar, search bar, rain overlay
│   ├── _auto_start: Deferred startup (AEGIS, feeds, loops)
│   └── _shutdown: Graceful teardown (threads, tray, DB)
│
├── Detection Engines
│   ├── AIEnhancedThreatDetector: ML-based threat scoring (IsolationForest/RandomForest/MLP)
│   ├── IntelligentThreatDetector: Heuristic + behavioral threat detection
│   ├── AdvancedProcessScanner: Process enumeration + suspicious behavior flagging
│   ├── PortScanDetector: Network port scan detection
│   ├── RansomwareDetector: Honeytoken canary files + encryption pattern detection
│   ├── RootkitDetector: Hidden process/driver/registry detection
│   ├── BootkitDetector: MBR/EFI boot integrity verification
│   └── CisaKevEngine: CISA Known Exploited Vulnerabilities matching
│
├── AEGIS 5-Layer Defense Framework
│   ├── Layer 1: AegisDataNeutralizer (data sanitization)
│   ├── Layer 2: AegisVault (encrypted storage)
│   ├── Layer 3: AegisMemoryDefense (memory protection)
│   ├── Layer 4a: AegisAntiDebug (debugger detection)
│   ├── Layer 4b: AegisTorRouter (anonymization)
│   ├── Layer 4c: AegisWFPBlocker (Windows Filtering Platform)
│   └── Orchestrator: AegisOrchestrator (coordination)
│
├── Threat Intelligence
│   ├── SecureThreatIntelligenceDownloader: Feed fetching + parsing
│   ├── ThreatIntelEngine: IOC correlation + enrichment
│   ├── ThreatLearningEngine: ML pattern learning
│   ├── YaraEngine: 104 YARA rule matching
│   └── KnownThreats: 750+ malware family signatures
│
├── Infrastructure
│   ├── HardwareProfile: System capability detection + adaptive tuning
│   ├── PerformanceOptimizer: Resource management + GC scheduling
│   ├── PerformanceCache: TTL + LRU caching layer
│   ├── Database: SQLite wrapper with thread-safe locking
│   ├── ErrorLogger: Structured logging with rotation
│   ├── ConfigManager: JSON-based persistent configuration
│   └── FalsePositiveDB: Alert suppression management
│
└── UI Components
    ├── ImmersiveRainCanvas: Animated rain overlay (threat-level reactive)
    ├── ColorScheme/Colors: Centralized theme tokens
    └── 27 Tab Builders (_build_*_tab methods)
```

## External Modules

### Active (imported by main app)

| Module | Size | Purpose | Import Guard |
|--------|------|---------|-------------|
| `kimwolf_botnet_detector.py` | 37KB | Botnet C2 domain/IP/MAC detection | try/except ImportError |
| `enhanced_memory_manager.py` | 13KB | Advanced memory tracking + GC optimization | try/except ImportError |
| `security_hardening.py` | 17KB | Windows security configuration hardening | try/except ImportError |
| `defender_compatibility.py` | 17KB | Windows Defender exclusion management | try/except ImportError |
| `enhanced_logging.py` | 10KB | Structured rotating log handler | try/except ImportError |
| `revolutionary_enhancements.py` | 24KB | Quantum/neural security placeholders | try/except ImportError |
| `gpu_detector_fix.py` | 9KB | GPU detection (NVML→nvidia-smi→GPUtil→WMI) | try/except ImportError |

### Standalone (not imported by main app)

| Module | Size | Purpose | Status |
|--------|------|---------|--------|
| `advanced_threat_engine.py` | 116KB | Extended threat detection engine | Orphan — not wired |
| `advanced_threat_analyzer.py` | 42KB | Behavioral threat analysis | Orphan — not wired |
| `advanced_file_analyzer.py` | 35KB | Deep file analysis (PE/Office/PDF) | Orphan — not wired |
| `advanced_gauge_system.py` | 36KB | Alternative gauge rendering | Orphan — not wired |
| `advanced_hardware_monitor.py` | 40KB | Extended hardware telemetry | Orphan — not wired |
| `advanced_threat_remediation.py` | 63KB | Automated threat response | Orphan — not wired |
| `ai_security_engine.py` | 33KB | AI-powered security analysis | Orphan — not wired |
| `behavior_scanner.py` | 60KB | Process behavior monitoring | Orphan — not wired |
| `behavioral_analyzer.py` | 18KB | Behavioral baseline + anomaly scoring | Orphan — not wired |
| `ml_behavioral_analyzer.py` | 23KB | ML-based behavioral analysis | Orphan — not wired |
| `ml_optimization_engine.py` | 29KB | Performance tuning via ML | Orphan — not wired |
| `threat_detection_engine.py` | 34KB | Alternative threat detection | Orphan — not wired |
| `threat_intelligence.py` | 79KB | Legacy 11-source intel downloader | Replaced by inline |
| `threat_feed_aggregator.py` | 45KB | Feed aggregation framework | Orphan — not wired |
| `threat_intelligence_updater.py` | 32KB | Feed update scheduler | Orphan — not wired |
| `threat_hunt_engine.py` | 23KB | Standalone threat hunting | Orphan — not wired |
| `threat_response_center.py` | 46KB | Incident response coordination | Orphan — not wired |
| `vulnerability_scanner.py` | 102KB | CVE vulnerability scanning | Orphan — not wired |
| `network_monitor.py` | 42KB | Network traffic analysis | Orphan — not wired |
| `process_monitor.py` | 24KB | Process monitoring | Orphan — not wired |
| `file_monitor.py` | 14KB | File integrity monitoring | Orphan — not wired |
| `file_scanner.py` | 28KB | Malware file scanning | Orphan — not wired |
| `file_sandbox.py` | 2KB | Sandboxed file execution | Orphan — not wired |
| `ransomware_detector.py` | 46KB | Standalone ransomware detection | Orphan — not wired |
| `email_security.py` | 32KB | Email threat analysis | Orphan — not wired |
| `emergency_response.py` | 24KB | Incident response automation | Orphan — not wired |
| `iot_scanner.py` | 41KB | IoT device vulnerability scanning | Orphan — not wired |
| `usb_protection.py` | 13KB | USB device security | Orphan — not wired |
| `parental_controls.py` | 31KB | Content filtering | Orphan — not wired |
| `system_cleanup.py` | 19KB | Disk/temp/cache cleanup | Orphan — not wired |
| `system_hardening.py` | 24KB | OS hardening automation | Orphan — not wired |
| `downpour_cleanup_module.py` | 83KB | Deep system cleanup | Orphan — not wired |
| `downpour_remote_access.py` | 31KB | Remote management | Orphan — not wired |
| `downpour_vpn_module.py` | 26KB | VPN integration | Orphan — not wired |
| `browser_protection.py` | 11KB | Browser extension security | **CONSOLIDATED v29.30** |
| `advanced_device_profiler.py` | 75KB | Device profiling + bypass analysis | **DECLINED** (evasion) |
| `defender_enhancer.py` | 18KB | Extended Defender integration | Orphan — not wired |
| `defender_bypass_system.py` | 2KB | AV bypass utilities | **DECLINED** (offensive) |
| `adaptive_security_bypass.py` | 3KB | Security bypass adaptation | **DECLINED** (offensive) |
| `enhanced_bypass_system.py` | 4KB | Enhanced bypass routines | **DECLINED** (offensive) |
| `mega_threat_signatures.py` | 45KB | Extended malware signatures | Orphan — not wired |

### Support Files

| File | Purpose |
|------|---------|
| `config.py` | Shared configuration constants |
| `health_check.py` | Quick system health verification |
| `downpour_health_check.py` | Extended health diagnostics |
| `backup_verifier.py` | Backup integrity verification |
| `device_adaptation_engine.py` | Hardware-adaptive configuration |
| `hardware_monitor_enhanced.py` | Enhanced hardware telemetry |
| `enhanced_security_dashboard.py` | Extended security dashboard |
| `enhanced_ui_components.py` | Reusable UI widgets |
| `enhanced_hardware_integration.py` | Deep hardware integration |

## Database Schema

### SQLite (`titanium.db` / `ultimate_threat_intel`)

| Table | Purpose |
|-------|---------|
| `malicious_ips` | Known malicious IP addresses |
| `malicious_domains` | Known malicious domains |
| `malware_hashes` | Known malware file hashes |
| `feed_updates` | Feed fetch history + metadata |
| `feed_status` | Feed health (OK/FAIL/STALE/PENDING) |
| `aegis_events` | AEGIS defense layer event log |
| `fp_suppressions` | False positive suppression rules |
| `threats` | Active/resolved threat records |

## Tab Index (27 tabs)

| # | Tab Name | Builder Method | Key Features |
|---|----------|---------------|--------------|
| 1 | Dashboard | `_build_dashboard` | Health score, quick actions, threat summary |
| 2 | Processes | `_build_proc_tab` | Live process tree, GPU attribution, mitigation |
| 3 | Network | `_build_net_tab` | Connection monitor, OSINT lookups, port scanning |
| 4 | Threats | `_build_threats_tab` | Alert feed, browser scan, threat actions |
| 5 | Scanner | `_build_scanner_tab` | File/hash scanning, YARA matching |
| 6 | Intel | `_build_intel_tab` | Feed management, custom feeds, compliance |
| 7 | Performance | `_build_performance_tab` | Live gauges, timeline chart, process waterfall |
| 8 | AEGIS | `_build_aegis_tab` | 5-layer defense controls |
| 9 | Audit | `_build_audit_tab` | Security audit + hardening scores |
| 10 | DNS | `_build_dns_tab` | DNS monitoring, cache, blocklist, DoH |
| 11 | Firewall | `_build_firewall_tab` | Windows Firewall rule management |
| 12 | Parental | `_build_parental_tab` | Content filtering controls |
| 13 | Cleanup | `_build_cleanup_tab` | Disk cleanup, temp files |
| 14 | Ransomware | `_build_ransomware_tab` | Honeytoken canaries, detection |
| 15 | Memory | `_build_memory_tab` | Memory forensics |
| 16 | Services | `_build_services_tab` | Windows service threat analysis |
| 17 | Privacy | `_build_privacy_tab` | Privacy audit + controls |
| 18 | DDoS | `_build_ddos_tab` | DDoS shield + blocklist |
| 19 | VPN | `_build_vpn_tab` | VPN connection management |
| 20 | Settings | `_build_settings_tab` | App configuration |
| 21 | Hunt | `_build_hunt_tab` | Proactive threat hunting |
| 22 | Sandbox | `_build_sandbox_tab` | File detonation sandbox |
| 23 | WiFi | `_build_wifi_tab` | WiFi security analysis |
| 24 | IoT | `_build_iot_tab` | IoT device discovery |
| 25 | USB | `_build_usb_tab` | USB device guard |
| 26 | Timeline | `_build_timeline_tab` | Security event timeline |
| 27 | Logs | `_build_log_tab` | Application log viewer |

## OSINT Integration Map (34+ feeds + 20+ lookup APIs)

### Inline Lookups (keyless)
IPinfo.io, BGPView, HackerTarget, IP-API, Hudson Rock, urlscan.io, crt.sh, 
CyberChef, HIBP Pwned Passwords, Wayback Machine

### API-Key Lookups (optional)
VirusTotal, AbuseIPDB, Shodan, Censys, GreyNoise, AlienVault OTX, 
Pulsedive, ONYPHE, EmailRep.io, ThreatBook, ThreatWinds

### Feed Sources
abuse.ch (URLhaus, ThreatFox, Feodo Tracker, MalwareBazaar, SSL Blacklist),
Spamhaus (DROP/EDROP), PhishTank, CISA KEV, Emerging Threats, IPsum, 
CINS Army, OpenPhish, Tor Exit Nodes, Blocklist.de, DarkAPI, ThreatRadar
