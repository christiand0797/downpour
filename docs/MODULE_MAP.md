# Downpour v29 Titanium - Module Map

Downpour uses a modular architecture with over 40 supporting Python modules that handle specialized security functions. This document maps out the modules, their core purpose, and current status within the application architecture.

## Core Engines & Detection Modules

| Module Name | Description | Status |
|-------------|-------------|--------|
| `downpour_v29_titanium.py` | Main application file (51,800+ lines). Contains GUI, controller, and integrates all subsystems. | **Active** (Core) |
| `advanced_threat_engine.py` | Primary threat detection framework and correlation logic. | **Active** |
| `advanced_threat_analyzer.py` | In-depth file and process behavior analysis. | **Active** |
| `threat_detection_engine.py` | Signature and heuristic based threat detection routing. | **Active** |
| `ransomware_detector.py` | Entropy monitoring, shadow copy watch, canary files/honeytokens. | **Active** |
| `kimwolf_botnet_detector.py` | Specific detection logic and IOCs for Kimwolf and other botnets (150+ IOCs). | **Active** |
| `ai_security_engine.py` | ML-powered anomaly detection and KEV correlation. | **Active** |
| `ml_behavioral_analyzer.py` | Behavioral baselining and anomaly scoring using sklearn. | **Active** |
| `ml_optimization_engine.py` | Optimization for machine learning inference and training tasks. | **Active** |
| `behavior_scanner.py` | Scans for known malicious behavior patterns and injects alerts. | **Active** |
| `behavioral_analyzer.py` | Base behavioral analytics functions (often superseded by ML variants). | *Legacy/Active* |

## Threat Intelligence & Remediation

| Module Name | Description | Status |
|-------------|-------------|--------|
| `threat_intelligence.py` | Legacy 11-source threat-intelligence downloader (not wired into the main app). | *Legacy* |
| `threat_intelligence_updater.py` | KEV/EPSS/CVE live update engine, powers the OSINT feed aggregation. | **Active** |
| `threat_feed_aggregator.py` | Consolidates various OSINT feeds (URLhaus, AbuseCH, etc). | **Active** |
| `mega_threat_signatures.py` | 750+ malware family signature database. | **Active** |
| `advanced_threat_remediation.py` | 5-phase threat remediation engine (kill, quarantine, block, etc). | **Active** |
| `threat_response_center.py` | Automated response and mitigation logic. | **Active** |
| `emergency_response.py` | Incident response automation and isolation protocols. | **Active** |

## Monitors & Sensors

| Module Name | Description | Status |
|-------------|-------------|--------|
| `process_monitor.py` | Live process tracking and injection detection. | **Active** |
| `network_monitor.py` | Live connection analysis, packet tracking, DNS tracking. | **Active** |
| `file_monitor.py` | File integrity and modification monitoring. | **Active** |
| `advanced_hardware_monitor.py` | CPU, RAM, Disk, and GPU telemetry extraction. | **Active** |
| `hardware_monitor_enhanced.py` | Enhanced hardware telemetry, thermal limits, and real-time load stats. | **Active** |
| `enhanced_hardware_integration.py` | Deep hardware integration logic for telemetry. | **Active** |
| `usb_protection.py` | USB device monitoring, blocking, and registry history. | **Active** |

## Scanners & Profilers

| Module Name | Description | Status |
|-------------|-------------|--------|
| `file_scanner.py` | YARA + hash scan engine (integrates with yara_rules). | **Active** |
| `vulnerability_scanner.py` | CVE-aligned vulnerability assessment and system patch scanning. | **Active** |
| `iot_scanner.py` | IoT device fingerprinting, Mozi/Kimwolf detection on local subnets. | **Active** |
| `browser_protection.py` | Extension audit, history analysis (consolidated inline into main app v29.30). | *Reference* |
| `email_security.py` | Phishing/malware email detection heuristics. | **Active** |
| `advanced_device_profiler.py` | Device/privilege profiler (evasion/bypass-capability oriented). | *Declined for wiring* |
| `threat_hunt_engine.py` | Proactive hunt logic (LOLBAS, BYOVD, persistence mechanisms). | **Active** |

## Hardening & System Integration

| Module Name | Description | Status |
|-------------|-------------|--------|
| `system_hardening.py` | DISA-STIG automated hardening and OS configuration checks. | **Active** |
| `security_hardening.py` | Additional security posture enforcement. | **Active** |
| `defender_compatibility.py` | Manages exclusions and integrations with Windows Defender. | **Active** |
| `defender_enhancer.py` | Enhances Defender capabilities via registry/powershell policies. | **Active** |
| `defender_bypass_system.py` / `enhanced_bypass_system.py` | EDR evasion detection and prevention logic. | **Active** |
| `memory_forensics.py` | Memory dump analysis and process injection detection. | **Active** |

## Utilities, Memory, & Dashboard

| Module Name | Description | Status |
|-------------|-------------|--------|
| `downpour_health_check.py` / `health_check.py` | Application self-diagnostics and state verification. | **Active** |
| `enhanced_memory_manager.py` | Memory pool management and garbage collection tuning. | **Active** |
| `downpour_cleanup_module.py` / `system_cleanup.py` | Log rotation, temp file cleanup, and cache purging. | **Active** |
| `enhanced_logging.py` | Advanced rotating file loggers and stream handlers. | **Active** |
| `enhanced_security_dashboard.py` | Dashboard metric aggregation and visual components. | **Active** |
| `enhanced_ui_components.py` | Custom Tkinter widgets (gauges, sparks, graphs). | **Active** |
| `adaptive_security_bypass.py` | Adaptive rule generation for bypassing known obfuscation. | **Active** |
| `device_adaptation_engine.py` | Adjusts scan intensity based on available hardware resources. | **Active** |
| `downpour_vpn_module.py` | VPN server fetching and configuration logic. | **Active** |
| `parental_controls.py` | Web filtering and app execution restriction logic. | **Active** |
| `backup_verifier.py` | Verifies integrity of critical system files/backups. | **Active** |
| `revolutionary_enhancements.py` | Experimental/beta feature staging ground. | **Active** |

## Note on Architecture
Many of these modules are designed to run in background daemon threads or ProcessPools. Communication back to the main UI (`downpour_v29_titanium.py`) is primarily handled through concurrent queues, Tkinter virtual events, or memory-mapped files to avoid blocking the main event loop.
