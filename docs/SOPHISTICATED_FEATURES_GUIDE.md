# Downpour v28 Titanium — Feature Overview

## Core Security Features

### Real-time Process Monitoring
Scans running processes using YARA rules, heuristics, and an IsolationForest
anomaly detector. Flags unsigned binaries, high-entropy executables, temp-path
launches, and unusual parent-child process relationships.

### Network Threat Detection
Monitors active TCP connections for known C2 beacon intervals, reverse-shell
port signatures, and suspicious remote IPs. Integrates with the threat database
for known-malicious IP lookups.

### Ransomware Behavioural Analysis
Tracks file-creation rates, entropy of written data, and canary-file
modification. Triggers configurable automated responses when thresholds
are exceeded.

### System Hardening
Applies Windows security hardening via PowerShell — enables PUA protection,
sets Defender cloud block level to High, disables LLMNR and WPAD, and
enforces SMB signing.

### Memory Forensics
Scans process memory regions for injection signatures, hollow process
indicators, and shellcode patterns.

### Project AEGIS (Five-Layer Defence)
1. Network perimeter monitoring
2. Host-based process auditing
3. Behavioural anomaly detection
4. Threat intelligence feed integration
5. Automated incident response

### Parental Controls
DNS-based web filter via the system hosts file. Screen-time scheduling,
app restriction list, and activity logging.

### GPU-Accelerated Scanning
Offloads hash computation and pattern matching to CUDA when an NVIDIA
GPU is available (requires `pynvml`).

---

## Support Modules

| Module | What it provides |
|---|---|
| `downpour_cleanup_module.py` | Temp, log, cache, quarantine cleanup + duplicate finder |
| `downpour_remote_access.py` | RAT/C2/reverse-shell detector, SmartServicesScanner |
| `downpour_vpn_module.py` | VPN status, DNS-leak test, IPv6 protection, kill-switch |
| `advanced_hardware_monitor.py` | CPU/GPU/memory/disk gauges with trend and velocity data |
| `device_adaptation_engine.py` | Hardware profiler, adaptive performance settings |
| `ml_optimization_engine.py` | ML-based strategy engine, learned device profiles |

---

## Defender Compatibility

The `defender_compatibility.py` module is a **read-only status reporter**.
It queries `Get-MpComputerStatus` to check whether real-time protection is
enabled and how many exclusion paths exist. It does not modify any Defender
settings.

Path exclusions (allow-listing only) are handled by `defender_bypass_system.py`
and `enhanced_bypass_system.py`. See `DEFENDER_BYPASS_GUIDE.md` for details.

---

## Performance Notes

The application uses:
- `ThreadPoolExecutor` for parallel scans
- `IsolationForest` + `RandomForestClassifier` (sklearn) for ML detection
- Exponential smoothing on hardware gauge readings
- LRU caching on threat lookups
- SQLite WAL mode for low-latency database writes

Actual performance depends on your hardware. The "revolutionary" and
"quantum" branding in the code is descriptive shorthand for the
multi-layer detection architecture, not literal quantum computing.
