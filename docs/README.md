# Downpour v28 Titanium — Consolidated Package

## What It Is

Downpour v28 Titanium is a Windows security monitoring suite with a Tkinter GUI.
It provides real-time process monitoring, network threat detection, ransomware
behavioural analysis, system hardening, memory forensics, parental controls,
GPU-accelerated scanning, and the five-layer Project AEGIS defence framework.

---

## Quick Start

```cmd
LAUNCH.bat          # Recommended — run as Administrator
```

Or directly:

```cmd
python downpour_v28_titanium.py
```

---

## System Requirements

| | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 x64 | Windows 11 x64 |
| Python | 3.9 | 3.11+ |
| RAM | 4 GB | 16 GB |
| Storage | 1 GB free | 5 GB SSD |
| Permissions | Standard user | Administrator |

Administrator rights are needed to apply Defender path exclusions and
to use system-hardening features. The app runs in a reduced-capability
mode without them.

---

## Core Files

| File | Purpose |
|---|---|
| `downpour_v28_titanium.py` | Main application (~44 k lines) |
| `revolutionary_enhancements.py` | Performance helpers, neural threat scorer |
| `enhanced_memory_manager.py` | GC tuning, memory pressure monitoring |
| `security_hardening.py` | Input validation, path sanitisation, encryption |
| `defender_compatibility.py` | Defender status checker, exclusion manager |
| `enhanced_logging.py` | Structured session logging |
| `downpour_cleanup_module.py` | Temp/log/cache/quarantine cleanup |
| `downpour_remote_access.py` | RAT/C2/reverse-shell detection |
| `downpour_vpn_module.py` | VPN status, DNS-leak test, kill-switch |
| `advanced_hardware_monitor.py` | Real-time hardware gauge data |
| `device_adaptation_engine.py` | Device profiler for adaptive settings |
| `ml_optimization_engine.py` | ML-based performance strategy engine |

---

## Installation

Install core runtime dependencies:

```cmd
pip install psutil cryptography requests numpy scikit-learn
```

Install all optional features (GPU, PDF, CV, charts):

```cmd
pip install -r requirements.txt
```

---

## Running the Health Check

```cmd
python downpour_health_check.py
```

This validates syntax, required symbols, all bug fixes, and checks for
any Defender-disabling code — 52 checks total.

---

## Launcher

Use `LAUNCH.bat` (run as Administrator). It:

1. Detects your Python installation automatically
2. Applies a Defender path exclusion for the project folder
3. Installs `psutil` and `cryptography` if missing
4. Launches `downpour_v28_titanium.py`

---

## Documentation Index

| File | Contents |
|---|---|
| `DEFENDER_BYPASS_GUIDE.md` | How path exclusions work |
| `ENHANCED_BYPASS_GUIDE.md` | Enhanced compatibility system |
| `COMPREHENSIVE_INSTALLATION_GUIDE.md` | Full install walkthrough |
| `TROUBLESHOOTING.md` | Common issues and fixes |
| `ADMIN_TROUBLESHOOTING.md` | Administrator-specific issues |

---

## Troubleshooting

**Import errors** — run `pip install -r requirements.txt`

**Permission denied** — run as Administrator

**Defender flagging files** — run `LAUNCH.bat` as Administrator to apply
the path exclusion, then wait a minute for it to propagate

**GUI does not open** — check `downpour.log` in the project folder for
the specific error; most startup errors are caught and logged there
