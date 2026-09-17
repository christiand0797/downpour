# Downpour v29 Titanium - Quick Reference Card

## Quick Start
```cmd
LAUNCH_DOWNPOUR.bat    # Run as Administrator (recommended)
# Or directly:
python downpour_v29_titanium.py
```

## Essential Commands
```powershell
# Compile check
& '<Python312 dir>\python.exe' -m py_compile downpour_v29_titanium.py

# AST duplicate method check
python -c "
import ast
with open('downpour_v29_titanium.py', encoding='utf-8', errors='replace') as f:
    tree = ast.parse(f.read())
for node in ast.walk(tree):
    if isinstance(node, ast.ClassDef) and node.name == 'downpour':
        names = [n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        dupes = {n for n in names if names.count(n) > 1}
        print(f'{len(names)} methods, {len(dupes)} duplicates:', dupes or 'none')
"

# Run tests
<Python312 dir>\python.exe -m pytest tests -q

# Health check (52 checks)
python downpour_health_check.py
```

## Critical Rules (Never Violate)

| Rule | Correct | Wrong |
|------|---------|-------|
| **DB on main thread** | `self._executor.submit(...)` + `self.after(0, callback)` | `self.db.execute()` in `after()` |
| **GUI from bg thread** | `self.after(0, lambda: ...)` | Direct `widget.config()` |
| **PowerShell** | `reg`, `wmic`, `netsh`, `certutil`, `MpCmdRun.exe` | `subprocess.run(['powershell', ...])` |
| **Python version** | 3.12.10 | 3.15 alpha, 3.11 |
| **Admin rights** | Required for Defender, hardening | Standard user |

## Key Classes Quick Access

| Class | File | Key Methods |
|-------|------|-------------|
| `downpour` | `downpour_v29_titanium.py` | Main app class |
| `ImmersiveRainCanvas` | `downpour_v29_titanium.py:~20257` | `start()`, `stop()`, `set_threat_level()`, `trigger_aurora()`, `trigger_meteor_shower()` |
| `ShardedContextManager` | `sharded_context.py` | `set()`, `get()`, `subscribe()`, `create_snapshot()` |
| `AegisPhysicalShield` | `downpour_v29_titanium.py:~21328` | Layer 1: IMSI, camera/mic/GPS gating |
| `AegisTCPStackGuard` | Layer 2 | TCP stack, port hijacking, RAT lockdown |
| `AegisIngestionEngine` | Layer 3 | All-threat ingestion & neutralization |
| `AegisNLPPhishingEngine` | Layer 4 | AI phishing/social engineering defense |
| `AegisMemoryShield` | Layer 5 | Volatile memory & anti-forensics |
| `HardwareMonitor` | `downpour_v29_titanium.py:~18062` | `start_background_refresh()`, `get_stats()` |

## Thread-Safe Patterns

```python
# BG thread -> GUI
def _add_alert(self, msg, color):
    if threading.current_thread() is not threading.main_thread():
        self.after(0, lambda: self._add_alert(msg, color))
        return
    # main thread code here

# BG thread -> DB
self._executor.submit(lambda: self.db.execute("SELECT ..."))
self.after(0, lambda result: self._ui_update(result))
```

## Key Files Map

| File | Purpose |
|------|---------|
| `downpour_v29_titanium.py` | Main app (~58K lines) |
| `sharded_context.py` | Distributed context with pub/sub |
| `revolutionary_enhancements.py` | Neural scorer, perf helpers |
| `enhanced_memory_manager.py` | GC tuning, memory monitoring |
| `security_hardening.py` | Input validation, encryption |
| `defender_compatibility.py` | Defender status, exclusions |
| `sensor_hub.py` | Central psutil snapshot distributor |
| `threat_feed_aggregator.py` | 300+ feed aggregator with HMAC integrity |
| `vulnerability_scanner.py` | CVE/KEV/CEV/EPSS scanner |
| `advanced_defense_suite.py` | 38-capability defense watchers |
| `intel_cache.py` | Persistent SQLite intel cache |
| `quarantine_core.py` | AES-GCM unified quarantine service |
| `pe_analyzer.py` | Static PE analysis with EMBER features |
| `trust_check.py` | WinVerifyTrust signature validation |
| `etw_monitor.py` | ETW kernel telemetry (process, registry, DNS, pipes) |
| `ransomware_canary.py` | Canary file deployment for instant ransomware detection |
| `credential_guard_monitor.py` | VBS/Credential Guard/HVCI tampering detection |
| `privilege_escalation_detector.py` | UAC bypass, privesc vector scanning |
| `boot_integrity_monitor.py` | Boot file integrity, BCD drift, Secure Boot |
| `sigma_engine.py` | Sigma rule engine (process + script block matching) |
| `dark_web_intel.py` | Dark web OSINT intelligence module |
| `threat_feed_mega.py` | Unified mega-feed module (15+ sources) |

## Detection Rules

| Directory | Count | Covers |
|-----------|-------|--------|
| `yara_rules/` | 26 files | Malware, ransomware, APT, C2, botnet, cryptominer, AMSI bypass, injection, info-stealers, supply chain, wipers, webshells, fileless, BYOVD, RAT, PS obfuscation, cred dumpers, browser threats, WiFi attacks |
| `sigma_rules/` | 17 files | LOLBins, credential access, defense evasion, persistence, lateral movement, PowerShell, discovery, scripting, privesc, impact, Kerberos, WMI, schtasks, exfiltration, BYOVD drivers, C2 beaconing, browser sideloading, BT recon |

## PowerShell Replacements

| PowerShell | Native Replacement |
|------------|-------------------|
| `Add-MpPreference` | `reg add` |
| `Get-MpPreference` | `reg query` |
| `Set-MpPreference` | `reg add` |
| `Get-MpComputerStatus` | `wmic` |
| `Get-WmiObject` | `wmic` |
| `Get-NetAdapter` | `wmic nic` |
| `Get-PnpDevice` | `wmic path Win32_PnPEntity` |
| `Get-DnsClientServerAddress` | `netsh interface ip show dns` |
| `Clear-RecycleBin` | `cmd /c rd /s /q %systemdrive%\$Recycle.Bin` |
| `Start-MpScan` | `MpCmdRun.exe -Scan -ScanType 2` |

## GitHub
- Repo: `github.com/christiand0797/downpour`
- Branch: `main` (single branch)
- Commit straight to `main`
