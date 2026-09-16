# Downpour v29 Titanium - Shared Context Document

## Project Overview
**Downpour v29 Titanium** is a Windows security monitoring suite with a Tkinter GUI (~58K lines in `downpour_v29_titanium.py`). It provides real-time process monitoring, network threat detection, ransomware behavioral analysis, system hardening, memory forensics, parental controls, GPU-accelerated scanning, and the five-layer Project AEGIS defence framework.

## Key Architecture Decisions

### 1. Single-File Monolithic Architecture
- **Decision**: Main application in single 58K-line file (`downpour_v29_titanium.py`)
- **Rationale**: Simpler deployment, no import chain issues
- **Trade-off**: Harder to navigate, requires AST duplicate-method checks

### 2. Threading Model
- **Main thread**: Tkinter event loop only
- **Background threads**: `ThreadPoolExecutor` (`self._executor`) for I/O, CPU work
- **Thread-safe GUI**: All widget updates via `self.after(0, callback)`
- **Background DB access**: Use `self._executor.submit()` + `self.after(0, callback)`

### 3. No PowerShell Policy
- **Rule**: Zero `subprocess.run(['powershell', ...])` calls
- **Reason**: PowerShell PATH hijacking risk, slow startup, quoting hell
- **Replacements**: `reg.exe`, `wmic`, `netsh`, `manage-bde`, `certutil`, `MpCmdRun.exe`, `ipconfig`, `sc`, `wevtutil`

### 4. Python Version Lock
- **Required**: Python 3.12.10 (not 3.15 alpha, not 3.11)
- **Reason**: 3.15 breaks wheels; 3.12 has stable compiled wheels for all deps
- **Launcher**: `LAUNCH.bat` enforces Python 3.12+

### 5. Main-Thread DB Rule
- **Never**: `self.db.execute()` in `after()` loops
- **Correct**: `self._executor.submit()` + `self.after(0, callback)`

## Current Status (v29.80)

### Completed Features
- **Rain Canvas v29.80**: Thunder audio, screen shake, rainbow, aurora, meteor shower, particle system, weather modes (rain/snow/sleet/storm/clear)
- **Sharded Context** (`sharded_context.py`): Distributed context with pub/sub, persistence, snapshots
- **Threat Feed Logging**: Structured JSONL with SHA-256 integrity chain, MITRE ATT&CK mapping, kill chain tracking
- **Export Threat Log**: CSV/JSON/HTML/Markdown with filtering (severity, engine, indicator type, time range, kill chain)
- **AEGIS 5 Layers**: Physical, TCP Stack, Ingestion, NLP Phishing, Memory Shield
- **300+ Threat Feeds**: With HMAC integrity, HTTPS-only, per-fetch SHA256
- **Sensor Hub**: Single psutil snapshot/5s fanned to consumers
- **Defense Suite**: 38 capabilities (security services, RDP, AppLocker, local groups, LSA, SMB, ASR, shell config watchers)
- **PowerShell Removal Complete**: All `subprocess.run(['powershell', ...])` replaced with native Windows commands
- **Sigma Rules**: 40+ detection rules covering LOLBins, credential access, defense evasion, persistence, lateral movement, PowerShell threats
- **ETW Monitor** (`etw_monitor.py`): Kernel-level telemetry — process creation, registry mods, named pipes, DNS queries, DLL loads
- **Ransomware Canary System** (`ransomware_canary.py`): Decoy file deployment with 5s integrity checks for instant ransomware detection
- **YARA Rules v29.82**: 20 rule files including AMSI bypass, info-stealers, DLL injection, supply chain attacks, wiper malware, webshells
- **Credential Guard Monitor** (`credential_guard_monitor.py`): VBS/HVCI/Secure Boot tampering detection
- **Privilege Escalation Detector** (`privilege_escalation_detector.py`): UAC bypass, AlwaysInstallElevated, unquoted paths, weak services
- **Boot Integrity Monitor** (`boot_integrity_monitor.py`): Boot file SHA-256 baselines, BCD drift, test-signing, ELAM checks

### Test Suite
- **389+ tests** passing (v29.72 baseline)
- Run: `<Python312 dir>\python.exe -m pytest tests -q`

## Active TODOs (from TODO.md)

### HIGH PRIORITY
- [ ] **GPU ML workloads** -- gpu_executor pool exists (50% cores) but no CUDA ML workloads (cupy/tensorflow not installed)
- [ ] **Tab overlap on small windows** -- `minsize(1280, 700)` helps but ttk.Notebook has no native tab scrolling

### MEDIUM PRIORITY
- [ ] Unit tests for thread-safety mechanisms (partial: 16 tests in `test_thread_safety.py`)
- [ ] Consolidate 19+ OSINT lookup buttons into dispatcher

### LOW PRIORITY
- [ ] System tray minimize support (pystray installed, needs wiring)
- [ ] Dark mode detection for Windows 11
- [ ] Export-to-PDF for security reports

## Critical Files for New Agents

| File | Lines | Purpose |
|------|-------|---------|
| `downpour_v29_titanium.py` | ~58K | Main app, GUI, all core logic |
| `sharded_context.py` | ~976 | Distributed context management with pub/sub |
| `revolutionary_enhancements.py` | ~2K | Neural scorer, performance helpers |
| `enhanced_memory_manager.py` | ~1K | GC tuning, memory monitoring |
| `security_hardening.py` | ~1K | Input validation, encryption |
| `defender_compatibility.py` | ~400 | Defender status, exclusions |
| `sensor_hub.py` | ~700 | Central psutil snapshot distributor |
| `threat_feed_aggregator.py` | ~1.5K | 300+ feed aggregator with HMAC integrity |
| `vulnerability_scanner.py` | ~2K | CVE/KEV/CEV/EPSS scanner |
| `advanced_defense_suite.py` | ~4K | 38-capability defense watchers |
| `intel_cache.py` | ~500 | Persistent SQLite intel cache |
| `quarantine_core.py` | ~1K | AES-GCM unified quarantine service |
| `pe_analyzer.py` | ~500 | Static PE analysis with EMBER features |
| `trust_check.py` | ~300 | WinVerifyTrust signature validation |
| `dark_web_intel.py` | ~600 | Dark web OSINT intelligence (Tor exit nodes, leak sites) |
| `threat_feed_mega.py` | ~700 | Unified mega-feed module (15+ sources) |
| `etw_monitor.py` | ~400 | ETW-based kernel telemetry (process, registry, DNS, pipes) |
| `ransomware_canary.py` | ~350 | Canary file deployment and monitoring for instant ransomware detection |
| `credential_guard_monitor.py` | ~280 | VBS/Credential Guard/HVCI tampering detection |
| `privilege_escalation_detector.py` | ~350 | UAC bypass, privesc vector scanning |
| `boot_integrity_monitor.py` | ~350 | Boot file integrity, BCD drift, Secure Boot monitoring |
| `sigma_engine.py` | ~1.2K | Sigma rule engine (process creation + script block matching) |

## Verification Commands (Run Before/After Changes)

```powershell
# 1. Compile check
& '<Python312 install dir>\python.exe' -m py_compile downpour_v29_titanium.py

# 2. AST duplicate method check
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

# 3. Run tests
<Python312 install dir>\python.exe -m pytest tests -q

# 4. Run health check (52 validation checks)
python downpour_health_check.py
```

## Key Conventions

### Thread-Safe GUI
```python
# From background thread - ALWAYS marshal to main thread
def _add_alert(self, msg, color):
    if threading.current_thread() is not threading.main_thread():
        self.after(0, lambda: self._add_alert(msg, color))
        return
    # ... main thread code
```

### Error Handling Pattern
```python
try:
    # risky operation
except Exception as e:
    _safe_log('ComponentName', 'description', e)
    # never re-raise in background threads
```

## PowerShell Ban
**Zero `subprocess.run(['powershell', ...])` calls allowed**

| PowerShell | Native Replacement |
|------------|-------------------|
| `Add-MpPreference` | `reg add` |
| `Get-MpPreference` | `reg query` |
| `Set-MpPreference` | `reg add` |
| `Get-MpComputerStatus` | `wmic /namespace:\\root\cimv2\security\microsoftvolumeencryption path Win32_EncryptableVolume` |
| `Get-WmiObject` | `wmic` |
| `Get-NetAdapter` | `wmic nic` |
| `Get-PnpDevice` | `wmic path Win32_PnPEntity` |
| `Get-DnsClientServerAddress` | `netsh interface ip show dns` |
| `Clear-RecycleBin` | `cmd /c rd /s /q %systemdrive%\$Recycle.Bin` |
| `Start-MpScan` | `MpCmdRun.exe -Scan -ScanType 2` |

## Agent Coordination

Agents coordinate via these files (see `AGENT_COORDINATION.md` for full protocol):
- `WORK_QUEUE.json` -- task queue with status tracking
- `AGENT_REGISTRY.json` -- agent capabilities and heartbeats
- `sharded_context.py` -- runtime context sharing via `ShardedContextManager`
- `CLAUDE.md` -- rules and constraints all agents must follow

## Launch
```cmd
LAUNCH_DOWNPOUR.bat    # Recommended -- run as Administrator
# Or directly:
python downpour_v29_titanium.py
```

## GitHub
- Repo: `github.com/christiand0797/downpour`
- Branch: `main` (single branch, no long-lived branches)
- Commit straight to `main`
