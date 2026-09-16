# Downpour v29 Titanium - Agent Context Document

## Project Overview
**Downpour v29 Titanium** is a Windows security monitoring suite with a Tkinter GUI (~58K lines in `downpour_v29_titanium.py`). It provides real-time process monitoring, network threat detection, ransomware behavioral analysis, system hardening, memory forensics, parental controls, GPU-accelerated scanning, and the five-layer Project AEGIS defence framework.

## Quick Start for New Agents

1. **Read `CLAUDE.md`** first -- it has the rules every agent must follow.
2. **Read `SHARED_CONTEXT.md`** -- current project state and architecture.
3. **Check `WORK_QUEUE.json`** -- claim a task before starting work.
4. **Register in `AGENT_REGISTRY.json`** -- update your heartbeat.
5. **Run verification** before and after changes (see below).

```cmd
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

## Architecture Overview

### Core Components
| File | Lines | Purpose |
|------|-------|---------|
| `downpour_v29_titanium.py` | ~58K | Main application, GUI, all core logic |
| `sharded_context.py` | ~976 | Distributed context management with pub/sub |
| `revolutionary_enhancements.py` | ~2K | Neural scorer, performance helpers |
| `enhanced_memory_manager.py` | ~1K | Memory pressure monitoring, GC tuning |
| `security_hardening.py` | ~1K | Input validation, path sanitisation, encryption |
| `defender_compatibility.py` | ~400 | Defender status checker, exclusion manager |
| `enhanced_logging.py` | varies | Structured session logging |
| `downpour_cleanup_module.py` | varies | Temp/log/cache/quarantine cleanup |
| `sensor_hub.py` | ~700 | Single psutil snapshot per tick (5s) fanned to consumers |
| `threat_feed_aggregator.py` | ~1.5K | 300+ threat intelligence feeds with HMAC integrity |
| `vulnerability_scanner.py` | ~2K | CVE/KEV/CEV/EPSS scanning |
| `pe_analyzer.py` | ~500 | Static PE analysis with EMBER features |
| `advanced_defense_suite.py` | ~4K | 38-capability defense watchers |
| `intel_cache.py` | ~500 | Persistent SQLite intel cache |
| `quarantine_core.py` | ~1K | AES-GCM unified quarantine service |
| `trust_check.py` | ~300 | WinVerifyTrust signature validation |

### Key Architectural Patterns
1. **Thread-safe GUI**: All widget updates via `self.after(0, callback)` from background threads
2. **Executor pattern**: `self._executor` (ThreadPoolExecutor) for background work; results via `self.after(0, callback)`
3. **Main-thread DB rule**: Never call `self.db.*` directly from `after()` loops; use `self._executor.submit()`
4. **No PowerShell**: Use native Windows commands (`reg`, `wmic`, `netsh`, `manage-bde`, `certutil`, `MpCmdRun.exe`)
5. **Sharded context**: Distributed context management with pub/sub in `sharded_context.py`

### Key Classes & Their APIs

#### `ImmersiveRainCanvas` (downpour_v29_titanium.py:~20257)
- Header animation with rain, lightning, aurora, meteors, particles
- Methods: `start()`, `stop()`, `set_threat_level(0-100)`, `set_storm_phase()`, `set_weather_mode()`, `trigger_meteor_shower()`, `trigger_aurora()`, `trigger_lightning_forks()`

#### `ShardedContextManager` (sharded_context.py)
```python
mgr = ShardedContextManager(shard_count=16)
mgr.set(key, value, scope=ContextScope.SHARED, ttl=3600, tags={'tag1'})
value = mgr.get(key)
mgr.subscribe(pattern, callback)
mgr.create_snapshot(name)
mgr.restore_snapshot(name)
```

#### AEGIS Layers (downpour_v29_titanium.py)
| Layer | Class | Purpose |
|-------|-------|---------|
| 1 | `AegisPhysicalShield` | IMSI catcher detection, camera/mic/GPS gating, hardware data diode |
| 2 | `AegisTCPStackGuard` | TCP stack & port hijacking prevention, RAT lockdown, DNS shield |
| 3 | `AegisIngestionEngine` | All-threat ingestion & neutralization |
| 4 | `AegisNLPPhishingEngine` | AI phishing & social engineering defense |
| 5 | `AegisMemoryShield` | Volatile memory & anti-forensics shield |

## Common Pitfalls to Avoid

1. **Never call `self.db.*` from main-thread `after()` loops** -- use `self._executor.submit()`
2. **Never call `tkinter` methods from background threads** -- use `self.after(0, lambda: ...)`
3. **No PowerShell in subprocess** -- use native Windows commands
4. **Run on Python 3.12** -- 3.15 alpha breaks wheels; 3.12.10 is stable
5. **Run as Administrator** for Defender exclusions and system hardening
6. **Duplicate method check** -- run AST check before committing
7. **Verify new modules are actually called** -- this codebase has repeatedly had well-built modules that were never wired into any live code path

## Useful Paths
- Project root: `C:\Users\purpl\Desktop\downpour_consolidated\`
- Main app: `downpour_v29_titanium.py`
- Data dir: `downpour_data/` (auto-created)
- Logs: `downpour_data/logs/`
- Quarantine: `downpour_data/quarantine/`
- Config: `downpour_data/config/settings.ini`
- Temp scripts: `_temp_scripts/` (move working scratch here, not project root)

## Documentation Index (docs/)
| File | Contents |
|------|----------|
| `README.md` | Quick start, requirements, troubleshooting |
| `TODO.md` | Current state, verified items, remaining work |
| `CHANGELOG.md` | Version history |
| `MODULE_MAP.md` | File-to-function mapping |
| `SECURITY_AUDIT_2026-09-07.md` | Security audit findings |
| `TODO_v30_DDoS.md` | DDoS mitigation tasks |
| `IMPROVEMENT_CATALOG.md` | Feature improvement catalog |

## GitHub
- Repo: `github.com/christiand0797/downpour`
- Branch: `main` (single branch, no long-lived branches)
- Commit straight to `main`
- Latest: v29.80
