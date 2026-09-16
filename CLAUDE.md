# Downpour v29 Titanium - Agent Rules

## Read These First
1. `SHARED_CONTEXT.md` -- project architecture, current status, key decisions
2. `AGENTS.md` -- detailed agent onboarding, class APIs, pitfalls
3. `WORK_QUEUE.json` -- claim a task before starting work
4. `AGENT_REGISTRY.json` -- register yourself, update heartbeat

## Absolute Rules (never violate)

### Code Rules
- **Python 3.12.10 only** -- do NOT use whatever `python` resolves to on PATH
- **No PowerShell in subprocess** -- use `reg`, `wmic`, `netsh`, `certutil`, `MpCmdRun.exe`
- **Main-thread DB rule** -- never `self.db.execute()` in Tkinter `after()` loops; use `self._executor.submit()` + `self.after(0, callback)`
- **Thread-safe GUI** -- never touch widgets from background threads; always `self.after(0, lambda: ...)`
- **Run AST duplicate-method check** before AND after every edit session on `downpour_v29_titanium.py`
- **Verify new modules are wired** -- grep for function/method names; if it only appears in its own `def` line, it's dead code

### Agent Coordination Rules
- **Claim before working** -- update `WORK_QUEUE.json` status to `in_progress` before touching code
- **Update heartbeat** -- keep `AGENT_REGISTRY.json` heartbeat current
- **Log findings** -- add significant discoveries to `SHARED_CONTEXT.md`
- **Don't duplicate work** -- check `WORK_QUEUE.json` completed tasks before starting
- **Clean up temp files** -- put scratch scripts in `_temp_scripts/`, not project root
- **Don't remove code** -- only fix, improve, or add; ask the user before removing anything

### Verification Workflow
Run before AND after every edit session:
```cmd
# 1. Compile check
& '<Python312 dir>\python.exe' -m py_compile downpour_v29_titanium.py

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
<Python312 dir>\python.exe -m pytest tests -q
```

## Shared Context System

The `ShardedContextManager` in `sharded_context.py` provides runtime context sharing between components:
```python
from sharded_context import get_context_manager, ContextScope, ContextProxy

mgr = get_context_manager()
mgr.set("key", value, scope=ContextScope.SHARED, ttl=3600)
value = mgr.get("key")
mgr.subscribe("pattern", callback)

# Component-specific proxy
proxy = ContextProxy(mgr, "MyComponent")
proxy["status"] = "running"
```

### Using Shared Context for Agent Handoff
When an agent hits usage limits and needs to hand off:
1. Save current progress to shared context: `mgr.set("agent:progress", {...}, scope=ContextScope.PERSISTENT)`
2. Update `WORK_QUEUE.json` with progress notes
3. Update `AGENT_REGISTRY.json` status to `handoff`
4. The next agent reads context: `mgr.get("agent:progress")`

## File Organization

| Directory | Purpose |
|-----------|---------|
| `/` (root) | Active source files, coordination docs |
| `_ARCHIVE/` | Deprecated versions, old code |
| `_legacy_launchers/` | Old batch/python launchers |
| `_temp_scripts/` | Scratch files from agent sessions |
| `docs/` | Documentation, changelogs, audit reports |
| `tests/` | pytest test suite |
| `yara_rules/` | YARA detection rules |
| `sigma_rules/` | Sigma detection rules |
| `downpour_data/` | Runtime data (auto-created) |

## Key Integration Points

### Adding a New Detection Module
1. Create module with standalone class
2. Wire into `_manual_start_security_monitors()` in main app
3. Use `sensor_hub.py` for psutil data (don't create new pollers)
4. Map to MITRE ATT&CK techniques
5. Route alerts through `_queue_alert()` pipeline
6. Add tests in `tests/`
7. Verify it's actually called (grep for the function name)

### Adding a New Threat Feed
1. Add to `threat_feed_aggregator.py` feed list
2. HTTPS only -- no HTTP feeds
3. Use HMAC manifest verification
4. Require 2+ source corroboration before auto-action
5. Add to `intel_cache.py` for persistence

## GitHub
- Repo: `github.com/christiand0797/downpour`
- Branch: `main` (single branch, commit directly)
- Python 3.12.10 required
