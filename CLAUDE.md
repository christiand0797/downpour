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

### Adding Sigma Rules
1. Drop `.yml` or `.json` files into `sigma_rules/`
2. Engine loads them via `sigma_engine.load_user_rules()` on next start
3. Supported logsources: `process_creation` (Image, CommandLine, ParentImage, User) and `ps_script` (ScriptBlockText)
4. Supported modifiers: `contains`, `startswith`, `endswith`, `re`, `and/or/not`, `1 of sel*`, `all of them`
5. Unsupported constructs (aggregation, correlation) are skipped safely

### Adding YARA Rules
1. Add `.yar` files to `yara_rules/`
2. Include `meta` block with author, version, date, category, severity, mitre
3. YARA-X (Rust rewrite) is preferred engine; falls back to yara-python

### Using ETW Monitor
```python
from etw_monitor import start_monitoring, stop_monitoring, get_monitor
start_monitoring(callback=my_alert_handler)
stats = get_monitor().get_stats()
alerts = get_monitor().drain_alerts()
```

### Using Ransomware Canary System
```python
from ransomware_canary import deploy_canaries, get_canary_system
count = deploy_canaries(callback=my_alert_handler)
status = get_canary_system().get_status()
alerts = get_canary_system().get_alerts()
```

### Using Credential Guard Monitor
```python
from credential_guard_monitor import start_credguard_monitoring, get_credguard_monitor
start_credguard_monitoring(callback=my_alert_handler)
status = get_credguard_monitor().get_status()
```

### Using Privilege Escalation Detector
```python
from privilege_escalation_detector import start_privesc_detection, get_privesc_detector
start_privesc_detection(callback=my_alert_handler)
alerts = get_privesc_detector().get_alerts()
```

### Using Boot Integrity Monitor
```python
from boot_integrity_monitor import start_boot_monitoring, get_boot_monitor
start_boot_monitoring(callback=my_alert_handler)
status = get_boot_monitor().get_status()
```

### Using TLS Certificate Monitor
```python
from tls_certificate_monitor import start_tls_monitoring, get_tls_monitor
start_tls_monitoring(callback=my_alert_handler)
status = get_tls_monitor().get_status()
alerts = get_tls_monitor().get_alerts()
```

### Using AD & Kerberos Attack Detector
```python
from ad_attack_detector import start_ad_detection, get_ad_detector
start_ad_detection(callback=my_alert_handler)
# Also usable for real-time process scanning:
alert = get_ad_detector().scan_command_line("rubeus.exe", "rubeus.exe kerberoast")
```

### Using Clipboard Security Monitor
```python
from clipboard_monitor import start_clipboard_monitoring, get_clipboard_monitor
start_clipboard_monitoring(callback=my_alert_handler)
status = get_clipboard_monitor().get_status()
alerts = get_clipboard_monitor().get_alerts()
```

### Using Named Pipe Monitor
```python
from named_pipe_monitor import start_pipe_monitoring, get_pipe_monitor
start_pipe_monitoring(callback=my_alert_handler)
status = get_pipe_monitor().get_status()
alerts = get_pipe_monitor().get_alerts()
```

### Using Token Manipulation Detector
```python
from token_manipulation_detector import start_token_detection, get_token_detector
start_token_detection(callback=my_alert_handler)
# Real-time command line scanning:
alert = get_token_detector().scan_command_line("juicypotato.exe", "juicypotato.exe -l 1337")
```

### Using DPAPI Monitor
```python
from dpapi_monitor import start_dpapi_monitoring, get_dpapi_monitor
start_dpapi_monitoring(callback=my_alert_handler)
status = get_dpapi_monitor().get_status()
alerts = get_dpapi_monitor().get_alerts()
```

### Using WiFi Security Intelligence
```python
from wifi_security_intelligence import start_wifi_intelligence, get_wifi_intel
start_wifi_intelligence(callback=my_alert_handler, scan_interval=45.0)
status = get_wifi_intel().get_status()
networks = get_wifi_intel().scan_now()
inventory = get_wifi_intel().get_network_inventory()
```

### Using C2 Beacon Detector
```python
from beacon_detector import start_beacon_detection, get_beacon_detector
start_beacon_detection(callback=my_alert_handler)
status = get_beacon_detector().get_status()
tracked = get_beacon_detector().get_tracked_connections()
```

### Using Browser Security Monitor
```python
from browser_security_monitor import start_browser_monitoring, get_browser_monitor
start_browser_monitoring(callback=my_alert_handler)
status = get_browser_monitor().get_status()
inventory = get_browser_monitor().get_extension_inventory()
```

### Using Bluetooth Security Monitor
```python
from bluetooth_security_monitor import start_bt_monitoring, get_bt_monitor
start_bt_monitoring(callback=my_alert_handler)
status = get_bt_monitor().get_status()
devices = get_bt_monitor().get_device_inventory()
```

### Using Print Spooler Monitor
```python
from print_spooler_monitor import start_spooler_monitoring, get_spooler_monitor
start_spooler_monitoring(callback=my_alert_handler)
status = get_spooler_monitor().get_status()
# Real-time command line scanning for PrintNightmare patterns:
alert = get_spooler_monitor().scan_command_line("rundll32.exe", "AddPrinterDriverEx")
```

### Using COM Hijack Detector
```python
from com_hijack_detector import start_com_detection, get_com_detector
start_com_detection(callback=my_alert_handler)
status = get_com_detector().get_status()
alerts = get_com_detector().get_alerts()
```

### Using DNS Security Monitor
```python
from dns_security_monitor import start_dns_monitoring, get_dns_monitor
start_dns_monitoring(callback=my_alert_handler)
status = get_dns_monitor().get_status()
# Analyze a domain for suspicious characteristics:
alert = get_dns_monitor().check_domain("xyzab123random.tk")
```

### Using Keystroke Injection / BadUSB Detector
```python
from keystroke_injection_detector import start_badusb_detection, get_badusb_detector
start_badusb_detection(callback=my_alert_handler)
status = get_badusb_detector().get_status()
alerts = get_badusb_detector().get_alerts()
```

### Using Network Share Monitor
```python
from network_share_monitor import start_share_monitoring, get_share_monitor
start_share_monitoring(callback=my_alert_handler)
status = get_share_monitor().get_status()
inventory = get_share_monitor().get_share_inventory()
```

### Using Shadow Copy / VSS Monitor
```python
from shadow_copy_monitor import start_vss_monitoring, get_vss_monitor
start_vss_monitoring(callback=my_alert_handler)
status = get_vss_monitor().get_status()
alerts = get_vss_monitor().get_alerts()
```

### Using Lateral Movement Detector
```python
from lateral_movement_detector import start_lateral_detection, get_lateral_detector
start_lateral_detection(callback=my_alert_handler)
alerts = get_lateral_detector().get_alerts()
# Real-time command line scanning for lateral tools:
alert = get_lateral_detector().scan_command_line("psexec.exe", "psexec.exe \\\\target -s cmd")
```

### Using Data Exfiltration Monitor
```python
from data_exfiltration_monitor import start_exfil_monitoring, get_exfil_monitor
start_exfil_monitoring(callback=my_alert_handler)
status = get_exfil_monitor().get_status()
alerts = get_exfil_monitor().get_alerts()
```

### Using Anti-Forensics Detector
```python
from anti_forensics_detector import start_antiforensics_detection, get_antiforensics_detector
start_antiforensics_detection(callback=my_alert_handler)
status = get_antiforensics_detector().get_status()
# Real-time command line scanning:
alert = get_antiforensics_detector().scan_command_line("sdelete.exe", "sdelete -p 3 secret.docx")
```

### Using Scheduled Task Monitor
```python
from scheduled_task_monitor import start_schtask_monitoring, get_schtask_monitor
start_schtask_monitoring(callback=my_alert_handler)
status = get_schtask_monitor().get_status()
alerts = get_schtask_monitor().get_alerts()
```

### Using WMI Persistence Detector
```python
from wmi_persistence_detector import start_wmi_persist_detection, get_wmi_persist_detector
start_wmi_persist_detection(callback=my_alert_handler)
status = get_wmi_persist_detector().get_status()
inventory = get_wmi_persist_detector().get_subscription_inventory()
```

### Using Gaming Protection Monitor
```python
from gaming_protection_monitor import start_gaming_protection, get_gaming_monitor
start_gaming_protection(callback=my_alert_handler)
status = get_gaming_monitor().get_status()
alerts = get_gaming_monitor().get_alerts()
```

## GitHub
- Repo: `github.com/christiand0797/downpour`
- Branch: `main` (single branch, commit directly)
- Python 3.12.10 required
