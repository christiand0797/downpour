# Downpour Shared Context

## Current State (Updated: 2026-09-08T02:30:00Z)

### ✅ COMPLETED - Critical Fixes
1. **ERR_QUIC_PROTOCOL_ERROR Fixed** - Removed 10 false-positive DDoS block rules that were blocking Google Cloud IPs (34.x.x.x, 35.x.x.x, 160.x.x.x) used by Claude/Chrome QUIC traffic over UDP 443
2. **Performance Tab** - Reduced from 70+ gauges to 28 essential (4×7 grid), fixed sparkline "black box" rendering issue
3. **Tab Reorganization** - 28→16 tabs, added **Remediation History** (auto-revert) and **Possible Threats** (pre-verification) tabs
4. **False Positive Analysis** - Context-aware port scoring with confidence thresholds, two-strike DDoS auto-block rule
5. **Rain Effect Optimization** - Reduced particle pools, lower storm intensity, maintains visual quality
6. **Firewall Cleanup** - Ran cleanup script as admin, only legitimate KIMWOLF C2 blocks remain

### ✅ COMPLETED - New Features (agent-main-001)
7. **Remediation History Tab** - Full auto-revert with quarantine restore, firewall rule removal, action logging
   - All remediation paths (full engine, basic, remediate-all) now log to `_remediation_log`
   - Auto-revert handles: quarantine restore, firewall rules, process kill (noted), registry (noted)
   - Export to CSV, detail view, sorting
8. **Possible Threats Tab** - Pre-verification holding area
   - Verify & move to main threat log, dismiss, investigate (VT, AbuseIPDB, GreyNoise)
   - Auto-population via `_add_possible_threat()` method
   - Context menu with threat intel lookup
   - Stats tracking (High/Medium/Low severity)
9. **MITRE ATT&CK Mapping Across All Detection Modules**
   - Main App: `MITRE_MAP` expanded to 100+ techniques
   - Behavior Scanner: `BEHAVIOR_TO_MITRE` with 100+ mappings
   - Network Monitor: `NETWORK_MITRE_MAP` with 35+ network techniques
   - Threat Detection Engine: `PORT_PROFILES` for context-aware port analysis
   - All detection paths auto-tag with MITRE ATT&CK technique IDs and names
10. **Rain Effect 60fps Cap** - Explicit fps limiter in `ImmersiveRainCanvas._animate()` with 16.67ms minimum interval
11. **Laptop/Desktop Detection** - Hardware profile detects battery, lid state, thermal throttling
    - Laptop-specific: reduced rain intensity on battery, thermal throttling reduces worker counts
    - Added `is_laptop`, `battery_percent`, `battery_plugged`, `lid_state`, `thermal_throttling`, `thermal_state` to HardwareProfile
12. **Network Baseline Learning & Anomaly Detection**
    - NetworkMonitor tracks threats/hour, C2 servers detected, exfiltration attempts, lateral movement, DNS tunneling, port scans
    - OSINT reputation checking (GreyNoise, AbuseIPDB, Shodan, Censys, ThreatWinds, ThreatRadar)
    - MITRE ATT&CK tagging for all network detections
    - Real-time metrics for Performance tab
13. **Encrypted Credential Store for VPN/Proxy**
    - VPNKillSwitch and VPNManager use DPAPI-compatible Windows Credential Manager via netsh
    - QUIC protocol error handling with explicit allow rules for DNS(53), HTTP(80), HTTPS(443), QUIC(443 UDP), LAN subnets
    - Kill switch allows HTTP/HTTPS/QUIC/LAN traffic while blocking everything else

### ✅ COMPLETED - Security Architecture Audit (agent-audit-007, 2026-09-07)

14. **Full-project security architecture audit** (read-only, v29.42v) —
    end-to-end attack surface mapped; top-5 risk matrix produced. Full report:
    `docs/SECURITY_AUDIT_2026-09-07.md`. Top risks: (1) Defender
    self-exclusion blind spot (ExclusionProcess `python.exe` + global
    `.pyc`/`.pyd` extension exclusions + user-writable-dir ExclusionPath, ASR
    rule restored to AuditMode not Enabled); (2) feed ingestion has NO
    integrity verification (`VERIFICATION_HASHES` are placeholder strings) and
    feeds drive automatic netsh blocks; (3) PowerShell command-injection from
    threat-name interpolation in remediation; (4) no privilege segregation;
    (5) config/quarantine/DB tamperability (`chmod` is a no-op on Windows).
    Follow-ups queued as TASK-011…TASK-018 (3 CRITICAL, 3 HIGH, 2 MEDIUM).
    Also fixed: duplicate TASK-006 in `WORK_QUEUE.json` (marked superseded),
    malformed trailing tokens in `AGENT_REGISTRY.json` (was invalid JSON).

### ✅ COMPLETED - Security Hardening v29.42w (2026-09-08)

15. **TASK-011 (CRITICAL)** — Defender exclusions narrowed to DATA DIRS ONLY
    (downpour_data / downpour_v27_data / downpour_tmp) across
    `enhanced_bypass_system.run()`, `defender_compatibility`
    (apply_defender_settings + create_defender_exclusions) and ALL 3
    launchers; `ExclusionProcess python.exe` and global `.pyc`/`.pyd`
    ExclusionExtension calls REMOVED; ASR rule 3b576869 restore switched
    AuditMode → **Enabled**.
16. **TASK-012 (CRITICAL)** — `_remove_wmi_subscription`: WMI class name
    validated against `^[A-Za-z_][A-Za-z0-9_]*$` + consumer name
    single-quote-escaped before PowerShell interpolation. Correction:
    `advanced_threat_analyzer.py:446` was already quote-doubling (audit
    over-stated it).
17. **TASK-014 (HIGH)** — `config.json` HMAC-SHA256 signing with
    DPAPI-protected key (`config.json.sig` + `config.json.key`, RAW fallback),
    tamper flag + `register_tamper_callback`, hot-reload path reuses the
    verified `_load_from_file`. Tests: 2 hot-reload tests updated to the
    signed-edit contract + new `test_tamper_detection_rejects_unsigned_edit`.
    **139/139 tests pass.** Open: surface `ConfigManager.tamper_detected` in UI.
18. **TASK-017 (MED)** — KEV hot-path: `file_scanner._get_kev_index()` +
    `process_monitor._get_kev_products()` shared hourly caches (thread-safe,
    hash-map lookups, backoff on scanner failure),
    `threat_detection_engine._get_vuln_scanner()` singleton, whole-token
    product match (kills the file_scanner.py:70 FP). Partial progress:
    TASK-013 (HTTPS-only done), TASK-015 (`_safe_procs` path-bound done).
19. **TASK-016 (HIGH)** — quarantine unified in new
    `quarantine_core.py`: AES-256-GCM (DPAPI-protected key, XOR fallback),
    **write-ahead** manifest + self-verified encrypted copy BEFORE original delete,
    collision-safe naming, tamper-refusing hash-verified restore with full
    metadata (DACL/SACL/Owner/timestamps). Wired into
    `advanced_threat_remediation._quarantine_file`, main `mitigate()`,
    `_remediation_revert`, and `system_cleanup.restore_quarantined_files`.
    Legacy XOR sidecars stay restorable. Boot-time reconciliation
    (`reconcile_quarantine()`) for orphaned quarantine entries.
    **154/154 tests pass** (quarantine_core tests have API mismatch — see TASK-016 notes).
20. **TASK-013 (CRITICAL)** — Feed integrity: HTTPS-only enforced in
    `_verify_url_security` (plain-HTTP allowlist removed).
    `FeedManifestVerifier` added to `threat_feed_aggregator.py` — signed
    HMAC-SHA256 manifests with DPAPI-protected key, verified before parsing.
    Corroboration gate added to `ultimate_threat_intel` `ThreatDatabase.get_indicator_sources()`
    and `kimwolf_botnet_detector._check_corroboration()` — requires 2+ independent
    feed sources before firewall blocks / hosts file modifications. Auto-actions
    now skip with 'no corroboration' message when single-source only.
21. **TASK-015 (HIGH)** — `trust_check.py`: WinVerifyTrust-based signature
    validation via PowerShell Get-AuthenticodeSignature. `trusted_system_process()`
    requires: (1) name in allowlist, (2) image path under `%SystemRoot%\System32`
    or SysWOW64, (3) valid Microsoft/WHQL digital signature. Kernel pseudo-processes
    (system, registry) exempt from path/signature. Wired into:
    `downpour_v29_titanium._analyze` (connection scan skip),
    `behavior_scanner.analyze_running_processes` (exact name + path + signature),
    `threat_response_center` (masquerading warning T1036 when path not in Windows dir).
    `process_monitor.system_processes` documented as unreferenced legacy.
22. **TASK-018 (MED)** — `sensor_hub.py`: single psutil snapshot per tick (5s)
    fanned out over bounded queues (max 1000) to threat_detection, ransomware,
    network, and UI consumers. Rewired orphaned modules: process_monitor,
    network_monitor now consume from hub instead of independent psutil polls.
    Capped unbounded `network_monitor._dns_counts` with 5-min window + max 1000
    entries. Capped unbounded `_alert_dedup` with 1hr TTL + max 5000 entries.
20. **TASK-013 + TASK-015 (v29.42y)** — feed ingestion: both fetch paths
    HTTPS-only, per-fetch FEED-INTEGRITY sha256 audit lines, cert-exempt
    TLS hosts log loudly; agent-audit-001's HMAC manifest class merged
    (fixed its in-flight IndentationError); kimwolf `_block_ip_firewall`
    documented as dead code (audit auto-block claim corrected).
    Allowlists: `trust_check.py` (WinVerifyTrust + PSModulePath-safe
    Get-AuthenticodeSignature fallback, cached) wired into
    behavior_scanner (substring skip fixed — was `safe in name`!) and the
    threat_response_center display. **154/154 tests** (8 new).
    ENVIRONMENT GOTCHA: PowerShell spawned from this suite can fail with
    "module could not be loaded" when PSModulePath is inherited — strip it
    from the child env (see trust_check.verify_signature).

### 🔄 AVAILABLE FOR OTHER AGENTS

| Task | Assignee | Priority | Files |
|------|----------|----------|-------|
| TASK-011: Narrow Defender exclusions | ✅ DONE v29.42w | ~~CRITICAL~~ | enhanced_bypass_system.py, defender_compatibility.py, all 3 launchers |
| TASK-012: PS command-injection hardening | ✅ DONE v29.42w | ~~CRITICAL~~ | advanced_threat_remediation.py (analyzer call was already escaped) |
| TASK-013: Feed integrity (hash manifests, corroboration) | ✅ DONE v29.42y (HTTPS-only both fetch paths + sha256 audit lines; agent-audit-001's HMAC manifest class merged) | ~~CRITICAL~~ | downpour_v29_titanium.py, threat_feed_aggregator.py |
| TASK-014: Config.json signing / tamper alerting | ✅ DONE v29.42w | ~~High~~ | config.py + tests |
| TASK-015: Signature-bound allowlists | ✅ DONE v29.42y (trust_check.py; behavior_scanner substring-skip fixed) | ~~High~~ | trust_check.py (new), behavior_scanner.py, threat_response_center.py |
| TASK-016: Quarantine unification (AES-GCM + verified restore) | ✅ DONE v29.42x | ~~High~~ | quarantine_core.py (new), downpour_v29_titanium.py, advanced_threat_remediation.py, system_cleanup.py |
| TASK-017: KEV/EPSS hot-path cache | ✅ DONE v29.42w | ~~Medium~~ | file_scanner.py, process_monitor.py, threat_detection_engine.py |
| TASK-018: SensorHub consolidation + orphan retirement | ✅ DONE v29.42y | ~~Medium~~ | sensor_hub.py (new), downpour_v29_titanium.py, process_monitor.py, network_monitor.py, file_monitor.py, ransomware_detector.py |
| TASK-007: Automated test suite | ✅ DONE v29.43c | ~~Medium~~ | tests/test_task007_critical_paths.py, test_quarantine_core.py, test_trust_check.py, test_port_profiles.py |

---

## Key Code Locations

### Main Application
- `downpour_v29_titanium.py` - 55k+ lines, main Tkinter app class `downpour`
- Tab definitions: line ~23900 (`_TAB_DEFS`)
- Remediation tab: `_build_remediation_tab` (~line 26637)
- Possible Threats tab: `_build_possible_threats_tab` (~line 26918)
- Performance tab: `_build_performance_tab` (~line 29112)
- Rain canvas: `ImmersiveRainCanvas` class (~line 19048)
- HardwareProfile: line ~718
- Alert queue: `_queue_alert` (~line 38039)

### New Methods Added
- `_add_possible_threat()` - Auto-populate possible threats from detections (~line 27142)
- `_remediation_revert()` - Auto-revert logic for quarantine, firewall, etc.
- Remediation logging in `_threats_remediate_selected`, `_threats_remediate_all`, `_threats_basic_remediate`
- `_auto_tag_mitre()` - Auto-detect MITRE tags in Possible Threats tab
- `_get_mitre_tag()` / `_get_mitre_tag_full()` - Network MITRE tagging
- `_auto_tag_mitre()` - Behavior scanner MITRE tagging

### Network/VPN
- `downpour_vpn_module.py` - VPN kill switch, DNS leak test, QUIC handling
- `network_monitor.py` - Connection monitoring, port scan detection, baseline learning
- Firewall rules use `netsh advfirewall` with `CREATE_NO_WINDOW`

### Threat Detection
- `threat_detection_engine.py` - Port analysis with `PORT_PROFILES` confidence scoring
- `behavior_scanner.py` - Process/network behavior analysis with MITRE tagging
- `mega_threat_signatures.py` - `PORT_PROFILES`, `SUSPICIOUS_PORTS`, malware families

### Config/Hardware
- `config.py` - Configuration management
- `device_adaptation_engine.py` - Hardware profiling
- `advanced_hardware_monitor.py` - Real-time metrics
- `HardwareProfile` - Now includes laptop detection fields

### Security-Critical Locations (2026-09-07 audit — see docs/SECURITY_AUDIT_2026-09-07.md)
- Defender exclusions: `enhanced_bypass_system.py:58-68`, `defender_compatibility.py:98-99` (ExclusionProcess python.exe + .pyc/.pyd — to be removed, TASK-011)
- ASR rule toggle: `LAUNCH_V29_TITANIUM.bat:181-190` (disable during pip) + `:240` (restore — currently AuditMode, should be Enabled)
- Feed verification placeholders: `downpour_v29_titanium.py:10374-10379` (`VERIFICATION_HASHES` — strings, not hashes); HTTP feed allowlist `:10430-10441`
- PS injection sites: `advanced_threat_remediation.py:915-919` (WMI cleanup), `advanced_threat_analyzer.py:447-448` (Get-AuthenticodeSignature)
- Quarantine formats: `downpour_v29_titanium.py:9791-9810` (plain move), `advanced_threat_remediation.py:954-979` (XOR 0x5A), `threat_response_center.py` (GUI)
- Restore path (no hash verify): `system_cleanup.py:121-138`
- Name-only allowlists: `threat_response_center.py:58-77`, `process_monitor.py:102`, `downpour_v29_titanium.py:9325-9327`
- Corroboration gate: `downpour_v29_titanium.py:9737-9756` | "secure" temp dir chmod no-op: `:10385-10386`
- KEV hot-path constructs: `file_scanner.py:55`, `process_monitor.py:30`, `threat_detection_engine.py:830`

---

## Coordination Protocol

### For Other Agents:
1. **Claim a task** - Update `WORK_QUEUE.json` with your agent ID and `claimed_at`
2. **Register** - Add yourself to `AGENT_REGISTRY.json`
3. **Heartbeat** - Update `heartbeat` every 30-60 seconds while working
4. **Log progress** - Update task `status` and add notes
5. **Complete** - Set `status: completed` with `completed_at` timestamp

### File Lock Convention:
- Create `.lock.<filename>` before editing major files
- Delete after commit
- Max 5 minutes

### Communication:
- Use `SHARED_CONTEXT.md` for findings
- Task handoffs: update `WORK_QUEUE.json` with `from_agent`/`to_agent` notes
- Blockers: add `blocked_by` field to task

---

## Known Issues / Gotchas

1. **Tkinter threading** - All UI updates must use `self.after()` or `self._orig_after()`, never direct widget calls from background threads
2. **COM initialization** - Background threads using WMI/psutil need `pythoncom.CoInitializeEx(0)` 
3. **Admin required** - Firewall rules, network isolation need elevation
4. **psutil locking** - Global `_PSUTIL_LOCK` serializes all psutil calls (see line ~404 in main)
5. **Lazy tabs** - 8 tabs load on first click via `_on_tab_changed_lazy`
6. **Windows `os.chmod()` is a no-op** — `chmod(0o700)` on the "secure" temp dir (`downpour_v29_titanium.py:10385`) does NOT restrict access; default user ACLs apply. Use `icacls`/`win32security` DACLs.
7. **`VERIFICATION_HASHES` are placeholder strings, not hashes** (`:10374-10379`) and `_verify_url_security` allows plain HTTP for phishtank/nixspam/sysctl (`:10430-10441`) — feed data is NOT authenticated (TASK-013).
8. **Name-only allowlists are spoofable** — never add new name-based safe-process checks; use signature-bound validation (TASK-015).
9. **Never interpolate threat data into PowerShell strings** — f-string `{name}`/`{path}` in PS commands is admin-level command injection (TASK-012). Quote-double or use -EncodedCommand.
10. **Three quarantine formats coexist** (plain move / XOR-0x5A / GUI) — restore via `system_cleanup.py` does not hash-verify; unify before touching quarantine code (TASK-016).

---

## Next Steps for Other Agents

**agent-main-001**: TASK-013 follow-up DONE (wired HMAC manifest verify into threat_intelligence.py store path — threatfox, urlhaus, phishtank, malwarebazaar, emerging_threats, blocklist_de feeds now verify content before parsing) 
**agent-config-003**: surface `ConfigManager.tamper_detected` in the UI (flag + register_tamper_callback exist since v29.42w)
**agent-perf-002**: TASK-010 (GPU YARA acceleration — DEFERRED: yara-python has no GPU execution model)
**agent-audit-007**: TASK-016 follow-ups (boot-time reconciliation scan + quarantine-dir DACLs) when slots open
**unclaimed**: TASK-018 (SensorHub consolidation — MEDIUM, already completed per WORK_QUEUE)