# Downpour Security Architecture Audit — 2026-09-07 (v29.42v)

**Type:** Read-only audit. No code changed in this pass. Findings are tracked as
TASK-011…TASK-018 in `WORK_QUEUE.json` and mirrored in `docs/TODO.md` +
`SHARED_CONTEXT.md`. This file is the full reference; `_WORKLOG.md` has the
session summary.

**Scope:** `downpour_v29_titanium.py` (2.78 MB / ~52k lines) + ~60 support
modules, 4 launchers, 104 YARA rules, 10+ SQLite DBs, quarantine/remediation
stack, feed ingestion, test suite (93 tests passing).

---

## 1. Attack Surface Map

```
INGESTION (event sources)
- LAUNCH_V29_TITANIUM.bat: UAC elevation → Defender exclusions → firewall rules → python (admin)
- file_monitor.py:         win32 watcher threads per protected folder (ORPHANED — never started)
- ransomware_detector.py:  1s loop: 5s file-change scan + 10s process scan (actual file sensor)
- process_monitor.py:      psutil poll 10s (orphaned; main app runs its own _proc_loop 60s)
- network_monitor.py:      psutil.net_connections poll 10s (orphaned; main app has own net loop)
- config.py:               watchdog Observer on config.json (hot-reload)
- threat_feed_aggregator / threat_intelligence_updater: HTTP/HTTPS IOC feed downloads (18 feeds)
- iot_scanner.py:          active subnet port scans (connect_ex, 255 hosts)
- usb_protection.py:       device arrival monitoring

DETECTION (in-process, all threads share the admin token)
- AdvancedProcessScanner.scan_all(): ThreadPoolExecutor (0.75x cores cap 32)
- threat_detection_engine.py / mega_threat_signatures.py: port profiles, cmdline regexes, 750+ families
- behavior_scanner.py / ml_behavioral_analyzer.py: sklearn IsolationForest/RF (joblib)
- kimwolf_botnet_detector.py: 150+ IOC botnet detector, auto netsh blocks
- ransomware_detector.py: entropy, canaries, snapshots, shadow-copy watch
- vulnerability_scanner.py: KEV/EPSS enrichment

RESPONSE (destructive, all admin)
- mitigate() (main): suspend/kill_tree/quarantine(plain move)/network_isolate/firewall_block
- advanced_threat_remediation.py: 5-phase (XOR 0x5A quarantine, service/WMI/task/registry cleanup)
- threat_response_center.py: GUI kill/quarantine/netsh reset
- emergency_response.py: disable ALL NICs, lock workstation
- system_cleanup.py: restore quarantined files, purge FP DB entries

PERSISTENCE: 12+ SQLite DBs, JSON logs, remediation log w/ auto-revert
```

## 2. Top-5 Risk Matrix

| # | Risk | Location | Severity |
|---|------|----------|----------|
| 1 | **Self-inflicted Defender blind spot.** `ExclusionPath` = user-writable app dir + `ExclusionProcess` = `python.exe` + **global** `ExclusionExtension` `.pyc`/`.pyd`. Launcher also sets ASR rule `3b576869` Disabled during pip and only restores to **AuditMode**. Any malware dropped in the app dir, or delivered as Python bytecode anywhere, is invisible to Defender. | `enhanced_bypass_system.py:58-68`, `defender_compatibility.py:98-99`, `LAUNCH_V29_TITANIUM.bat:181-190,240` | **CRITICAL** |
| 2 | **Unauthenticated, MITM-able feed ingestion drives automated system changes.** `self.VERIFICATION_HASHES` are placeholder strings, not hashes (`downpour_v29_titanium.py:10374-10379`); plain HTTP allowed for phishtank/nixspam/sysctl (`:10430-10441`); feed IOCs flow into automatic netsh blocks (`kimwolf_botnet_detector.py:368-372`) and auto-remediation. Poisoned feed = attacker-controlled admin-level action. | same + `threat_feed_aggregator.py`, `threat_intelligence_updater.py` | **CRITICAL** |
| 3 | **PowerShell command-injection from threat data.** `_remove_wmi_subscription` interpolates cls/name from threat data into PS (`advanced_threat_remediation.py:915-919`). (Correction v29.42w: `advanced_threat_analyzer.py:446` was already quote-doubling — initially over-stated.) A `'` or `$(...)` in a name breaks out **as admin**. **FIXED v29.42w** — class validation + quote-escaping. | advanced_threat_remediation.py | **CRITICAL** ✅ fixed |
| 4 | **No privilege segregation.** The whole 52k-line GUI + parsers + YARA + sklearn + 20+ threads + ProcessPool workers run elevated; any crash/exploit in any module yields the highest-integrity context in the process. | whole codebase | **HIGH** |
| 5 | **Tamperability.** `config.json` hot-reloads any edit (`config.py:78-85`); DBs/logs/quarantine live in the user-writable dir with no ACLs/signing; `os.chmod(0o700)` on the "secure" temp dir is a **no-op on Windows** (`downpour_v29_titanium.py:10385-10386`). | `config.py`, `downpour_v29_titanium.py:10381-10399` | **HIGH** |

## 3. Pipeline Latency & Bottlenecks

1. **Redundant sensor stack** — process_monitor (10s), ransomware_detector
   (5s/10s), network_monitor (10s), main `_proc_loop` (60s) each snapshot
   psutil independently behind the global `_PSUTIL_LOCK`. Same data
   fetched/parsed/scored 3-4x.
2. **Per-call engine construction** — `VulnerabilityScanner()` (full DB init)
   is constructed **per file** in `file_scanner.py:55`, per process in
   `process_monitor.py:30`, per CVE in `threat_detection_engine.py:830`, then
   linearly scans the KEV catalog. Worst O(files x catalog) hotspot.
3. **Synchronous disk I/O in monitor loops** — hashing + DB writes inline in
   `ransomware_detector.monitoring_loop`; `create_emergency_backup()` copies
   user files inside the loop (~line 945); archive decompression inline in
   `file_scanner.py:570-596`.
4. **Thread-pool churn** — fresh ThreadPoolExecutor per scan tick; wedged
   workers leak abandoned pools (`shutdown(wait=False)`, `:9301`) — the exact
   176→341 thread growth seen in `_WORKLOG.md` v29.41k5.
5. **Feed write storms** — `_store_parsed_iocs` executemany bursts + geo/OSINT
   network calls adjacent to monitor paths.

**Refactor (TASK-017/018):** one `SensorHub` (one snapshot per tick → bounded
queues → analyze pool → act pool); persistent scan pool with
`max_tasks_per_child=1` for the sklearn path (kills the joblib
nested-parallelism deadlock class); KEV/EPSS as static hash-map indexes
refreshed on interval; all hashing/backup work on a dedicated IO worker;
single DB writer per file (WAL).

## 4. Privilege Segregation (target)

| Plane | Privilege | Contents |
|-------|-----------|----------|
| Actor service | Elevated, minimal | netsh / sc / WMI-cleanup / Set-MpPreference / quarantine moves / registry hardening |
| Analysis workers | Restricted-token child processes (Job object: no UI, no net write, no cross-process access) | file/PE parsing, YARA, archive unpacking, regex, entropy, ML, **feed parsing** |
| UI | Medium IL, non-elevated | Tkinter; talks to actor via ACL'd named pipe — never calls netsh itself |
| Untrusted decode | AppContainer/sandbox | archive extraction first (decompression bombs/path traversal parsed inline today) |

Keep admin: `advanced_threat_remediation`, `emergency_response`,
`threat_response_center` (firewall actions), `kimwolf_botnet_detector`
(firewall), `system_hardening`. Demote: `file_scanner`,
`advanced_file_analyzer`, `behavioral_analyzer`, `ml_behavioral_analyzer`,
feed parsers, `memory_forensics`. A parser crash then costs one worker, not
the admin session.

## 5. Detection Gaps (unmonitored persistence/RAT vectors)

1. **WMI event subscriptions** (`ActiveScriptEventConsumer`,
   `CommandLineEventConsumer`) — remediation can remove them, nothing watches
   creation in real time.
2. **Scheduled task creation** — string heuristic only
   (`behavior_scanner.py` `schtask_create`); no live TaskScheduler ETW channel.
3. **Service creation/modification** (EventLog 7045) — no subscription.
4. **DLL hijacking / planting** — no monitor for writes to PATH-order dirs.
5. **Process hollowing / thread injection** — `memory_forensics.py` is
   on-demand only; scanner checks PPID spoofing but not
   unmap/write-remote-memory patterns.
6. **Real-time registry watch** — Run/RunOnce/Winlogon/Services keys only
   checked on-demand (`threat_hunt_engine.py`) / cleanup
   (`downpour_cleanup_module.py`).
7. **DNS-layer visibility** — port-53 connection-count only
   (`network_monitor.py:664-679`, code comments admit it); no DoH detection,
   no query-name entropy/NXDOMAIN/DGA scoring.
8. **Beaconing** — static interval tuple (`downpour_remote_access.py:58`), no
   jitter-tolerant statistical scoring.
9. **Driver-load / BYOVD in real time** — hunt engine only, on-demand.

Concrete detection logic (defensive):

```python
# Real-time persistence watcher (one thread): WMI subscription poll +
# RegNotifyChangeKeyValue on Run/RunOnce/Winlogon/Shell keys +
# Win32_ProcessStartTrace subscription for sc.exe / schtasks.exe / reg.exe
# parents -> alert with parent-child + cmdline (T1543.003, T1053.005, T1112)

# Beacon scoring per (process, dst_ip): n >= 8 callbacks and
# coefficient_of_variation(intervals) < 0.3, jitter-tolerant
# (intervals within +/-25% of median count as regular) -> T1071 alert

# DLL-hijack heuristic (T1574.001): on process start, if a writable
# non-system dir precedes the legit DLL location in loader search order and a
# same-named DLL exists there -> CRITICAL

# Hollowing heuristic (T1055.012): parent==child creator + child image-base
# region unbacked + child cmdline claims a signed binary that fails
# signature check -> CRITICAL

# DoH detection (T1071): non-browser process with sustained 443 to known
# DoH resolver IP/ASN, or <5 total conns but sustained 443, no SNI match
```

YARA gap to add (structural, not string-only like the current 104 rules):

```yara
rule Suspicious_Hollowing_Indicators {
  meta: mitre = "T1055"
  strings:
    $nt1 = "NtUnmapViewOfSection" ascii
    $zw1 = "ZwUnmapViewOfSection" ascii
    $ctx = "CONTEXT_FULL" ascii
    $res = "NtResumeThread" ascii
  condition: uint16(0)==0x5A4D and 2 of ($nt1,$zw1,$ctx,$res) and filesize < 5MB
}
```

## 6. Evasion Resilience (attacker view + counter-heuristic)

| Evasion (visible mechanism) | Why it works today | Counter-heuristic |
|---|---|---|
| Name allowlist spoofing | `KNOWN_SAFE_PROCESSES` / `system_processes` trust names only; `_safe_procs` skips connection scans by name (`:9325-9327`) | Bind to (name, signed system path, signature subject) — TASK-015 |
| Config hot-reload tamper | Any `.json` edit reloads (`config.py:78-85`) | HMAC-signed config + reject/alert — TASK-014 |
| Defender exclusion abuse | Suite installs python.exe/.pyc/.pyd exclusions any attacker can read and aim at | Narrow exclusions — TASK-011 |
| Threshold evasion | Corroboration gate needs score >=60 + >=3 reasons, or a "strong" keyword (`:9737-9756`) | Indicator class-diversity scoring + time-adaptive host baselines |
| Polling-window sleep | File sensor samples 5s/60s windows; process scan 60s; DNS flag needs >50 conns | ETW event-driven sensors for critical paths; quiet-window burst heuristic |
| Static YARA bypass | Flat nocase strings; two fixed shellcode preambles (`:9180-9182`) | Structural rules (entropy, writable+executable sections) + opcode diversity |
| Feed poisoning | No verification; feeds drive auto-actions | TASK-013 |
| Path TOCTOU | Detection and mitigation re-read paths at action time | Open exclusive handle at detection; hash-verify before acting |
| Straight-up kill | No self-protection; same-user taskkill ends the suite | Section 8 plan |

## 7. False Positive Stress-Test

| Rule | Over-breadth | FP class |
|---|---|---|
| 3389 in BOTH `KNOWN_SAFE_PORTS` and `RAT_PORTS` (`threat_response_center.py:87,99`) | Contradictory sets | Any RDP user |
| `'reg add'`/`'bitsadmin'`/`'/start hidden'` cmdline patterns (`process_monitor.py:126-129`) | Capability flagging (the philosophy `file_scanner.py:91-100` explicitly rejected for files) | Admin scripts, updaters |
| >50 port-53 conns -> DNS tunneling (`network_monitor.py:664-679`) | Volume-only, no query analysis | DCs, Pi-hole, corporate resolvers |
| PPID-spoof +35 (`:9716-9719`) | Fires on legit transient service spawns | Service hosting |
| YARA plain-text capability strings (`Invoke-Expression`, `sc stop`, `reg add`) | Plain-text markers | Chocolatey/DSC/IT scripts |
| `file_name_lower in entry.product.lower()` (`file_scanner.py:70`) | Product-name substring | Files named after products |
| High-entropy file-change triggers | Encrypted backups, DBs, .zip stores | Backup/dev tooling |

Refinements (sensitivity-preserving): route ALL port semantics through
`PORT_PROFILES` (single source of truth — delete local `RAT_PORTS` /
`suspicious_ports` copies, which also fixes the 3389 contradiction);
capability+context for cmdline rules (reg add only on Run/RunOnce/Services
targets from non-installer parents); score indicator classes, not keyword
substrings (`:9741-9746`); two-strike + confidence decay globally, feeding
the `fp_suppression.py` fingerprint cache in both directions.

## 8. Anti-Tamper / Blind-Termination Hardening Plan

1. Run the sensor/actuator as a **Windows Service** with `sc failure`
   recovery actions + a separate watchdog process (mutual heartbeat over a
   DACL'd named pipe; missed heartbeat -> restart + tamper event to the
   Windows Event Log).
2. **Lock own artifacts**: DACLs (deny write/DELETE for non-SYSTEM) on the
   quarantine dir, DBs, logs, config; HMAC-sign `config.json` and quarantine
   manifests (DPAPI machine-scope key); verify at every read.
3. **Tamper detection**: alert on `Set-MpPreference` invocations, deletion of
   Downpour files, deletion of `DOWNPOUR_*` firewall rules, service-stop
   attempts — each snapshots the actor process (path, parent, hash).
4. **Signed code manifest** checked at startup — the app dir is
   Defender-excluded and user-writable, so code replacement is currently
   undetectable.
5. **Sensor liveness**: per-folder watch threads die permanently after one
   unhandled error class (`file_monitor.py:265-331`); add a supervisor with
   backoff + a user-visible "sensor down" state wired into `_heartbeat_loop`.

## 9. Edge-Case Error Handling Findings

- Per-folder `_file_watch_loop` threads exit permanently on one error class
  (`file_monitor.py:265-331`) — silent monitoring death, no UI signal.
- `emergency_response.isolate_network` treats ANY socket error as success
  (`:203-212`) — a firewall-blocked host reads as "isolated" with adapters up.
  Verify adapter status, not a probe.
- `network_monitor._dns_counts` is an unbounded dict keyed by remote IP
  (`:665-668`) — memory DoS via many unique outbound IPs. Cap it.
- `_alerted_dedup` dict unbounded (`:23314`) — needs maxlen/TTL.
- Abandoned scan pools (`shutdown(wait=False)`, `:9301`) leak wedged threads.
- Silent `except` in sensor loops means "looks alive, does nothing" — every
  sensor needs a `last_success` timestamp surfaced on the heartbeat dashboard.
- No post-crash state reconciliation at boot (half-completed quarantines are
  never checked).

## 10. Quarantine & Reversibility

Three divergent implementations coexist:
1. `mitigate()` (main): plain `shutil.move` to `locked/{name}.locked` —
   silent name-collision overwrite, no metadata, no crypto (`:9791-9810`).
2. `advanced_threat_remediation.py`: XOR-0x5A + sidecar JSON (`:954-979`) —
   not encryption; no key management; no HMAC.
3. `threat_response_center.py`: GUI path.

Risks: `shutil.move` is copy-then-delete across volumes (power cut mid-move =
permanent user-file loss); metadata written AFTER the move (crash between =
unrestoreable orphan); `system_cleanup.py:121-138` restore never re-verifies
hash, never restores DACLs/attributes, and marks `restored=1` even when the
quarantine file is missing; XOR'd files restored by that path come back
**corrupted** (format mismatch between implementations).

Fix (TASK-016): ONE quarantine service — AES-GCM (DPAPI key), signed manifest
written BEFORE original delete (write-ahead), move-by-handle, restore =
decrypt -> re-hash -> verify -> restore ACLs from manifest -> then mark;
keep the copy N days after restore; boot-time reconciliation raises
user-visible alerts on orphans.

## 11. Production-Readiness & Roadmap

**Verdict: feature-rich prototype with good engineering hygiene (93 tests,
WAL + locked main DB, executor post-back pattern, FP fingerprinting,
post-mortem culture) — not production-grade as a security product** (elevated
monolith, Defender self-exclusions, unverified feeds, 3 quarantine formats,
dev artifacts in repo root, no installer/signing/service mode).

- **Phase 1 — Stop the bleeding (1-2 wks):** TASK-011 (exclusions), TASK-012
  (PS injection), TASK-013 (feed integrity), TASK-014 (config signing).
- **Phase 2 — Privilege & process split (2-4 wks):** UI/analysis/actor split
  (Section 4), SensorHub consolidation (TASK-018), persistent pools with
  `max_tasks_per_child`.
- **Phase 3 — Unify persistence (2-4 wks):** TASK-016 quarantine service, one
  DB writer per file, retire the orphaned monitor modules.
- **Phase 4 — Detection depth (4-8 wks):** ETW sensors (process/file/registry/
  TaskScheduler/EventLog 7045), real-time persistence watcher, beacon
  statistics, DNS-layer logging, DLL-hijack + hollowing heuristics,
  signature-bound allowlists (TASK-015), KEV cache (TASK-017).
- **Phase 5 — Production envelope (ongoing):** service + watchdog + tamper
  alerting, signed installer, code signing, crash-upload channel, telemetry
  with privacy controls, decompose the monolith into IPC-separated packages
  (detection / response / telemetry / UI).

## 12. Remediation Status (updated v29.42w, 2026-09-08)

| Item | Status |
|---|---|
| Risk 1 — Defender self-exclusions | **FIXED** (TASK-011): data-dir-only exclusions in enhanced_bypass_system/defender_compatibility + all 3 launchers; ExclusionProcess/ExclusionExtension removed; ASR restore now Enabled |
| Risk 2 — Feed ingestion integrity | **DONE v29.42y** (TASK-013): both fetch paths HTTPS-only + FEED-INTEGRITY sha256 audit lines + permissive-TLS warnings; agent-audit-001's HMAC manifest class merged; audit CORRECTION — kimwolf auto-block is dead code, live blocking is user-initiated |
| Risk 3 — PS command injection | **FIXED** (TASK-012): WMI cleanup validates + escapes; analyzer call was already safe (audit corrected) |
| Risk 4 — Privilege segregation | PARTIAL (TASK-018): `_dns_counts` memory-DoS cap shipped; SensorHub main-loop migration + service split remain the architectural path |
| Risk 5 — Config tamperability | **FIXED for config** (TASK-014): HMAC-signed config + tamper flag/callbacks; quarantine-dir ACLs remain open under TASK-016 |
| TASK-015 — allowlists | **DONE v29.42y** — trust_check.py (path + WinVerifyTrust/Get-AuthenticodeSignature, cached); behavior_scanner substring skip fixed; _safe_procs path-bound; display no longer trusts name alone |
| TASK-017 — KEV hot-path cache | **DONE** |
| TASK-016 — quarantine unification | **DONE v29.42x → v29.43d** — v2 QuarantineService merged (agent-audit-001) + all call sites rewired (agent-audit-007); collision fix + legacy migration v29.43c; GUI producer migrated v29.43d. ALL producers unified |
| TASK-018 — SensorHub consolidation | OPEN (MEDIUM) |
