# Downpour v29 Titanium — Enhancement Worklog

## Branch: main

## Session 2026-09-08 — v29.44: improvement catalog (external security tooling research)
- ✅ Created `docs/IMPROVEMENT_CATALOG.md` — 21 actionable improvements sourced
  from the security tooling landscape, organized by impact/effort:
  - **Detection**: YARA-X (Rust, 5-10× faster), Hyperscan (multi-pattern DFA),
    ETW kernel telemetry (replaces polling), EMBER ML static PE analysis,
    Sigma rules (3000+ community detections), AMSI integration, LOLBins
  - **Performance**: Aho-Corasick IOC matching (O(n) for 750+ patterns),
    RE2 (no ReDoS), functools.lru_cache on hot paths
  - **Self-Protection**: Process mitigation policies (SetProcessMitigationPolicy
    via ctypes — blocks shellcode injection, DLL hijacking, direct syscalls),
    Windows Job Objects (child process restriction)
  - **Threat Intel**: STIX/TAXII, MISP, government feeds
  - **Code Quality**: structlog, pydantic, tenacity, rich
- ✅ Baseline re-verified: **205/205 tests pass** (no regressions).

## Session 2026-09-08 — v29.43j: streaming legacy migration (memory-blowup fix in migration path)
- 🐞 **Same memory-blowup class as v29.43e, in the migration path**:
  `migrate_legacy_entries` read whole legacy artifacts into RAM
  (`f.read_bytes()`) and re-encrypted them as a second full copy — plus a
  latent TypeError (`_get_or_create_key(root)` — the v2 signature takes no
  args) in the AES branch that would have crashed any legacy AES migration.
- ✅ Rewrote the migration to stream: `_legacy_decrypt_stream(src, method,
  key, dst)` decrypts chunk-by-chunk into a tmp plaintext (hash on the
  fly), then `_encrypt_stream_file(tmp, q_path)` v2-encrypts it — constant
  memory end-to-end. Hash verified against the sidecar before registration.
- ✅ Fixed the latent AES-branch key bug with `_legacy_key_for(root)` (reads
  the v1 `.quarantine_key` explicitly — DPAPI/RAW).
- ✅ Restored the `no_metadata` counter dropped in the streaming rewrite.
- ✅ Verification: py_compile OK; **205/205 tests pass** (all legacy/XOR/
  plain-migration cases green through the streaming path).

## Session 2026-09-08 — v29.43i: sensor hub lifecycle + liveness surfacing (TASK-018 completion)
- 🐞 **Found the missing hub start**: `start_sensor_hub()` was defined and
  imported but NEVER CALLED — the "rewired" orphan monitors
  (process_monitor/network_monitor) consumed from a hub that never ran.
  Fixed: `_manual_start_monitoring` now starts the hub when monitoring
  begins (guarded by SENSOR_HUB_AVAILABLE).
- ✅ **Heartbeat liveness surfacing** (audit §8.5): `_heartbeat_loop` now
  queries `get_sensor_hub().liveness_report()` — the [ALIVE] line includes
  `sensors_alive=N`, and any sensor past the 180s staleness threshold is
  logged via logger.warning + error_logger ('SensorLiveness').
- ✅ **3 new source-structure tests** (suite pattern — main file read as
  text, never imported): hub start on monitoring, heartbeat liveness
  surfacing, boot self-checks wiring. **205/205 tests pass.**

## Session 2026-09-08 — v29.43h: boot self-checks wiring + sensor liveness + personal-path scrub
- ✅ **Boot-time self-checks wired into `_auto_start`** (audit §8.4/§9 — the
  last unwired piece): a daemon thread 30s after launch runs (a)
  `code_integrity.verify_baseline` — TOFU baseline on first run, loud
  error-logger alerts on modified/missing code files or baseline tamper
  (the app dir is Defender-excluded, so this is the only code-replacement
  detection); (b) `migrate_legacy_entries` + `reconcile_quarantine` —
  pre-v2 quarantine artifacts ingested and orphaned entries reconciled at
  boot instead of waiting for a manual system_cleanup run. Non-blocking,
  never raises into the GUI.
- ✅ **Sensor liveness registry** (audit §8.5): `sensor_hub.mark_alive(name)`
  + `liveness_report(stale_after)` — the hub marks itself every tick; any
  loop can register. Stalled sensors are detectable instead of silently
  dead. 3 new tests.
- ✅ **Personal-path scrub completed**: `docs/SMART_REPAIR_GUIDE.md` (the
  last tracked file with a `C:\Users\<user>` path, JSON-escaped form) and
  `_WORKLOG.md`/`docs/TODO.md` scrubbed in v29.43d-g. GitHub tree now has
  zero local-username path exposure in the current tree.
- ✅ Verification: py_compile OK; **202/202 tests pass** (3 new liveness
  cases).

## Session 2026-09-08 — v29.43g: cross-agent bug fixes (manifest init crash + migration over-scan)
- 🐞 **Fixed FeedManifestVerifier first-run crash** (found via the concurrent
  agent's wiring of it into `threat_intelligence.py`): `__init__` called
  `_load_or_create_key()` BEFORE `MANIFEST_DIR.mkdir()` — on a fresh checkout
  the DPAPI write AND the RAW fallback write both failed with
  FileNotFoundError (the except-block re-raised). Dir is now created before
  any key write. This un-breaks `test_functional.py::test_threat_intelligence`.
- 🐞 **Fixed migrate_legacy_entries over-scan** (found via
  test_migrate_skips_v2_owned_files): the migration scanned EVERY file in
  the legacy root and ingested the service's OWN storage — renaming
  `.quarantine_key` and `quarantine.db` as "legacy" artifacts, corrupting
  the v2 service on the next run. Now ingests only known content types
  (`.quarantined` / `.locked` / `.quar`).
- ✅ Confirmed the concurrent agent completed the TASK-013 follow-up
  themselves: `threat_intelligence.py` now constructs the manifest verifier
  (task noted in queue).
- ✅ Verification: py_compile OK; **199/199 tests pass**.

## Session 2026-09-08 — v29.43f: code_integrity self-check + isolate_network fix
- ✅ **New `code_integrity.py`** (audit §8.4 — the app dir is Defender-
  excluded and user-writable, so code replacement was undetectable): signed
  self-integrity manifest — every .py/.yar under the app dir is sha256'd,
  the manifest is HMAC-signed with a DPAPI-protected key
  (`downpour_data/code_integrity.key`), and `verify_baseline()` reports
  modified/missing/extra files + baseline tamper. CLI: `python
  code_integrity.py baseline|verify`. Wired as section 6b in
  downpour_health_check.py. Honest limitation documented: a same-user
  attacker can delete key+baseline, but that act is itself a loud alert.
- 🐞 Fixed `emergency_response.isolate_network` false-success (audit §9):
  verification now checks ADAPTER STATUS via psutil instead of a socket
  probe — the old code treated any connection failure (firewall rule, DNS
  outage) as "isolated" while adapters were still up.
- 🐞 Fixed 2 self-bugs during testing: build_manifest skip-check used
  ABSOLUTE path parts (misfired when the tree lives under a skipped dir
  name like downpour_tmp — pytest tmp_path); verify_baseline popped _meta
  before signing (save signs the whole dict — shapes must match).
- ✅ Verification: py_compile OK; **199/199 tests pass** (8 new).

## Session 2026-09-08 — v29.43e: quarantine streaming format (memory-DoS fix) + TASK-010 deferred
- 🐞 **Memory-DoS fix in the v2 quarantine service**: `quarantine()` read the
  WHOLE file into RAM and `_encrypt()` doubled it (a multi-GB sample = a
  multi-GB spike); `restore()` did read + decrypt + write + re-read (~3×).
  New streamed format: `DQS2` magic + 8B nonce prefix + per-64KiB-chunk
  AES-GCM (nonce = prefix + counter BE32 — unique per chunk, constant
  memory). Files ≤64MB keep the single-shot format; ≥threshold use the
  stream path with a decrypt-hash self-verification at quarantine and a
  streaming-hash verify on restore. Old v0/v1 formats remain restorable
  (format detected by the first 4 bytes).
- ✅ 2 new tests (stream roundtrip with forced 1KB threshold + stream tamper
  refusal) — **191/191 tests pass**.
- ⏸️ **TASK-010 deferred (honest close-out)**: yara-python compiles rules to
  a CPU VM — there is no GPU execution model to offload to, so the claimed
  CUDA acceleration is not achievable with the current matcher. A real
  implementation needs a custom engine (e.g. Hyperscan-class) + a rule
  translator. Machine has an RTX 3050 (hardware verified) — the gap is
  software. Recommend re-scoping or closing permanently.
- ✅ Also verified the concurrent agent's `sensor_hub.py` quality (bounded
  queues, dataclass snapshots, per-consumer callbacks, built-in DNS/dedup
  tracking) — solid implementation, no changes needed.

## Session 2026-09-08 — v29.43d: final quarantine unification (GUI producer migrated)
- ✅ **Last divergent producer migrated**: `_threats_quarantine_selected`
  (main:~55280) — the Threats-tab GUI quarantine — moved from plain
  `shutil.move` → `.quar` in `~/downpour_quarantine` (no manifest,
  collision-prone, unrestorable) to the v2 quarantine service
  (`quarantine_file(..., threat_type='gui-selected')`). Vault message now
  points at `downpour_data/quarantine/locked`; entry IDs shown in the UI;
  GUI-quarantined files are restorable via `_remediation_revert` /
  `restore_by_original_path` for the first time.
- ✅ Fixed two bugs in the concurrent agent's new tests
  (tests/test_task007_critical_paths.py): missing `import socket` (the DNS
  leak tests' NameError was silently swallowed by the production per-host
  exception handler, yielding empty `resolvers_found`) and the
  `Allow_HTTP`/`Allow_HTTPS` prefix collision in the kill-switch protocol
  assertions (substring match grabbed the wrong command; now matches the
  exact rule-name list element).
- ✅ Verified the concurrent agent's overnight work: corroboration gate in
  kimwolf/ultimate_threat_intel (TASK-013), sensor_hub.py (TASK-018 —
  single 5s psutil snapshot, orphan modules rewired, dedup caps). Queue
  updated: TASK-018 completed.
- ✅ Verification: py_compile OK; **187/187 tests pass**.

## Session 2026-09-08 — v29.43c: collision fix + legacy quarantine migration (TASK-016 residuals closed)
- 🐞 **Collision bug CONFIRMED and FIXED** in the v2 quarantine service:
  `timestamp` was computed but never used in `safe_name`, so re-quarantining
  the same file (re-infection cycle) or two identical-named+hashed files
  silently **overwrote the previous copy** while both DB entries pointed at
  it. Now timestamp-suffixed on clash (`test_collision_disambiguation`).
- ✅ **Legacy migration shipped**: `migrate_legacy_entries()` ingests
  pre-v2 artifacts into the v2 service — v1 `.quarantined` + `.meta.json`
  sidecars (AES-GCM via the legacy `.quarantine_key`, or XOR-0x5A;
  hash-verified before registration) and plain `.locked`/`.quar` moves
  (no source hash — integrity now rides on the v2 signed manifest).
  Original path preserved; legacy artifacts renamed `*.migrated`, never
  deleted; v2-owned files skipped.
- ✅ Wired into `system_cleanup` reconcile flow (migration runs before the
  service reconcile). Residual: the GUI `_threats_quarantine_selected`
  producer (main:~55285) still writes plain `.quar` — migrate that method
  to the service next.
- ✅ Verification: py_compile OK; **175/175 tests pass** (4 new: collision
  disambiguation, XOR-sidecar migration incl. service restore, plain
  `.quar` ingest, v2-owned skip).

## Session 2026-09-08 — v29.43b: quarantine_core v2 merge (concurrent rewrite) + TASK-007 critical-path tests
- 🔀 **agent-audit-001 fully rewrote quarantine_core.py mid-session** with a
  new architecture: `QuarantineService` (SQLite-tracked `QuarantineEntry`,
  own DB at `downpour_data/quarantine/quarantine.db`), write-ahead
  manifests, AES-GCM content encryption, and **per-file security-descriptor
  preservation** (`_get_file_security`/`_restore_file_security` — DACLs are
  now saved on quarantine and restored on restore, which supersedes my
  dir-level `harden_quarantine_dacl`; that function no longer exists).
- ✅ **All four quarantine call sites rewired to the v2 API** (their rewrite
  broke them): `advanced_threat_remediation._quarantine_file`, main
  `mitigate()` quarantine branch, `_remediation_revert` (service lookup is
  by original path, single root), and `system_cleanup`
  (`restore_quarantined_files` uses `restore_by_original_path(orig_path)`
  with a raw DB-hash-verified fallback for legacy rows;
  `reconcile_quarantine_state` runs the service reconcile).
- ✅ `tests/test_quarantine_core.py` rewritten for the v2 API (7 cases:
  roundtrip, restore-by-path, tamper refusal, list/reconcile, missing
  source, metadata preservation) using an isolated fixture that points the
  service's storage constants at tmp dirs.
- ✅ **TASK-007 critical paths** (tests/test_task007_critical_paths.py, 12
  cases): VPNKillSwitch fail-closed enable/disable (BlockAll-first
  ordering, RFC1918 LAN coverage), `_block_ip` (incl. a NEW netsh
  parameter-injection fix — `remoteip` now validates via
  ipaddress.ip_address, crafted "IPs" with extra netsh args are refused),
  revert-wiring source assertions, VPNThreatFeedManager DB roundtrip.
- 🐞 Found while testing: a **fourth quarantine producer** I'd missed —
  `_threats_quarantine_selected` (main:~55285) plain-moves to `*.quar` in
  `~/downpour_quarantine` (no manifest, collision-prone). Logged as a
  TASK-016 migration residual. Also possible same-name+hash collision in
  the v2 `safe_name` (timestamp computed but seemingly unused in the path)
  — flagged for agent-audit-001.
- ⚠️ **Migration gap**: quarantine content in the OLD formats (v1
  `.quarantined`+`.meta.json`, plain `.locked`, GUI `.quar`) is not
  restorable by the v2 service — `system_cleanup` falls back to raw
  DB-hash-verified moves for those rows. A one-time migration/ingest pass
  is open work.
- ✅ Verification: py_compile OK; **171/171 tests pass**.

## Session 2026-09-08 — v29.43a: TASK-013 manifest wiring + TASK-018 fix + concurrent trust_check merge
- ✅ **TASK-013 nit closed**: `FeedManifestVerifier` (agent-audit-001's HMAC
  manifest class) is now WIRED into `threat_feed_aggregator.update_feed` —
  policy: no manifest → trust-on-first-use baseline (logged); hash changed →
  **rolling re-sign** (dynamic IOC feeds legitimately change content —
  strict pinning would have rejected every legitimate update after the
  first fetch); feeds can opt into strict pinning via
  `feed_config['strict_manifest']`; an invalid manifest SIGNATURE (local
  tampering) is always rejected. Added `get_expected_hash()`/`resign()`.
- ✅ **TASK-018 partial**: `network_monitor._dns_counts` capped at 4096
  entries with clear-on-overflow (memory-DoS fix from the audit).
- ✅ **TASK-007 partial**: `tests/test_port_profiles.py` (7 cases) validates
  the concurrent agent's PortProfile rework — bounds, legit-process
  confidence drop, malware confidence cap, 80/443 FP guard. Found a DATA
  issue for agent-audit-001: **port 1433 is defined twice** in
  PORT_PROFILES (MEDIUM_RISK :491 shadowed by LOW_RISK :513 — later wins).
- 🔀 **Concurrent trust_check merge (agent-audit-001 rewrote my module)**:
  they replaced my ctypes WinVerifyTrust implementation with a
  PowerShell-only signer-subject check and renamed the public API. Merged:
  kept their signer-subject policy + richer name list + pseudo-process
  exemptions, restored (1) the public `is_system_image` (their rename broke
  threat_response_center + test imports), (2) the **PSModulePath-stripped
  child env** (their version reintroduced the PowerShell loading failure),
  (3) the System32 path-prefix hole (no-backslash prefixes matched
  `System32evil\`), (4) cache keys now include mtime/size (a replaced
  binary at the same path no longer gets a stale verdict). Their main-file
  import (`trusted_system_process`/`is_trusted_system_process`) is
  compatible with the merged module.
- ✅ Verification: py_compile OK; **165/165 tests pass** (7 new port-profile
  cases; trust_check tests updated to the merged API).

## Session 2026-09-08 — v29.42z: TASK-016 follow-ups (reconciliation scan + DACL hardening)
- ✅ `reconcile_quarantine()` in quarantine_core: manifest/content cross-check
  (orphan manifests, unmanifested content, legacy `.locked` census) with an
  optional DB pass marking rows whose content is missing as `restored=2`.
- ✅ `harden_quarantine_dacl()`: icacls with language-neutral SIDs
  (`*S-1-5-18` SYSTEM, `*S-1-5-32-544` Administrators), inheritance
  disabled, elevated-only (non-elevated runs skip — locking the dir would
  lock the app out), per-process attempt guard to prevent retry spam;
  auto-invoked on the first quarantine per dir.
- ✅ Wired: `system_cleanup` runs reconciliation before restore in
  `--auto`/`--restore` flows + new dedicated `--reconcile` flag;
  `quarantine_core` CLI gained `--reconcile/--db/--harden-dacl`.
- ✅ Tests: 4 new reconcile/DACL cases — **158/158 pass**. Concurrent agent
  touch since last sync: `ultimate_threat_intel/__init__.py` (their
  indicator-store work) — no conflicts.

## Session 2026-09-08 — v29.42y: TASK-013 + TASK-015 close-out (feed integrity + signature-bound allowlists)
- ✅ **TASK-013 (CRITICAL)** — feed ingestion integrity, both fetch paths:
  - Main `ThreatIntelEngine._fetch_feed`: **plain-HTTP fallback removed**
    (HTTPS-only; a feed that can't serve TLS fails loudly in feed health
    instead of being silently downgraded to unauthenticated transport);
    per-fetch `FEED-INTEGRITY feed= sha256= bytes= host=` audit lines;
    bounded `_feed_integrity` last-good-hash record; cert-exempt
    (`_CERT_EXEMPT`) permissive-TLS hosts now emit a loud warning.
  - `threat_feed_aggregator.fetch_feed`: refuses non-HTTPS urls + same
    FEED-INTEGRITY sha256 audit line.
  - **Concurrent-agent merge**: agent-audit-001 landed an HMAC signed-
    manifest class (`create_manifest`/`verify_feed`) in
    threat_feed_aggregator mid-session — complementary; repaired their
    in-flight IndentationError (orphan `class FeedParser:` header at :134).
  - **Audit correction**: kimwolf `_block_ip_firewall` has ZERO call sites
    (dead code) — the "feeds drive automatic netsh blocks" claim was
    overstated; live blocking is user-initiated or the Aegis C2Blocker.
- ✅ **TASK-015 (HIGH)** — signature-bound allowlists via new
  `trust_check.py`: `is_system_image()` (path under %SystemRoot%),
  `verify_signature()` (WinVerifyTrust via ctypes, cached per
  path/mtime/size, with a **PSModulePath-safe Get-AuthenticodeSignature
  fallback**), `trusted_system_process()`. Wired:
  - `behavior_scanner.analyze_running_processes`: the old skip was a
    **substring** match (`safe in name`) — any process whose name merely
    contained 'system' was skipped entirely; now exact name + system path
    + signature.
  - `threat_response_center` process-info panel: name-match alone no
    longer prints "[OK] KNOWN SAFE" — warns on masquerading (T1036) when
    the image path is not the Windows directory.
  - `process_monitor.system_processes` documented as unreferenced (the
    live gating is the main-file check + trust_check).
- 🐞 Two real bugs found while testing trust_check: (1) WinVerifyTrust
  returns HRESULTs as a **signed** c_int, so `ret == 0x800B0001` never
  matched (now masked with `& 0xFFFFFFFF`); (2) the PowerShell fallback
  failed under an inherited venv `PSModulePath` — fixed by stripping
  PSModulePath from the child env (an environment gotcha worth remembering
  for ANY PowerShell spawn from this suite).
- ✅ Verification: py_compile OK on all 7 touched files; **154/154 tests**
  (8 new in `tests/test_trust_check.py`).

## Session 2026-09-08 — v29.42x: TASK-016 quarantine unification + concurrent-agent sync
- ✅ **TASK-016 (HIGH)** — shipped `quarantine_core.py`, the single canonical
  quarantine implementation, and wired every real path to it:
  - `quarantine_file()`: AES-256-GCM (DPAPI-protected key, XOR-0x5A fallback
    when cryptography/win32crypt unavailable) using chunked
    8B-nonce-prefix + 4B-counter construction (unique nonce per 64 KiB
    chunk, constant memory); **write-ahead** — encrypted copy + manifest are
    written AND self-verified before the original is deleted; collision-safe
    dest naming (fixes mitigate()'s silent `{name}.locked` overwrite).
  - `restore_file()`: decrypts to a temp file next to the original, verifies
    SHA-256 (manifest or caller-supplied DB hash) BEFORE `os.replace` —
    tampered quarantine content is refused, never restored. Supports legacy
    `advanced_threat_remediation` XOR `.meta.json` sidecars and manifest-less
    `.locked` files (verified only when a hash is supplied).
  - Wired: `advanced_threat_remediation._quarantine_file`, main `mitigate()`
    quarantine branch, `_remediation_revert` (was a **silent no-op** — it
    scanned `~/downpour_quarantine` for a `*.quar` suffix NO producer ever
    wrote; now manifest lookup by original path across both quarantine
    roots), `system_cleanup.restore_quarantined_files` (hash-verified;
    `restored=2` = evidence-lost instead of lying `restored=1`).
  - `threat_response_center` / dashboard quarantine buttons are UI stubs
    (no file ops) — no change needed.
- ✅ Tests: new `tests/test_quarantine_core.py` (7 cases: roundtrip,
  collision naming, tamper-refusal, legacy-XOR sidecar, restore-by-path,
  .locked fallback + wrong-hash refusal). **146/146 tests pass.**
  Found+fixed during testing: manifest-less restore needs the caller's
  `original_path` (added as an explicit `restore_file` parameter).
- 🔎 **Concurrent agent sync (agent-audit-001)**: diffed their working-tree
  changes — expanded MITRE technique map in `behavior_scanner.py` (note:
  several duplicate dict keys — `fileless_execution`, `dll_injection`,
  `process_hollowing`, `thread_hijack`, `atom_bombing` — are harmless but
  sloppy; later entries win; a `'dll_search hijacking'` typo key is dead),
  context-aware `PortCategory`/`PortProfile` rework in
  `mega_threat_signatures.py`, large `vulnerability_scanner.py` rework,
  `network_monitor`/`downpour_vpn_module`/`browser_protection`/
  `enhanced_logging` updates, new `history_manager.py`. No conflicts with
  my files (quarantine paths untouched by them). Also repaired a stray
  unindented `{` in `WORK_QUEUE.json` (re-appeared at the duplicate
  TASK-006 object).

## Session 2026-09-08 — v29.42w: security hardening round 1 (TASK-011/012/013/014/015/017)
- ✅ **TASK-011 (CRITICAL)**: Defender exclusions narrowed to DATA DIRS ONLY.
  `enhanced_bypass_system.run()` excludes `downpour_data`/`downpour_v27_data`/
  `downpour_tmp` only; `ExclusionProcess python.exe` + global
  `ExclusionExtension .pyc/.pyd` calls REMOVED; `defender_compatibility`
  (apply_defender_settings + create_defender_exclusions) scoped likewise;
  all 3 launchers: data-dir ExclusionPath, no process/extension exclusions,
  and ASR rule 3b576869 restore switched **AuditMode → Enabled**.
- ✅ **TASK-012 (CRITICAL)**: `_remove_wmi_subscription`
  (advanced_threat_remediation) validates the WMI class name against
  `^[A-Za-z_][A-Za-z0-9_]*$` and single-quote escapes the consumer name
  before PS interpolation (was admin-level command injection from threat
  data). CORRECTION: `advanced_threat_analyzer.py:446`
  Get-AuthenticodeSignature was ALREADY quote-doubling — audit over-stated;
  no change needed there.
- ✅ **TASK-014 (HIGH)**: config.json tamper defense in config.py — HMAC-SHA256
  signature (`config.json.sig`) written on every save with a DPAPI-protected
  key (`config.json.key`, RAW fallback when win32crypt unavailable); loads
  AND hot-reloads verify (hot-reload now reuses the verified
  `_load_from_file`); mismatch/missing-sig keeps the previous config, sets
  `tamper_detected`, fires `register_tamper_callback`. First run adopts an
  unsigned file and signs on next save. Tests: hot-reload + callback tests
  updated to the signed-edit contract; new
  `test_tamper_detection_rejects_unsigned_edit` (needed a 1.2s wait to
  outlast ConfigChangeHandler's 1.0s debounce). Note: `import logging` moved
  to the top of config.py — the bottom-of-file import wasn't bound yet when
  `ConfigManager()` constructs at import time (caught by pytest as a
  collection NameError).
- ✅ **TASK-017 (MED)**: KEV hot-path caches — `file_scanner._get_kev_index()`
  (hash→entries map + product list, hourly TTL, thread-safe, backoff on
  scanner failure), `process_monitor._get_kev_products()` (same pattern),
  `threat_detection_engine._get_vuln_scanner()` singleton. No more
  per-file/per-process `VulnerabilityScanner()` construction + linear catalog
  scans. file_scanner product match tightened to whole-token (kills the
  `file_scanner.py:70` FP).
- ⚠️ **TASK-013 partial**: `_verify_url_security` now HTTPS-only (the
  phishtank/nixspam/sysctl plain-HTTP allowlist removed); the unused
  placeholder VERIFICATION_HASHES dict deleted (nothing ever read it).
  Remaining: signed per-feed hash manifests in the fetch path, per-fetch
  sha256 logging, corroboration gate for auto-blocks.
- ⚠️ **TASK-015 partial**: main `_safe_procs` connection-scan skip now
  requires the image path under `%SystemRoot%\System32|SysWOW64`
  (svchost.exe in %TEMP% is connection-scanned again; system/registry
  pseudo-procs exempt by name). Remaining: WinVerifyTrust binding for
  KNOWN_SAFE_PROCESSES / system_processes.
- ✅ Verification: py_compile OK on all 9 touched files; **139/139 tests
  pass** (up from 139 baseline incl. the new tamper-detection test).
- ℹ️ Concurrency note: `agent-audit-001` updated WORK_QUEUE/TODO for 011/012
  mid-session; queue reconciled (011/012/014/017 completed; 013/015 partial;
  restored TASK-013's accidentally-dropped assignee/priority lines and the
  TASK-012 brace indentation).

## Session 2026-09-07 — v29.42v: Full-project security architecture audit (read-only)
- ✅ Mapped the complete integrated attack surface (ingestion → detection →
  response → persistence) across the monolith + ~60 modules. Full reference
  written to `docs/SECURITY_AUDIT_2026-09-07.md`; queue TASK-011…TASK-018.
- ⚠️ **CRITICAL #1 — Defender self-exclusion blind spot**: exclusions taken at
  launch are `ExclusionPath` = the user-writable app dir, `ExclusionProcess` =
  `python.exe`, and **global** `ExclusionExtension` `.pyc`/`.pyd`
  (`enhanced_bypass_system.py:58-68`, `defender_compatibility.py:98-99`); ASR
  rule `3b576869` is restored to **AuditMode** not Enabled
  (`LAUNCH_V29_TITANIUM.bat:240`). Any same-user dropper into the app dir, or
  any malicious Python bytecode anywhere, is invisible to Defender.
- ⚠️ **CRITICAL #2 — Feed ingestion integrity**: `self.VERIFICATION_HASHES`
  are placeholder strings (`'verified_abusech_source'`), not hashes
  (`downpour_v29_titanium.py:10374-10379`); plain-HTTP feeds explicitly
  allowed (`:10430-10441`); feed IOCs drive automatic netsh blocks
  (`kimwolf_botnet_detector.py:368-372`) and auto-remediation.
- ⚠️ **CRITICAL #3 — PowerShell injection from threat data**:
  `_remove_wmi_subscription` interpolates threat names into PS
  (`advanced_threat_remediation.py:915-919`); `-LiteralPath '{path}'`
  interpolation (`advanced_threat_analyzer.py:447-448`). Quote/`$(...)` in a
  name executes as admin.
- ⚠️ **HIGH #4** — no privilege segregation (parsers/YARA/sklearn share the
  elevated token). **HIGH #5** — tamperability: `config.json` hot-reloads any
  edit (`config.py:78-85`); `os.chmod(0o700)` on the "secure" temp dir is a
  no-op on Windows (`downpour_v29_titanium.py:10385-10386`).
- ℹ️ Latency: `VulnerabilityScanner()` constructed **per file/process** on hot
  paths (`file_scanner.py:55`, `process_monitor.py:30`,
  `threat_detection_engine.py:830`) + linear KEV scans; 4 redundant psutil
  pollers; `network_monitor._dns_counts` unbounded dict (`:665-668`).
- ℹ️ Reliability: 3 divergent quarantine formats (plain move w/ collision
  overwrite `:9791-9810`; XOR 0x5A `advanced_threat_remediation.py:954-979`;
  GUI path); restore path (`system_cleanup.py:121-138`) never re-verifies
  hash, never restores DACLs, marks `restored=1` even when file is missing.
- ℹ️ Housekeeping: fixed malformed trailing `] }` in `AGENT_REGISTRY.json`
  (was invalid JSON), resolved duplicate TASK-006 in `WORK_QUEUE.json` (the
  pending agent-net-004 copy superseded by the completed agent-main-001 one),
  registered `agent-audit-007`.

## Session 2026-08-20 — v29.42i: Intel feed health — surface load failure instead of silent Pending
- ✅ `_refresh_feed_health` `_load` swallowed DB failures (`except: pass`) leaving
  `Status` stuck `Pending` forever. Now logs to `IntelFeedHealth/load failed`
  and surfaces `Feed health: load failed — see error log` in `_intel_status`
  so the operator sees the failure instead of silent stale.

## Session 2026-08-20 — v29.42h: Feed hygiene round 2 — 4 more adblock hosts pruned (SomeoneWhocares/MVPS/Cameleon/AdGuard)
- ✅ Second pass removed `someonewhocares`/`mvps_winhelp`/`cameleon`/`adguard_dns`
  (4 hosts, 15-40k ad domains each) — same class as the 12 pruned in v29.42c.
  Total pruned 16, feeds 34 → 18 high-fidelity. `py_compile` OK, 93/93 tests.

## Session 2026-08-20 — v29.42g: Revolutionary enhancements dummy shim — now logs idle gpu_executor
- ✅ Dummy shim at `downpour_v29_titanium.py:217` reserved 50% cores for
  `gpu_executor` but never logged that it was idle (torch `2.10.0+cpu` only).
  Next audit re-flagged it. Added one-time `logger.info` at import: "CPU
  fallback active, gpu_executor idle (50% cores reserved but no CUDA workloads)".

## Session 2026-08-20 — v29.42f: GPU fallback — GPUTIL even when NVML present but 0
- ✅ NVML path `if NVML_AVAILABLE: ... elif GPUTIL_AVAILABLE: ...` never tried
  GPUTIL when NVML was present but returned `0` (headless / no GPU) — gauges
  stayed `0` instead of `N/A` or GPUTIL fallback. Changed to `if NVML: try;
  if gpu_percent==0 and GPUTIL: try` so headless boxes get GPUTIL fallback.

## Session 2026-08-20 — v29.42e: WMI thermal throttled + sensors fallback — CPU temp now live without COM storm
- ✅ WMI `MSAcpi_ThermalZoneTemperature` COM call (~300 ms) ran on EVERY tick
  when `cpu_temp==0`, and the 30s throttle patch had a duplicate `except` and
  broken cache write-back (`_wmi_temp_cache` never stored). Fixed to 30s throttle
  with `psutil.sensors_temperatures()` fast-path first, cache write-back, and
  single `except`. Warm fetch stays ~1.3s.

## Session 2026-08-20 — v29.42d: Silent exception swallowing hardened — HwMonitor + Intel feed health now log
- ✅ Audit found 550× `except: pass` — critical path `HwMonitor` bg loop
  (`while _bg_running: try: _fetch() except: pass` at `17392`) swallowed the
  `0xc0000005` psutil crash that killed k9, and `IntelFeedHealth` `_load`
  (`38733`) swallowed DB failures leaving Status stuck `Pending`.
- ✅ FIX: `HwMonitor` bg loop now `error_logger.log('HwMonitor','bg fetch failed',_e)`;
  `_refresh_feed_health` `_load` and `submit` now log to `IntelFeedHealth`.
  Adaptive interval still signals failure via health gauge instead of stale `0%`.

## Session 2026-08-20 — v29.42c: Threat feed hygiene — 12 dead/non-IOC sources pruned
- ✅ Explore audit found 18+ dead/key-required adblock feeds wasting 48 MB parallel
  fetch budget + bloating `titanium.db` with 100k+ ad/tracking domains (not IOCs)
  on every tick — `disconnect_track/mal/ad` (3), `hagezi_pro/tif/ultimate/multi`
  (4, 300-700k each), `easylist/easyprivacy/fanboy_annoyance` (3, 70k+ each),
  plus `malshare`/`virusshare` API endpoints (always 403 anon, require key).
- ✅ FIX (FIX-v29.42c): removed the 10 adblock + 2 API-key entries from `FEEDS`
  and `SECURE_FEEDS` (kept one DNS blocklist `hagezi_light` + `steven_black` for
  DNS security feature). `Malware Patrol` (`malwarepatrol_ipv4/domains/urls` at
  `12638`) and `C2IntelFeeds` (`drb-ra` at `12215/12390`) already present as
  verified keyless replacements — no new feed added this pass. `py_compile` OK,
  93/93 tests.

## Session 2026-08-20 — v29.42b: Perf sweep — 4× unthrottled walks merged, live cadence restored
- ✅ Explore audit found 4 unthrottled full-system walks per 1-3s tick defeating the
  adaptive cadence: `process_count/thread_count` (2 walks every tick), `disk_partitions`
  (re-enumerated mounts + `disk_usage` every tick, cache never written back),
  `net_connections` 3× per tick (ESTABLISHED count + tcp/udp breakdown + top-PID
  enrichment), and WMI `MSAcpi_ThermalZoneTemperature` (~300 ms COM call every tick).
- ✅ FIX: `process_count/thread_count` throttled to 10s cache (`_proc_counts_cache`);
  `disk_partitions` 60s cache with proper write-back (`_disk_parts_cache/_ts`);
  `net_connections(kind='inet')` merged to single per-tick `_get_net_conns()` cache
  (3 walks → 1); WMI thermal throttled to 30s with `psutil.sensors_temperatures()`
  fast-path fallback. Warm fetch `2.16s → 1.32s`, cold `3.43s → 5.45s` (first
  status snapshot still ~2.6s but now cached 10s). 93/93 tests.

## Session 2026-08-20 — v29.42a: Perf gauge visibility — black box no longer covers label
- ✅ User report: "black box covers parts of the gauges" on the Performance tab.
  Prior fix (v29.28 label at size+18 → size+8, sparkline +14..+29 → +26..+42)
  left only ~8px between label descenders and the dark sparkline strip
  (`#06080f` rectangle), so the strip visually touched the label on 170px
  gauges — looked like a black box over the label.
- ✅ FIX (FIX-v29.42a): canvas height `SIZE+52 → SIZE+60`, label `size+8 → size+10`,
  sparkline strip `+26..+42 → +30..+46`. Gap label→strip 8px → 20px, bottom
  margin 10px → 14px. Updated `test_gauge_label_not_under_sparkline` to accept
  the new layout (still asserts `#06080f` strip exists but below label band).
  93/93 tests.

## Session 2026-08-19h — v29.41k5h: psutil native crash hardened + Perf sweep live-data cadence
- ✅ K9 smoke (PID 7904) died at 60 min with `0xc0000005` in `_psutil_windows.pyd`
  — Windows Event `Faulting module: _psutil_windows.pyd, Exception 0xc0000005,
  Faulting PID 0x1EE0`. psutil keeps global mutable state (`_pmap`,
  `_LOWEST_PID`, shared C buffers in `net_connections`/`cpu_percent`) with no
  module lock; concurrent system-wide calls from hw-monitor thread (1-3s
  `_fetch` with 2× `net_connections` + 2× `process_iter`), Perf executor
  `Refresh Now` (`self.hw._fetch()` direct) and heartbeat `cpu_percent`
  corrupted the C buffers — classic psutil Windows race, triggered at the
  hourly feed update when executor churn peaked.
- ✅ FIX (FIX-v29.41k5h):
  - Module-level `_PSUTIL_LOCK = RLock()` + `_PSUTIL_ORIG` dict + wrapper
    `_wrap_psutil_func`: patches 19 psutil system-wide functions at import
    (`process_iter` generator holds lock for whole iteration via try/finally,
    `net_connections`/`pids`/`cpu_percent`/`cpu_times`/`virtual_memory`/…
    scoped). Every `import psutil` in the app hits the locked wrappers; per-
    Process instance methods already carry their own lock.
  - `HardwareMonitor._fetch` single-flight (`_fetch_in_flight` Future): bg
    thread, `get_stats` fallback and Refresh Now coalesce to one sweep (was
    duplicate 3-9s sweeps). Verified: 6 concurrent fetches coalesce to one
    0.2s sweep with correct result sharing.
  - Sweep trimmed: `open_files` via `num_handles()` (~6× cheaper, 0.9s→0.15s per
    100 pids, ~2.7s saved per sweep) and `process_iter(['status'])` cached to
    10s snapshot deriving both running/sleeping/zombie + pid-set from one pass
    (was twice per fetch, ~1.9s). DNS latency already 30s-throttled.
  - 12-thread concurrent psutil hammer verified no crash; single-flight
    coalescing verified. 92/92 tests.
- ✅ OSINT4ALL audit: fetched `start.me/p/L1rEYQ/osint4all` (1,411 tools, 77
  categories) and catalogued live threat-intel sources (Malware Patrol high-risk
  IPs/IoCs/Tor, AlienVault OTX, etc.). Current 34 feeds already cover the
  core categories; no new feed added this session — hardening took priority
  after the native crash, but the Perf sweep now delivers sub-3s live cadence
  for the 129+ gauges.

## Session 2026-08-19g — v29.41k5g: feed-health refresh change-detection (kill remaining FREEZEs)
- Post-k5f smoke (PID 13376, v29.41k5f code) still logged 13 FREEZEs
  (1.6-2.4s, first batch 04:06-04:08, second 04:10) — but the main-thread
  stacks had CHANGED: no more DB reads (k5f worked; worst block 4.9s → 2.4s).
  Sampler dominant-loc + other-threads now showed `_apply_feed_health` →
  `tree.get_children('')`/`tree.item`/`tree.set` (Tcl `tk.call` round-trips)
  while other threads sat in `executemany`.
- ✅ Root cause: `_apply_feed_health` re-issued per-row `tree.item('tags')`
  read + `tree.set` + `tree.item(tags=)` on EVERY refresh — a few hundred Tcl
  round-trips even when no feed status changed. Each Tcl call needs the Tcl
  client mutex + GIL; under the writer/training storm those serialize and the
  500ms mainloop tick drifts past 1.5s → FALSE FREEZE reports on a busy-but-
  alive loop, and real latency for the user.
- ✅ FIX (FIX-v29.41k5g): render change-detection. `_feed_health_rendered`
  cache stores the last-rendered `(value, tags, base_tag)` per iid. Unchanged
  rows issue ZERO Tcl calls (base tag reused from cache → no read either).
  iids missing from `tree.get_children('')` are pruned so the cache never
  grows stale. First render still seeds base tag from `tree.item(iid,'tags')`.
- ✅ Verified: 92/92 tests (new `test_feed_health_render_skips_unchanged_rows`
  asserts the cache, the `(value, tags)` skip, base-tag reuse, and pruning).
- ✅ Smoke PID 7904 (k5g code, launched 04:20): FREEZE classification by
  stack — `_apply_feed_health` in blocks: **0** (was deterministic before),
  `_fetch_feed`: 0. Remaining 26 FREEZEs over 27 min are 1.5-1.9s GIL
  boundary bursts while `executemany` @ `_store_parsed_iocs` (IOC write
  storm) + `_worker` threads saturate the GIL; two 5.8s outliers coincided
  with a `subprocess.Popen` + alert-drain `createcommand` Tcl-lock wait.
  Steady state clean: threads ~62-71, RSS ~690-815MB (training spike, then
  flat), CPU 10-12%, ALIVE cadence steady. No DB read ever appears in the
  main-thread stacks (k5f holds).

## Session 2026-08-19f — v29.41k5f: DB reader/writer split kills main-thread read stalls
- ✅ Root cause of the startup/intel FREEZE warnings (1.5-5s main-thread
  blocks): `Database` serialised EVERY query through one `RLock` around the
  single persistent WAL connection. A main-thread `SELECT` therefore blocked
  behind background bulk `executemany()` batches (BEGIN + N inserts + COMMIT,
  fsync-bound). WAL already supports concurrent readers — the app lock just
  never allowed it.
- ✅ FIX (FIX-v29.41k5f): dedicated reader connection + lock.
  - `_read_conn` / `_read_lock`: lazy SQLite connection with identical PRAGMAs
    (WAL, synchronous=NORMAL, 32MB cache, temp_store=MEMORY).
  - `execute()` classifies via the existing `_needs_commit` regex; pure reads
    (SELECT / non-mutating PRAGMA) route to `_read_conn`, DML/DDL stay on the
    writer `_conn`/`_lock` unchanged. `executemany` untouched (still exclusive
    writer).
  - `_close()` closes both connections; `_read_reconnect_if_needed()` recreates
    the reader.
- ✅ Safety: no `RETURNING` / WITH-clause writes, no ATTACH/VACUUM/SAVEPOINT
  across `execute`, no external code acquires `db._lock` (comment refs only).
- ✅ Verified: concurrent stress (writer hammering 200-row INSERT OR REPLACE
  batches; 50 reads) — 50 reads in 0.005s total, 0 reads >250ms. 91/91 tests
  (new test builds an isolated temp-DB `Database` and asserts reader/writer are
  distinct connections with WAL-visible reads). Smoke PID 13756 stable through
  the edit.

## Session 2026-08-19e — v29.41k5e: DNS live-monitor dedup (kill duplicate rows + alarm spam)
- ✅ `_dns_monitor_loop` polls the Windows DNS client cache — a full snapshot —
  every 3s. It re-inserted ALL cached entries each cycle: identical rows
  accumulated forever, the `Queries` counter ratcheted endlessly, and the same
  threatening domain re-fired `[R] BLOCKLIST HIT` / DGA alerts on EVERY poll.
- ✅ FIX (FIX-v29.41k5e): introduced a seen-set of `(domain,data,rtype)` keys
  (`self._dns_mon_seen`, lazily init on the monitor thread). Only genuinely
  new cache entries insert rows, bump `q_count`/`t_count`, or alert. Count
  label changed from `Cache entries:` (was factually wrong — it counted
  processed snapshot rows, not cached entries) to `Queries:`. `_dns_clear_
  monitor` resets the seen-set so an explicit Clear re-captures the current
  state instead of staying dark.
- ✅ Regression test (source-level assertions for dedup guard + reset). 90/90
  tests. Smoke PID 13756 stable through the edit.

## Session 2026-08-19d — v29.41k5d: VPN Mirror-2 fetch HTTPS-first + full egress HTTPS audit
- ✅ Completed an audit of every `urllib.request.urlopen` call site (38
  found). All but one were already HTTPS or user-configurable (DoH template,
  OSINT download URLs). The one remaining plain-HTTP-only egress was the VPN
  tab's Mirror-2 server-list source (`http://lab.mahidol.ac.th/vpngate/api/
  iphone/`).
- ✅ FIX (FIX-v29.41k5d): `_vpn_load_servers` now builds an HTTPS-first
  candidate list per source — `https://` promoted from `http://`, original
  `http://` retained as terminal fallback. `raw` initialised to `''` so a
  dead source degrades to a logged/skipped source instead of an unbound
  NameError; both parsers (vpngate_csv, protonvpn_json, generic_json) handle
  empty input gracefully within their existing try/except.
- ✅ Regression test asserting the https-first promotion block. 89/89 tests.
- ✅ Smoke PID 13756 stable through all edits (threads 23, RSS ~161MB).

## Session 2026-08-19c — v29.41k5c: intel feed fetches HTTPS-first with HTTP fallback
- ✅ Audit of network egress found the same ip-api-style HTTPS gap in
  `_fetch_feed`: a `_HTTP_OK` host set (`sysctl.org`, `data.phishtank.com`,
  `pgl.yoyo.org`, `someonewhocares.org`) was hard-locked to plain `http://`
  forever, and any feed whose HTTPS attempt failed was skipped entirely for
  the whole cycle (no fallback).
- ✅ FIX (FIX-v29.41k5c): every feed now builds an HTTPS-first candidate list
  (`https://` promoted from `http://`) with the original `http://` kept as the
  final fallback. The permissive SSL context (for expired/self-signed cert
  hosts) still completes a TLS handshake, so exempt hosts now go HTTPS too.
  `_HTTP_OK` deleted; backoff (0/2/6s) retained per candidate.
- ✅ Regression test: `_fetch_feed` invoked with an `http://` feed URL must
  open `https://` first and succeed in a single call (fake urlopen context
  manager needed `__enter__`/`__exit__` for the `with` block). 88/88 tests.
- ✅ Smoke PID 13756 still stable (threads 23, RSS ~161MB) while models train
  in the background; no joblib/scan-worker wedges.

## Session 2026-08-19b — v29.41k5b: Network tab Country column made live + all 5 geo call sites unified on HTTPS-first helper
- ✅ Audit found the Network tab's Country column was hard-coded `''` forever
  (every row showed a blank country; no lookup ever ran). Real live-data gap.
- ✅ FIX (FIX-v29.41k5b):
  - Added `_geo_cache` dict + `_async_geo(ip)` (async ip-api.com countryCode
    lookup on the executor). Country cells now resolve live for public IPs;
    private IPs (192.168.*, 10.*, 172.*, 127.*, 169.254.*, fe80::, ::1) stay
    blank to keep the free ip-api rate limit clean; failures/misses degrade to
    `--` and never block or raise.
  - Added shared `_ip_api_get(self, ip, fields, timeout)` helper: HTTPS-first
    for privacy, plain-HTTP fallback (the free JSON endpoint is HTTP-only),
    uniform `downpour/29` UA, returns `{}` on total failure.
  - Routed ALL FIVE geo call sites through `_ip_api_get`: live Country column
    (`_async_geo`), Intel-tab GeoIP (`_intel_geoip`), alert-action GeoIP
    (`_alert_action_geoip`), Net-tab Geo-Locate (`_geolocate_ip`),
    alert-feed `_geolocate_one`. Four of them were previously plain-HTTP only
    (which the free tier silently rejects) — they now get the HTTPS-first +
    fallback too. `grep http://ip-api` = 0 matches now.
- ✅ Verified: `py_compile` OK; **87/87 tests** (added geo regression tests:
  `_async_geo` failure marks `--`; `_ip_api_get` is HTTPS-first with `{}`
  on total failure). Smoke PID threads stable 67–80; 17 transient FREEZE
  warnings over 40 min (all DB-write contention, ≤2s), ZERO scan-worker /
  joblib events.

## Session 2026-08-19a — v29.41k5: scan-worker/joblib thread explosion + Perf-tab live-data restore
- ✅ Root cause of the smoke-test thread/memory runaway: **ThreadPoolExecutor
  ("scan-worker") + sklearn 1.9.0 + joblib 1.5.3 nested-parallelism deadlock**.
  Every 60s `_proc_loop` → `scan_all()` → each worker's
  `predict_proba()`/`decision_function()` deadlocked in joblib's `_retrieve`
  (nested joblib dispatch from inside a pool worker). The `with`-block
  `shutdown(wait=True)` never returned and `_proc_loop` rescheduled
  unconditionally → pools piled up: threads 176 → 229 → 296 → **341** in
  ~50 min, 64+ workers permanently wedged in
  `joblib.parallel._retrieve` → `analyze_process_sklearn`, RSS crawled
  2.4→2.56GB. Prior session (PID 1668) was unaffected only because models
  weren't trained yet (`_models_trained` False → early return).
- ✅ Fixes in `downpour_v29_titanium.py`:
  - Post-fit `self._iso_forest.n_jobs = 1` + `self._rf_classifier.n_jobs = 1`
    (FIX-v29.41k5) — single-sample inference gains nothing from n_jobs>1, and
    the nested joblib dispatch can no longer fire.
  - `scan_all()` split into `_scan_all_locked()` with a `_scan_in_progress`
    overlap guard (returns `[]` while a scan is draining) and explicit
    `pool.shutdown(wait=False, cancel_futures=True)`; `as_completed(futures,
    timeout=90)` abandons wedged workers so `_proc_loop` can never stack pools.
- ✅ Perf-tab live-data restore (FIX-v29.41k5): the ~8.5s `open_files` walk ran
  on EVERY fetch tick (verified: `open_files 500 pids` = 8.5s; full `_fetch` =
  ~14s) — so the whole Perf tab effectively refreshed ~1×/14s despite the 1-3s
  loop. Now sampled every 15s (bounded at 300 pids, cached in between).
  top-procs rows gained live `rss_mb`, `disk_rd_kbs`, `disk_wr_kbs` and `conns`
  (one shared `net_connections` walk filtered to the top-20 candidate PIDs —
  enrichment is O(top-N), not O(all procs)). Treeview columns:
  pid/name/cpu%/mem%/rssMB/rd/wr/conns/gpu/status.
- ✅ winfo_exists Tcl-safety (uncommitted from prior session, folded in):
  `_tk_alive` flag + `_winfo_ok()` helper replacing all 16 worker-thread
  `winfo_exists()` calls; `_shutdown()` clears the flag first.
- ✅ Verified: smoke PID threads stable at 67–80 (was climbing 176→341); ALIVE
  cadence clean; fetch cadence restored (non-open_files ticks ~3s).
  `py_compile` OK; **84/84 tests** (added TestV2941K5ScanWorkerFix +
  TestV2941K5PerfTabLive regression guards).

## Session 2026-08-18a — v29.41k4: parse-pool child isolation kills the phantom main-process memory leak
- ✅ Root cause: the main-process "leak" (97–116 MB/min reports, RSS ratcheting
  to 1.27GB mid-wave) was **not** an accumulator in the app — it was
  **ProcessPoolExecutor children monitoring themselves**. Under Windows `spawn`,
  every parse worker re-imports `downpour_v29_titanium.py`, which imports the
  `enhanced_memory_manager` singleton (L169) and starts **tracemalloc + a
  monitor thread in each child**, logging the worker's own memory view into the
  shared `downpour.log` (166MB at `text.splitlines()`, 183MB at
  `connection.py:251`, 42–71MB decode/gzip buffers). tracemalloc-tracing every
  parse allocation slowed the children, so the parent pool queue backed up with
  large pickled payloads → parent RSS ratcheted and reports looked like a real
  leak.
- ✅ Fix (in `enhanced_memory_manager.py`):
  - `_is_spawn_child()` detects non-main processes (`current_process().name`
    not MainProcess/SpawnMainProcess); children neutralize the singleton
    (`enabled=False`) + `tracemalloc.stop()`. Workers are `SpawnProcess-1/2`.
  - Leak growth now computed from **this process's own RSS**
    (`psutil.Process(os.getpid()).memory_info().rss`, new `rss_bytes` field)
    instead of system-wide `used_bytes` (which counted other apps and caused
    false 87–110 MB/min alarms).
  - Leak report surfaces `top allocations:` (first 6 tracemalloc sites) and
    `top types:` (top 10 gc type counts); gc counts captured BEFORE the
    tracemalloc snapshot so the report's own Traceback/Statistic objects don't
    pollute the histogram.
  - Fixed `NameError: interval` in the monitor loop — it silently slept 60s
    per iteration; now 15s (HIGH pressure) / 30s. Leak detection every 10
    snapshots.
- ✅ Verified with 8 memprobes + 15 leak-test sessions: main PID 1668 RSS flat
  at **660–665MB across a full 10-min staggered wave cycle** (probe 8,
  00:41–00:51), waves spike ~1.27GB then release to baseline; only ONE clean
  report in the 08-18 session (00:36, 5.13 MB/min — post-wave transient), zero
  since. Pre-fix reports (16–116 MB/min) discarded as child-contaminated.
- ✅ 75/75 tests; `py_compile` OK.

## Session 2026-08-17a — v29.41k3: boot-storm freezes eliminated via intel dedupe + bounded workers
- ✅ Root cause: the 9.3–53.8s boot freezes (main thread parked in trivial
  `tk.call('configure'...)` / `after` for seconds) were a **boot-window CPU/IO
  storm**, not intel logic alone: freezes began before the intel DB init, and
  the first boot had 0 `feed_status` writes yet still froze. Two concurrent
  updaters both re-downloaded the same OSINT feeds (URLhaus/Feodo/SSLBL/
  ThreatFox/Bazaar/Spamhaus ...): the legacy `_scheduled_feed_update`
  (`ThreatIntelligenceManager.update_all_feeds`) and the new `_intel_auto_loop`
  (`ThreatIntelEngine.update_staggered`).
- ✅ Fixes (all in `downpour_v29_titanium.py`):
  - Intel auto-update flipped to default ON (`'auto_update': 'true'`,
    6h interval) so the staggered engine owns feed refreshes.
  - `_scheduled_feed_update` **stands down** when auto-update is enabled
    (re-arms hourly; only falls back to legacy `update_all_feeds` when
    auto-update is off).
  - `update_staggered` parses on ONE shared `ProcessPoolExecutor(max_workers=2)`
    (`_get_shared_parse_pool` ~L11873, created lazily, reused across all waves)
    with 120s future timeouts + in-process fallback — no per-call
    `ProcessPoolExecutor(max(4, cpu-2))` fork storm.
  - `AIEnhancedThreatDetector._train_models_background` defers the first fit
    ~60s (daemon-thread sleep) and caps `n_jobs` to 2 — IsolationForest/RF
    full `n_jobs=-1` was flooding every core during boot.
- ✅ Diagnostics that got us there: `_freeze_sampler` snapshots other-thread
  top frames too (`_freeze_diag_othr`); `_freeze_check` prints
  `<other threads during block:>`. Sampled other-threads during blocks were
  sklearn fits, `pathlib.stat`/`read_text`, subprocess readers, watchdog
  observers, feed DB writes — all concurrent at boot.
- ✅ Verified: fresh boot smoke test (`2026-08-17 20:45` session) ran the full
  build, auto-start, staggered feed waves (feed_status rows written live at
  20:48–20:49, e.g. easylist 5,845 / firehol_l2 16,490 / fanboy_annoyance
  25,725 IOCs) with **zero FREEZE events** and responsive mainloop
  (`[ALIVE]` every 10s, `pending_after` draining to 0). 75/75 tests.

## Session 2026-08-16a1 — v29.41k: main-thread freeze elimination (rain + net UI)
- ✅ Root-caused recurring 1.5–28.5s GUI freezes with a background
  `freeze-sampler` daemon thread (120ms samples of the main-thread stack via
  `sys._current_frames()`, 3s dominant-location vote) + per-section `_fmark`
  timing inside the animation loop. Two real culprits dominated:
  1. **Rain canvas** `ImmersiveRainCanvas._animate`: frames cost 1–4.4s in the
     loaded app vs 2.8ms standalone (each Tk `coords()` ≈ 4–90ms under
     software-render/load). The old 10fps `after(100)` loop stole whole
     seconds whenever anything else ran concurrently.
  2. **`_update_network_ui`** ran on the main thread every 5s and rebuilt
     hundreds of Treeview rows via `_net_tree.item()` roundtrips sampled as
     6–21.5s freezes — even while the rain was hard-frozen.
- ✅ Rain fixes (all in `downpour_v29_titanium.py`):
  - Fg/stipple/outline/fill itemconfig caching (skip redundant Tk reconfigs).
  - Splash/streak pool resets limited to previously-used slots
    (`_splash_last_used`, `_streak_last_used`) — killed the 50/70 pointless
    off-screen reset coords per frame.
  - Adaptive degradation: `_load_ema` (0.7/0.3) of frame cost drives
    `_anim_allowed` backoff 100→1200ms; when >150ms the cosmetic layers
    (splashes/fog/puddles/mist/lightning/**stars**) are skipped.
  - Rotating drop stride `_update_drops(dt_scale, stride, degraded)` — only
    1/N drops touched per frame, slice rotates so every drop still animates;
    stride also scales linearly with EMA (`1 + ema/150`, capped 40) so a
    pathological 3.6s frame degrades to ~3 coords().
  - Hard freeze hysteresis: frame >700ms or EMA>600 → `_anim_frozen` (static
    sky ~25s, ticks at 500ms); resume seeds `_anim_allowed=1200` and
    **EMA=6000** with a 12-frame `_anim_probe_ticks` window (max stride,
    freeze suppressed) so recovery ramps up gracefully instead of re-freezing
    the instant full speed returns.
  - Degrade path purges `_splashes/`_streaks` residue each frame (spawned in
    `_update_drops` but never aged out when `_update_splashes` is skipped) —
    had grown to `splashes=156 streaks=253` → 844ms wipe-out frame on resume.
- ✅ Net UI fix: `_update_network_ui` now hard-skips when the Network tab is
  off-screen (`winfo_viewable()==0`) and diffs a **rotating 60-row slice**
  per pass instead of the whole tree — a 300-row refresh is spread over ~5
  passes so it can never stall one frame.
- ✅ Result (fresh run ~13 min, launched 04:47): **zero FREEZE logs** in the
  first 8 min, then only 3 minor 1.5–1.8s hiccups from a `_drain_alert_queue`
  reschedule + one mist frame mid-probe vs. previous runs' 2–26.7s freezes
  every few seconds. Steady state is now nominal.
- ✅ `pytest.ini` added (testpaths=tests; norecursedirs=_ARCHIVE
  /_legacy_launchers/downpour_tmp/.venv) — bare `pytest` used to recurse into
  legacy `_ARCHIVE` GUI/feed tests and die; now 75/75 clean.
- ✅ 75/75 tests; boot smoke clean.

## Session 2026-08-16a2 — v29.41k2: kill residual 1.5–21.4s freezes (idle backoff + coords-cost degradation)
- ✅ Tally of the 3 residual 1.5–3s freezes from session a1 (`_day_tally2.txt`,
  1210 freezes/7h) showed the freeze-checker now catches mostly **periodic
  drain-loop backlog**: three separate sub-200ms main-thread loops
  (`_early_drain` @200ms, `_drain_alert_queue` @150ms, `_schedule_ui_updates`
  @150ms) with `_pending_after` drained redundantly by two of them. On a
  loaded box each Tk call costs 4–90ms, so constant-wakeup drains built an
  accumulated Tcl backlog that tripped the 1.5s check even with rain fixed.
- ✅ **Idle backoff** on all three drains: `_early_drain` and
  `_drain_alert_queue` re-arm at **1s when nothing was queued** (150–200ms
  only when they actually drained work); `_schedule_ui_updates` re-arms at
  500ms idle / 150ms busy. `_did_work` flags added to each. (~5× fewer
  main-thread wakeups in steady state.)
- ✅ Root-caused the still-periodic **9.9–21.4s freezes**: the rain stride
  keyed off the *frame-cost* EMA, which oscillates — cheap probe frames decay
  the EMA to ~83, the linear stride term collapses to 1, and a full 120-drop
  frame at ~80ms/coords = a 10s main-thread block, freeze, probe, repeat.
- ✅ **Coords-cost self-regulation** (decoupled from frame EMA):
  - `_update_drops` times its actual `coords()` calls and keeps a
    `_coords_cost_ema` (0.7/0.3, updated only when ≥5 calls sampled).
  - `_animate` computes the drop stride from a hard **~50ms coords budget**:
    `stride = ceil(n_drops / floor(50ms / per-coords-cost))`, capped 80, so a
    80ms/coords box touches ~2 drops/frame regardless of EMA state.
  - `_degrade` is now ALSO true whenever `_coords_cost_ema >= 8` — cosmetic
    layers (stars/splash/fog/mist/lightning) stay off while canvas ops are
    intrinsically expensive, so they can't run a multi-second frame the moment
    the frame EMA falls back to 100ms. Seeded `_coords_cost_ema = 8.0` at init.
- ✅ Result (fresh run 20:10:33, observed ~6 min): **zero FREEZE logs**, no
  RAIN freeze/resume cycling at all, CPU ~34% idle-ish, alerts flowing. Prior
  run of the same commit: 9.9–21.4s freezes every ~30–60s.
- ✅ 75/75 tests; boot smoke clean.

## Session 2026-08-14b9 — v29.41j: wire 4 more dead Perf gauges to live `_ti_ref`
- ✅ Systematic gauge audit (130 gauge keys vs `_fetch` writes) confirmed every
  key is written — but a second audit of `self._*` reads found 4 more never-
  assigned attrs feeding gauges: `_file_threats_last_hour` (FILE THREATS/H),
  `_malware_detected_total` (MALWARE DETECTED), `_phishing_urls_total`
  (PHISHING URLS), `_suspicious_dns_total` (SUSPICIOUS DNS). All four now read
  the live cached `ThreatIntelligenceManager` (`_file_threats_hour`,
  `_total_malware_hashes`, `_total_phishing_urls`, `_total_suspicious_dns`).
  The wired-key regression suite is the same-class guarantee.
- ✅ 75/75 tests; clean boot smoke; pushed `fc9fb9b`.

## Session 2026-08-14b8 — v29.41i: wire 4 dead Perf-tab gauges to real counters
- ✅ Gauge audit found 4 more stuck-at-zero gauges: SEC EVENTS / OSINT
  LOOKUPS / OSINT TODAY / OSINT CACHE were read in `_fetch` via `getattr(self,
  '_x', 0)` but written NOWHERE. Wired:
  - SEC EVENTS → `_queue_alert` increments `_security_events_today` (daily
    reset via `_events_counter_day`).
  - OSINT total/today/cache → new `_bump_osint_lookup(cache_hit)` helper,
    called from `check_ip` (distinguishes cache hit/miss), `check_url`,
    `check_hash`; daily reset via `_osint_day`.
- ✅ 74/74 tests (new regression test); pushed `db8042e`.

## Session 2026-08-14b7 — v29.41h: vuln-scanner None-crash trio + CEV DB timeout
- ✅ Log audit surfaced two recurring crash signatures (last seen Aug 11, 102
  hits each): `detect_exploit_attempts` bug — `proc.info.get('cmdline',
  [])` can be `None` (psutil sets attr to None on AccessDenied for the attr
  list in process_iter), so `' '.join(None)` → "can only join an iterable".
  Fixed with `proc_info.get('cmdline') or []`. `check_privilege_escalations`
  — `proc_info.get('username', '')` also can be None → `.endswith` on None.
  Fixed with `(proc_info.get('username') or '')`.
- ✅ `get_cev_score` (read every fetch tick) opened each connection with the
  5s default timeout; long feed-writer transactions → "database is locked"
  (351 hits). Bumped to `timeout=30`.
- ✅ 73/73 tests (2 new regression tests); pushed `1e8b21b`.

## Session 2026-08-14b6 — v29.41g: feed updates off the Tk main thread
- ✅ `_scheduled_feed_update` called `ti.update_all_feeds()` directly in the
  `after` callback — URLhaus `csv_recent` full-dump per-row inserts froze the
  GUI for minutes (observed: 4+ min blocked). Both `_scheduled_feed_update` and
  `_scheduled_feed_health_check` now spawn `threading.Thread(daemon=True)`
  workers; the hourly/30-min reschedule stays on the main thread via `self.after`
  and feed-alert queuing is marshaled back with `self.after(0, ...)`.
- ✅ Validated during live ingest: GUI mainloop stays ALIVE + responsive
  (alerts/pending_after counters ticking) the entire time URLhaus is ingesting.
- ✅ 72/72 tests; pushed `6b1e271`.
- ℹ️ URLhaus ingest itself remains slow (~minutes) — per-row `add_malicious_url`
  DB insert, pre-existing. Now non-blocking, so acceptable.

## Session 2026-08-14b5 — v29.41f: missing `_record_feed_history` + VS DB-init cache
- ✅ **Real bug found via boot smoke**: every OSINT feed update (threatfox/
  urlhaus/phishtank/malwarebazaar) crashed with `'ThreatIntelligenceManager'
  object has no attribute '_record_feed_history'` — `_feed_history` dict was
  initialized in `__init__` but the `_record_feed_history` method was never
  written. Feed updates failed silently every launch; only visible in
  `downpour.log`. Added the method (appends (ts, ioc_count), capped at
  `_max_history_points=100`). ThreatFox now updates `[OK]` in ~3s.
- ✅ **Second DB-init-per-tick offender**: the CVE gauges block also did
  `VulnerabilityScanner()` fresh every fetch tick → `[OK] Vulnerability scanner
  database initialized` logged ~every 15s. Cached once as `_vs_ref` on the
  monitor (same pattern as `_ti_ref` in v29.41e). Post-fix: DB init appears
  only once at startup.
- ✅ 71/71 tests; clean boot confirmed (2 VS inits total, zero feed errors);
  pushed `d3f0a16`.
- ℹ️ Known: `_scheduled_feed_update` runs `update_all_feeds()` on the Tk main
  thread; URLhaus full-dump insert can block the GUI for minutes. Pre-existing,
  not addressed in this session.

## Session 2026-08-14b4 — v29.41d/e: net/process anomaly gauges live + TI cache
- ✅ **v29.41d**: net anomaly gauges (PORT SCAN/H, EXFIL/H, DNS TUN/H,
  LATERAL/H) now served by a *throttled* (10s) live `net_monitor.
  analyze_connections()` classification — port_scan/data_exfil/dns_tunneling/
  connection_flood alert types map to the gauges, `_nm_alert_map` reused
  between ticks so the full psutil connection walk doesn't run every 1-3s.
  Process anomaly gauges (INJECT/H, DISGUISE/H, SUS LOC/H, SUS CMD/H,
  HIGH CPU/H) classify the live scanned process list (`_PKEY` keyword map).
  EXFIL/H is the NET gauge — behavior's exfil counter uses setdefault; the
  heatmap `c2_servers_total` reads from live beaconing alerts too. Caught a
  real ordering bug headless: behavior block overwrote net exfil — fixed via
  setdefault precedence. 25 live-gauge assertions pass on a fake app.
- ✅ **v29.41e**: `ThreatIntelligenceManager` does DB init in `__init__` and
  was constructed fresh 2× per fetch tick — now cached once as `_ti_ref` on
  the monitor (both file-threat + OSINT feed blocks share it).
- ✅ 69/69 tests; boot smoke → zero stderr; pushed `db9c00a`.

## Session 2026-08-14b3 — v29.41c: behavior gauges → live [BEHAVIOR] findings
- ✅ **Last orphan-gauge group**: KEYLOG/SCREEN/INJECT/CRED/PERSIST/EVASION/
  EXFIL/LATERAL-H read `behavior_scanner.BehaviorScanner(db=None)` — a module
  the app never starts (it even documents wiring into a different app). Static
  0 forever.
- ✅ **Fix**: when the `_app` backref exists, the eight behavior gauges now
  classify `[BEHAVIOR]` keyed findings from the app's LIVE scanned process
  list (`_processes` → `scan_all()` → `risk_reasons`, refreshed continuously
  by `_proc_loop`). Live path only writes when ≥1 behavior found; otherwise
  the orphan fallback still satisfies the keys (never NameErrors).
- ✅ 65/65 tests pass; boot smoke 50s → zero stderr; pushed `b553e04`.
- ✅ All three orphan-monitor gauge groups (file, proc/net threats, behavior)
  are now wired to genuine live app data.

## Session 2026-08-14b2 — v29.41b: PROC/NET THREAT gauges → live app data
- ✅ **Same orphan-module class of bug**: NET THREATS / PROC THREATS read
  `network_monitor` / `process_monitor` singletons that are never `.start()`ed
  anywhere in the app — static 0 regardless of what the app is doing.
- ✅ **Fix**: with the `_app` backref present, PROC THREATS counts suspicious
  from the app's LIVE `_processes` list (refreshed continuously by
  `_proc_loop` → `scanner.scan_all()`), and NET THREATS runs the app's live
  `net_monitor.analyze_connections()` for alert count. Without a backref
  (headless tests) it falls back to the orphan singletons. `nm`/`pm` local
  refs stay always-bound so the finer-grained anomaly gauges below never
  NameError on the live path.
- ✅ 64/64 tests pass; boot smoke 50s → zero stderr; pushed `090b250`.
- ⏳ Next: the 8 behavior gauges (KEYLOG/SCREEN/INJECT/CRED/PERSIST/EVASION/
  LATERAL/H) still read the orphan `behavior_scanner` module.

## Session 2026-08-14b — v29.41: file gauges bound to the LIVE RansomwareDetector
- ✅ **Follow-up on v29.40c**: the `fm` fix bound the *orphan* `file_monitor`
  module (`get_monitor()`), but that module is never `.start()`ed anywhere in
  the app — its counters (`_file_modifications_hour`, etc.) could never move,
  so MOD/H, CREATE/H, DELETE/H, SUS CREATE/H, RANSOM/H would stay 0 forever.
- ✅ **Fix**: `HardwareMonitor._fetch` now prefers the app's LIVE
  `RansomwareDetector` — `self.hw._app = self` backref wired in the app
  constructor, and the file gauges compute real per-hour counts from
  `ransomware._file_changes` deque (watchdog-fed; created/suspicious-extension/
  ransomware-note classification inline via KnownThreats lists). Falls back to
  the old orphan binding only when no app backref exists (headless tests).
- ✅ Verified headless with a fake app + deque: mod/create/delete/sus/ransom
  all counted correctly; fallback path returns 0 without raising. Full suite
  63/63 pass; boot smoke test 45s → zero stderr. Pushed `26a0177`.

## Session 2026-08-14a — v29.40c: boot crash fix + live Performance data pipeline
- ✅ **CRITICAL boot regression**: `downpour_v29_titanium.py` exited code 1 at
  line 114 with `AttributeError: module 'logging' has no attribute 'handlers'`.
  Python 3.13+ dropped the implicit `logging.handlers` attribute binding; the
  explicit `import logging.handlers as _crash_handlers` now loads it.
- ✅ **Env root-cause**: repo `.venv` was built on Python 3.15.0a6 (an alpha —
  no binary wheels). Pillow imported with `SystemError: PIL._imaging uses
  unknown slot ID 85`. Rebuilt `.venv` on the repo's documented
  `<Python312 install dir>\python.exe`
  (all 20 deps install; netifaces dropped — EOL with no py3.12 wheel and zero
  usage in the codebase). Added setuptools (provides the `distutils` shim GPUtil
  still needs on 3.12). Full GUI now boots GUI clean (zero stderr).
- ✅ **Live-data pipeline fixes** (Performance tab): `_fetch` referenced
  `fm`/`bs` that were never defined → ~15 file/behavior anomaly gauges silently
  NameError-zeroed every tick. Both are now lazily bound and cached on the
  monitor (`_file_monitor_ref` / `_behavior_scanner_ref`). Swap/page-fault rate
  block borrowed the disk block's local `dt` (NameError on some machines) —
  now owns its own `_dt_m`. `_force_perf_ui` 10s safety timer was defined but
  never scheduled — wired into `_auto_start`.
- ✅ **Perf-loop hardening**: `_perf_loop` could stack executor submissions on a
  slow tick — added `_perf_inflight` guard. It now also honors
  `_adaptive_prf_ms` (HardwareProfiler.adapt_to_load) so under CPU/RAM pressure
  the throttle actually engages.
- ✅ **Dead-landmine removal**: `_update_hw_ui`'s except-block referenced
  undefined `pct`/`score`/`max_score`/`color` (masked real errors with a
  NameError). `_start_hw_thread` read a never-set `_hw_ms`. Both removed.
- ✅ **Interpreter selection**: `find_latest_python()` unconditionally preferred
  the newest Python (→ 3.15.0a6, breaking wheels). It now skips alpha/beta/rc
  (`releaselevel == 'final'`) and parses `py --list` correctly.
- ✅ **Launcher**: added Python 3.14 discovery paths + replaced eol-only
  `netifaces`/`pynvml` notes in requirements prose.
- ✅ **Gauge refinement**: GAUGES table had same-key duplicates (DISK QUEUE,
  FILE THREATS/H, EXFIL/H) where only one of the pair of canvases ever updated;
  plus cross-key visual dupes (DISK READ/WRITE, MEM FRAG, PAGE FAULTS, FEED
  ERRORS). Deduplicated → 129 unique live gauges; added UPTIME.
- ✅ **AEGIS guard**: alert wiring now uses `getattr(..., None)` so a missing
  optional layer can't blow up the startup callback chain.
- ✅ Tests: +10 regression guards (`TestV2940Reliability`) → 60/60 pass,
  py_compile OK, `_fetch` headless round-trip verified (no NameError; anomaly
  keys bound; swap/page-fault/disk rates live). Pushed `c526c10..22cf5c5`.

## Session 2026-08-13n — v29.34: Phase 3 tooltip sweep across all main tabs
- ℹ️. **Gap**: Phase 3 audit counted 122 `tk.Button` creations vs only 72
  `_tooltip` calls — 55 bare buttons across the main (non-DNS) tabs had no
  hover help. Factory loops and dialog Close/Cancel buttons were the
  legitimate leftovers; everything actionable still needed a tip.
- ℹ️. **Added tooltips (41 buttons)**: PANIC, all 6 ECP engine buttons +
  START ALL ENGINES, 4 triage buttons, Privacy Mode + Score, global HUNT,
  packet-capture bar (Start Capture/Stop/Check Rogue DHCP), intel feed
  management (Add Feed/Fetch Now/Remove Selected/Import from File/Feed
  Statistics), Scanner header (RUN FULL SCAN/FIX ALL/Check Zero-Days),
  DNS monitor (Clear/Export Log), DNS cache (View/Flush/Scan/Export), DNS
  blocklist (Block/Unblock/Import/Export), DNSSEC (Validate/Full Audit),
  poison/system-domain/router-DNS checks, firewall Load Events, GreyNoise
  lookup + Unblock Selected, fingerprint Re-arm/Clear All, hardening
  Rollback Selected.
- ℹ️. Named every button in a `_xxx_btn: Any` var instead of `.pack()`/`.grid()`
  on a throwaway so `self._tooltip()` can attach cleanly.
- ℹ️. Tooltip calls 72 → 113; remaining 14 bare are self-explanatory dialog
  Close/Cancel/❌ and factory loops (labels already describe action, and the
  `_btn` factory at 44635 already supports `tip=`).
- ℹ️. 46/46 tests pass; py_compile OK; 751 methods / 0 dupes; pushed
  `c505cdf..ba41d9c`.

## Session 2026-08-13m — v29.33: tooltips across all DNS sub-tabs
- ✅ **Gap**: the DNS tabs' button-factory helpers (`_qbtn`, `_srv_btn`,
  `_hbtn`, `_enc_btn`, `_tbtn`) had no tooltip support at all, so ~30 DNS
  buttons showed no hover help. The generic `_btn` helpers used elsewhere
  already took `tip=` (positional) — the DNS ones were the stragglers.
- ✅ **Fix**: added `tip=None` + `self._tooltip(btn, tip)` to all five DNS
  helpers, and wrote per-button help for the Overview quick-actions, Servers
  (apply/show/reset/latency/leak), Hosts editor actions, DoH enablers, the
  14-button Advanced tools column, 7-button Security-tests column, 7-button
  Repair/Harden column, and the secure-provider "Load ->" button.
- ✅ Also kept every created button reference in a named var (no more
  `.pack()`/`.grid()` on a throwaway) so tooltips attach cleanly.
- ✅ 46/46 tests pass; py_compile OK; pushed `1e2b193..e165e69`.

## Session 2026-08-13l — v29.32: live DNS Overview panel
- ✅ **Bug found**: `_dns_refresh_overview` had zero callers — its build
  comment said "now called from _auto_start()" but that kickoff was removed
  during FIX-v28p38 loop cleanup. The DNS Overview info panel + threat score
  never updated after first paint.
- ✅ **Fix**: restored `after(4000, self._dns_refresh_overview)` one-shot and
  added `_dns_overview_loop` (60s throttle) — refreshes only while the DNS
  tab is visible, with an in-flight busy guard (set in `_dns_refresh_overview`
  before the fetch thread starts, cleared on the `after(0)` UI postback) plus
  a 180s stuck-fetch safety reset. Uses `_orig_after` for the reschedule,
  matching the perf loop.
- ✅ Tests: `TestDnsOverviewLiveV2932` (4 cases) — caller exists, loop wired
  into auto_start, loop never raises on a bare instance, busy guard raised.
  Full suite 46/46 pass; py_compile OK; pushed `62117b3..13b3f90`.

## Session 2026-08-13k — v29.31: tooltips for the last bare buttons
- ✅ Scanned every `tk.Button(` assignment in the main file (script-based
  tooltip-gap audit). Most flagged sites already bind `_tooltip`; the real
  stragglers were 9 named buttons: Rain toggle, Storm cycle, Settings gear,
  Widget toggle, tab-strip ◀/▶ scroll arrows, CVE "Apply Mitigation for This
  CVE", TPM/BitLocker bypass toggle, and the DNS Live Monitor start/stop.
- ✅ All 9 now have `_tooltip(...)` bindings with short action/state
  explanations. `py_compile` OK; 31/31 unit tests pass.

## Session 2026-08-13k2 — v29.30b follow-up: hasattr() recursion fix on bare instances
- ✅ **Bug**: the v29.30b warm-history pre-pass used `hasattr(self, '_perf_history')`
  guard clauses. On a bare `object.__new__(downpour)` test instance (no Tk
  runtime), `hasattr()` for a *missing* attribute recurses via
  `Misc.__getattr__ → self.tk` → RecursionError — silently swallowed by the
  blanket `except`, so the pre-pass never ran and the new
  `TestWarmPerfHistoryV2930b` tests (6) all failed.
- ✅ **Fix**: the four lazy-init guards now use `'<attr>' not in self.__dict__`
  membership (no `__getattr__` involved) — strictly more robust, identical
  behavior on real Tk instances. Also patched the concurrent session's
  `test_winfo_exists_false_returns_early` which asserted with `hasattr()`.
- ✅ Result: 42/42 tests pass, py_compile OK, AST 750 methods / 0 dupes,
  pushed to GitHub.

## Session 2026-08-13k — v29.30b: warm Performance history (gauges never idle)
- ✅ **Gap**: `_update_perf_ui` early-returned whenever the Perf tab wasn't
  visible, so sparkline history and ▲/▼ deltas only accumulated while you
  watched — opening the tab always started from an empty, flat history and
  the adaptive DISK/NET rate ceilings began cold at 0.
- ✅ **Fix**: a cheap warm-history pre-pass now runs *before* the
  tab-visibility guard — every `_perf_gauge_meta` key's value is appended to
  its 30-point deque and per-key deltas computed every tick regardless of
  tab. The visible loop only redraws canvases, reading the warm history
  (removed the old duplicate/triple appends so history has one source).
- ✅ Bonus: adaptive ceilings now learn from background traffic, so DISK/NET
  needles are already scaled correctly when the tab is opened.
- ✅ Verified `py_compile` OK; 31/31 unit tests pass.

## Session 2026-08-13j — v29.30: inline browser-extension security scan
- ✅ **Gap**: `browser_protection.py` (a defensive orphan module: extension
  manifest risk scoring + browser KEV matching) was never wired into the v29
  app; `manifest.json` / `extension_risk` had zero hits in the main file.
  The v29 Threats tab had no browser-extensions surface at all.
- ✅ **Wiring decision (Phase 5)**: rather than importing the standalone
  module (which owns its own `logging.basicConfig`, spawns a daemon thread,
  and depends on `VulnerabilityScanner` + `pythoncom`), consolidated the
  capability inline as `_scan_browser_extensions` / `_browser_cve_check` /
  `_browser_ext_dir` — reusing the already-running `CisaKevEngine` singleton
  for browser→KEV matching instead of a second KEV copy.
- ✅ Scan covers Chrome, Edge, Brave, Firefox (profiles), Opera, Vivaldi, Arc;
  Chromium-family walks `{User Data}/{Profile}/Extensions/{id}/{ver}/manifest.json`,
  Firefox scans profile `extensions` dirs. Risk score = unique suspicious
  permissions ×25 (tabs, webRequest, <all_urls>, cookies, proxy, debugger,
  desktopCapture, clipboardRead, nativeMessaging, management, downloads.open,
  history…), +15 for unnamed/empty-name extensions, capped at 100.
- ✅ Runs on `_io_executor` (never blocks main thread); `_queue_alert` +
  `after(0)` postback; summary via `messagebox.showinfo`. Rate-limited alerts
  auto-apply (`_queue_alert` global 2/s cap). No new runtime deps.
- ✅ Wired into Threats toolbar: `🌐 Browser Scan` button with tooltip.
- ✅ **Declined**: `advanced_device_profiler.py` is evasion/anti-security
  tooling (bypass-capability analysis, adaptation strategies for covert ops)
  — explicitly NOT wired in, consistent with Phase 5 rule "do NOT strengthen
  bypass/evasion orphans".
- ✅ New tests: `TestBrowserScanV2930` (5 tests, 36 total). 36/36 pass,
  py_compile OK, AST 750 methods / 0 dupes, full-project audit clean.

## Branch: main

## Session 2026-08-13i — v29.29: risk-confirmation gates on destructive actions
- ✅ **Gap**: the Threat Action Panel (right-click alert response) ran kill/
  block/suspend/root-cause with ZERO confirmation — one click on the wrong
  row force-killed a process tree or firewall-blocked IPs. Threats tab
  `_threats_kill_selected` also `taskkill /F` without asking.
- ✅ **`_confirm_risk(title, message, action, icon)`** — centralized risk
  gate: always `askyesno` first, runs `action` ONLY on confirmation,
  returns bool. Headless/test-safe: if the dialog can't be shown it returns
  False and refuses the destructive action.
- ✅ Wired into Threat Action Panel (Block All IPs / Kill PIDs / Quarantine /
  Suspend / Root Cause) and Threats tab Kill Selected (with per-alert
  preview + unsaved-work warning).
- ✅ New tests: `TestRiskConfirmation` (3 tests, 31 total). 31/31 pass,
  py_compile OK, AST OK.

## Branch: main

## Session 2026-08-13h — v29.28: Performance tab overhaul (layout + live data)
- ✅ **Bug (the "black box covering half of them")**: `_draw_gauge` drew the
  gauge label at y=`size+18` but `_draw_sparkline` renders a dark fill box at
  `size+14..size+29` and is drawn AFTER the gauge — the box covered the label
  on every gauge. Label now renders at `size+8` (its own reserved band above
  the sparkline strip).
- ✅ **Adaptive gauge ceilings**: DISK/NET rate gauges shipped with static
  ceilings (7000 MB/s, 102400 KB/s) so needles stayed pinned at 0 for any
  realistic traffic. Now `_rate_keys` derive a dynamic ceiling from observed
  history (`ceil(peak*1.4/100)*100`), updated in `_perf_gauge_meta` so both
  needle and sparkline scale together. Gauge never flickers between frames.
- ✅ **GPU column in perf process table**: same `_gpu_proc_map` attribution as
  the Processes tab (VRAM MB when readable) — 12 rows now shown.
- ✅ **Live network + disk tables**: new "LIVE NETWORK INTERFACES" (per-NIC
  send/recv KB/s + link speed, UP/DOWN color) and "DISK PARTITIONS" (used%
  with warn/full coloring) treeviews fed from existing `nic_stats` /
  `disk_partitions` stats — real-time, no new deps.
- ✅ **Bug**: `_perf_scroll_canvas.bind_all('<MouseWheel>')` hijacked wheel
  scroll for ALL tabs after the perf tab was built. Now checks
  `winfo_containing()` so only hovers over the perf grid scroll it.
- ✅ **Tooltips**: Refresh Now / Pause/Resume / Export CSV header buttons.
- ✅ New tests: `TestPerfTabV2928` (5 tests, 28 total). Verified: 28/28 pass,
  py_compile OK, AST OK.

## Branch: main

## Session 2026-08-13g — v29.27: perf-loop live kickoff + Threat Web Stack deep-links
- ✅ **Bug**: the Performance tab was written with an interval slider, pause/
  resume and adaptive `self.after()` rescheduling, but the any initial
  `after(2000, self._perf_loop)` kickoff was commented out — the loop only
  ever called *itself* recursively, so the entire "live" Performance tab
  never updated after first paint (gauges stuck on `...` and pills at 0).
  Suspicion confirmed by grepping every `_perf_loop` reference: zero
  external trigger existed.
- ✅ `_auto_start` now schedules `self.after(2000, self._perf_loop)` — it's
  read-only telemetry (no side effects), so it runs live from launch like
  the alert drainer, instead of being gated behind the Engine Control Panel.
- ✅ **Threat Web Stack** button in Intel tab + `_intel_threat_web_links()` /
  `_intel_threat_web_stack()` — keyless browser deep-links for the OSINT4ALL
  curated threat-intel sources that expose no unkeyed JSON API: Cisco Talos,
  Hybrid Analysis, PhishTank, ANY.RUN, Joe Sandbox. IOC percent-encoded.
- ✅ New tests: `tests/test_thread_safety.py::TestThreatWebStack` (5 new
  tests, 23 total). Verified: 23/23 pass, py_compile OK, project AST 0
  failures.

## Branch: main

## Session 2026-08-13f — v29.26: Windows 11 immersive dark title bar
- ✅ **Gap**: "dark mode detection for Windows 11" TODO — the app is dark but
  the native title bar used system light chrome.
- ✅ **`_apply_dark_titlebar()`** — sets DWMWA_USE_IMMERSIVE_DARK_MODE (attr
  20 Win11 / 19 Win10 fallback) on the real top-level HWND (`GetParent` of
  `winfo_id`), and reads `AppsUseLightTheme` registry → `_system_dark_theme`.
  All ctypes, fully wrapped, never raises.
- ✅ Called at loading reveal + after final title set.
- ✅ Live-verified: DwmSetWindowAttribute rc=0 on a real window (both attrs);
  current machine reads dark theme (AppsUseLightTheme=0).
- ✅ 2 new unit tests (18 total). py_compile OK; main file **741 methods /
  0 dupes**; project AST **0 failures**.

## Branch: main

## Session 2026-08-13e — v29.25: first unit tests + FP fingerprint fix
- ✅ **Gap**: TODO item "Unit tests for thread-safety mechanisms (none exist)"
  finally started. `tests/test_thread_safety.py` (pytest): 16 tests for
  `_fp_fingerprint`, `_fp_is_suppressed`, `_queue_alert` suppression +
  rate limit, and the executor `after(0)` post-back pattern.
- ✅ Uses `object.__new__(downpour)` so pure logic runs without a full Tk
  app. `Python312\python.exe -m pytest tests -q` → 16 passed.
- ✅ **Bug caught + fixed**: `_fp_fingerprint('... 45.88.48.238 :443')` did
  NOT equal `_fp_fingerprint('... 45.88.48.238')` — the port became a
  trailing `*N*` token, so an IP:port FP confirmation couldn't suppress the
  bare-IP alert (and vice-versa). Added an IP[:port] unit regex
  `\b\d{1,3}(\.\d{1,3}){3}(?:\s*:\s*\d{1,5})?\b` → `*IP*` before the generic
  port strip. The docstring claimed this collapsed; the tests proved it
  didn't. (This is exactly why the "no tests" item existed.)
- ✅ Verified: 16/16 pass; py_compile OK; main file **740 methods / 0 dupes**;
  project AST **0 failures**.

## Branch: main

## Session 2026-08-13d — v29.24: GPUDetector module shipped
- ✅ **Bug**: `enhanced_security_dashboard.py` imports `gpu_detector_fix`
  (`from gpu_detector_fix import GPUDetector`) but the module never existed —
  guarded import silently degraded GPU info in that dashboard forever.
- ✅ Created **`gpu_detector_fix.py`**: `GPUDetector.get_gpu_info()` returning
  the exact dict schema the dashboard reads (`available/name/usage/
  memory_used/memory_total/memory_percent/temperature/fan_speed/power_draw/
  clock_speed/memory_clock/driver_version/gpu_count/multi_gpu`).
- ✅ Layered detection: NVML (nvidia_ml_py → pynvml) → nvidia-smi CLI →
  GPUtil → WMI. All paths wrapped; always returns a dict, never raises.
- ✅ Live-verified: RTX 3050 via NVML (33%, 557/8192MB, 38C); dashboard
  AST parses and imports GPUDetector cleanly. Project AST **0 failures**.
- ✅ README: added feature rows for tray, perf-tab, PDF export, GPU
  attribution, keyless infra OSINT.

## Branch: main

## Session 2026-08-13c — v29.23: per-process GPU attribution
- ✅ **Gap**: GPU gauges worked (NVML) but the Processes tab had no per-process
  GPU visibility — couldn't tell which PIDs were GPU-accelerated.
- ✅ `_proc_loop` background scan now runs `nvidia-smi --query-compute-apps=
  pid,used_memory --format=csv,noheader,nounits` (timeout 8s, CREATE_NO_WINDOW)
  and caches `self._gpu_proc_map` on the executor thread.
- ✅ `_update_proc_ui` adds a **GPU** column (VRAM in MB when readable, else
  `[GPU]` marker) — new col in the `cols`/`widths` tuples, diff-based update
  untouched.
- ✅ `_show_proc_detail` shows the GPU line in the detail panel.
- ✅ Live-verified: 14 GPU processes detected on the RTX 3050; `[N/A]` VRAM
  fallback (non-admin) exercised; `_sort_proc_tree` uses column-name API so
  the new col sorts fine.
- ✅ Dependency: uses the bundled `nvidia-smi` CLI — no new Python packages.
- ✅ Verified: py_compile OK; main file **740 methods / 0 dupes**; project AST
  **0 failures**.

## Branch: main

## Session 2026-08-13b — v29.22: real PDF export for security reports
- ✅ **Bug**: `_export_compliance_pdf` was a stub — it just showed a messagebox
  telling the user to save a .txt and use a PDF printer.
- ✅ **Bug**: `_run_nsa_security_report` pushed results only to the alerts
  panel and then discarded them — the full assessment was never persisted.
- ✅ **`_export_pdf_report(title, subtitle, headers, rows, notes)`** — generic
  reportlab PDF writer. Save dialog on main thread, build on `_executor`.
  Teal-on-dark styled: wrapped Paragraph cells, dark header row, PASS/FAIL
  row shading, timestamp, optional notes bullets.
- ✅ **`_export_compliance_pdf`** — now dumps the live compliance tree into a
  real PDF (with failing/warning count note); guards empty-tree with a
  "run Full Audit first" hint.
- ✅ **`_save_nsa_report_pdf(report, critical, grade)`** — executor-side PDF
  writer for the NSA assessment; auto-writes to
  `~/Documents/DownpourReports/downpour_nsa_report_<ts>.pdf` and shows a
  completion dialog. `_run_nsa_security_report` calls it after the summary.
- ✅ Dependency: reportlab verified installed + live-built a valid `%PDF-1.4`
  file with the exact table/style code used. No new installs.
- ✅ Verified: py_compile OK; main file **740 methods / 0 dupes**; project AST
  **0 failures**.

## Branch: main

## Session 2026-08-13a — v29.21: Performance tab live controls + keyless infra OSINT
- ✅ Checkpointed the uncommitted sprint (perf controls + 3 keyless OSINT
  lookups) as v29.21.
- ✅ **Performance tab**: `_toggle_perf_pause` (pause/resume monitoring without
  losing state), `_on_interval_change` (2-30s slider, applies live to adaptive
  intervals), `_draw_sparkline` (real sparklines on perf canvases, re-rendered
  on interval change).
- ✅ **`_osint_ipinfo_lookup`** — keyless IPinfo.io ASN/geo/anycast/bogon
  attribution. Live-verified: `8.8.8.8` → `AS15169 Google LLC / US`.
- ✅ **`_osint_bgpview_lookup`** — keyless BGPView BGP routing graph for IPs and
  ASNs. NOTE: `api.bgpview.io` DNS fails on this network (possibly blocked);
  verified the code's web-page fallback path handles it.
- ✅ **`_osint_hacktarget_lookup`** — keyless HackerTarget multi-recon
  (reverse-IP, GeoIP, DNS, ASN). Live-verified both endpoints.
- ✅ **Bug fixed**: all 6 HackerTarget URLs used `api.hacktarget.com` (no `er`) —
  nonexistent host, DNS-fail. Corrected to `api.hackertarget.com` /
  `hackertarget.com`. Caught by live-testing each endpoint before commit.
- ✅ All three OSINT lookups wired into Network tab, Intel tab, DNS Advanced
  Tools via `_executor` + `after(0)` post-back.
- ✅ Verified: py_compile OK; main file **738 methods / 0 dupes**; project AST
  **0 failures**; keyless endpoints live-tested.

## Branch: main

## Session 2026-08-12g — v29.20: system tray icon (restore path)
- ✅ **Bug**: `minimize_to_tray` config + `_on_close`'s `withdraw()` existed,
  but NO tray icon was ever created — closing the window hid the app with no
  way to restore it (the TODO's "tray never shipped" item).
- ✅ **`_setup_tray_icon()`** — builds a pystray `Icon` (PIL-drawn 64x64
  shield) with Show / Minimize / Exit menu actions, `run_detached()` so it
  owns its own thread and never blocks the Tk loop. Wired into `_auto_start`
  at 8s. Guards on `PYSTRAY_AVAILABLE` + already-running.
- ✅ **`_tray_restore()`** — main-thread deiconify/lift/focus (with brief
  topmost flash so it appears above other windows).
- ✅ **`_tray_toggle()`** — hide/show toggle for the menu item.
- ✅ **`_on_close`** — now fires a `[TRAY]` alert on minimize so the user
  knows where the app went.
- ✅ **`_shutdown`** — stops `_tray_icon` before tearing down Tk.
- ✅ Verified: pystray API surface live-checked (`run_detached`/`stop`/menu/
  PIL icon all OK); py_compile OK; main file **733 methods / 0 dupes**;
  project AST **0 failures**.

## Branch: main

## Session 2026-08-12f — v29.19: OSINT multi-lookup email classification fix
- ✅ **Bug**: `_osint_multi_lookup` had no email branch — emails fell into the
  domain `else`, producing broken links (`dom = ioc.split('/')[0]` →
  `test@example.com`).
- ✅ Added `is_email` detection (before IP/hash/domain) with an email source
  stack: HIBP account, Hudson Rock email, EmailRep.io, DeHashed, Hunter.io,
  VT domain-of-domain, crt.sh, Google. Removed the now-redundant
  unconditional HIBP breach link (folded into domain branch).
- ✅ Verified classification with 8 cases (IP/hash/email/domain/URL/all pass),
  and removed a leftover duplicated `elif is_hash` block my first edit
  created (AST caught it, compile + audit clean after).
- ✅ Verified: py_compile OK; main file **730 methods / 0 dupes**; project
  AST **0 failures**.

## Branch: main

## Session 2026-08-12e — v29.18: slow-feed result-timeout tuning
- ✅ Investigated the `fut.result(timeout=30)` in `update_all`: empirically
  confirmed with a 60s-slow feed test that `as_completed` only yields
  finished futures, so the 30s timeout never fired and MITRE CTI (48MB)
  already counted as OK. The old 30s was therefore misleading AND a latent
  bug — any refactor to a plain `futures` loop would have falsely failed
  every slow feed.
- ✅ Raised to `timeout=150` with a documented budget comment (3x15s download
  attempts + backoff + 120s multiprocess parse = worst case) so it's
  defense-in-depth, not a slow-feed killer.
- ✅ Verified: py_compile OK; main file **730 methods / 0 dupes**; project
  AST **0 failures**.

## Branch: main

## Session 2026-08-12d — v29.17: feed fetch retry with backoff
- ✅ `_fetch_feed` upgraded from 2 immediate attempts to **3 attempts with
  backoff** `(0s, 2s, 6s)` — transient timeouts / 5xx / flaky certs recover
  instead of the feed being marked failed for the whole cycle. Last-attempt
  errors still recorded in `self._feed_errors` → `feed_status`.
- ✅ Cross-checked the periodic path: `_intel_auto_loop` re-runs `update_all`
  when due (default 6h) and checks every 10 min, so a feed that fails the
  3-attempt backoff still retries on the next scheduled cycle.
- ✅ Verified: py_compile OK; main file **730 methods / 0 dupes**; project
  AST **0 failures**.

## Branch: main

## Session 2026-08-12c — v29.16: DB-backed false-positive auto-suppression
- ✅ **`fp_suppressions` table** (fingerprint PK, confirmed, suppressed,
  first_seen, last_seen, sample_msg) in the DB schema DDL.
- ✅ **`_fp_fingerprint(msg)`** — normalizes an alert into a stable key:
  bracket category kept, body lowercased, ports/IPs→`*N*`, hashes→`*H*`,
  whitespace collapsed, trimmed to 64 chars. Verified collisions: same
  IP+port → same key, distinct ports → distinct keys, hashes stable.
- ✅ **`_fp_load_cache()` / `_fp_cache_update()`** — loads `fp_suppressions`
  into an in-memory dict on the executor at startup (6s in `_auto_start`);
  `_queue_alert` hot path only does a dict lookup, no DB on main thread.
- ✅ **`_fp_is_suppressed(msg)`** in `_queue_alert` — drops known-FP alerts
  before they reach the UI.
- ✅ **`_fp_confirm(msg)`** — persists a Mark-FP confirmation (executor
  write); auto-suppresses at `_FP_SUPPRESS_THRESHOLD = 3` confirms, fires a
  `[FP] Auto-suppressed` alert, keeps `first_seen` via COALESCE. Verified in
  isolation: confirms 1-2 no-op, 3rd flips suppressed=True, 4th dropped.
- ✅ **`_threats_mark_fp`** now calls `_fp_confirm` (persisted, not just an
  in-memory status flip).
- ✅ **`_threats_fp_manager`** modal — lists active suppressions (fingerprint
  + confirm count), `Re-arm Selected` (`_fp_unsuppress`), `Clear All`
  (`_fp_clear_all`), both executor writes. New `🤫 FP Blocklist` button in
  the Threats tab toolbar.
- ✅ Verified: py_compile OK; main file **730 methods / 0 dupes**; project
  AST **0 failures**.

## Branch: main

## Session 2026-08-12b — v29.15: Feed health dashboard in Intel tab
- ✅ **`_refresh_feed_health()`** — async reader: `intel.get_feed_status()`
  (`feed_status` table: feed_name / last_update / records_added / error)
  runs on `self._executor`, rows marshaled back via `after(0)`.
- ✅ **`_apply_feed_health(rows)`** — main-thread updater colors the Intel-tab
  feed Status column (which sat on "Pending" forever despite real DB data):
  `[OK] N IOCs - hh:mm` (keeps darkweb/clearnet/gov/community tag),
  `[FAIL] err` (red `feed_err` over-ride), `[STALE]` >3 days (yellow
  `feed_stale`), `[PENDING]` when feed_status has no row. Also sets the
  `_intel_status` summary label to `ok / failed / tracked` counts.
- ✅ Wired: `_feed_refresh_loop` periodic, `_update_intel_now` post-update,
  and a one-shot first paint in `_auto_start` (5s). Adds `feed_err`/
  `feed_stale` tag configs + `_intel_feed_stale_days = 3` in `_build_intel_tab`.
- ✅ Verified: py_compile OK; main file **720 methods / 0 dupes**; project AST
  **0 failures**.

## Branch: main

## Session 2026-08-12a — v29.14: main-thread DB freeze cleanup (v31p2)
- ✅ **Freeze fix round 2**: audited every `count_intel()` / `SELECT COUNT(*)`
  call site for main-thread risk. Eliminated 5+ remaining main-thread DB blocks:
  - New shared helper `_refresh_ioc_count_display()` — runs `db.count_intel()`
    on `self._executor`, posts the label update back via `self.after(0, ...)`,
    with `hasattr`/membership guards so it is safe from both main-thread
    loops and background threads.
  - `_update_network_ui` (30s loop) — was calling `count_intel()` inline on main.
  - `_auto_start` — one-shot `count_intel()` on main at startup.
  - `_feed_refresh_loop` — replaced the per-loop inline executor closure with
    the shared helper (dedupe).
  - `_update_intel_now` — posted `count_intel()` to main in its after(0) lambda.
  - `_aegis_fetch_extra_feeds` — same main-thread after(0) pattern.
  - `_refresh_aegis_stats` (15s AEGIS loop) — both `SELECT COUNT(*) FROM
    aegis_events` and the 10-row `ORDER BY id DESC LIMIT 10` were on main.
    Wired `_aegis_fetch_events` (executor) → `_apply_aegis_events` (main).
- ✅ Audit results: main file now **718 methods / 0 dupes**; py_compile OK;
  project-wide AST **0 failures** (removed stray `zz_dbaudit.py`,
  `zz_health.py` BOM-broken temp scripts).

## Branch: main

## Session 2026-08-11m — v29.13: Hudson Rock infostealer lookup + freeze fix (v31p1)
- ✅ `_osint_hudsonrock_lookup(ioc)` — keyless Hudson Rock **Cavalier** API
  (sidebar source: OSINT4ALL "OSINT for Cybersecurity" — Exposure & breach
  context). Dispatch: email → `search-by-email`, domain → `search-by-domain`.
  Renders affected-machine count, corporate/user creds exposed, most-recent
  compromise date, AV present on infected machines, employee/user/third-party
  split + compromised login URLs for domains. Fires `[BREACH]` alert signal.
- ✅ `_osint_hudsonrock_show(text, ioc)` — display + open cavalier.hudsonrock.com
- ✅ Buttons: `Hudson Rock` in Intel tab Threat Response row; `[BREACH]
  Infostealer Check` in DNS Advanced Tools (via `_dns_adv_hudsonrock` wrapper);
  `Hudson Rock` added to `_osint_multi_lookup` domain deep-link stack.
- ✅ **Freeze fix**: `_refresh_status_pills` ran `SELECT COUNT(*) FROM threats`
  on the *main thread* every 10s — with `db._lock` already held by background
  bulk-insert threads this blocks the UI (same documented root cause as the
  earlier `_feed_refresh_loop` fix). Moved the count to `self._executor` +
  `self.after(0, _apply_threat_pill)`. Status pills now non-blocking.
- ✅ Verified live: email-with-hits, clean domain (`total=0`), real exposure
  domain (tesla.com → 29,630 creds), no-hit email (`stealers=[]`).
- ✅ Project: 0 AST failures; main file 715 methods / 0 dupes; py_compile OK.
- ✅ Committed previously-untracked `ultimate_threat_intel/__init__.py`
  (live runtime for threat_feed_aggregator: ThreatDatabase schema + registry)
  — it was showing as untracked despite being imported at runtime.

## Branch: enhance/all-mods-v29 (historical; now committed on main)

## Completed (Phases 1-2)
- ✅ Removed 2249 illegal `: Any` annotations (token-stream CRLF-safe rewriter)
- ✅ Fixed 6 global/nonlocal annotation conflicts
- ✅ Implemented RemoteAccessController.disable_vector / enable_vector / disable_all_remote_access (@staticmethod)
- ✅ Repointed THREAT FEEDS gauge from broken ultimate_threat_intel stub to working threat_feed_aggregator
- ✅ Added `_make_button()` shared helper + tooltips to: Scanner, Processes, Network, Hardening, AEGIS, Intel, Firewalls, Threats detail panel

## Session 2026-08-11k — DNS tab inline urlscan.io search (v29.12)
- ✅ `_dns_adv_urlscan()` — reuses keyless `_osint_urlscan_search` on the DNS domain field; empty-domain guard
- ✅ Live github.com domain search verified

## Session 2026-08-11j — Keyless inline AlienVault OTX lookup (v29.11)
- ✅ `_osint_otx_lookup(ioc)` — OTX general endpoint, keyless; IP/domain/hostname/URL/file dispatch
- ✅ ASN/geo/reputation/pulse-count/pulse-names + community false-positive notice
- ✅ Live keyless 8.8.8.8 verified; fixed urllib.parse quote bug

## Session 2026-08-11i — Inline ThreatFox IOC search (v29.10)
- ✅ `_osint_threatfox_lookup(ioc)` — ThreatFox API (search_hash / search_ioc exact-match), same abuse.ch Auth-Key
- ✅ Renders malware family/threat type/confidence/Malpedia per hit; no-result dialog
- ✅ Verified both dispatches + keyless fallback; abuse.ch slice complete (MalwareBazaar + URLhaus + ThreatFox)

## Session 2026-08-11h — Inline URLhaus lookup (v29.9)
- ✅ `_osint_urlhaus_lookup(ioc)` — URLhaus API dispatch (hash→payload/, URL→url/, IP/domain→host/), reuses abuse.ch Auth-Key
- ✅ Blacklist state (Surbl + Spamhaus DBL labels), VT ratio, payload drops, recent malware URLs
- ✅ Verified hash/URL/host paths + keyless fallbacks

## Session 2026-08-11g — Inline MalwareBazaar hash lookup (v29.8)
- ✅ `_osint_malwarebazaar_lookup(ioc)` — POST get_info (MD5/SHA1/SHA256), free Auth-Key header; signature/file/type/timestamps/tags/vendor-intel
- ✅ Live probe: endpoint now 401 without Auth-Key → added Settings key field + keyless page fallback
- ✅ Verified hit/not-found/non-hash/keyless paths

## Session 2026-08-11f — Inline Netlas.io host lookup (v29.7)
- ✅ `_osint_netlas_lookup(ioc)` — Netlas host API (Bearer key): IP (ASN/netblock/org/geo/PTR/ports/software) + domain (WHOIS/related domains/NS/MX/ports)
- ✅ `netlas_key` Settings field; `Netlas` button in Intel Threat Response row
- ✅ Verified IP + domain paths, keyless fallback, empty input

## Session 2026-08-11e — Inline Censys host-view lookup (v29.6)
- ✅ `_osint_censys_lookup(ioc)` — Censys Search API v2 host view (API ID + Secret basic auth): ports/services, TLS cert subject/issuer, ASN/geo/DNS; keyless → public page
- ✅ Settings: `censys_api_id` + `censys_secret` masked fields (replaces dead `censys_enabled` boolean)
- ✅ `Censys` button in Intel Threat Response row; `_osint_censys_show()` Tk callback
- ✅ Keyed path verified via mocked v2 response; keyless path opens host page

## Session 2026-08-11d — Keyless urlscan.io public search (v29.5)
- ✅ `_osint_urlscan_search(ioc)` — no-key urlscan.io public search: IP → `ip:`, URL → `page.url:`, else `domain:`; verdicts+scores surfaced, index page opened
- ✅ `is:` operator 403s keyless on this network → switched to `ip:` (live-verified)
- ✅ `urlscan Search` button in Intel Threat Response row; `_urlscan_search_show()` Tk callback

## Session 2026-08-11c — MISP import firewall-block option (v29.4)
- ✅ `_intel_import_misp()` prompts to firewall-block imported IPs (askyesno) — `Downpour_MISP_<ip>` netsh inbound rules, cap 250 (`_MISP_BLOCK_IMPORT_CAP`), blocked/failed/skipped tally
- ✅ Decline path = no firewall work; import unaffected; accept/decline verified via fake netsh harness

## Session 2026-08-11b — MISP/STIX indicator sharing (v29.3)
- ✅ `_intel_import_misp()` — imports MISP event JSON / STIX 2.0 bundle / plain IOC text into titanium.db intel tables (source `MISP-Import:<file>`)
- ✅ `_misp_extract_iocs()` recursive parser (Event/Attribute/objects/response containers, dedupe, generic fallback)
- ✅ MISP type hints incl. `filename|sha256` composite; STIX indicator.pattern + ipv4-addr/domain-name/url/file SCO; multi-label domain classifier
- ✅ `_intel_export_misp()` — exports malicious_ips/domains/urls/hashes as MISP-format JSON event (uuid/info/date/Attribute with type/category/to_ids/comment)
- ✅ Buttons `[MISP] Import IOCs` + `[MISP] Export Event` in Intel Threat Response row
- ✅ Round-trip verified vs temp DB (import→store→export), no duplicates; `py_compile` OK
- ✅ `docs/TODO_v30_DDoS.md` — all 6 DDoS checklist items marked complete

## Session 2026-08-11 — Email-auth DNS check + DNS allowlist bug fix (v29.2)
- ✅ `_dns_adv_email_security()` SPF/DMARC/DKIM check in DNS Advanced Tools (DNS-only, no key)
- ✅ SPF verdict regex handles `-all`/`~all`/`+all`/missing; DMARC `p=` tag regex fixes `sp=reject` false-positive; DKIM multi-selector probe (google/selector1/etc.)
- ✅ **FIXED latent bug**: `_DNS_SAFE_CMD_RE` had a literal backspace byte (`\x08`) instead of `\b`, making every `_dns_run_cmd()` return `[BLOCKED]` — whole DNS tab tooling was silently dead; now `\b`, all 7 call patterns verified
- ✅ Live-verified: google.com (SPF `~all` WARN / DMARC `p=reject` OK / DKIM google selector OK), github.com (DMARC `p=quarantine; sp=reject` now correctly WARN)
- ✅ `_txt_for()` extracts quoted TXT values via regex (nslookup puts value on a separate line from `text =`)

## Session 2026-08-10 — DDoS v30 bootstrap + OSINT4ALL indicator stack (v29.1)
- ✅ Fixed duplicate/conflicting DDoS blocklist persistence (v29 flat dict vs v30 wrapper) — all blocks now land in one JSON store
- ✅ `_ddos_load_blocklist` now backward-compatible + actually removes expired firewall rules on load
- ✅ Wired v30 DDoS Shield UI buttons (Shield / Rate Monitor / Block All / Export / Purge) + startup restore in `_start_loops`
- ✅ OSINT4ALL stack: multi-lookup deep-links (VT/AbuseIPDB/Talos/GreyNoise/Shodan/Censys/OTX/urlscan/HA/MalwareBazaar/SecurityTrails/DNSlytics)
- ✅ Inline AbuseIPDB + Shodan + **Pulsedive** + **ONYPHE** lookups (free API keys; web-page fallback when keyless)
- ✅ HIBP **Pwned Passwords** k-anonymity check (no key) — live-verified vs real API (`password` → 52M hits)
- ✅ GeoIP proxy/hosting flags; Settings → OSINT API Keys (4 fields); extended multi-lookup with Pulsedive/ONYPHE/ANY.RUN/Joe Sandbox/URLhaus/HIBP
- ✅ **DNS tab**: crt.sh CT subdomain discovery (retry + Certspotter fallback, live-verified), Domain OSINT Stack deep-link (14 infra sources incl. Wayback/Archive.today/ViewDNS/DNSDumpster/MXToolbox/Wappalyzer/BuiltWith/Netlas/ZoomEye/FullHunt)
- ✅ **Intel tab**: EmailRep.io inline email reputation (key configurable, page fallback) + GCHQ CyberChef decode with pre-loaded value; Settings → 5 OSINT API key fields
- ✅ **Session 4**: GreyNoise Community noise-vs-targeted triage (Network tab, keyed), Wayback Machine availability check (no-key, no-history = phishing flag), urlscan.io one-click scan submit (Intel tab, keyed); Settings → 7 OSINT API key fields
- ✅ Verified: py_compile + module import + functional tests all pass under Python 3.12

## Phase 3 — Tooltip conversion (in progress)
Remaining button blocks needing tooltips (NO _tooltip / _make_button yet):
- Emergency tab: big panic button (24337), actions loop (24377) — 9 buttons
- Parental tab: 3 buttons (24306, 24309, 24312)
- Ransomware tab: 5 main buttons loop (24473), 3 dir buttons (24532, 24535, 24538)
- Memory tab: 5 buttons loop (24720)
- CVE tab: 7 buttons loop (26037)
- VPN tab: local btn() wrapper (27652) — 9 buttons total (action bar + filter bar)
- Settings tab: revert (27352), bypass (27378), save/export/import (27411-27419), test email (27457), zero trust (27518-27533) — 10 buttons
- Hunt tab: HUNT/STOP (29321, 29329), actions loop (29397) — 10 buttons
- Sandbox tab: browse (30633), detonate/static/clear (30658-30664) — 4 buttons
- Remote Access tab: 4 buttons loop (38837)
- Duplicates cleanup sub-tab: local _btn (40177) — 3 buttons
- Large Files cleanup sub-tab: local _btn (40659) — 2 buttons
- Empty Folders cleanup sub-tab: browse (40891), local _btn (40898) — 3 buttons
- Disk Usage cleanup sub-tab: browse (41328), local _btn (41335) — 2 buttons
- Security Cleanup sub-tab: 7 buttons loop (~41531)
- WiFi tab: 4 buttons loop (42591)
- Timeline tab: 4 main (42898-42907), 4 quick filter + 1 all (42936-42942)
- IoT tab: 7 buttons loop (44436)
- USB tab: 6 buttons loop (43209), remove/save whitelist (43273, 43277)

## Phase 4 — Performance tab overhaul (HIGH PRIORITY)
- "no black box covering half of them" → fix canvas/gauge layout bug
- working gauges (live stats, animated)
- top-N process table, history sparklines
- refresh interval control, freeze/pause, export CSV
- 10x better

## Phase 4b — Modernize GUI
- Keep rain + crescent moon theme
- Add risk warning popups for destructive actions

## Phase 5 — Consolidate orphan modules
- threat_detection_engine, advanced_threat_analyzer, ml_behavioral_analyzer, behavioral_analyzer, behavior_scanner, threat_intelligence (none imported)
- Wire useful ones in; do NOT strengthen bypass/evasion orphans
- Fix broken threat databases

## Phase 6 — Cleanup
- Delete _*.py throwaway scripts + .bak + _illegal_any.json
- .gitignore: add *.pyi, .mypy_cache/, _mypy_*.txt, pyrightconfig.json, stub dirs
- requirements.txt: ensure ALL deps present (torch, scipy, etc) — no optional skips

## Phase 7 — Docs
- README.md: fix 27 tabs (not 24), 104 YARA, real feed count, real FIM count
- docs/README.md, docs/LAUNCHER_GUIDE.md fixes
- docs/AI_Integration.md (0 bytes) — write it
- docs/MODULE_MAP.md — create
- docs/CHANGELOG.md update

## Phase 8 — Verify + push
- py_compile all 58+ modules + main file
- Commit on enhance/all-mods-v29
- git push to origin

## Session 2026-07-10 — Pyright type-fix blitz (1,147→0 errors)
- **Root cause of 806 tkinter None errors**: Removed dead `except ImportError: tk = None` block
- **~180 import None errors**: Annotated ALL `= None` in try/except ImportError blocks with `: Any` (GPUtil, wmi, sklearn, torch, cryptography, requests, pystray, colorama, etc.)
- **~15 instance var None errors**: Added `: Any` to `self._conn`, `self._scaler`, `self._iso_forest`, `self._rf_classifier`, `self._neural_net`, `self.security_auditor`, `self.cleanup_engine`, `self.dup_finder`, `self._iot_scanner`
- **3 runtime bugs fixed**: Missing `url` arg in `_fetch_feed()`, wrong `command_line` kwarg in `_report_apt_detection()`, wrong arg count in `_update_proc_ui()`
- **~15 Optional type signatures**: Fixed function defaults (`str = None` → `Optional[str] = None`)
- **20 redeclaration warnings fixed**: Removed redundant parameter re-annotations
- **1 unused expression fixed**: `getattr(x, None) and x.stop()` → proper `if` guard
- **Config fixes**: `reportRedeclaration` → `"warning"`, retained `reportAttributeAccessIssue: false`
- **stub fixes**: `apply_revolutionary_enhancements(target: Any = None)` in `revolutionary_enhancements/__init__.pyi`
- **Result**: 0 pyright errors, 102 warnings (all `reportUnusedVariable`), app launches clean to mainloop
- **Blocked**: Pillow/matplotlib/scikit-learn/yara-python can't be built — no C compiler + no cp315 wheels yet (Python 3.15.0a6)

## Session 2026-08-13x — v29.35: fix failing test + Phase 3 tooltip sweep (WiFi/IoT/USB/Timeline/VPN/Settings/Hunt/Sandbox)
- ✅ Fixed failing test TestTabIndicatorV2934b::test_indicator_created_before_tab_change_binding by searching for the exact binding string rather than a bare event name that matched a comment.
- ✅ Verified Phase 3 tooltip sweep for WiFi, IoT, USB, Timeline, VPN, Settings, Hunt, and Sandbox tabs (tooltips were already correctly populated).
- ✅ Tests: 50 pass (1720 methods)
