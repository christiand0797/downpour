# Downpour Improvement Catalog — External Research (v29.44)

**Generated:** 2026-09-08 · **Source:** Security tooling landscape knowledge base
**Purpose:** Actionable improvements for future development sessions, organized by
impact and implementation effort. Each item includes the pip package, the specific
Downpour module it improves, and the expected benefit.

---

## 1. HIGH IMPACT — Detection Engines

### 1a. YARA-X: Google's Rust rewrite of YARA  ✅ SHIPPED v29.46
- **Status:** DONE — `yara_x_engine.py`; yara-x 1.20 in the venv, all 14
  `yara_rules/*.yar` rulesets compile (lenient Compiler path), yara-python
  fallback, ~6 ms per-file scans. See `_WORKLOG.md` v29.46.
- **Package:** `yara-x` (pip)
- **Speedup:** 5–10× over yara-python for large rule sets; better memory profile
- **Improves:** `advanced_file_analyzer.py`, `file_scanner.py` — all 104 YARA rules
- **Migration path:** yara-x is API-compatible with yara-python for most rules;
  swap the import, re-compile, run the test suite. Rules with unsupported
  modules (openssl, hash) need porting.
- **Why it matters:** The current yara-python scans 104 rules serially on one
  thread. Yara-X compiles to native Rust with SIMD instructions and Aho-Corasick
  pre-filtering — the 5–10× speedup directly reduces scan latency from ~200ms
  to ~20ms per file batch.

### 1b. Hyperscan: Intel's high-performance regex matching
- **Package:** `hyperscan` (pip; requires `libhyperscan` native lib)
- **Improves:** `behavior_scanner.py` (SUSPICIOUS_CMDLINE_PATTERNS),
  `threat_detection_engine.py` (port profiles), `downpour_v29_titanium.py`
  (_analyze regex checks), `file_scanner.py` (suspicious content patterns)
- **Why it matters:** The current Python `re` module is single-threaded and
  backtracks on complex patterns. Hyperscan compiles hundreds of patterns into
  a single DFA that matches ALL patterns simultaneously in a single pass —
  10–100× faster than sequential `re.match()` calls for multi-pattern scanning.
- **Implementation:** Replace the per-pattern `re.search()` loop in
  `behavior_scanner._analyze_cmdline()` with a single `hyperscan.scan()` call
  over the cmdline string. Compile all SUSPICIOUS_CMDLINE_PATTERNS at startup
  into one Hyperscan database.

### 1c. ETW: Event Tracing for Windows (kernel-level telemetry)
- **Package:** `krabsetw` (Microsoft's C++ ETW library with Python bindings)
  or `python-etw` (pure Python wrapper)
- **Improves:** ALL monitoring modules — replaces polling with push-based events
- **Why it matters:** The current architecture polls psutil every 5–60s. ETW
  delivers kernel-level events (process creation, thread injection, registry
  modification, file I/O, image load, network connect) **in real time with zero
  polling**. This closes the detection gap for fast attacks that complete
  between polling cycles (sleep-based evasion defeated).
- **Key ETW providers to subscribe:**
  - `Microsoft-Windows-Kernel-Process` (process create/exit, thread events)
  - `Microsoft-Windows-Kernel-File` (file create/write/delete/rename)
  - `Microsoft-Windows-Kernel-Registry` (registry key/value operations)
  - `Microsoft-Windows-Kernel-Network` (TCP/UDP connect/accept)
  - `Microsoft-Windows-DNS-Client` (DNS queries with domain names)
- **Fallback:** `win32evtlog.EvtSubscribe()` for Windows Event Log channels
  (Security event ID 4688 process creation, Sysmon event IDs 1/3/11/12/13)

### 1d. EMBER: Static PE Malware Classification (ML)
- **Package:** `lightgbm` (pip) + EMBER model weights
- **Improves:** `advanced_file_analyzer.py` — adds ML-based PE scoring alongside
  YARA rules and entropy analysis
- **Why it matters:** EMBER (Endgame Malware BEnchmark for Research) is a
  LightGBM model trained on 1.1M PE files that scores static features
  (imports, sections, entropy, strings, byte histogram) with 95%+ accuracy.
  It catches zero-day/unseen malware that signature-based YARA rules miss.
- **Features extracted:** PE header fields, section entropy, import table
  function names, byte histogram (256 bins), string counts, COFF character-
  istics. All extractable via `pefile` (already in requirements.txt).
- **Implementation:** Extract EMBER features in `advanced_file_analyzer.py`,
  score with a pre-trained LightGBM model, add the score to the risk pipeline.

### 1e. Sigma Rules: Standardized Detection Format  ✅ SHIPPED v29.46
- **Status:** DONE — `sigma_engine.py` (stdlib, no pysigma dependency):
  24-rule curated starter pack + `sigma_rules/` drop-in loader (JSON +
  YAML-subset), matched against live process cmdlines and PowerShell 4104
  script blocks. See `_WORKLOG.md` v29.46.
- **Package:** `pysigma` (pip) — NOT needed; stdlib implementation avoids
  the extra dependency
- **Improves:** Adds 3000+ community detection rules from the Sigma HQ
  repository (github.com/SigmaHQ/sigma) in a standard YAML format
- **Why it matters:** Sigma is the "YARA for logs" — a community-driven
  repository of detection rules covering APT techniques, LOLBins, malware
  families, and cloud attacks. pySigma converts Sigma rules to Python-native
  queries or Windows Event Log filters.
- **Implementation:** Download the Sigma HQ ruleset, convert relevant rules
  to Downpour's detection format, and load them as additional detection
  signatures in the behavior scanner and event log analysis.

---

## 2. HIGH IMPACT — Performance

### 2a. functools.lru_cache on hot paths
- **Package:** stdlib (no pip needed)
- **Improves:** Every module with repeated computations
- **Why it matters:** Several hot-path functions recompute the same values on
  every call. Adding `@functools.lru_cache(maxsize=N)` to pure functions
  eliminates redundant computation at zero cost.
- **Specific targets:**
  - `code_integrity.build_manifest()` — add cache for repeated verifications
  - `mega_threat_signatures.get_all_signatures()` — called per file scan

### 2b. Aho-Corasick multi-pattern string matching
- **Package:** `ahocorasick-rs` (pip; Rust implementation)
- **Improves:** IOC string matching in `file_scanner.py`, `mega_threat_
  signatures.py`, `behavior_scanner.py`
- **Why it matters:** Scanning a file for 750+ malware family names using
  sequential `str.find()` or `re.search()` is O(n*m). Aho-Corasick matches
  ALL patterns simultaneously in O(n) regardless of pattern count. For 750
  family names against a 100MB file: 750× re.search calls → 1 Aho-Corasick scan.
- **Implementation:** Build the automaton at startup from all known malware
  family names, replace the per-name search loop with a single scan.

### 2c. RE2: Linear-time regex (no backtracking DoS)
- **Package:** `google-re2` (pip)
- **Improves:** All regex scanning; prevents ReDoS (Regular expression
  Denial of Service)
- **Why it matters:** Python's `re` module uses backtracking — a crafted
  input can cause catastrophic backtracking (exponential time), which is
  a DoS vector if an attacker controls the string being scanned. RE2 uses
  a DFA that guarantees linear time regardless of pattern complexity.
- **Implementation:** Replace `re.compile()` with `re2.compile()` for the
  scanning patterns in behavior_scanner and file_scanner. Fall back to
  `re` if RE2 is not installed.

---

## 3. MEDIUM — Threat Intelligence

### 3a. STIX/TAXII: Structured Threat Information eXchange  ✅ SHIPPED v29.46
- **Status:** DONE — `stix_taxii_feed.py` (stdlib + requests, no
  stix2/taxii2-client dependency): TAXII 2.1 discovery/collections/objects
  with `next`-cursor pagination, Basic/Bearer auth, STIX 2.1 pattern
  extraction (ip/domain/url/hashes/registry). Disabled by default until the
  user configures `downpour_data/stix_taxii_config.json`. See `_WORKLOG.md`
  v29.46.
- **Package:** `stix2`, `taxii2-client` (pip) — NOT needed; stdlib
  implementation avoids the extra dependencies
- **Improves:** `threat_feed_aggregator.py`, `threat_intelligence.py`
- **Why it matters:** STIX 2.1 is the OASIS standard for threat indicator
  exchange. TAXII 2.1 is the transport protocol. Major ISACs, government
  CERTs, and commercial feeds publish in STIX format.
- **Sources unlocked:** CISA AIS, MISP instances, commercial feeds

### 3b. MISP: Open Source Threat Intelligence Platform
- **Package:** `pymisp` (pip)
- **Improves:** `threat_feed_aggregator.py`
- **Why it matters:** MISP is the largest open-source threat sharing
  platform with 10,000+ organizations sharing indicators.

### 3c. Government feeds (free, no key)
- CISA Malware Analysis Reports (MAR) — hashes + YARA rules
- CISA ICS-CERT advisories — industrial control system threats
- NCSC (UK) threat reports
- BSI (Germany) botnet C2 lists

---

## 4. MEDIUM — Self-Protection

### 4a. Process Mitigation Policies (anti-tamper)
- **Package:** `ctypes` (stdlib)
- **Improves:** The main app's resistance to process injection and tampering
- **Why it matters:** The audit identified that the app runs unprotected —
  any same-user process can inject code, read memory, or terminate it.
- **Key policies:**
  - `ProcessDynamicCodePolicy` — blocks dynamic code generation (shellcode)
  - `ProcessSystemCallDisablePolicy` — blocks direct system calls
  - `ProcessExtensionPointDisablePolicy` — disables DLL injection via
    AppInit_DLLs, Winlogon notification packages
  - `ProcessControlFlowGuardPolicy` — enables Control Flow Guard
- **Implementation:** ~30 lines of ctypes to call `SetProcessMitigationPolicy`
  at startup. Blocks common exploitation techniques against the Downpour
  process itself.

### 4b. Windows Job Objects (child process restriction)
- **Package:** `pywin32` (already in requirements)
- **Improves:** Prevents child processes (YARA scanners, PE analyzers) from
  escaping monitoring and ensures they terminate if the parent dies.
- **Implementation:** `win32job.CreateJobObject()` with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, assign child processes.

---

## 5. MEDIUM — New Detection Techniques

### 5a. DNS query monitoring (via ETW or DNS cache)
- **Improves:** `network_monitor.py` — the audit identified DNS-layer
  visibility as a blind spot
- **Why it matters:** C2 over DoH (DNS over HTTPS) bypasses port-53
  monitoring. DNS query names are the best C2 indicator (DGA, tunneling,
  TXT record exfil).
- **Implementation:** ETW `Microsoft-Windows-DNS-Client` provider or
  periodic `ipconfig /displaydns` cache enumeration with DGA scoring.

### 5b. AMSI (Antimalware Scan Interface) integration
- **Package:** `ctypes` (stdlib)
- **Improves:** Script-based threat detection — PowerShell, VBScript, JS
- **Why it matters:** AMSI is the Windows anti-malware interface all script
  hosts call before execution. Registering as an AMSI provider lets Downpour
  inspect obfuscated PowerShell that bypasses file scanning.
- **Implementation:** Consume AMSI events via ETW provider
  `Microsoft-Antimalware-Scan-Interface` or register as a full AMSI provider
  via COM (complex but powerful).

### 5c. LOLBins detection
- **Improves:** `behavior_scanner.py`
- **Key LOLBins:** `mshta.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`,
  `wmic.exe`, `rundll32.exe`, `msbuild.exe`, `installutil.exe`, `csc.exe`
- **Implementation:** Monitor process creation for these binaries + suspicious
  parent-child relationships + command-line patterns. Flag combinations
  matching known attack patterns (MITRE ATT&CK LOLBINs).

---

## 6. LOW — Code Quality & Infrastructure

### 6a. structlog: Structured JSON logging
- **Package:** `structlog` (pip)
- **Improves:** `enhanced_logging.py`
- **Why:** JSON key-value logs enable aggregation and querying

### 6b. pydantic: Configuration validation
- **Package:** `pydantic` (pip)
- **Improves:** `config.py`
- **Why:** Type-safe config models instead of raw dicts

### 6c. tenacity: Retry logic
- **Package:** `tenacity` (pip)
- **Improves:** Feed fetch retries, PE analysis retries
- **Why:** Declarative exponential backoff instead of hand-rolled loops

### 6d. rich: Terminal output + progress bars
- **Package:** `rich` (pip)
- **Improves:** CLI tools (system_cleanup, health_check, code_integrity)
- **Why:** Rich tables, progress bars, syntax highlighting

---

## Priority Matrix

| # | Item | Impact | Effort | Priority |
|---|------|--------|--------|----------|
| 1a | YARA-X (Rust rewrite) | High | Low (swap import) | **P0** ✅ v29.46 |
| 1c | ETW kernel telemetry | High | Medium | **P0** |
| 2b | Aho-Corasick IOC matching | High | Low | **P0** ✅ v29.45 (ioc_scanner.py) |
| 1d | EMBER ML static analysis | High | Medium | **P1** |
| 1b | Hyperscan regex engine | High | Medium | **P1** |
| 4a | Process mitigation policies | High | Low | **P1** ✅ v29.44b (process_mitigation.py) |
| 5a | DNS query monitoring | High | Medium | **P1** |
| 2a | functools.lru_cache | Medium | Low | **P2** |
| 1e | Sigma rules | Medium | Medium | **P2** ✅ v29.46 (sigma_engine.py) |
| 2c | RE2 (no ReDoS) | Medium | Low | **P2** |
| 3a | STIX/TAXII | Medium | Medium | **P2** ✅ v29.46 (stix_taxii_feed.py) |
| 4b | Job Objects | Medium | Low | **P2** |
| 5c | LOLBins detection | Medium | Low | **P2** |
| 3c | Government feeds | Medium | Low | **P2** |
| 5b | AMSI integration | High | High | **P3** |
| 3b | MISP integration | Medium | Medium | **P3** |
| 6a | structlog | Low | Low | **P3** |
| 6b | pydantic | Low | Low | **P3** |
| 6c | tenacity | Low | Low | **P3** |
| 6d | rich | Low | Low | **P3** |

## Quick Wins (P0, implementable in one session)

1. **YARA-X swap**: `pip install yara-x-python` → change import → re-compile rules
2. **Aho-Corasick**: `pip install ahocorasick-rs` → build automaton from
   mega_threat_signatures family names → replace sequential search
3. **Process mitigation**: ~30 lines of ctypes to enable dynamic code
   prohibition + extension point disable on the Downpour process
4. **functools.lru_cache**: Add decorators to hot-path functions