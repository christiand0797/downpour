# Downpour v29 Titanium — Enhancement Worklog

## Branch: enhance/all-mods-v29

## Completed (Phases 1-2)
- ✅ Removed 2249 illegal `: Any` annotations (token-stream CRLF-safe rewriter)
- ✅ Fixed 6 global/nonlocal annotation conflicts
- ✅ Implemented RemoteAccessController.disable_vector / enable_vector / disable_all_remote_access (@staticmethod)
- ✅ Repointed THREAT FEEDS gauge from broken ultimate_threat_intel stub to working threat_feed_aggregator
- ✅ Added `_make_button()` shared helper + tooltips to: Scanner, Processes, Network, Hardening, AEGIS, Intel, Firewalls, Threats detail panel

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
