"""
threat_hunt_engine.py — Downpour v29 Titanium
================================================
Applies techniques from the Anthropic Cybersecurity Skills library:
  - hunting-for-living-off-the-land-binaries   (LOLBAS abuse detection)
  - building-detection-rules-with-sigma        (portable Sigma rule export)
  - hunting-for-registry-run-key-persistence   (persistence hunting)
  - hunting-for-scheduled-task-persistence
  - hunting-for-persistence-via-wmi-subscriptions
  - hunting-for-startup-folder-persistence
  - deploying-ransomware-canary-files          (honeytoken/canary detection)

Every function here maps directly to a MITRE ATT&CK technique ID so
findings integrate cleanly with Downpour's existing MITRE tagging engine.
"""
from __future__ import annotations
import os
import re
import json
import time
import uuid
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

log = logging.getLogger("Downpour.ThreatHunt")


# ============================================================================
# 1. LOLBAS — Living-off-the-Land Binaries (skill: hunting-for-living-off-...)
#    T1218 System Binary Proxy Execution family
# ============================================================================

LOLBAS_BINARIES: dict[str, dict[str, Any]] = {
    "certutil.exe":  {"mitre": "T1140/T1105", "risk": "download/decode payloads",
                       "flags": [r"-urlcache", r"-decode", r"-encode", r"-verifyctl"]},
    "mshta.exe":      {"mitre": "T1218.005", "risk": "HTA script execution",
                       "flags": [r"http", r"vbscript:", r"javascript:"]},
    "rundll32.exe":   {"mitre": "T1218.011", "risk": "arbitrary DLL export execution",
                       "flags": [r"javascript:", r"url\.dll", r"advpack\.dll"]},
    "regsvr32.exe":   {"mitre": "T1218.010", "risk": "Squiblydoo scriptlet execution",
                       "flags": [r"/i:http", r"scrobj\.dll"]},
    "msiexec.exe":    {"mitre": "T1218.007", "risk": "remote MSI install",
                       "flags": [r"/i\s+http", r"/q.*http"]},
    "wmic.exe":       {"mitre": "T1047", "risk": "remote process create / persistence",
                       "flags": [r"process\s+call\s+create", r"/format:"]},
    "cmstp.exe":      {"mitre": "T1218.003", "risk": "INF-based UAC bypass + payload",
                       "flags": [r"/s\s", r"\.inf"]},
    "bitsadmin.exe":  {"mitre": "T1197", "risk": "BITS job payload staging",
                       "flags": [r"/transfer", r"/addfile"]},
    "installutil.exe":{"mitre": "T1218.004", "risk": ".NET proxy execution",
                       "flags": [r"/logfile=", r"/u\s"]},
    "odbcconf.exe":   {"mitre": "T1218.008", "risk": "DLL registration proxy",
                       "flags": [r"regsvr"]},
    "forfiles.exe":   {"mitre": "T1202", "risk": "indirect command execution",
                       "flags": [r"/c\s"]},
    "pcalua.exe":     {"mitre": "T1202", "risk": "program compatibility proxy exec",
                       "flags": [r"-a\s"]},
    "msbuild.exe":    {"mitre": "T1127.001", "risk": "inline C# task execution",
                       "flags": [r"\.csproj", r"\.xml"]},
    "mavinject.exe":  {"mitre": "T1055.001", "risk": "DLL injection into running process",
                       "flags": [r"/injectrunning"]},
    "wscript.exe":    {"mitre": "T1059.005", "risk": "VBScript execution",
                       "flags": [r"\.vbs", r"\.js"]},
    "cscript.exe":    {"mitre": "T1059.005", "risk": "VBScript execution (console)",
                       "flags": [r"\.vbs", r"\.js"]},
}


@dataclass
class HuntFinding:
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    technique: str = ""
    mitre: str = ""
    severity: str = "medium"
    title: str = ""
    detail: str = ""
    evidence: dict = field(default_factory=dict)


def hunt_lolbas_abuse(process_name: str, cmdline: str, parent_name: str = "") -> HuntFinding | None:
    """
    Flag a process launch as LOLBin abuse if the binary is on the LOLBAS
    watch-list AND its command line matches a known-malicious flag pattern.
    Legitimate System32-path invocations with no suspicious flags are ignored
    to keep false-positive rate low (per skill guidance: baseline normal use).
    """
    pname = process_name.lower().strip()
    entry = LOLBAS_BINARIES.get(pname)
    if not entry:
        return None
    cl = cmdline.lower()
    for pattern in entry["flags"]:
        if re.search(pattern, cl, re.IGNORECASE):
            return HuntFinding(
                technique="LOLBAS Abuse",
                mitre=entry["mitre"],
                severity="high",
                title=f"Suspicious {process_name} usage ({entry['risk']})",
                detail=f"cmdline matched pattern '{pattern}'",
                evidence={"process": process_name, "cmdline": cmdline[:300],
                          "parent": parent_name})
    return None


# ============================================================================
# 2. Persistence hunting (skills: hunting-for-registry-run-key-persistence,
#    hunting-for-scheduled-task-persistence, hunting-for-persistence-via-wmi-
#    subscriptions, hunting-for-startup-folder-persistence)
# ============================================================================

RUN_KEY_PATHS = [
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
]
STARTUP_FOLDERS = [
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",
    r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp",
]
# Legit vendor paths that commonly appear in Run keys — used to reduce noise
_TRUSTED_PREFIXES = (
    "c:\\program files\\", "c:\\program files (x86)\\", "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
)


def hunt_registry_run_keys(entries: list[dict]) -> list[HuntFinding]:
    """
    entries: [{'key': 'HKCU\\...\\Run', 'name': 'Updater', 'value': 'C:\\...\\x.exe'}, ...]
    Flags entries pointing outside Program Files / Windows, or into Temp/AppData
    roots — the classic persistence-drop location per the skill's IOC list.
    """
    findings: list[HuntFinding] = []
    suspicious_roots = ("\\temp\\", "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
                        "\\appdata\\local\\", "\\downloads\\",
                        "\\public\\", "\\programdata\\", "\\users\\public\\")
    for e in entries:
        raw_val = str(e.get("value", "")).lower().strip()
        # FIX: registry Run values are almost always quoted, e.g.
        # '"C:\...\uTorrent.exe" /MINIMIZED' — the leading quote silently
        # defeated every startswith() check below, causing 100% false
        # negatives on real-world autorun entries (verified: uTorrent,
        # a legit-but-example case, was completely missed before this fix).
        val = raw_val.lstrip('"').strip()
        if any(val.startswith(p) for p in _TRUSTED_PREFIXES):
            continue
        if any(root in val for root in suspicious_roots) or val.startswith("c:\\users\\"):
            findings.append(HuntFinding(
                technique="Registry Run Key Persistence",
                mitre="T1547.001",
                severity="high",
                title=f"Suspicious autorun entry: {e.get('name', '?')}",
                detail=f"Points to non-standard location: {e.get('value', '')}",
                evidence=e))
    return findings


def hunt_scheduled_tasks(tasks: list[dict]) -> list[HuntFinding]:
    """
    tasks: [{'name': ..., 'action': ..., 'author': ..., 'hidden': bool}, ...]
    Flags tasks with hidden flag set, PowerShell/encoded actions, or actions
    pointing at user-writable directories — mirrors the skill's triage logic.
    """
    findings: list[HuntFinding] = []
    for t in tasks:
        action = str(t.get("action", "")).lower()
        suspicious = (
            t.get("hidden") is True
            or "-enc " in action or "-encodedcommand" in action
            or "\\appdata\\" in action or "\\temp\\" in action
            or re.search(r"powershell.*-w\s+hidden", action)
        )
        if suspicious:
            findings.append(HuntFinding(
                technique="Scheduled Task Persistence",
                mitre="T1053.005",
                severity="high",
                title=f"Suspicious scheduled task: {t.get('name', '?')}",
                detail=action[:200],
                evidence=t))
    return findings


def hunt_wmi_subscriptions(subs: list[dict]) -> list[HuntFinding]:
    """
    subs: [{'filter': ..., 'consumer': ..., 'binding': ...}]
    Any __EventFilter/__EventConsumer/__FilterToConsumerBinding triad found
    outside known-good AV/monitoring tooling is a T1546.003 persistence flag.
    """
    findings: list[HuntFinding] = []
    for s in subs:
        consumer = str(s.get("consumer", "")).lower()
        if any(k in consumer for k in ("powershell", "cmd.exe", "wscript", "scrcons")):
            findings.append(HuntFinding(
                technique="WMI Event Subscription Persistence",
                mitre="T1546.003",
                severity="critical",
                title="WMI persistence subscription detected",
                detail=f"Consumer: {s.get('consumer','?')}  Filter: {s.get('filter','?')}",
                evidence=s))
    return findings


def hunt_startup_folder(files: list[dict]) -> list[HuntFinding]:
    """
    files: [{'path': ..., 'signed': bool, 'age_days': int}]
    Flags unsigned, recently-dropped executables/scripts in Startup folders.
    """
    findings: list[HuntFinding] = []
    for f in files:
        path = str(f.get("path", "")).lower()
        if not path.endswith((".exe", ".bat", ".vbs", ".js", ".ps1", ".lnk")):
            continue
        if not f.get("signed", False) and f.get("age_days", 999) < 14:
            findings.append(HuntFinding(
                technique="Startup Folder Persistence",
                mitre="T1547.001",
                severity="medium",
                title=f"Unsigned recent startup item: {f.get('path','?')}",
                detail=f"Age: {f.get('age_days','?')} days, unsigned",
                evidence=f))
    return findings


# ============================================================================
# 3. Sigma rule export (skill: building-detection-rules-with-sigma)
#    Converts a Downpour HuntFinding/alert into a portable, shareable Sigma
#    YAML rule so findings can be fed into an external SIEM (Splunk/Elastic/
#    Sentinel) via sigmac/pySigma backends.
# ============================================================================

def finding_to_sigma_yaml(finding: HuntFinding) -> str:
    """Render a HuntFinding as a standalone Sigma detection rule (YAML text,
    no external YAML lib dependency — hand-built to avoid adding a new
    requirement for a single-purpose export)."""
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, finding.finding_id + finding.title))
    mitre_tag = finding.mitre.split("/")[0].lower().replace("t", "t") if finding.mitre else ""
    evidence_lines = "\n".join(
        f"        {k}: '{str(v)[:120]}'" for k, v in finding.evidence.items()
    ) or "        placeholder: 'n/a'"

    return f"""title: {finding.title}
id: {rule_id}
status: experimental
description: >
  Auto-generated by Downpour v29 Titanium ThreatHuntEngine.
  {finding.detail}
references:
    - https://attack.mitre.org/techniques/{mitre_tag.upper().replace('.', '/')}
author: Downpour v29 Titanium (auto-generated)
date: {finding.timestamp[:10]}
tags:
    - attack.{finding.technique.lower().replace(' ', '_')}
    - {('attack.' + mitre_tag) if mitre_tag else 'attack.unknown'}
level: {finding.severity}
logsource:
    category: process_creation
    product: windows
detection:
    selection:
{evidence_lines}
    condition: selection
falsepositives:
    - Legitimate administrative tooling matching the same pattern
    - Review before enabling in blocking mode
"""


def export_findings_to_sigma_pack(findings: list[HuntFinding], out_dir: str) -> list[str]:
    """Write one .yml Sigma rule file per finding. Returns list of written paths."""
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for f in findings:
        fname = re.sub(r"[^a-zA-Z0-9_-]", "_", f.title)[:60] + f"_{f.finding_id}.yml"
        fpath = os.path.join(out_dir, fname)
        try:
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write(finding_to_sigma_yaml(f))
            written.append(fpath)
        except Exception as e:
            log.warning("Sigma export failed for %s: %s", f.finding_id, e)
    return written


# ============================================================================
# 4. Ransomware canary / honeytoken files
#    (skills: deploying-ransomware-canary-files,
#             implementing-honeytokens-for-breach-detection)
#    T1486 Data Encrypted for Impact — earliest possible tripwire.
# ============================================================================

CANARY_FILENAMES = [
    "IMPORTANT - Do Not Delete - Financial Records 2024.docx",
    "Passwords_Backup.xlsx",
    "Tax_Documents_2024.pdf",
    "Family Photos - DO NOT MOVE.zip",
    "_CANARY_DO_NOT_TOUCH_.txt",
]


def deploy_canary_files(target_dirs: list[str]) -> list[dict]:
    """
    Drop small, uniquely-hashed decoy files into user-facing directories
    (Desktop, Documents, Downloads). Any modification, deletion, rename, or
    content-hash change is a near-certain ransomware/insider-threat signal —
    canaries are the fastest, lowest-noise T1486 tripwire available and
    require no ML model or entropy baseline to work.
    """
    deployed = []
    for d in target_dirs:
        if not os.path.isdir(d):
            continue
        for fname in CANARY_FILENAMES:
            fpath = os.path.join(d, fname)
            if os.path.exists(fpath):
                continue
            try:
                token = uuid.uuid4().hex
                content = f"DOWNPOUR_CANARY_TOKEN::{token}\nGenerated: {datetime.now().isoformat()}\n"
                content_bytes = content.encode("utf-8")
                # FIX: write in binary mode — text mode on Windows silently
                # translates \n -> \r\n, which made every canary's on-disk
                # hash differ from the hash computed at deploy time, causing
                # 100% false-positive "tampered" alerts on every check.
                with open(fpath, "wb") as fh:
                    fh.write(content_bytes)
                # Mark hidden+system on Windows so it doesn't clutter the user's view
                try:
                    import ctypes
                    FILE_ATTRIBUTE_HIDDEN = 0x02
                    FILE_ATTRIBUTE_SYSTEM = 0x04
                    ctypes.windll.kernel32.SetFileAttributesW(
                        fpath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
                except Exception:
                    pass
                deployed.append({
                    "path": fpath,
                    "token": token,
                    "sha256": hashlib.sha256(content_bytes).hexdigest(),
                    "deployed_at": datetime.now().isoformat(),
                })
            except Exception as e:
                log.debug("Canary deploy failed for %s: %s", fpath, e)
    return deployed


def check_canary_files(deployed: list[dict]) -> list[HuntFinding]:
    """Verify each deployed canary is unmodified and still present."""
    findings: list[HuntFinding] = []
    for c in deployed:
        path = c["path"]
        if not os.path.exists(path):
            findings.append(HuntFinding(
                technique="Ransomware Canary Triggered",
                mitre="T1486",
                severity="critical",
                title="CANARY FILE DELETED — possible ransomware/wiper activity",
                detail=f"Canary at {path} is missing",
                evidence=c))
            continue
        try:
            with open(path, "rb") as fh:
                current_hash = hashlib.sha256(fh.read()).hexdigest()
            if current_hash != c["sha256"]:
                findings.append(HuntFinding(
                    technique="Ransomware Canary Triggered",
                    mitre="T1486",
                    severity="critical",
                    title="CANARY FILE MODIFIED — possible ransomware encryption",
                    detail=f"Hash changed at {path}",
                    evidence=c))
        except Exception as e:
            log.debug("Canary check failed for %s: %s", path, e)
    return findings


def default_canary_targets() -> list[str]:
    """Standard user-facing directories to seed with canaries."""
    home = os.path.expanduser("~")
    return [
        os.path.join(home, "Desktop"),
        os.path.join(home, "Documents"),
        os.path.join(home, "Downloads"),
        os.path.join(home, "Pictures"),
    ]


# ============================================================================
# 5. BYOVD — Bring Your Own Vulnerable Driver (researched July 2026)
#    T1068 Exploitation for Privilege Escalation + T1562.001 Impair Defenses
#    Directly relevant: the "Deadlock" ransomware group (active since Jul 2025,
#    resurged June 2026 with 75 victims/month) uses BYOVD to kill EDR/AV kernel-
#    side BEFORE encryption starts — this is the exact technique that disables
#    tools like Downpour itself if unmonitored. LOLDrivers-documented signed-
#    but-vulnerable drivers below are the most widely abused in the wild.
# ============================================================================

KNOWN_VULNERABLE_DRIVERS: dict[str, dict[str, Any]] = {
    "rtcore64.sys":     {"cve": "CVE-2019-16098", "vendor": "MSI Afterburner",
                          "risk": "arbitrary kernel r/w — used to disable EDR"},
    "gdrv.sys":         {"cve": "unpatched",        "vendor": "GIGABYTE",
                          "risk": "arbitrary kernel r/w"},
    "dbutil_2_3.sys":   {"cve": "CVE-2021-21551",   "vendor": "Dell",
                          "risk": "kernel privilege escalation — widely abused by ransomware crews"},
    "zamguard64.sys":   {"cve": "CVE-2021-31728",   "vendor": "Zemana AntiMalware SDK",
                          "risk": "process/thread termination from kernel — classic AV-killer"},
    "zam64.sys":        {"cve": "CVE-2021-31728",   "vendor": "Zemana AntiMalware SDK",
                          "risk": "process/thread termination from kernel"},
    "winring0x64.sys":  {"cve": "multiple/unsigned-abuse", "vendor": "OpenLibSys",
                          "risk": "arbitrary MSR/kernel memory access — cryptominer & ransomware favorite"},
    "asio2.sys":        {"cve": "CVE-2021-42556-class", "vendor": "ASUS AI Suite",
                          "risk": "arbitrary kernel memory r/w"},
    "asio3.sys":        {"cve": "CVE-2021-42556-class", "vendor": "ASUS AI Suite",
                          "risk": "arbitrary kernel memory r/w"},
    "procexp152.sys":   {"cve": "abuse-of-legit-driver", "vendor": "Sysinternals Process Explorer",
                          "risk": "kernel handle to terminate protected AV/EDR processes"},
    "procexp154.sys":   {"cve": "abuse-of-legit-driver", "vendor": "Sysinternals Process Explorer",
                          "risk": "kernel handle to terminate protected AV/EDR processes"},
    "truesight.sys":    {"cve": "CVE-2024-8899-class", "vendor": "Adlice RogueKiller (TrueSight)",
                          "risk": "actively abused by BlackByte/other EDR-killer toolkits since 2023"},
    "aswarpot.sys":     {"cve": "driver-abuse",      "vendor": "Avast Anti-Rootkit",
                          "risk": "abused to terminate competing security products"},
    "iqvw64.sys":       {"cve": "CVE-2015-2291",     "vendor": "Intel Ethernet diagnostics",
                          "risk": "classic long-lived vulnerable driver, still abused"},
}


def hunt_byovd_abuse(loaded_drivers: list[dict]) -> list[HuntFinding]:
    """
    loaded_drivers: [{'name': 'rtcore64.sys', 'path': ..., 'signed': bool}, ...]
    Flags any driver matching the known-vulnerable list regardless of valid
    signature — these are LEGITIMATELY SIGNED drivers being abused for their
    documented kernel-level flaws, so signature checks alone won't catch them.
    This is precisely how modern EDR-killer toolkits (used by Deadlock, BlackByte,
    and other 2025-2026 ransomware crews) blind security tools before encrypting.
    """
    findings: list[HuntFinding] = []
    for d in loaded_drivers:
        dname = str(d.get("name", "")).lower().strip()
        entry = KNOWN_VULNERABLE_DRIVERS.get(dname)
        if not entry:
            continue
        findings.append(HuntFinding(
            technique="BYOVD — Vulnerable Driver Loaded",
            mitre="T1068/T1562.001",
            severity="critical",
            title=f"Known-vulnerable driver loaded: {d.get('name')}",
            detail=f"{entry['vendor']} driver ({entry['cve']}) — {entry['risk']}",
            evidence=d))
    return findings


def enumerate_loaded_drivers() -> list[dict]:
    """
    Live enumeration of currently loaded kernel drivers via psutil/WMI,
    matched against KNOWN_VULNERABLE_DRIVERS by filename.
    Falls back gracefully if WMI is unavailable.
    """
    drivers: list[dict] = []
    try:
        import wmi  # type: ignore[import-untyped]
        c = wmi.WMI()
        for drv in c.Win32_SystemDriver():
            path = str(getattr(drv, "PathName", "") or "")
            name = os.path.basename(path).lower() if path else str(getattr(drv, "Name", "")).lower()
            drivers.append({"name": name, "path": path, "signed": True})  # signed status
            # not independently verified here — see hunt_byovd_abuse note
    except Exception as e:
        log.debug("Driver enumeration failed (WMI unavailable): %s", e)
    return drivers
