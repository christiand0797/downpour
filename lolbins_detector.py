"""
LOLBINS DETECTOR — v29.44 (improvement catalog §5c)
================================================================================
Living-off-the-Land Binaries detection: monitors abuse of signed Windows
binaries. Maps detections to MITRE ATT&CK.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List

_log = logging.getLogger(__name__)


@dataclass
class LOLBinFinding:
    binary: str
    technique_id: str
    technique_name: str
    severity: str
    description: str
    parent_process: str
    command_line: str


LOLBIN_RULES: Dict[str, List[Dict]] = {
    'mshta.exe': [
        {'pattern': r'javascript', 'tid': 'T1218.005',
         'name': 'Mshta JavaScript Execution', 'severity': 'high'},
        {'pattern': r'vbscript', 'tid': 'T1218.005',
         'name': 'Mshta VBScript Execution', 'severity': 'high'},
        {'pattern': r'http[s]?://', 'tid': 'T1105',
         'name': 'Mshta Remote Payload Download', 'severity': 'critical'},
    ],
    'regsvr32.exe': [
        {'pattern': r'/i:http|scrobj', 'tid': 'T1218.010',
         'name': 'Regsvr32 Squiblydoo', 'severity': 'critical'},
    ],
    'certutil.exe': [
        {'pattern': r'-urlcache|/urlcache|-split', 'tid': 'T1105',
         'name': 'Certutil Download', 'severity': 'high'},
        {'pattern': r'-decode|/decode', 'tid': 'T1132.001',
         'name': 'Certutil Decode', 'severity': 'medium'},
    ],
    'bitsadmin.exe': [
        {'pattern': r'/transfer|/create|/download', 'tid': 'T1197',
         'name': 'Bitsadmin Transfer', 'severity': 'high'},
    ],
    'wmic.exe': [
        {'pattern': r'process\s+call\s+create', 'tid': 'T1047',
         'name': 'WMIC Process Creation', 'severity': 'high'},
        {'pattern': r'shadowcopy\s+delete', 'tid': 'T1490',
         'name': 'WMIC Shadow Copy Delete', 'severity': 'critical'},
    ],
    'rundll32.exe': [
        {'pattern': r'javascript', 'tid': 'T1218.011',
         'name': 'Rundll32 JS Execution', 'severity': 'high'},
    ],
    'msbuild.exe': [
        {'pattern': r'\.csproj', 'tid': 'T1127',
         'name': 'MSBuild Abuse', 'severity': 'high'},
    ],
    'powershell.exe': [
        {'pattern': r'-enc\b|-encodedcommand', 'tid': 'T1027',
         'name': 'PS Encoded Command', 'severity': 'high'},
        {'pattern': r'downloadstring|downloadfile|iex\s',
         'tid': 'T1059.001', 'name': 'PS Download Cradle',
         'severity': 'critical'},
    ],
}

SUSPICIOUS_PARENTS = {
    'winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe',
    'mshta.exe', 'wscript.exe', 'cscript.exe', 'cmd.exe',
    'powershell.exe',
}

LEGITIMATE_PARENTS: Dict[str, set] = {
    'mshta.exe': {'cmd.exe', 'explorer.exe'},
    'regsvr32.exe': {'cmd.exe', 'msiexec.exe'},
    'certutil.exe': {'cmd.exe', 'mmc.exe', 'powershell.exe'},
    'bitsadmin.exe': {'cmd.exe', 'powershell.exe', 'svchost.exe'},
    'wmic.exe': {'cmd.exe', 'powershell.exe', 'mmc.exe'},
    'powershell.exe': {'cmd.exe', 'explorer.exe', 'svchost.exe'},
    'rundll32.exe': {'svchost.exe', 'explorer.exe'},
    'msbuild.exe': {'cmd.exe', 'devenv.exe'},
}


def detect_lolbins(binary_name: str, command_line: str,
                   parent_process: str = '') -> List[LOLBinFinding]:
    """Detect LOLBins abuse for a single process."""
    binary = binary_name.lower().strip()
    rules = LOLBIN_RULES.get(binary)
    if not rules:
        return []
    cmdline_lower = command_line.lower()
    findings: List[LOLBinFinding] = []
    for rule in rules:
        if re.search(rule['pattern'], cmdline_lower, re.IGNORECASE):
            severity = rule['severity']
            parent = parent_process.lower().strip()
            if parent in SUSPICIOUS_PARENTS:
                legit = LEGITIMATE_PARENTS.get(binary, set())
                if parent not in legit:
                    severity = 'critical'
            findings.append(LOLBinFinding(
                binary=binary, technique_id=rule['tid'],
                technique_name=rule['name'], severity=severity,
                description=f'{binary}: {rule["name"]}',
                parent_process=parent_process,
                command_line=command_line[:200]))
    return findings


def detect_lolbins_batch(processes: List[Dict]) -> List[LOLBinFinding]:
    """Detect LOLBins across a batch of process snapshots."""
    all_findings: List[LOLBinFinding] = []
    pid_map: Dict[int, str] = {}
    for proc in processes:
        pid_map[proc.get('pid', 0)] = proc.get('name', '')
    for proc in processes:
        name = (proc.get('name') or '').lower()
        if not name:
            continue
        cmdline = ' '.join(proc.get('cmdline') or [])
        parent_pid = proc.get('ppid', 0)
        parent_name = pid_map.get(parent_pid, '')
        all_findings.extend(detect_lolbins(name, cmdline, parent_name))
    return all_findings


__all__ = ['LOLBinFinding', 'LOLBIN_RULES', 'detect_lolbins',
           'detect_lolbins_batch', 'SUSPICIOUS_PARENTS']