"""
SIGMA RULE ENGINE — v29.46 (improvement catalog item 1e)
================================================================================
Ingests Sigma detection rules — the 3000+ rule community standard maintained
at SigmaHQ/sigma (Detection Rule License 1.1) — and evaluates them against
local Windows process-creation and PowerShell script-block telemetry.

  * BUNDLED_RULES  — curated starter pack of Sigma-compatible rules. Sigma
    YAML is a JSON superset, so bundled rules ship as JSON dicts with the
    exact same schema (title/id/logsource/detection/level/tags).
  * match_process()      — evaluate process_creation rules against an image +
                           command line (+ optional parent image / user).
  * match_script_block() — evaluate PowerShell script-block rules against
                           script text (Event ID 4104).
  * scan_process_snapshot() — psutil snapshot of live processes, evaluated
                           through match_process (catches long-running
                           threats whose creation event was missed).
  * load_user_rules()    — drop extra rules into sigma_rules/ as .json or
                           .yml; a stdlib-only YAML-subset parser handles the
                           common Sigma layout (no PyYAML dependency).

Field modifiers supported: (equals), contains, startswith, endswith, re.
Selection logic supports dict selections (AND across fields, OR within a
field's list), list-of-dicts (OR of dicts), keyword string lists, and the
condition subset: 'sel', 'a and b', 'a or b', 'not', parentheses,
'1 of sel*', 'all of sel*', 'N of them'.

MITRE ATT&CK tags (attack.tXXXX) are parsed into the technique field so
findings bridge into the existing Downpour alert pipeline unchanged.

Stdlib-only, offline-safe, never raises into the caller.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
USER_RULES_DIR = SCRIPT_DIR / 'sigma_rules'

_MAX_CMDLINE = 4096  # guard against absurd inputs


@dataclass
class SigmaFinding:
    """One Sigma rule hit (mirrors persistence_watchers.PersistenceAlert)."""
    rule_id: str
    title: str
    level: str          # LOW/MEDIUM/HIGH/CRITICAL
    technique: str      # first attack.tXXXX tag, or ''
    description: str
    detail: str         # human-readable matched-field summary
    source: str = 'process'   # 'process' | 'script_block'
    rule_name: str = ''


def _normalize_level(level: str) -> str:
    return {'critical': 'CRITICAL', 'high': 'HIGH', 'medium': 'MEDIUM',
            'low': 'LOW', 'informational': 'LOW'}.get(
                str(level or '').strip().lower(), 'MEDIUM')


def _technique_from_tags(tags: Any) -> str:
    """First attack.tXXXX tag → 'T1059.001' style string."""
    if not tags:
        return ''
    for tag in tags:
        m = re.match(r'attack\.t(\d{4}(?:\.\d{3})?)$',
                     str(tag).strip().lower())
        if m:
            return 'T' + m.group(1)
    return ''


# Bundled starter pack follows (curated from public SigmaHQ rule logic,
# Detection Rule License 1.1 — schema is standard Sigma, shipped as JSON).
BUNDLED_RULES: List[Dict[str, Any]] = [
    {
        'title': 'PowerShell Encoded Command',
        'id': 'b5a2b61c-2a1a-4b1e-9e2f-3c4d5e6f7a8b',
        'status': 'stable',
        'description': 'Detects PowerShell started with an encoded '
                       '(-enc / -EncodedCommand) command line — a classic '
                       'obfuscated execution primitive.',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith':
                              ['\\powershell.exe', '\\pwsh.exe']},
            'selection_enc': {'CommandLine|contains':
                              ['-enc ', ' -enc', '-encodedcommand',
                               '/encodedcommand']},
            'condition': 'selection_img and selection_enc',
        },
        'falsepositives': ['Signed admin automation scripts'],
        'level': 'high',
        'tags': ['attack.execution', 'attack.defense_evasion',
                 'attack.t1059.001', 'attack.t1027'],
    },
    {
        'title': 'PowerShell Download Cradle (WebClient/IEX)',
        'id': 'c7d3f9a1-8e42-4c6a-b5d1-9f2e3a4b5c6d',
        'status': 'stable',
        'description': 'Detects classic PowerShell download cradles '
                       '(DownloadString/DownloadFile/Net.WebClient feeding '
                       'Invoke-Expression).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith':
                              ['\\powershell.exe', '\\pwsh.exe']},
            'selection_cradle': {'CommandLine|contains': [
                'downloadstring', 'downloadfile', 'downloaddata',
                'net.webclient', 'invoke-expression', 'iex ',
                'frombase64string', 'invoke-restmethod -uri',
                'invoke-webrequest -uri']},
            'condition': 'selection_img and selection_cradle',
        },
        'falsepositives': ['Admin scripts pulling known modules'],
        'level': 'high',
        'tags': ['attack.command_and_control', 'attack.t1105',
                 'attack.execution', 'attack.t1059.001'],
    },
    {
        'title': 'Certutil Download of Remote File',
        'id': 'd8e4a0b2-9f53-4d7b-c6e2-0a3f4b5c6d7e',
        'status': 'stable',
        'description': 'Detects certutil.exe using -urlcache/-split to fetch '
                       'remote content (LOLBAS T1105).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\certutil.exe'},
            'selection_flag': {'CommandLine|contains':
                               ['-urlcache', 'urlcache']},
            'condition': 'selection_img and selection_flag',
        },
        'falsepositives': ['PKI admin tooling'],
        'level': 'high',
        'tags': ['attack.command_and_control', 'attack.t1105',
                 'attack.defense_evasion', 'attack.t1140'],
    },
    {
        'title': 'Certutil Decode to Drop Payload',
        'id': 'e9f5b1c3-0a64-4e8c-d7f3-1b4a5c6d7e8f',
        'status': 'stable',
        'description': 'Detects certutil -decode used to materialize a '
                       'base64 payload on disk.',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\certutil.exe'},
            'selection_flag': {'CommandLine|contains':
                               ['-decode', '/decode']},
            'condition': 'selection_img and selection_flag',
        },
        'falsepositives': ['Certificate administration'],
        'level': 'medium',
        'tags': ['attack.defense_evasion', 'attack.t1140'],
    },
    {
        'title': 'Bitsadmin Transfer Job',
        'id': 'a0b6c2d4-1b75-4f9d-e8a4-2c5b6d7e8f9a',
        'status': 'stable',
        'description': 'Detects bitsadmin.exe /transfer downloading remote '
                       'files (T1197).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\bitsadmin.exe'},
            'selection_flag': {'CommandLine|contains':
                               ['/transfer', '/create', '/addfile']},
            'condition': 'selection_img and selection_flag',
        },
        'falsepositives': ['Manual BITS admin use'],
        'level': 'medium',
        'tags': ['attack.command_and_control', 'attack.t1197'],
    },
    {
        'title': 'Mimikatz Command Line',
        'id': 'b1c7d3e5-2c86-4a0e-f9b5-3d6c7e8f9a0b',
        'status': 'stable',
        'description': 'Detects well-known Mimikatz strings on a command '
                       'line (sekurlsa::logonpasswords, dcsync, ...).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection': {'CommandLine|contains': [
                'sekurlsa::logonpasswords', 'sekurlsa::pth',
                'lsadump::sam', 'lsadump::dcsync', 'mimikatz',
                'invoke-mimikatz']},
            'condition': 'selection',
        },
        'falsepositives': ['Red-team tooling with matching names'],
        'level': 'critical',
        'tags': ['attack.credential_access', 'attack.t1003.001',
                 'attack.t1003.006'],
    },
    {
        'title': 'LSASS Memory Dump via comsvcs MiniDump',
        'id': 'c2d8e4f6-3d97-4b1f-0ac6-4e7d8f9a0b1c',
        'status': 'stable',
        'description': 'Detects rundll32.exe loading comsvcs.dll MiniDump to '
                       'dump LSASS (T1003.001).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\rundll32.exe'},
            'selection_dll': {'CommandLine|contains': ['comsvcs']},
            'selection_call': {'CommandLine|contains': ['minidump']},
            'condition': 'all of selection*',
        },
        'falsepositives': [],
        'level': 'critical',
        'tags': ['attack.credential_access', 'attack.t1003.001'],
    },
    {
        'title': 'LSASS Dump Tooling on Command Line',
        'id': 'd3e9f5a7-4e08-4c2a-1bd7-5f8e9a0b1c2d',
        'status': 'stable',
        'description': 'Detects common LSASS dump tooling (procdump -ma '
                       'lsass, sqldumper, out-minidump).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection': {'CommandLine|contains': [
                '-ma lsass', 'sqldumper', 'out-minidump',
                'comsvcs.dll,#24']},
            'condition': 'selection',
        },
        'falsepositives': ['Crash-dump collection by admins'],
        'level': 'high',
        'tags': ['attack.credential_access', 'attack.t1003.001'],
    },
    {
        'title': 'Shadow Copy Deletion via vssadmin',
        'id': 'e4f0a6b8-5f19-4d3b-2ce8-6a9f0b1c2d3e',
        'status': 'stable',
        'description': 'Detects vssadmin.exe deleting shadow copies — the '
                       'classic ransomware inhibit-recovery move (T1490).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\vssadmin.exe'},
            'selection_cmd': {'CommandLine|contains': ['delete shadows']},
            'condition': 'selection_img and selection_cmd',
        },
        'falsepositives': ['Storage admin maintenance'],
        'level': 'critical',
        'tags': ['attack.impact', 'attack.t1490'],
    },
    {
        'title': 'Shadow Copy Deletion via WMIC',
        'id': 'f5a1b7c9-602a-4e4c-3df9-7b0a1c2d3e4f',
        'status': 'stable',
        'description': 'Detects wmic shadowcopy delete (T1490).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection': {'CommandLine|contains': ['shadowcopy delete']},
            'condition': 'selection',
        },
        'falsepositives': [],
        'level': 'critical',
        'tags': ['attack.impact', 'attack.t1490'],
    },
    {
        'title': 'BCDedit Recovery/Boot Status Tampering',
        'id': 'a6b2c8da-713b-4f5d-4e0a-8c1b2d3e4f5a',
        'status': 'stable',
        'description': 'Detects bcdedit disabling recovery or ignoring boot '
                       'failures (ransomware T1490 companion).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\bcdedit.exe'},
            'selection_cmd': {'CommandLine|contains': [
                'recoveryenabled no', 'bootstatuspolicy ignoreallfailures']},
            'condition': 'selection_img and selection_cmd',
        },
        'falsepositives': [],
        'level': 'critical',
        'tags': ['attack.impact', 'attack.t1490'],
    },
    {
        'title': 'USN Journal Deletion (fsutil)',
        'id': 'b7c3d9eb-824c-4a6e-5f1b-9d2c3e4f5a6b',
        'status': 'stable',
        'description': 'Detects fsutil deleting the USN change journal to '
                       'hinder forensic recovery (T1070.002).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\fsutil.exe'},
            'selection_cmd': {'CommandLine|contains':
                              ['deletejournal', 'usn deletejournal']},
            'condition': 'selection_img and selection_cmd',
        },
        'falsepositives': [],
        'level': 'high',
        'tags': ['attack.defense_evasion', 'attack.t1070.002'],
    },
    {
        'title': 'Windows Event Log Clearing (wevtutil)',
        'id': 'c8d4eafc-935d-4b7f-6a2c-0e3d4f5a6b7c',
        'status': 'stable',
        'description': 'Detects wevtutil cl / clear-log wiping event '
                       'channels (T1070.001).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\wevtutil.exe'},
            'selection_cmd': {'CommandLine|contains':
                              ['cl ', 'clear-log']},
            'condition': 'selection_img and selection_cmd',
        },
        'falsepositives': ['Log maintenance scripts'],
        'level': 'high',
        'tags': ['attack.defense_evasion', 'attack.t1070.001'],
    },
    {
        'title': 'Registry Run Key Persistence via reg.exe',
        'id': 'd9e5fb0d-a46e-4c80-7b3d-1f4e5a6b7c8d',
        'status': 'stable',
        'description': 'Detects reg.exe adding a CurrentVersion\\Run '
                       'auto-start value (T1060 / T1547.001).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\reg.exe'},
            'selection_cmd': {'CommandLine|contains': [
                'currentversion\\run', 'currentversion\\runonce']},
            'condition': 'selection_img and selection_cmd',
        },
        'falsepositives': ['Software installers registering auto-start'],
        'level': 'medium',
        'tags': ['attack.persistence', 'attack.t1547.001'],
    },
    {
        'title': 'Suspicious Service Creation via sc.exe',
        'id': 'eaf6ac1e-b57f-4d91-8c4e-2a5f6b7c8d9e',
        'status': 'stable',
        'description': 'Detects sc.exe create with a binPath pointing into '
                       'user-writable space (T1543.003).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\sc.exe'},
            'selection_create': {'CommandLine|contains': ['create ']},
            'selection_path': {'CommandLine|contains': [
                '\\users\\', '\\appdata\\', '\\temp\\', '\\programdata\\',
                '%temp%']},
            'condition': 'selection_img and selection_create and '
                         'selection_path',
        },
        'falsepositives': ['Legit service installs into ProgramData'],
        'level': 'high',
        'tags': ['attack.persistence', 'attack.t1543.003'],
    },
    {
        'title': 'Scheduled Task Creation for Persistence',
        'id': 'fba7bd2f-c680-4ea2-9d5f-3b6a7c8d9e0f',
        'status': 'stable',
        'description': 'Detects schtasks /create invoking powershell/cmd/'
                       'mshta/rundll32 (T1053.005).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\schtasks.exe'},
            'selection_create': {'CommandLine|contains': ['/create']},
            'selection_susp': {'CommandLine|contains': [
                'powershell', 'cmd /c', 'cmd.exe /c', 'mshta', 'rundll32',
                'certutil', 'wscript', 'cscript']},
            'condition': 'selection_img and selection_create and '
                         'selection_susp',
        },
        'falsepositives': ['Admin task scheduling'],
        'level': 'medium',
        'tags': ['attack.persistence', 'attack.execution',
                 'attack.t1053.005'],
    },
    {
        'title': 'RDP Enablement via Registry (fDenyTSConnections)',
        'id': 'acb8ce30-d791-4fb3-0e6a-4c7b8d9e0f1a',
        'status': 'stable',
        'description': 'Detects reg add enabling RDP — common attacker '
                       'lateral-access preparation.',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\reg.exe'},
            'selection_key': {'CommandLine|contains':
                              ['fdenytsconnections']},
            'selection_val': {'CommandLine|contains': ['/d 0x0', '/d 0 ']},
            'condition': 'selection_img and selection_key and selection_val',
        },
        'falsepositives': ['Helpdesk enabling RDP intentionally'],
        'level': 'medium',
        'tags': ['attack.lateral_movement', 'attack.t1021.001'],
    },
    {
        'title': 'Netsh Portproxy Redirection',
        'id': 'bdc9df41-e8a2-40c4-1f7b-5d8c9e0f1a2b',
        'status': 'stable',
        'description': 'Detects netsh interface portproxy add — traffic '
                       'redirection/pivoting (T1090).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\netsh.exe'},
            'selection_pp': {'CommandLine|contains': ['portproxy']},
            'selection_add': {'CommandLine|contains': ['add']},
            'condition': 'selection_img and selection_pp and selection_add',
        },
        'falsepositives': ['Admin port forwarding setups'],
        'level': 'medium',
        'tags': ['attack.command_and_control', 'attack.t1090'],
    },
    {
        'title': 'Mshta Executing Remote Script',
        'id': 'cecaea52-f9b3-41d5-2a8c-6e9d0f1a2b3c',
        'status': 'stable',
        'description': 'Detects mshta.exe with an http/ftp target — '
                       'payload staging without disk writes (T1218.005).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\mshta.exe'},
            'selection_proto': {'CommandLine|contains':
                                ['http://', 'https://', 'ftp://']},
            'condition': 'selection_img and selection_proto',
        },
        'falsepositives': [],
        'level': 'high',
        'tags': ['attack.defense_evasion', 'attack.execution',
                 'attack.t1218.005'],
    },
    {
        'title': 'Regsvr32 Remote Scriptlet (Squiblydoo)',
        'id': 'dfdbfb63-0ac4-42e6-3b9d-7f0e1a2b3c4d',
        'status': 'stable',
        'description': 'Detects regsvr32 with /i: pointing at remote content '
                       '(T1218.010).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\regsvr32.exe'},
            'selection_proto': {'CommandLine|contains':
                                ['/i:http', 'scrobj']},
            'condition': 'selection_img and selection_proto',
        },
        'falsepositives': [],
        'level': 'high',
        'tags': ['attack.defense_evasion', 'attack.t1218.010'],
    },
    {
        'title': 'Rundll32 JavaScript URL Execution',
        'id': 'eaecac74-1bd5-43f7-4c0e-8a1f2b3c4d5e',
        'status': 'stable',
        'description': 'Detects rundll32.exe invoking javascript:/vbscript: '
                       'URLs (T1218.011).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith': '\\rundll32.exe'},
            'selection_js': {'CommandLine|contains':
                             ['javascript:', 'vbscript:']},
            'condition': 'selection_img and selection_js',
        },
        'falsepositives': [],
        'level': 'high',
        'tags': ['attack.defense_evasion', 'attack.t1218.011'],
    },
    {
        'title': 'Office App Spawning Suspicious Child',
        'id': 'fbedbd85-2ce6-4408-5d1f-9b2a3c4d5e6f',
        'status': 'stable',
        'description': 'Detects Word/Excel/PowerPoint spawning cmd/'
                       'powershell/mshta/script hosts — macro-delivery '
                       'indicator (T1566.001).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_parent': {'ParentImage|endswith':
                                 ['\\winword.exe', '\\excel.exe',
                                  '\\powerpnt.exe', '\\outlook.exe']},
            'selection_child': {'Image|endswith':
                                ['\\cmd.exe', '\\powershell.exe',
                                 '\\mshta.exe', '\\wscript.exe',
                                 '\\cscript.exe', '\\rundll32.exe']},
            'condition': 'selection_parent and selection_child',
        },
        'falsepositives': ['Rare legit Office automation'],
        'level': 'high',
        'tags': ['attack.initial_access', 'attack.execution',
                 'attack.t1566.001'],
    },
    {
        'title': 'Account Added to Administrators Group',
        'id': 'a0cfd296-3df7-4519-6e2a-0c3b4d5e6f7a',
        'status': 'stable',
        'description': 'Detects net localgroup administrators ... /add — '
                       'privilege escalation primitive (T1078.003).',
        'logsource': {'category': 'process_creation', 'product': 'windows'},
        'detection': {
            'selection_img': {'Image|endswith':
                              ['\\net.exe', '\\net1.exe']},
            'selection_grp': {'CommandLine|contains':
                              ['localgroup administrators',
                               'localgroup  administrators']},
            'selection_add': {'CommandLine|contains': ['/add']},
            'condition': 'selection_img and selection_grp and selection_add',
        },
        'falsepositives': ['IT onboarding automation'],
        'level': 'high',
        'tags': ['attack.privilege_escalation', 'attack.persistence',
                 'attack.t1078.003'],
    },
    {
        'title': 'PowerShell Download Cradle (Script Block)',
        'id': 'b1d0e3a7-4ea8-462b-7f3c-1d4e5f6a7b8c',
        'status': 'stable',
        'description': 'Detects download cradles inside PowerShell script '
                       'blocks (Event 4104) — fileless staged execution.',
        'logsource': {'category': 'ps_script', 'product': 'windows'},
        'detection': {
            'selection_web': {'ScriptBlockText|contains': [
                'downloadstring', 'net.webclient', 'downloadfile',
                'invoke-expression', 'frombase64string',
                'invoke-restmethod', 'invoke-webrequest']},
            'selection_proto': {'ScriptBlockText|contains':
                                ['http://', 'https://']},
            'condition': 'selection_web and selection_proto',
        },
        'falsepositives': ['Admin scripts pulling known modules'],
        'level': 'high',
        'tags': ['attack.execution', 'attack.t1059.001',
                 'attack.command_and_control', 'attack.t1105'],
    },
]


# ══════════════════════════════════════════════════════════════════════════════
# Selection / modifier matching
# ══════════════════════════════════════════════════════════════════════════════
_MODIFIER_SPLIT = re.compile(r'\|')
_REGEX_CACHE: Dict[str, re.Pattern] = {}


def _split_field(raw_field: str) -> Tuple[str, str]:
    """'CommandLine|contains' → ('CommandLine', 'contains')."""
    parts = _MODIFIER_SPLIT.split(str(raw_field).strip(), maxsplit=1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip().lower()
    return parts[0].strip(), ''


def _compiled_regex(pattern: str) -> Optional[re.Pattern]:
    rx = _REGEX_CACHE.get(pattern)
    if rx is None:
        try:
            rx = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            _log.debug('sigma bad regex %r: %s', pattern, exc)
            return None
        _REGEX_CACHE[pattern] = rx
    return rx


def _match_value(actual: Any, expected: Any, modifier: str) -> bool:
    """One field-value comparison under a Sigma modifier. Never raises."""
    if expected is None:                      # field|null check
        return actual in (None, '')
    if actual is None:
        return False
    actual_s = str(actual)
    if isinstance(expected, (list, tuple, set)):
        return any(_match_value(actual, exp, modifier) for exp in expected)
    expected_s = str(expected)
    try:
        if modifier in ('contains',):
            return expected_s.lower() in actual_s.lower()
        if modifier in ('startswith', 'beginswith'):
            return actual_s.lower().startswith(expected_s.lower())
        if modifier in ('endswith',):
            return actual_s.lower().endswith(expected_s.lower())
        if modifier in ('re', 'regex'):
            rx = _compiled_regex(expected_s)
            return bool(rx and rx.search(actual_s))
        # plain equality — case-insensitive, int-friendly
        if isinstance(expected, (int, float)) and not isinstance(expected, bool):
            try:
                return float(actual_s.strip()) == float(expected)
            except ValueError:
                return False
        if isinstance(expected, bool):
            return actual_s.strip().lower() in (
                ('true', '1') if expected else ('false', '0', ''))
        return actual_s.strip().lower() == expected_s.strip().lower()
    except Exception as exc:                  # defensive — never raise
        _log.debug('sigma _match_value: %s', exc)
        return False


def _event_get(event: Dict[str, Any], field_name: str) -> Any:
    """Case-insensitive field lookup on a flat event dict."""
    for k, v in event.items():
        if str(k).lower() == str(field_name).lower():
            return v
    return None


def _match_field_map(event: Dict[str, Any], fmap: Dict[str, Any]) -> bool:
    """Dict selection: AND across fields, OR within each field's list."""
    if not fmap:
        return False
    for raw_field, expected in fmap.items():
        field_name, modifier = _split_field(raw_field)
        actual = _event_get(event, field_name)
        if field_name.lower() == 'keywords':
            # keyword selection matches against the whole event message
            actual = ' '.join(str(v) for v in event.values() if v)
            actual = actual[:_MAX_CMDLINE * 2]
        if not _match_value(actual, expected, modifier):
            return False
    return True


def _match_selection(event: Dict[str, Any], selection: Any) -> bool:
    """One Sigma selection node against an event."""
    if isinstance(selection, dict):
        return _match_field_map(event, selection)
    if isinstance(selection, (list, tuple)):
        # list of dicts → OR of dicts; list of scalars → OR (keyword list)
        if not selection:
            return False
        for item in selection:
            if isinstance(item, dict):
                if _match_field_map(event, item):
                    return True
            elif _match_value(
                    ' '.join(str(v) for v in event.values() if v)
                    [:_MAX_CMDLINE * 2], item, 'contains'):
                return True
        return False
    return False


def _match_event_or_them(event: Dict[str, Any], detection: Any) -> bool:
    """Fallback for detections without an explicit condition: ANY selection
    matching counts as a hit (Sigma 'of them' default behaviour)."""
    if not isinstance(detection, dict):
        return False
    for key, value in detection.items():
        if key == 'condition' or key == 'timeframe':
            continue
        if _match_selection(event, value):
            return True
    return False


# ══════════════════════════════════════════════════════════════════════════════
# Condition evaluator — 'sel', 'a and b', 'a or b', 'not x', parens,
# '1 of sel*', 'all of sel*', 'N of them'
# ══════════════════════════════════════════════════════════════════════════════
_OF_RE = re.compile(r'^(all|\d+)\s+of\s+(them|[\w*]+)$', re.IGNORECASE)


def _selection_names(detection: Dict[str, Any]) -> List[str]:
    return [k for k in detection
            if k not in ('condition', 'timeframe')]


def _eval_of_clause(clause: str, detection: Dict[str, Any],
                    event: Dict[str, Any]) -> Optional[bool]:
    """Return True/False for an 'N of X' clause, None if not an OF clause."""
    m = _OF_RE.match(clause.strip())
    if not m:
        return None
    quant, target = m.group(1).lower(), m.group(2).lower()
    names = _selection_names(detection)
    if target != 'them':
        base = target.rstrip('*')
        if target.endswith('*'):
            names = [n for n in names if n.lower().startswith(base)]
        else:
            names = [n for n in names if n.lower() == base]
    if not names:
        return False
    hits = sum(1 for n in names
               if _match_selection(event, detection.get(n)))
    if quant == 'all':
        return hits == len(names)
    try:
        need = int(quant)
    except ValueError:
        return False
    return hits >= need


def _tokenize_condition(cond: str) -> List[str]:
    tokens, buf, i = [], cond.strip(), 0
    while i < len(buf):
        ch = buf[i]
        if ch.isspace():
            i += 1
            continue
        if ch == '(':
            tokens.append('(')
            i += 1
            continue
        if ch == ')':
            tokens.append(')')
            i += 1
            continue
        if buf[i:i + 3].lower() == 'and' and (
                i + 3 >= len(buf) or not buf[i + 3].isalnum()):
            tokens.append('and')
            i += 3
            continue
        if buf[i:i + 2].lower() == 'or' and (
                i + 2 >= len(buf) or not buf[i + 2].isalnum()):
            tokens.append('or')
            i += 2
            continue
        if buf[i:i + 3].lower() == 'not' and (
                i + 3 >= len(buf) or not buf[i + 3].isalnum()):
            tokens.append('not')
            i += 3
            continue
        if ch == '1' and buf[i:i + 5].lower() == '1 of ':
            j = buf.find(' ', i + 5)
            j = len(buf) if j == -1 else j
            tokens.append(buf[i:j].lower())
            i = j
            continue
        if ch.isdigit() or (ch in 'abcdefghijklmnopqrstuvwxyz'
                            '_*') or ch.isalnum():
            j = i
            while j < len(buf) and (buf[j].isalnum() or buf[j] in '_*'):
                j += 1
            tokens.append(buf[i:j])
            i = j
            continue
        # unknown character — treat the rest as one identifier (defensive)
        tokens.append(buf[i:])
        i = len(buf)
    return tokens


class _CondParser:
    """Recursive-descent evaluator for the supported condition subset."""

    def __init__(self, tokens: List[str], detection: Dict[str, Any],
                 event: Dict[str, Any]):
        self.toks = tokens
        self.pos = 0
        self.detection = detection
        self.event = event

    def peek(self) -> Optional[str]:
        return self.toks[self.pos] if self.pos < len(self.toks) else None

    def next(self) -> Optional[str]:
        tok = self.peek()
        self.pos += 1
        return tok

    def parse(self) -> bool:
        val = self.expr()
        return bool(val)

    def expr(self) -> bool:                     # OR level
        val = self.term()
        while self.peek() == 'or':
            self.next()
            rhs = self.term()
            val = val or rhs
        return val

    def term(self) -> bool:                     # AND level
        val = self.factor()
        while self.peek() == 'and':
            self.next()
            rhs = self.factor()
            val = val and rhs
        return val

    def factor(self) -> bool:
        tok = self.peek()
        if tok is None:
            return False
        if tok == '(':
            self.next()
            val = self.expr()
            if self.peek() == ')':
                self.next()
            return val
        if tok == 'not':
            self.next()
            return not self.factor()
        if tok == 'and' or tok == 'or':         # malformed — skip
            self.next()
            return False
        self.next()
        nxt = self.peek()
        if nxt is not None and (nxt == 'of' or
                                (tok.isdigit() and
                                 str(nxt).lower() == 'of')):
            # '1 of sel*' / 'all of them' — 'of' wasn't tokenized as part
            self.next()                          # consume 'of'
            target = self.next() or 'them'
            clause = f'{tok} of {target}'
            of_val = _eval_of_clause(clause, self.detection, self.event)
            if of_val is None:
                return False
            return of_val
        # plain identifier
        ident = str(tok).lower()
        names = {n.lower(): n for n in self.detection}
        if ident in names:
            return _match_selection(
                self.event, self.detection[names[ident]])
        of_val = _eval_of_clause(ident, self.detection, self.event)
        if of_val is not None:
            return of_val
        return False


# ══════════════════════════════════════════════════════════════════════════════
# Rule store + public match API
# ══════════════════════════════════════════════════════════════════════════════
def _rule_applies_to_process(rule: Dict[str, Any]) -> bool:
    ls = rule.get('logsource') or {}
    cat = str(ls.get('category', '')).lower()
    prod = str(ls.get('product', '')).lower()
    svc = str(ls.get('service', '')).lower()
    return (cat == 'process_creation' or
            (not cat and prod == 'windows' and not svc))


def _rule_applies_to_script(rule: Dict[str, Any]) -> bool:
    ls = rule.get('logsource') or {}
    cat = str(ls.get('category', '')).lower()
    svc = str(ls.get('service', '')).lower()
    prod = str(ls.get('product', '')).lower()
    return (cat in ('ps_script', 'ps_classicstart', 'script_block') or
            svc == 'powershell' or
            (not cat and prod == 'windows' and svc == 'powershell'))


def _evaluate_rule(rule: Dict[str, Any],
                   event: Dict[str, Any]) -> Tuple[bool, str]:
    """(matched, matched_detail) for one rule against one event."""
    detection = rule.get('detection') or {}
    if not detection:
        return False, ''
    cond = detection.get('condition')
    matched = False
    if not cond:
        matched = _match_event_or_them(event, detection)
    else:
        try:
            parser = _CondParser(_tokenize_condition(str(cond)),
                                 detection, event)
            matched = parser.parse()
        except Exception as exc:            # malformed condition — fallback
            _log.debug('sigma condition %r: %s', cond, exc)
            matched = _match_event_or_them(event, detection)
    if not matched:
        return False, ''
    return True, _describe_match(rule, event)


def _describe_match(rule: Dict[str, Any], event: Dict[str, Any]) -> str:
    detection = rule.get('detection') or {}
    bits: List[str] = []
    for key, sel in detection.items():
        if key in ('condition', 'timeframe') or not isinstance(sel, dict):
            continue
        if _match_selection(event, sel):
            for raw_field in sel:
                fname, _mod = _split_field(raw_field)
                if fname.lower() == 'keywords':
                    continue
                val = _event_get(event, fname)
                if val:
                    bits.append(f'{fname}={str(val)[:80]}')
    if not bits:
        bits = [f'{k}={str(v)[:60]}' for k, v in
                list(event.items())[:2] if v]
    return ' · '.join(bits[:3])


def _rule_to_finding(rule: Dict[str, Any], detail: str,
                     source: str) -> SigmaFinding:
    return SigmaFinding(
        rule_id=str(rule.get('id', '')),
        title=str(rule.get('title', 'Sigma rule hit')),
        level=_normalize_level(str(rule.get('level', 'medium'))),
        technique=_technique_from_tags(rule.get('tags')),
        description=str(rule.get('description', ''))[:200],
        detail=detail[:200],
        source=source,
        rule_name=str(rule.get('title', '')))


def match_process(image: str, cmdline: str,
                  parent_image: str = '', user: str = '') -> List[SigmaFinding]:
    """Evaluate all process_creation Sigma rules against one process event."""
    if not image and not cmdline:
        return []
    event = {
        'Image': str(image or '')[:_MAX_CMDLINE],
        'CommandLine': str(cmdline or '')[:_MAX_CMDLINE],
        'ParentImage': str(parent_image or '')[:_MAX_CMDLINE],
        'User': str(user or '')[:128],
        'message': f'{image or ""} {cmdline or ""}'[:_MAX_CMDLINE * 2],
    }
    findings: List[SigmaFinding] = []
    for rule in get_rules():
        if not _rule_applies_to_process(rule):
            continue
        try:
            matched, detail = _evaluate_rule(rule, event)
        except Exception as exc:            # defensive — never raise
            _log.debug('sigma match_process: %s', exc)
            continue
        if matched:
            findings.append(_rule_to_finding(rule, detail, 'process'))
    return findings


def match_script_block(script_text: str) -> List[SigmaFinding]:
    """Evaluate PowerShell script-block (4104-style) rules against text."""
    text = str(script_text or '')[:_MAX_CMDLINE * 4]
    if not text.strip():
        return []
    event = {'ScriptBlockText': text, 'message': text}
    findings: List[SigmaFinding] = []
    for rule in get_rules():
        if not _rule_applies_to_script(rule):
            continue
        try:
            matched, detail = _evaluate_rule(rule, event)
        except Exception as exc:
            _log.debug('sigma match_script_block: %s', exc)
            continue
        if matched:
            findings.append(_rule_to_finding(rule, detail, 'script_block'))
    return findings


def scan_process_snapshot(max_processes: int = 600) -> List[SigmaFinding]:
    """Snapshot live processes via psutil and evaluate them all — catches
    long-running suspicious processes whose creation event predates
    Downpour's start."""
    try:
        import psutil
    except ImportError:
        return []
    findings: List[SigmaFinding] = []
    seen: set = set()
    try:
        for proc in psutil.process_iter(['pid', 'exe', 'name', 'cmdline',
                                         'username']):
            try:
                info = proc.info
                cmdline = ' '.join(info.get('cmdline') or [])
                if not cmdline:
                    continue
                image = info.get('exe') or info.get('name') or ''
                for f in match_process(image, cmdline,
                                       user=info.get('username') or ''):
                    key = (f.rule_id, info.get('pid'))
                    if key in seen:
                        continue
                    seen.add(key)
                    f.detail = (f'pid={info.get("pid")} '
                                f'{f.detail}')[:200]
                    findings.append(f)
                if len(findings) >= max_processes:
                    break
            except Exception:
                continue
    except Exception as exc:                # defensive — never raise
        _log.debug('sigma scan_process_snapshot: %s', exc)
    return findings


# ══════════════════════════════════════════════════════════════════════════════
# Rule store
# ══════════════════════════════════════════════════════════════════════════════
_loaded_rules: Optional[List[Dict[str, Any]]] = None


def get_rules() -> List[Dict[str, Any]]:
    """All active rules (bundled + user). Loaded lazily, cached."""
    global _loaded_rules
    if _loaded_rules is None:
        rules: List[Dict[str, Any]] = []
        rules.extend(BUNDLED_RULES)
        rules.extend(load_user_rules())
        _loaded_rules = rules
        _log.info('Sigma engine loaded: %d bundled + %d user rules',
                  len(BUNDLED_RULES), len(rules) - len(BUNDLED_RULES))
    return _loaded_rules


def reload_rules() -> int:
    """Force re-load (picks up new files dropped into sigma_rules/)."""
    global _loaded_rules
    _loaded_rules = None
    return len(get_rules())


def get_engine_info() -> Dict[str, Any]:
    rules = get_rules()
    levels: Dict[str, int] = {}
    for r in rules:
        lv = _normalize_level(str(r.get('level', 'medium')))
        levels[lv] = levels.get(lv, 0) + 1
    return {'bundled': len(BUNDLED_RULES), 'total': len(rules),
            'levels': levels, 'user_dir': str(USER_RULES_DIR)}


# ══════════════════════════════════════════════════════════════════════════════
# User-rule loading — .json (full Sigma) + minimal YAML-subset parser
# ══════════════════════════════════════════════════════════════════════════════
def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        return s[1:-1]
    return s


def _split_flow_list(s: str) -> List[Any]:
    """Split '[a, b, "c d"]' flow-sequence text into items (quote-aware)."""
    items: List[Any] = []
    buf, in_q, q = [], False, ''
    for ch in s:
        if in_q:
            buf.append(ch)
            if ch == q:
                in_q = False
            continue
        if ch in ('"', "'"):
            in_q, q = True, ch
            buf.append(ch)
            continue
        if ch == ',':
            items.append(''.join(buf))
            buf = []
            continue
        buf.append(ch)
    tail = ''.join(buf).strip()
    if tail:
        items.append(tail)
    out: List[Any] = []
    for it in items:
        t = _strip_quotes(it)
        if t.lower() in ('true', 'false'):
            out.append(t.lower() == 'true')
        elif re.fullmatch(r'-?\d+', t):
            out.append(int(t))
        else:
            out.append(t)
    return out


def _parse_scalar(s: str) -> Any:
    s = s.strip()
    if s.startswith('[') and s.endswith(']'):
        return _split_flow_list(s[1:-1])
    return _coerce_scalar(s)


def _coerce_scalar(s: str) -> Any:
    t = _strip_quotes(s)
    if t.lower() in ('true', 'false'):
        return t.lower() == 'true'
    if t.lower() in ('null', '~', ''):
        return None
    if re.fullmatch(r'-?\d+', t):
        return int(t)
    return t


def _minimal_yaml_load(text: str) -> Optional[Dict[str, Any]]:
    """Parse the common Sigma YAML layout: nested 'key: value' maps,
    '- item' lists, flow lists [..], block scalars | and >. Handles the
    ~90% subset of SigmaHQ rules that don't use anchors/complex types."""
    try:
        lines: List[Tuple[int, str]] = []
        for raw in str(text).splitlines():
            if not raw.strip() or raw.strip().startswith('#'):
                continue
            if raw.strip() in ('---', '...'):
                continue
            indent = len(raw) - len(raw.lstrip(' '))
            lines.append((indent, raw.rstrip()))
        value, _pos = _yaml_block(lines, 0, 0)
        return value if isinstance(value, dict) else None
    except Exception as exc:
        _log.debug('sigma yaml parse: %s', exc)
        return None


def _yaml_block(lines: List[Tuple[int, str]], pos: int,
                indent: int) -> Tuple[Any, int]:
    """Parse one block starting at lines[pos]. Returns (value, next_pos)."""
    if pos < len(lines) and lines[pos][1].lstrip().startswith('- '):
        items: List[Any] = []
        while pos < len(lines):
            ind, line = lines[pos]
            if ind < indent or not line.lstrip().startswith('- '):
                break
            items.append(_parse_scalar(line.lstrip()[2:]))
            pos += 1
        return items, pos
    mapping: Dict[str, Any] = {}
    while pos < len(lines):
        ind, line = lines[pos]
        if ind < indent:
            break
        stripped = line.lstrip()
        if ':' not in stripped:
            pos += 1
            continue
        key, _, rest = stripped.partition(':')
        key = _strip_quotes(key)
        rest = rest.strip()
        if rest:
            if not rest.startswith(('"', "'")) and ' #' in rest:
                rest = rest.split(' #', 1)[0].strip()
            if rest in ('|', '>'):
                pos += 1
                parts: List[str] = []
                while pos < len(lines) and lines[pos][0] > ind:
                    parts.append(lines[pos][1].strip())
                    pos += 1
                mapping[key] = (('\n' if rest == '|' else ' ')
                                .join(parts))
                continue
            mapping[key] = _parse_scalar(rest)
            pos += 1
            continue
        pos += 1
        if pos < len(lines) and lines[pos][0] > ind:
            child, pos = _yaml_block(lines, pos, lines[pos][0])
            mapping[key] = child
        elif pos < len(lines) and lines[pos][0] == ind and \
                lines[pos][1].lstrip().startswith('- '):
            child, pos = _yaml_block(lines, pos, ind)
            mapping[key] = child
        else:
            mapping[key] = None
    return mapping, pos


def _validate_rule(rule: Any) -> bool:
    """Minimum Sigma shape: title + detection with at least one selection."""
    if not isinstance(rule, dict):
        return False
    det = rule.get('detection')
    return bool(rule.get('title')) and isinstance(det, dict) and len(det) >= 1


def load_user_rules(directory: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Load Sigma rules from <repo>/sigma_rules/ (.json and .yml/.yaml).
    Invalid/unrecognized files are skipped with a debug log."""
    rules: List[Dict[str, Any]] = []
    base = Path(directory) if directory else USER_RULES_DIR
    try:
        if not base.is_dir():
            return rules
        for path in sorted(base.iterdir()):
            suffix = path.suffix.lower()
            if suffix not in ('.json', '.yml', '.yaml'):
                continue
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
                if suffix == '.json':
                    data = json.loads(text)
                else:
                    data = _minimal_yaml_load(text)
                candidates = data if isinstance(data, list) else [data]
                for cand in candidates:
                    if _validate_rule(cand):
                        rules.append(cand)
            except Exception as exc:
                _log.debug('sigma user rule %s: %s', path.name, exc)
    except Exception as exc:                # defensive — never raise
        _log.debug('sigma load_user_rules: %s', exc)
    return rules


__all__ = ['SigmaFinding', 'BUNDLED_RULES', 'match_process',
           'match_script_block', 'scan_process_snapshot', 'get_rules',
           'reload_rules', 'get_engine_info', 'load_user_rules',
           'USER_RULES_DIR']
