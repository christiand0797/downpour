#!/usr/bin/env python3
"""
PORT FIREWALL UNBLOCK - v29.50
Detects and unblocks firewall rules and ports that Downpour itself created.
================================================================================
Downpour's blocking features (DDoS shield, remote-access block, emergency
isolate, VPN kill-switch, C2-block, hunt-block, MISP-block, lock-down,
sandbox-block, worm-isolation) all create Windows Firewall rules with a
case-insensitive "Downpour"/"DOWNPOUR" name prefix. Over 22 distinct rule
name prefixes exist. Once a false positive or stale block is in place,
there was no single safe way to enumerate and remove them all - until
this module.

Usage:
  status()              - enumerate live Downpour rules (name/dir/action)
  unblock(dry_run=False) - remove ALL Downpour rules (audited)
  CLI:  python port_firewall_unblock.py            # status
        python port_firewall_unblock.py --apply    # unblock all

Standard library only; netsh is the OS interface. Safe: DRY-RUN by
default, every mutation is audited to downpour_data/port_unblock_audit.json.
"""
__version__ = "29.50.0"

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

AUDIT_PATH = (Path(__file__).resolve().parent / 'downpour_data' /
              'port_unblock_audit.json')
_NO_WIN = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)
_RULE_PREFIX = re.compile(r'^downpour', re.I)
_NETSH_TIMEOUT = 15


def _run(cmd):
    """Run netsh safely; returns (rc, combined_output)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=_NETSH_TIMEOUT, creationflags=_NO_WIN)
        return (r.returncode, (r.stdout or '') + (r.stderr or ''))
    except Exception as exc:
        return -1, str(exc)[:200]


def _parse_fw_rules(output):
    """Parse `netsh advfirewall firewall show rule name=all` output into
    structured dicts. Fields: name, dir, action, remoteip, localport,
    program, enabled."""
    rules = []
    current = {}
    for raw in str(output or '').splitlines():
        line = raw.rstrip()
        if not line.strip():
            if current.get('name'):
                rules.append(current)
            current = {}
            continue
        if ':' not in line:
            continue
        key, _, value = line.partition(':')
        key = key.strip()
        value = value.strip()
        lk = key.lower()
        if lk == 'rule name':
            current['name'] = value
        elif lk == 'enabled':
            current['enabled'] = value
        elif lk == 'direction':
            current['dir'] = value
        elif lk == 'action':
            current['action'] = value
        elif lk == 'program':
            current['program'] = value
        elif lk == 'remoteip':
            current['remoteip'] = value
        elif lk == 'localport':
            current['localport'] = value
        elif lk == 'protocol':
            current['protocol'] = value
    if current.get('name'):
        rules.append(current)
    return rules


def list_downpour_rules():
    """Enumerate live Windows Firewall rules whose name starts with
    'downpour' (case-insensitive). Returns a list of structured dicts."""
    rules = []
    for direction in ('in', 'out'):
        rc, out = _run(['netsh', 'advfirewall', 'firewall', 'show', 'rule',
                        'name=all', f'dir={direction}'])
        if rc != 0 and not out:
            continue
        for r in _parse_fw_rules(out):
            name = str(r.get('name', ''))
            if _RULE_PREFIX.match(name):
                r['dir'] = direction
                rules.append(r)
    return rules



def categorize(rule):
    """Map a Downpour rule to a friendly category for the UI/report."""
    name = str(rule.get('name', ''))
    action = str(rule.get('action', '')).lower()
    nl = name.lower()
    if 'ddos' in nl:
        cat = 'DDoS shield'
    elif 'killswitch' in nl or 'ks_' in nl:
        cat = 'VPN kill-switch'
    elif 'emergency' in nl:
        cat = 'Emergency isolate'
    elif 'lockdown' in nl:
        cat = 'Lock-down'
    elif 'worm' in nl:
        cat = 'Worm isolation'
    elif 'sandbox' in nl:
        cat = 'Sandbox'
    elif 'hunt' in nl:
        cat = 'Threat hunt'
    elif 'misp' in nl:
        cat = 'MISP feed'
    elif 'c2' in nl:
        cat = 'C2 block'
    elif 'alert' in nl:
        cat = 'Alert block'
    else:
        cat = 'Manual / misc'
    return cat + (' (block)' if action == 'block' else ' (allow)')


def unblock(rules=None, dry_run=True, audit=True):
    """Remove ALL Downpour firewall rules.

    Args:
      rules:    optional list from list_downpour_rules() (default: re-enum)
      dry_run:  True (default) = report only, NO mutation; False = delete
      audit:    write the action report to downpour_data/ audit JSON

    Returns a dict:
      {rules: [...], removed: [names], dry_run: bool, started, finished}
    """
    if rules is None:
        rules = list_downpour_rules()
    report: Dict[str, Any] = {
        'started': time.strftime('%Y-%m-%d %H:%M:%S'),
        'dry_run': bool(dry_run),
        'rules': rules,
        'removed': [],
        'errors': [],
    }
    for rule in rules:
        name = str(rule.get('name', ''))
        if not _RULE_PREFIX.match(name):
            continue
        if not dry_run:
            rc, out = _run(['netsh', 'advfirewall', 'firewall', 'delete',
                            'rule', f'name={name}'])
            if rc == 0:
                report['removed'].append(name)
            else:
                report['errors'].append(
                    f'{name}: rc={rc} {out.strip()[:120]}')
        else:
            report['removed'].append(name)
    report['finished'] = time.strftime('%Y-%m-%d %H:%M:%S')
    if audit:
        _audit_write(report)
    return report


def _audit_write(report):
    """Append the unblock report to the audit trail (keep last 50)."""
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        history: List[Dict[str, Any]] = []
        if AUDIT_PATH.exists():
            try:
                with open(AUDIT_PATH, 'r', encoding='utf-8') as f:
                    history = json.load(f)
            except Exception:
                history = []
        history.append(report)
        with open(AUDIT_PATH, 'w', encoding='utf-8') as f:
            json.dump(history[-50:], f, indent=2, default=str)
    except Exception:
        pass


def audit_trail():
    """Read the audit trail (empty list when absent)."""
    try:
        with open(AUDIT_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def status():
    """One-shot status for the GUI / health dashboard."""
    rules = list_downpour_rules()
    blocked = [r for r in rules
               if str(r.get('action', '')).lower() == 'block']
    return {
        'total': len(rules),
        'blocking': len(blocked),
        'categories': {c: sum(1 for r in rules if categorize(r) == c)
                       for c in sorted({categorize(r) for r in rules})},
        'rules': rules,
        'audit_runs': len(audit_trail()),
    }


if __name__ == '__main__':
    import sys
    if '--apply' in sys.argv:
        result = unblock(dry_run=False)
        print(json.dumps({k: v for k, v in result.items()
                          if k != 'rules'}, indent=2, default=str))
    else:
        print(json.dumps(status(), indent=2, default=str))

