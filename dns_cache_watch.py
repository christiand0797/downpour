"""
DNS CACHE SURVEILLANCE — v29.47 (improvement catalog item 5a, P1)
================================================================================
Polls the Windows DNS resolver cache (Get-DnsClientCache) and scores every
cached record with DGA heuristics — Shannon entropy of the registrable
labels, digit ratio, hyphen count, length, dictionary-word presence — plus
a known-good suffix allowlist to keep the false-positive rate sane.

Why the cache: the OS resolver caches EVERY lookup the machine makes, so a
DGA-beaconing implant is visible here even when the DNS query itself
happened outside Downpour's monitoring windows, and even for processes we
cannot inspect. This closes the "fast lookup between polls" gap for DNS.

  * collect_dns_cache()   — snapshot of cached (name, record-data) pairs
  * score_domain()        — 0-100 risk score + factor breakdown
  * run_dns_cache_check() — one pass; deduped against a persisted baseline
                            (downpour_data/dns_baseline.json) so domains
                            seen while Downpour was OFF are flagged at the
                            next start; repeat offenders are NOT re-alerted
                            every cycle.

Alert model mirrors firmware_posture.FirmwareAlert so findings bridge into
the existing alert pipeline ([DNS-CACHE] tag).
Stdlib-only; never raises into the caller.
"""
from __future__ import annotations

import json
import logging
import math
import os
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_PWSH = os.path.join(
    os.environ.get('SystemRoot', r'C:\Windows'),
    'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')

_log = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
BASELINE_PATH = SCRIPT_DIR / 'downpour_data' / 'dns_baseline.json'

_PS_TIMEOUT = 20
_ALERT_THRESHOLD = 70          # >= this score → MEDIUM alert
_HIGH_THRESHOLD = 85           # >= this score → HIGH alert
_MAX_CACHE_ROWS = 4000         # cap on parsed cache rows per pass


@dataclass
class DnsAlert:
    """One DNS-cache finding (mirrors FirmwareAlert shape)."""
    source: str          # 'dns_cache'
    technique: str       # MITRE ATT&CK id
    severity: str        # MEDIUM/HIGH
    description: str
    detail: str


# Suffixes treated as known-good infrastructure (full-domain suffix match).
# Kept tight: corporate-scale domains whose subdomains occasionally carry
# long random labels (CDN object IDs) that would trip the entropy check.
KNOWN_GOOD_SUFFIXES = (
    '.microsoft.com', '.windows.com', '.windowsupdate.com', '.msn.com',
    '.office.com', '.office365.com', '.outlook.com', '.live.com',
    '.google.com', '.googleapis.com', '.gstatic.com',
    '.googleusercontent.com', '.cloudflare.com', '.cloudflareclient.com',
    '.amazonaws.com', '.akamai.com', '.akamaiedge.net', '.akamaihd.net',
    '.edgekey.net', '.apple.com', '.icloud.com', '.cdn.mozilla.net',
    '.steampowered.com', '.riotgames.com', '.battle.net', '.nvidia.com',
    '.intel.com', '.amd.com', '.dell.com', '.hp.com', '.lenovo.com',
    '.asus.com', '.msi.com', '.gigabyte.com', '.spotify.com',
    '.netflix.com', '.youtube.com', '.github.com',
    '.githubusercontent.com', '.pypi.org', '.python.org', '.npmjs.org',
    '.docker.com', '.docker.io', '.ubuntu.com', '.debian.org',
    '.norton.com', '.mcafee.com', '.kaspersky.com', '.avast.com',
    '.bitdefender.com', '.eset.com', '.virustotal.com', '.abuse.ch',
)

# TLDs commonly abused by DGA families / bulletproof hosting
_RISKY_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'click',
    'link', 'fit', 'rest', 'cam', 'quest', 'cfd', 'sbs',
}

_COMMON_WORDS = (
    'www', 'mail', 'ftp', 'api', 'cdn', 'static', 'assets', 'media',
    'blog', 'shop', 'app', 'dev', 'test', 'stage', 'prod', 'admin',
    'login', 'auth', 'secure', 'payment', 'billing', 'download', 'update',
    'support', 'help', 'docs', 'news', 'smtp', 'imap', 'ns1', 'ns2',
    'dns', 'vpn', 'remote', 'portal', 'cloud', 'server', 'microsoft',
    'windows', 'office', 'google', 'apple', 'amazon', 'account',
)


def _shannon_entropy(label: str) -> float:
    """Shannon entropy (bits/char) of a label; 0.0 for empty."""
    if not label:
        return 0.0
    freq = Counter(label.lower())
    n = len(label)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def score_domain(domain: str) -> Dict[str, Any]:
    """DGA-style risk score (0-100) for one cached domain name."""
    domain = str(domain or '').strip().rstrip('.').lower()
    parts = [p for p in domain.split('.') if p]
    if len(parts) < 2 or not all(p for p in parts):
        return {'domain': domain, 'score': 0, 'factors': ['not a domain']}
    labels = '.'.join(parts[:-1])
    tld = parts[-1]
    if any(domain.endswith(sfx) for sfx in KNOWN_GOOD_SUFFIXES):
        return {'domain': domain, 'score': 0,
                'factors': ['known-good suffix']}
    factors: List[str] = []
    score = 0
    if tld in _RISKY_TLDS:
        score += 15
        factors.append(f'risky TLD .{tld}')
    entropy = _shannon_entropy(labels)
    if entropy >= 3.8:
        score += 30
        factors.append(f'high entropy {entropy:.2f}')
    elif entropy >= 3.3:
        score += 15
        factors.append(f'elevated entropy {entropy:.2f}')
    length = len(labels)
    if length >= 25:
        score += 15
        factors.append(f'long label {length}')
    elif length >= 18:
        score += 8
        factors.append(f'long-ish label {length}')
    digit_ratio = sum(c.isdigit() for c in labels) / max(1, length)
    if digit_ratio >= 0.4:
        score += 20
        factors.append(f'digit-heavy {digit_ratio:.0%}')
    elif digit_ratio >= 0.25:
        score += 10
        factors.append(f'digit-heavy-ish {digit_ratio:.0%}')
    hyphens = labels.count('-')
    if hyphens >= 4:
        score += 10
        factors.append(f'{hyphens} hyphens')
    words = [w for w in _COMMON_WORDS if w in labels]
    if words:
        score = max(0, score - 25)
        factors.append(f'dictionary words: {",".join(words[:2])}')
    return {'domain': domain, 'score': min(100, score),
            'factors': factors or ['benign characteristics']}


def _ps(command: str) -> Optional[str]:
    """Run a short PowerShell probe; None on any failure/timeout."""
    try:
        flags = 0
        if hasattr(subprocess, 'CREATE_NO_WINDOW'):
            flags = subprocess.CREATE_NO_WINDOW
        proc = subprocess.run(
            [_PWSH, '-NoProfile', '-NonInteractive',
             '-ExecutionPolicy', 'Bypass', '-Command', command],
            capture_output=True, text=True, timeout=_PS_TIMEOUT,
            creationflags=flags)
        if proc.returncode != 0:
            return None
        return (proc.stdout or '').strip() or None
    except Exception as exc:                # defensive — never raise
        _log.debug('dns_cache_watch _ps: %s', exc)
        return None


def collect_dns_cache() -> List[Tuple[str, str]]:
    """Snapshot the resolver cache as (name, record-data) pairs.
    Deduped, lowercased, capped at _MAX_CACHE_ROWS."""
    out = _ps('Get-DnsClientCache -ErrorAction SilentlyContinue | '
              'Select-Object -First ' + str(_MAX_CACHE_ROWS) +
              ' Entry,Data | ConvertTo-Json -Compress')
    if out:
        try:
            data = json.loads(out)
            rows = data if isinstance(data, list) else [data]
        except Exception as exc:
            _log.debug('dns cache parse: %s', exc)
            rows = []
        seen: set = set()
        pairs: List[Tuple[str, str]] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            name = str(row.get('Entry') or '').strip().rstrip('.').lower()
            if not name or name in seen or '.' not in name:
                continue
            seen.add(name)
            pairs.append((name, str(row.get('Data') or '')))
            if len(pairs) >= _MAX_CACHE_ROWS:
                break
        if pairs:
            return pairs
    # Fallback: ipconfig /displaydns — extract bare name lines only
    out2 = _ps('ipconfig /displaydns')
    if not out2:
        return []
    seen2: set = set()
    pairs2: List[Tuple[str, str]] = []
    for line in out2.splitlines():
        line = line.strip()
        if not line or ' ' in line or '.' not in line:
            continue
        if line.startswith('0.') or line.startswith('127.'):
            continue
        name = line.rstrip('.').lower()
        if not name or name in seen2 or any(
                c in name for c in ('/', '\\', ':', '%')):
            continue
        seen2.add(name)
        pairs2.append((name, ''))
        if len(pairs2) >= _MAX_CACHE_ROWS:
            break
    return pairs2


# ══════════════════════════════════════════════════════════════════════════════
# Baseline + one combined pass
# ══════════════════════════════════════════════════════════════════════════════
def _load_baseline() -> Dict[str, Any]:
    try:
        with open(Path(BASELINE_PATH), encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_baseline(baseline: Dict[str, Any]) -> None:
    try:
        path = Path(BASELINE_PATH)   # tolerate str or Path overrides
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(baseline, f, indent=1)
    except Exception as exc:
        _log.debug('dns baseline save: %s', exc)


def run_dns_cache_check() -> List[DnsAlert]:
    """One surveillance pass over the resolver cache.

    First run: TOFU — every cached domain enters the baseline silently.
    Later runs: only domains scoring >= _ALERT_THRESHOLD AND not previously
    baselined alert; the baseline then absorbs them so each suspicious
    domain alerts exactly once (unless flushed). Domains that score high
    but were baselined while OFF are flagged at first sight.
    """
    rows = collect_dns_cache()
    if not rows:
        return []
    baseline = _load_baseline()
    known: set = set(baseline.get('domains') or [])
    first_run = 'domains' not in baseline
    alerts: List[DnsAlert] = []
    newly_seen: set = set()
    for name, _data in rows:
        newly_seen.add(name)
        if name in known:
            continue
        scored = score_domain(name)
        score = int(scored.get('score', 0))
        if score >= _ALERT_THRESHOLD and not first_run:
            alerts.append(DnsAlert(
                source='dns_cache',
                technique='T1071.004' if score >= _HIGH_THRESHOLD
                else 'T1568',
                severity='HIGH' if score >= _HIGH_THRESHOLD else 'MEDIUM',
                description='DGA-like domain in resolver cache',
                detail=f'{name} (score {score}: '
                       f'{"; ".join(scored.get("factors", []))[:120]})'))
        known.add(name)
    if newly_seen and not first_run:
        # keep the baseline bounded: union with prior, cap at 20k entries
        merged = sorted(known)[:20000]
        baseline['domains'] = merged
        baseline['updated'] = len(merged)
        _save_baseline(baseline)
    elif first_run:
        baseline['domains'] = sorted(newly_seen)[:20000]
        baseline['updated'] = len(baseline['domains'])
        _save_baseline(baseline)
    return alerts


__all__ = ['DnsAlert', 'collect_dns_cache', 'score_domain',
           'run_dns_cache_check', 'KNOWN_GOOD_SUFFIXES', 'BASELINE_PATH',
           '_ALERT_THRESHOLD', '_HIGH_THRESHOLD']