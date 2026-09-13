"""
KEV CHECKER — CISA Known Exploited Vulnerabilities integration (v29.60)
================================================================================
Restores the KEV feature for the 6 modules that import `kev_checker`
(advanced_hardware_monitor, backup_verifier, enhanced_hardware_integration,
system_cleanup + the guarded `cisa_kev` fallback chain) — both modules were
MISSING from the repo, leaving `KEV_AVAILABLE=False` everywhere and the
CVE/hardware/backup KEV checks dead.

Data sources (first that works wins):
  1. downpour_data/cisa_kev.json  — shipped catalog snapshot (1709 entries)
  2. live CISA feed               — known_exploited_vulnerabilities.json
                                     (24h TTL cache, written back to the
                                     snapshot path)

Public API (exactly what consumers expect):
  * KEVChecker()            — checker instance
      .check_hardware(component_type, name) -> {is_vulnerable, cve_id, ...}
      .check_file(filename)                 -> {is_vulnerable, cve_id, ...}
      .check_product(name)                  -> match dict (product/vendor)
  * get_kev_catalog()       — module-level catalog list
  * check_kev_status(...)   — compatibility shim (cisa_kev parity)

Design: never raises — every lookup degrades to {is_vulnerable: False}.
"""
from __future__ import annotations

import io
import json
import logging
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
SNAPSHOT_PATH = SCRIPT_DIR / 'downpour_data' / 'cisa_kev.json'
LIVE_FEED_URL = ('https://www.cisa.gov/sites/default/files/feeds/'
                 'known_exploited_vulnerabilities.json')
_TTL = 24 * 3600.0     # 24h refresh window

_catalog_cache: Dict[str, Any] = {'ts': 0.0, 'entries': None}


def _load_snapshot() -> List[Dict]:
    """Load the shipped KEV snapshot; [] on any failure."""
    try:
        data = json.load(io.open(SNAPSHOT_PATH, encoding='utf-8',
                                 errors='replace'))
        if isinstance(data, dict):
            vulns = data.get('vulnerabilities')
            if isinstance(vulns, list):
                return vulns
        if isinstance(data, list):
            return data
    except Exception as exc:
        _log.debug('kev snapshot load: %s', exc)
    return []


def _load_live() -> List[Dict]:
    """Refresh from the live CISA feed (24h TTL); falls back to snapshot."""
    global _catalog_cache
    now = time.time()
    if _catalog_cache['entries'] is not None and \
            now - _catalog_cache['ts'] < _TTL:
        return _catalog_cache['entries']
    entries: List[Dict] = []
    try:
        import requests
        r = requests.get(LIVE_FEED_URL, timeout=15)
        if r.status_code == 200:
            data = r.json()
            vulns = (data or {}).get('vulnerabilities')
            if isinstance(vulns, list):
                entries = vulns
                # Write back to the snapshot path (best-effort)
                try:
                    SNAPSHOT_PATH.parent.mkdir(parents=True, exist_ok=True)
                    with io.open(SNAPSHOT_PATH, 'w', encoding='utf-8') as f:
                        json.dump(data, f)
                except Exception as exc:
                    _log.debug('kev snapshot write-back: %s', exc)
    except Exception as exc:
        _log.debug('kev live fetch: %s', exc)
    if not entries:
        entries = _load_snapshot()
    _catalog_cache['ts'] = now
    _catalog_cache['entries'] = entries
    return entries


def get_kev_catalog() -> List[Dict]:
    """Module-level catalog accessor (same name vulnerability_scanner
    exposes — consumers call either)."""
    return _load_live()


class KEVChecker:
    """KEV lookups for hardware components and files. Never raises."""

    def __init__(self):
        self._entries: Optional[List[Dict]] = None
        self._index: Optional[Dict[str, List[Dict]]] = None

    def _ensure_loaded(self) -> None:
        if self._entries is None:
            self._entries = _load_live()

    @staticmethod
    def _sev(entry: Dict) -> str:
        # KEV entries don't carry CVSS severity; derive from ransomware
        # association.
        if 'ransomware' in str(
                entry.get('knownRansomwareCampaignUse') or '').lower():
            return 'CRITICAL'
        return 'HIGH'

    # v29.60b: bare generic product words that substring-match unrelated
    # names ('16-CORE Processor' vs WordPress/Drupal 'Core') are the
    # classic KEV fuzzy-match false positive.
    _GENERIC_PRODUCTS = {
        'core', 'server', 'client', 'agent', 'manager', 'master',
        'software', 'app', 'system', 'update', 'framework', 'ui',
        'portal', 'plugin', 'module', 'service', 'console',
    }

    def _match(self, name: str) -> Optional[Dict]:
        """Fuzzy product match against the KEV catalog.

        v29.60b hardening: the entry's PRODUCT name (>= 4 chars) must
        appear in the queried name, and generic single-word products
        ('Core', 'Server', ...) never substring-match. Vendor-only token
        matches were too loose — every 'amd'/'intel' CPU would
        false-positive off any single vendor-matching KEV entry."""
        self._ensure_loaded()
        if not name or not self._entries:
            return None
        nl = str(name).lower()
        best: Optional[Dict] = None
        best_score = 0
        for e in self._entries:
            product = str(e.get('product') or '').strip().lower()
            if len(product) < 4 or product in self._GENERIC_PRODUCTS:
                continue
            if product not in nl:
                continue
            # Bare vendor-name products ('AMD', 'Intel') matched against
            # a name that merely contains the vendor are the classic
            # false positive — require something beyond the bare vendor.
            vendor = str(e.get('vendorProject') or '').strip().lower()
            if product == vendor and len(product) <= 6:
                continue
            score = len(product)
            if score > best_score:
                best_score = score
                best = e
        return best

    # -- public API ----------------------------------------------------------
    def check_hardware(self, component_type: str, name: str) -> Dict:
        """Match a hardware component name against the KEV catalog."""
        result: Dict[str, Any] = {'is_vulnerable': False, 'cve_id': None,
                                  'severity': None,
                                  'component': component_type}
        try:
            entry = self._match(name)
            if entry:
                result.update({
                    'is_vulnerable': True,
                    'cve_id': entry.get('cveID'),
                    'severity': self._sev(entry),
                    'product': entry.get('product'),
                    'vendor': entry.get('vendorProject'),
                })
        except Exception as exc:
            _log.debug('check_hardware(%s): %s', name, exc)
        return result

    def check_file(self, filename: str) -> Dict:
        """Match a file (software) name against the KEV catalog."""
        result: Dict[str, Any] = {'is_vulnerable': False, 'cve_id': None,
                                  'severity': None}
        try:
            # Strip extension/version noise for the match
            stem = re.sub(r'\.(exe|msi|dll|sys|ocx)$', '',
                          str(filename or ''), flags=re.I)
            stem = re.sub(r'[-_.]?[vV]?\d+(\.\d+)+$', '', stem)
            entry = self._match(stem)
            if entry:
                result.update({
                    'is_vulnerable': True,
                    'cve_id': entry.get('cveID'),
                    'severity': self._sev(entry),
                    'product': entry.get('product'),
                    'vendor': entry.get('vendorProject'),
                })
        except Exception as exc:
            _log.debug('check_file(%s): %s', filename, exc)
        return result

    def check_product(self, name: str) -> Dict:
        """Product/vendor match with the full KEV entry attached."""
        result: Dict[str, Any] = {'is_vulnerable': False}
        try:
            entry = self._match(name)
            if entry:
                result.update({'is_vulnerable': True, 'entry': entry,
                               'cve_id': entry.get('cveID'),
                               'severity': self._sev(entry)})
        except Exception as exc:
            _log.debug('check_product(%s): %s', name, exc)
        return result


# Module-level singleton (consumers create one per call — keep this cheap)
_checker: Optional[KEVChecker] = None


def _get_checker() -> KEVChecker:
    global _checker
    if _checker is None:
        _checker = KEVChecker()
    return _checker


def check_kev_status(product: str = '', cve_id: str = '') -> Dict:
    """cisa_kev parity shim: look up by product name or CVE id."""
    try:
        if cve_id:
            cve = str(cve_id).upper()
            for e in _load_live():
                if str(e.get('cveID') or '').upper() == cve:
                    return {'found': True, 'entry': e,
                            'is_vulnerable': True}
            return {'found': False, 'is_vulnerable': False}
        if product:
            r = _get_checker().check_product(product)
            return {'found': r.get('is_vulnerable', False),
                    'is_vulnerable': r.get('is_vulnerable', False),
                    'entry': r.get('entry')}
    except Exception as exc:
        _log.debug('check_kev_status: %s', exc)
    return {'found': False, 'is_vulnerable': False}


class CISAKEVClient:
    """cisa_kev parity client (the guarded fallback import path)."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    def get_catalog(self) -> List[Dict]:
        return _load_live()

    def check_product(self, name: str) -> Dict:
        return _get_checker().check_product(name)

    def check_kev(self, cve_id: str) -> Dict:
        return check_kev_status(cve_id=cve_id)

