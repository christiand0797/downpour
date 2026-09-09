"""
MISP FEED CLIENT — v29.47 (improvement catalog item 3b)
================================================================================
Pulls machine-readable indicators from a MISP instance (the open-source
threat-intelligence sharing platform) into Downpour's indicator pipeline
via the standard MISP REST API.

  * fetch_misp_attributes() — POST /attributes/restSearch with an
    optional timestamp watermark; handles both response shapes seen in the
    wild ({"response": {"Attribute": [...]}} and {"response": [...]}).
  * extract_indicators() — maps MISP attribute types to flat indicator
    records: md5/sha1/sha256 → hash, ip-dst/ip-src → ip, domain/hostname
    → domain, url → url.
  * sync_once() — full sync across the configured instance; results
    cached to downpour_data/misp_indicators.json for the GUI.

CONFIG (downpour_data/misp_config.json — disabled until the user fills it
in; the app never phones out otherwise):
    {
      "enabled": true,
      "url": "https://misp.example.com",
      "api_key": "<Authkey from MISP automation page>",
      "verify_tls": true,
      "days_back": 1,
      "max_attributes": 5000
    }
Shares the stix_taxii_feed conventions: requests-only, hard timeouts,
never raises, disabled-by-default.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    _REQUESTS_AVAILABLE = False

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / 'downpour_data'
CONFIG_PATH = DATA_DIR / 'misp_config.json'
CACHE_PATH = DATA_DIR / 'misp_indicators.json'
STATE_PATH = DATA_DIR / 'misp_state.json'

HTTP_TIMEOUT = 30
_MAX_ATTRIBUTES_DEFAULT = 5000

# MISP attribute type → indicator type
_TYPE_MAP = {
    'md5': 'hash', 'sha1': 'hash', 'sha256': 'hash',
    'ip-dst': 'ip', 'ip-src': 'ip', 'ip': 'ip',
    'domain': 'domain', 'hostname': 'domain',
    'domain|ip': 'domain',
    'url': 'url', 'uri': 'url',
}


def default_config() -> Dict[str, Any]:
    """Disabled-by-default config template the user fills in."""
    return {
        'enabled': False,
        'url': 'https://misp.example.com',
        'api_key': '',
        'verify_tls': True,
        'days_back': 1,
        'max_attributes': _MAX_ATTRIBUTES_DEFAULT,
    }


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load the user's MISP config; missing file → disabled template."""
    cfg_path = Path(path) if path else CONFIG_PATH
    try:
        if cfg_path.is_file():
            with open(cfg_path, encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                data.setdefault('enabled', False)
                data.setdefault('url', '')
                data.setdefault('api_key', '')
                return data
    except Exception as exc:
        _log.debug('misp load_config: %s', exc)
    return default_config()


def save_config(config: Dict[str, Any], path: Optional[Path] = None) -> bool:
    """Persist the config (creates downpour_data/ if needed)."""
    cfg_path = Path(path) if path else CONFIG_PATH
    try:
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cfg_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        return True
    except Exception as exc:
        _log.debug('misp save_config: %s', exc)
        return False


def _load_state(path: Optional[Path] = None) -> Dict[str, Any]:
    state_path = Path(path) if path else STATE_PATH
    try:
        if state_path.is_file():
            with open(state_path, encoding='utf-8') as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception as exc:
        _log.debug('misp load_state: %s', exc)
    return {}


def _save_state(state: Dict[str, Any], path: Optional[Path] = None) -> None:
    state_path = Path(path) if path else STATE_PATH
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True)
        with open(state_path, 'w', encoding='utf-8') as f:
            json.dump(state, f)
    except Exception as exc:
        _log.debug('misp save_state: %s', exc)


# ══════════════════════════════════════════════════════════════════════════════
# Attribute extraction
# ══════════════════════════════════════════════════════════════════════════════
def extract_indicators(attributes: List[Dict[str, Any]],
                       source_name: str = '') -> List[Dict[str, str]]:
    """MISP attributes → flat indicator records. Only supported types with
    non-empty values contribute; domain|ip splits into two records."""
    out: List[Dict[str, str]] = []
    seen: set = set()
    for attr in attributes or []:
        if not isinstance(attr, dict):
            continue
        if str(attr.get('deleted', '0')) in ('1', 'True', 'true'):
            continue
        attr_type = str(attr.get('type') or '').strip()
        value = str(attr.get('value') or '').strip()
        if not attr_type or not value:
            continue
        ind_type = _TYPE_MAP.get(attr_type)
        if ind_type is None:
            continue
        candidates = [(ind_type, value)]
        if attr_type == 'domain|ip' and '|' in value:
            dom, _, ip = value.partition('|')
            candidates = [('domain', dom), ('ip', ip)]
        label = str(attr.get('comment') or '')[:80]
        event_id = str(attr.get('event_id') or '')
        if event_id:
            label = f'event {event_id}' + (f' — {label}' if label else '')
        for itype, val in candidates:
            val = val.strip()
            if not val:
                continue
            key = (itype, val.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({'type': itype, 'value': val, 'name': label,
                        'source': source_name})
    return out


# ══════════════════════════════════════════════════════════════════════════════
# REST fetch
# ══════════════════════════════════════════════════════════════════════════════
def _request_attributes(config: Dict[str, Any], timestamp: str
                        ) -> Tuple[List[Dict[str, Any]], str]:
    """POST /attributes/restSearch. Returns (attributes, error)."""
    if not _REQUESTS_AVAILABLE:
        return [], 'requests library unavailable'
    base = str(config.get('url') or '').rstrip('/')
    if not base:
        return [], 'no url configured'
    api_key = str(config.get('api_key') or '')
    if not api_key:
        return [], 'no api_key configured'
    body: Dict[str, Any] = {
        'returnFormat': 'json',
        'limit': int(config.get('max_attributes') or
                     _MAX_ATTRIBUTES_DEFAULT)}
    if timestamp:
        body['timestamp'] = timestamp
    try:
        resp = requests.post(
            f'{base}/attributes/restSearch',
            headers={'Authorization': api_key,
                     'Accept': 'application/json',
                     'Content-Type': 'application/json',
                     'User-Agent': 'Downpour/29.47'},
            json=body, timeout=HTTP_TIMEOUT,
            verify=config.get('verify_tls', True))
        if resp.status_code == 403:
            return [], 'auth failed (403 — check api_key)'
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:
        return [], str(exc)[:160]
    response = payload.get('response') if isinstance(payload, dict) else None
    if isinstance(response, dict):                 # MISP 2.4+ shape
        attrs = response.get('Attribute') or []
    elif isinstance(response, list):               # older shape
        attrs = response
    else:
        attrs = []
    return [a for a in attrs if isinstance(a, dict)], ''


def sync_once(config: Optional[Dict[str, Any]] = None,
              path: Optional[Path] = None) -> Dict[str, Any]:
    """Full sync against the configured MISP instance. Never raises.
    Returns a health dict + indicators; persists a timestamp watermark so
    the next sync only pulls NEW attributes."""
    started = time.time()
    cfg = config if config is not None else load_config(path)
    result: Dict[str, Any] = {
        'enabled': bool(cfg.get('enabled')),
        'indicators': [],
        'count': 0,
        'status': 'disabled',
        'duration_s': 0.0,
    }
    if not result['enabled']:
        return result
    if not _REQUESTS_AVAILABLE:
        result['status'] = 'requests unavailable'
        return result
    state = _load_state()
    timestamp = str(state.get('last_timestamp') or '')
    if not timestamp:
        days_back = int(cfg.get('days_back') or 1)
        timestamp = str(int(time.time()) - days_back * 86400)
    attrs, err = _request_attributes(cfg, timestamp)
    if err:
        result['status'] = err
        return result
    indicators = extract_indicators(attrs, str(cfg.get('url') or 'misp'))
    result['indicators'] = indicators
    result['count'] = len(indicators)
    result['status'] = f'ok ({len(indicators)} indicators)'
    state['last_timestamp'] = str(int(time.time()))
    _save_state(state)
    _save_cache(result)
    result['duration_s'] = round(time.time() - started, 2)
    return result


def _save_cache(result: Dict[str, Any], path: Optional[Path] = None) -> bool:
    """Persist the last sync (indicators capped at 50k) for GUI use."""
    cache_path = Path(path) if path else CACHE_PATH
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            'synced_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'count': result.get('count', 0),
            'indicators': result.get('indicators', [])[:50000],
        }
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f)
        return True
    except Exception as exc:
        _log.debug('misp _save_cache: %s', exc)
        return False


def load_cache(path: Optional[Path] = None) -> Dict[str, Any]:
    """Last cached sync (or empty template)."""
    cache_path = Path(path) if path else CACHE_PATH
    try:
        if cache_path.is_file():
            with open(cache_path, encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception as exc:
        _log.debug('misp load_cache: %s', exc)
    return {'synced_at': '', 'count': 0, 'indicators': []}


__all__ = ['extract_indicators', 'sync_once', 'load_config', 'save_config',
           'default_config', 'load_cache', 'CONFIG_PATH', 'CACHE_PATH',
           '_REQUESTS_AVAILABLE']
