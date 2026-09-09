"""
STIX 2.1 / TAXII 2.1 FEED CLIENT — v29.46 (improvement catalog item 3a)
================================================================================
Pulls machine-readable threat intelligence from any TAXII 2.1 server into
Downpour's indicator pipeline. STIX/TAXII is the vendor-neutral standard used
by CISA AIS, MISP instances, ISACs and commercial feeds — this makes all of
them pluggable into Downpour without per-feed code.

  * TAXII21Client — discovery → api-roots → collections → objects, with
    Basic/Bearer auth, TLS-verify toggle, limit + 'next'-cursor pagination
    and hard timeouts (the house feed-fetch conventions).
  * extract_indicators() — parses STIX 2.1 indicator patterns into flat
    {type, value, name} records: ipv4/ipv6, domain-name, url, file hashes
    (SHA-256/SHA-1/MD5) and windows-registry-key.
  * sync_once() — full sync across every enabled server in the config;
    results cached to downpour_data/stix_indicators.json for the GUI.

CONFIG (downpour_data/stix_taxii_config.json — disabled until the user
fills in a server; the app never phones out otherwise):
    {
      "enabled": true,
      "servers": [
        {"name": "my-ais", "discovery_url": "https://<taxii-root>/",
         "username": "...", "password": "...", "token": "",
         "verify_tls": true, "collection_ids": ["*"], "max_objects": 5000}
      ]
    }
Stdlib + requests only; never raises into the caller.
"""
from __future__ import annotations

import json
import logging
import re
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
CONFIG_PATH = DATA_DIR / 'stix_taxii_config.json'
CACHE_PATH = DATA_DIR / 'stix_indicators.json'

HTTP_TIMEOUT = 30
_PAGE_LIMIT = 500                       # TAXII page size
_MAX_OBJECTS_DEFAULT = 5000
_TAXII_MIME = 'application/taxii+json;version=2.1'

# STIX 2.1 pattern → (indicator_type, extraction regex)
_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ('ip', re.compile(r"ipv4-addr:value\s*=\s*'([^']+)'")),
    ('ip', re.compile(r"ipv6-addr:value\s*=\s*'([^']+)'")),
    ('domain', re.compile(r"domain-name:value\s*=\s*'([^']+)'")),
    ('url', re.compile(r"url:value\s*=\s*'([^']+)'")),
    ('hash', re.compile(r"file:hashes\.'?SHA-?256'?\s*=\s*'([^']+)'",
                        re.IGNORECASE)),
    ('hash', re.compile(r"file:hashes\.'?SHA-?1'?\s*=\s*'([^']+)'",
                        re.IGNORECASE)),
    ('hash', re.compile(r"file:hashes\.'?MD5'?\s*=\s*'([^']+)'",
                        re.IGNORECASE)),
    ('registry', re.compile(
        r"windows-registry-key:key\s*=\s*'([^']+)'")),
]


def default_config() -> Dict[str, Any]:
    """Disabled-by-default config template the user fills in."""
    return {
        'enabled': False,
        'servers': [
            {
                'name': 'example-taxii-server',
                'discovery_url': 'https://taxii.example.com/taxii2/',
                'username': '',
                'password': '',
                'token': '',
                'verify_tls': True,
                'collection_ids': ['*'],
                'max_objects': _MAX_OBJECTS_DEFAULT,
            },
        ],
    }


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    """Load the user's TAXII config; missing file → disabled template."""
    cfg_path = Path(path) if path else CONFIG_PATH
    try:
        if cfg_path.is_file():
            with open(cfg_path, encoding='utf-8') as f:
                data = json.load(f)
            if isinstance(data, dict):
                data.setdefault('enabled', False)
                data.setdefault('servers', [])
                return data
    except Exception as exc:
        _log.debug('stix_taxii load_config: %s', exc)
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
        _log.debug('stix_taxii save_config: %s', exc)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# STIX 2.1 pattern extraction
# ══════════════════════════════════════════════════════════════════════════════
def extract_indicators(stix_objects: List[Dict[str, Any]],
                       source_name: str = '') -> List[Dict[str, str]]:
    """STIX objects → flat indicator records. Only objects of type
    'indicator' with a parseable 'pattern' contribute. Deduped."""
    out: List[Dict[str, str]] = []
    seen: set = set()
    for obj in stix_objects or []:
        if not isinstance(obj, dict) or obj.get('type') != 'indicator':
            continue
        pattern = str(obj.get('pattern', ''))
        if not pattern:
            continue
        label = str(obj.get('name') or '') or str(
            obj.get('description') or '')[:80]
        for ind_type, rx in _PATTERNS:
            for match in rx.finditer(pattern):
                value = match.group(1).strip()
                if not value:
                    continue
                key = (ind_type, value.lower())
                if key in seen:
                    continue
                seen.add(key)
                out.append({'type': ind_type, 'value': value,
                            'name': label, 'source': source_name})
    return out


def _request(session: Any, method: str, url: str, server: Dict[str, Any],
             params: Optional[Dict[str, Any]] = None
             ) -> Tuple[Optional[Dict[str, Any]], str]:
    """One TAXII request. Returns (json_dict|None, error_string)."""
    headers = {'Accept': _TAXII_MIME, 'User-Agent': 'Downpour/29.46'}
    token = str(server.get('token') or '')
    username = str(server.get('username') or '')
    password = str(server.get('password') or '')
    auth: Any = None
    if token:
        headers['Authorization'] = f'Bearer {token}'
    elif username:
        auth = (username, password)
    verify = server.get('verify_tls', True)
    try:
        resp = session.request(method, url, headers=headers, auth=auth,
                               params=params, timeout=HTTP_TIMEOUT,
                               verify=verify)
        if resp.status_code == 401:
            return None, 'auth failed (401)'
        if resp.status_code == 404:
            return None, 'not found (404)'
        resp.raise_for_status()
        try:
            return resp.json(), ''
        except ValueError:
            return None, 'non-JSON response'
    except Exception as exc:                # requests exceptions included
        return None, str(exc)[:160]


class TAXII21Client:
    """Minimal TAXII 2.1 client: discovery → collections → objects."""

    def __init__(self, server: Dict[str, Any], session: Any = None):
        self.server = dict(server)
        self.session = session or (
            requests.Session() if _REQUESTS_AVAILABLE else None)

    def discover(self) -> Tuple[List[str], str]:
        """Return api-roots list from the discovery endpoint."""
        base = str(self.server.get('discovery_url') or '')
        if not base:
            return [], 'no discovery_url configured'
        if self.session is None:
            return [], 'requests library unavailable'
        data, err = _request(self.session, 'GET', base, self.server)
        if data is None:
            return [], err or 'discovery failed'
        roots = data.get('api_roots') or []
        if isinstance(roots, str):
            roots = [roots]
        return [str(r).rstrip('/') + '/' for r in roots], ''

    def list_collections(self, api_root: str) -> Tuple[List[Dict[str, Any]],
                                                       str]:
        """Return collection dicts for one api-root."""
        if self.session is None:
            return [], 'requests library unavailable'
        data, err = _request(self.session, 'GET',
                             f'{api_root}collections/', self.server)
        if data is None:
            return [], err or 'collections fetch failed'
        colls = data.get('collections') or []
        return [c for c in colls if isinstance(c, dict)], ''

    def fetch_objects(self, api_root: str, collection_id: str,
                      max_objects: int = _MAX_OBJECTS_DEFAULT
                      ) -> Tuple[List[Dict[str, Any]], str]:
        """Page through one collection's STIX objects (limit + next cursor)."""
        if self.session is None:
            return [], 'requests library unavailable'
        url = f'{api_root}collections/{collection_id}/objects/'
        objects: List[Dict[str, Any]] = []
        params: Dict[str, Any] = {'limit': _PAGE_LIMIT}
        for _page in range((max_objects // _PAGE_LIMIT) + 2):
            data, err = _request(self.session, 'GET', url, self.server,
                                 params=params)
            if data is None:
                return objects, err or 'objects fetch failed'
            batch = data.get('objects') or []
            objects.extend(o for o in batch if isinstance(o, dict))
            if data.get('more') and data.get('next') and \
                    len(objects) < max_objects:
                params = {'limit': _PAGE_LIMIT, 'next': data['next']}
                continue
            break
        return objects[:max_objects], ''


# ══════════════════════════════════════════════════════════════════════════════
# Sync orchestration + cache
# ══════════════════════════════════════════════════════════════════════════════
def _sync_one_server(server: Dict[str, Any]) -> Tuple[List[Dict[str, str]],
                                                      str]:
    """Sync one server entry; returns (indicators, status)."""
    name = str(server.get('name') or 'unnamed')
    wanted = server.get('collection_ids') or ['*']
    if isinstance(wanted, str):
        wanted = [wanted]
    max_objects = int(server.get('max_objects') or _MAX_OBJECTS_DEFAULT)
    client = TAXII21Client(server)
    roots, err = client.discover()
    if err:
        return [], f'{name}: {err}'
    indicators: List[Dict[str, str]] = []
    for root in roots:
        collections, cerr = client.list_collections(root)
        if cerr:
            return indicators, f'{name}: {cerr}'
        for coll in collections:
            cid = str(coll.get('id') or '')
            title = str(coll.get('title') or cid)
            if '*' not in wanted and cid not in wanted and \
                    title not in wanted:
                continue
            objs, oerr = client.fetch_objects(root, cid, max_objects)
            if oerr:
                _log.debug('stix_taxii %s/%s: %s', name, title, oerr)
            indicators.extend(extract_indicators(objs, name))
            if len(indicators) >= max_objects:
                break
        if len(indicators) >= max_objects:
            break
    return indicators[:max_objects], f'{name}: ok ({len(indicators)})'


def sync_once(config: Optional[Dict[str, Any]] = None,
              path: Optional[Path] = None) -> Dict[str, Any]:
    """Full sync across enabled servers. Never raises. Returns a health
    dict + all indicators; also persists the cache for GUI display."""
    started = time.time()
    cfg = config if config is not None else load_config(path)
    result: Dict[str, Any] = {
        'enabled': bool(cfg.get('enabled')),
        'servers': [],
        'indicators': [],
        'duration_s': 0.0,
    }
    if not result['enabled']:
        result['servers'].append({'name': '(none)', 'status': 'disabled'})
        return result
    if not _REQUESTS_AVAILABLE:
        result['servers'].append({'name': '(client)',
                                  'status': 'requests unavailable'})
        return result
    total: List[Dict[str, str]] = []
    seen: set = set()
    for server in cfg.get('servers') or []:
        if not isinstance(server, dict) or not server.get('enabled', True):
            continue
        try:
            inds, status = _sync_one_server(server)
        except Exception as exc:            # defensive — never raise
            inds, status = [], f'{server.get("name", "?")}: {exc}'
        for ind in inds:
            key = (ind['type'], ind['value'].lower())
            if key in seen:
                continue
            seen.add(key)
            total.append(ind)
        result['servers'].append({
            'name': str(server.get('name') or '?'), 'status': status})
    result['indicators'] = total
    result['duration_s'] = round(time.time() - started, 2)
    _save_cache(result)
    return result


def _save_cache(result: Dict[str, Any], path: Optional[Path] = None) -> bool:
    """Persist the last sync (indicators capped at 50k) for GUI/report use."""
    cache_path = Path(path) if path else CACHE_PATH
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            'synced_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'servers': result.get('servers', []),
            'count': len(result.get('indicators', [])),
            'indicators': result.get('indicators', [])[:50000],
        }
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f)
        return True
    except Exception as exc:
        _log.debug('stix_taxii _save_cache: %s', exc)
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
        _log.debug('stix_taxii load_cache: %s', exc)
    return {'synced_at': '', 'servers': [], 'count': 0, 'indicators': []}


__all__ = ['TAXII21Client', 'extract_indicators', 'sync_once',
           'load_config', 'save_config', 'default_config', 'load_cache',
           'CONFIG_PATH', 'CACHE_PATH', '_REQUESTS_AVAILABLE']
