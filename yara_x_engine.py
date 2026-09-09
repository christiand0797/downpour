"""
YARA-X SCAN ENGINE — v29.46 (improvement catalog item 1a / P0)
================================================================================
Wires VirusTotal's YARA-X (Rust rewrite of YARA — SIMD + Aho-Corasick
prefilter, 5-10x faster than yara-python on large rule sets) into Downpour's
file-scanning pipeline, with a transparent yara-python fallback when the
yara-x wheel is not installed.

  * Compiles every yara_rules/*.yar file into its own ruleset (per-file
    compilation sidesteps cross-file duplicate-rule-identifier failures).
  * scan_bytes() / scan_file() return a normalized match dict regardless of
    which engine is active: {'rule', 'namespace', 'tags', 'meta'}.
  * get_engine_info() reports which engine is live — 'yara-x', 'yara-python'
    or 'none' — plus ruleset/rule counts for the GUI status line.

Thread-safe (a lock guards ruleset access; both engines' scan calls are
treated as non-reentrant). Offline-safe; never raises into the caller.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

SCRIPT_DIR = Path(__file__).resolve().parent
RULES_DIR = SCRIPT_DIR / 'yara_rules'
MAX_SCAN_SIZE = 64 * 1024 * 1024          # 64 MB cap per scanned buffer

try:
    import yara_x as _yx                  # pip install yara-x
    _YARA_X_AVAILABLE = True
except ImportError:
    _yx = None
    _YARA_X_AVAILABLE = False

try:
    import yara as _yp                    # yara-python fallback
    _YARA_PY_AVAILABLE = True
except ImportError:
    _yp = None
    _YARA_PY_AVAILABLE = False


class YaraXScanEngine:
    """Compile + scan through YARA-X, falling back to yara-python."""

    def __init__(self, rules_dir: Optional[Path] = None) -> None:
        self._rules_dir = Path(rules_dir) if rules_dir else RULES_DIR
        self._lock = threading.Lock()
        self._rulesets: List[Dict[str, Any]] = []   # [{'file','rules'}]
        self._compiled = False

    # -- compilation ------------------------------------------------------
    def _engine_name(self) -> str:
        if _YARA_X_AVAILABLE:
            return 'yara-x'
        if _YARA_PY_AVAILABLE:
            return 'yara-python'
        return 'none'

    def _compile_source(self, source: str) -> Optional[Any]:
        if _YARA_X_AVAILABLE:
            try:
                return _yx.compile(source)
            except Exception:
                pass                      # fall through to lenient Compiler
            try:
                # yara-x errors on unused patterns / exotic regexes where
                # yara-python only warns; ignore_invalid_rules salvages the
                # rest of the ruleset instead of dropping the whole file.
                comp = _yx.Compiler()
                comp.ignore_invalid_rules(True)
                comp.add_source(source)
                return comp.build()
            except Exception as exc:
                _log.debug('yara-x compile: %s', exc)
                return None
        if _YARA_PY_AVAILABLE:
            try:
                return _yp.compile(source=source)
            except Exception as exc:
                _log.debug('yara-python compile: %s', exc)
                return None
        return None

    def compile_rulesets(self) -> Dict[str, Any]:
        """Compile every *.yar file in yara_rules/ as its own ruleset."""
        with self._lock:
            self._rulesets = []
            files, failed = 0, 0
            if not self._rules_dir.is_dir():
                self._compiled = True
                return {'engine': self._engine_name(), 'rulesets': 0,
                        'failed': 0}
            for path in sorted(self._rules_dir.glob('*.yar')):
                files += 1
                try:
                    source = path.read_text(encoding='utf-8',
                                            errors='replace')
                except OSError as exc:
                    _log.debug('yara read %s: %s', path.name, exc)
                    failed += 1
                    continue
                rules = self._compile_source(source)
                if rules is None:
                    failed += 1
                    continue
                self._rulesets.append({'file': path.name, 'rules': rules})
            self._compiled = True
            return {'engine': self._engine_name(),
                    'rulesets': len(self._rulesets), 'failed': failed}

    def _ensure_compiled(self) -> None:
        if not self._compiled:
            self.compile_rulesets()

    # -- scanning ---------------------------------------------------------
    def _scan_with(self, rules: Any, data: bytes) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        if _YARA_X_AVAILABLE:
            try:
                results = rules.scan(data)
                for m in results.matching_rules:
                    try:
                        meta = dict(m.metadata)
                    except Exception:
                        meta = {}
                    matches.append({'rule': m.identifier,
                                    'namespace': m.namespace,
                                    'tags': list(m.tags), 'meta': meta})
            except Exception as exc:
                _log.debug('yara-x scan: %s', exc)
            return matches
        if _YARA_PY_AVAILABLE:
            try:
                for m in rules.match(data=data):
                    matches.append({'rule': m.rule,
                                    'namespace': m.namespace,
                                    'tags': list(m.tags or []),
                                    'meta': dict(m.meta or {})})
            except Exception as exc:
                _log.debug('yara-python scan: %s', exc)
        return matches

    def scan_bytes(self, data: bytes) -> List[Dict[str, Any]]:
        """Scan a bytes buffer across all compiled rulesets."""
        if not data:
            return []
        if len(data) > MAX_SCAN_SIZE:
            data = data[:MAX_SCAN_SIZE]
        self._ensure_compiled()
        out: List[Dict[str, Any]] = []
        with self._lock:
            for rs in self._rulesets:
                out.extend(self._scan_with(rs['rules'], data))
        return out

    def scan_file(self, path: Any) -> Dict[str, Any]:
        """Scan one file from disk. Never raises; returns an 'error' key."""
        result: Dict[str, Any] = {'path': str(path), 'matches': [],
                                  'error': ''}
        try:
            p = Path(path)
            size = p.stat().st_size
            if size > MAX_SCAN_SIZE:
                result['error'] = f'too large ({size} bytes)'
                return result
            result['matches'] = self.scan_bytes(p.read_bytes())
        except Exception as exc:            # defensive — never raise
            result['error'] = str(exc)[:160]
        return result

    def engine_info(self) -> Dict[str, Any]:
        self._ensure_compiled()
        return {'engine': self._engine_name(),
                'rulesets': len(self._rulesets),
                'rules_dir': str(self._rules_dir),
                'max_scan_size': MAX_SCAN_SIZE}


_module_engine: Optional[YaraXScanEngine] = None


def get_engine() -> YaraXScanEngine:
    """Shared module-level engine instance (lazy)."""
    global _module_engine
    if _module_engine is None:
        _module_engine = YaraXScanEngine()
    return _module_engine


def scan_bytes(data: bytes) -> List[Dict[str, Any]]:
    """Module convenience: scan a buffer with the shared engine."""
    return get_engine().scan_bytes(data)


def scan_file(path: Any) -> Dict[str, Any]:
    """Module convenience: scan a file with the shared engine."""
    return get_engine().scan_file(path)


def get_engine_info() -> Dict[str, Any]:
    """{'engine': 'yara-x'|'yara-python'|'none', 'rulesets': N, ...}"""
    return get_engine().engine_info()


__all__ = ['YaraXScanEngine', 'get_engine', 'scan_bytes', 'scan_file',
           'get_engine_info', 'RULES_DIR', 'MAX_SCAN_SIZE',
           '_YARA_X_AVAILABLE', '_YARA_PY_AVAILABLE']
