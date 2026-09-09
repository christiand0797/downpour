"""
FP Suppression Module — Shared false-positive auto-suppression logic.

This module provides the core fingerprinting and suppression logic used by
both the main Downpour app and the ThreatIntelligenceManager.
"""

import re
import threading
from datetime import datetime
from typing import Any, Optional


class FingerprintError(Exception):
    """Raised when fingerprint normalization fails."""
    pass


def fp_fingerprint(msg: str) -> str:
    """Build a stable FP key from an alert message.

    Normalizes away timestamps, ports, per-host detail so repeated
    nuisance alerts for the same category+indicator collapse to one key:
    '[BOTNET] C2 45.88.48.238' and '[BOTNET] C2 45.88.48.238 :443' both
    map to the same fingerprint.

    Args:
        msg: Alert message string

    Returns:
        Normalized fingerprint string

    Raises:
        FingerprintError: If regex normalization fails
    """
    try:
        text: str = msg.strip()
        # Keep the bracketed category, normalize the rest
        m = re.match(r'(\[[A-Z0-9_\-]+\])\s*(.*)', text, re.I)
        cat: str = (m.group(1).upper() if m else '[GEN]')
        body: str = (m.group(2) if m else text).lower()
        body = re.sub(r'\s+', ' ', body)
        # IP[:port] as a unit FIRST (dotted quad + optional :port) so
        # '45.88.48.238' and '45.88.48.238 :443' collapse to one key.
        body = re.sub(
            r'\b\d{1,3}(\.\d{1,3}){3}(?:\s*:\s*\d{1,5})?\b', ' *IP* ', body)
        body = re.sub(r'[:\.]?\d{1,5}\b', ' *N*', body)      # ports/ids
        body = re.sub(r'\b[0-9a-f]{8,}\b', ' *H*', body)      # hashes
        # Trim to a stable prefix (drop trailing CPU%/mem numbers etc.)
        return f"{cat}:{body[:64]}"
    except re.error as e:
        raise FingerprintError(f"Regex failed: {e}") from e


class FPSuppressionCache:
    """Thread-safe in-memory cache for FP suppression state."""

    def __init__(self, suppress_threshold: int = 3):
        self._cache: dict[str, dict[str, int | bool]] = {}
        self._loaded: bool = False
        self._lock = threading.RLock()
        self._suppress_threshold = suppress_threshold

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def suppress_threshold(self) -> int:
        return self._suppress_threshold

    def is_suppressed(self, msg: str) -> bool:
        """Hot-path suppression check — memory only, no DB."""
        try:
            if not self._loaded:
                return False
            fp: str = fp_fingerprint(msg)
            with self._lock:
                e = self._cache.get(fp)
            return bool(e and e.get('suppressed'))
        except Exception:
            return False

    def get_entry(self, fp: str) -> Optional[dict[str, int | bool]]:
        """Get cache entry for fingerprint."""
        with self._lock:
            return self._cache.get(fp)

    def set_entry(self, fp: str, confirmed: int, suppressed: bool) -> None:
        """Set cache entry for fingerprint."""
        with self._lock:
            self._cache[fp] = {'confirmed': confirmed, 'suppressed': suppressed}

    def replace_cache(self, cache: dict[str, dict[str, int | bool]]) -> None:
        """Atomically replace the entire cache (used after DB load)."""
        with self._lock:
            self._cache = cache
            self._loaded = True

    def get_suppressed_list(self) -> list[tuple[str, int, bool]]:
        """Get list of suppressed fingerprints for UI display."""
        with self._lock:
            return [(k, v['confirmed'], v['suppressed'])
                    for k, v in self._cache.items() if v.get('suppressed')]


def load_fp_cache(db, cache: FPSuppressionCache) -> None:
    """Load fp_suppressions from DB into cache (executor thread)."""
    try:
        rows: Any = db.execute(
            "SELECT fingerprint, confirmed, suppressed FROM fp_suppressions")
        new_cache: dict[str, dict[str, int | bool]] = {}
        for fp, confirmed, suppressed in rows:
            new_cache[fp] = {'confirmed': confirmed or 0,
                             'suppressed': bool(suppressed)}
        cache.replace_cache(new_cache)
    except Exception as e:
        _safe_log('FPSuppression', 'load_fp_cache failed', e)


def persist_fp_confirm(db, cache: FPSuppressionCache, msg: str) -> bool:
    """Persist a user FP confirmation; auto-suppress at threshold.

    Runs on the executor so the main thread never waits on db._lock.
    On reaching the threshold the fingerprint flips to suppressed, so
    future occurrences of the same alert are dropped in _queue_alert.

    Returns:
        True if the fingerprint was newly suppressed
    """
    try:
        fp: str = fp_fingerprint(msg)
        now: str = datetime.now().isoformat()
        row: Any = db.execute(
            "SELECT confirmed, suppressed FROM fp_suppressions WHERE fingerprint=?",
            (fp,))
        confirmed: int = (row[0][0] + 1) if row else 1
        already: bool = bool(row[0][1]) if row else False
        suppress: bool = already or (confirmed >= cache.suppress_threshold)
        db.execute(
            "INSERT OR REPLACE INTO fp_suppressions "
            "(fingerprint, confirmed, suppressed, first_seen, last_seen, sample_msg) "
            "VALUES (?,?,?,"
            "COALESCE((SELECT first_seen FROM fp_suppressions WHERE fingerprint=?),?),"
            "?, ?)",
            (fp, confirmed, 1 if suppress else 0, fp,
             row[0][2] if row else now, now, msg[:120]))
        if hasattr(db, 'commit'):
            db.commit()  # type: ignore[attr-defined]
        cache.set_entry(fp, confirmed, suppress)
        return suppress
    except Exception as e:
        _safe_log('FPSuppression', 'persist_fp_confirm failed', e)
        return False


def _safe_log(component: str, message: str, exc: Optional[Exception] = None) -> None:
    """Log to error_logger without ever raising."""
    try:
        from downpour_v29_titanium import error_logger
        error_logger.log(component, message, "ERROR", exc)
    except Exception:
        pass