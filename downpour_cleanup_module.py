#!/usr/bin/env python3
"""
downpour_cleanup_module.py - Downpour v29 Titanium
Comprehensive system cleanup: temp files, logs, caches, registry remnants,
quarantine management, and graceful application shutdown helpers.
"""
from __future__ import annotations
__version__ = "29.0.0"
import gc
import glob
import logging
import os
import stat
import shutil
import sqlite3
import threading
import time
import winreg
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
logger = logging.getLogger(__name__)
LOG_RETENTION_DAYS = 30
QUARANTINE_RETENTION_DAYS = 90
MAX_LOG_SIZE_MB = 50
TEMP_PATTERNS: List[str] = [
    "downpour_*.tmp", "downpour_*.log.bak",
    "dp_scan_*.json", "dp_cache_*.pkl", "downpour_backup_*.log",
]
# Stale secure sandbox directories created each run — cleaned on graceful shutdown
SECURE_TMP_PATTERN = "downpour_secure_*"
DOWNPOUR_REG_KEYS: List[Tuple[int, str]] = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Downpour"),
    (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Downpour"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Downpour"),
]

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass
class CleanupResult:
    """Result of a cleanup operation."""
    operation: str
    success: bool
    bytes_freed: int = 0
    files_removed: int = 0
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

# NOTE: CleanupReport is fully defined later (GUI-compatible version).
# The lightweight version here is kept for DownpourCleaner internals only.
@dataclass
class _LegacyCleanupReport:
    """Internal aggregated cleanup report used by DownpourCleaner."""
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: str = ""
    results: List[CleanupResult] = field(default_factory=list)

    @property
    def total_bytes_freed(self) -> int:
        return sum(r.bytes_freed for r in self.results)

    @property
    def total_files_removed(self) -> int:
        return sum(r.files_removed for r in self.results)

    @property
    def all_errors(self) -> List[str]:
        return [e for r in self.results for e in r.errors]

    def finish(self) -> None:
        self.completed_at = datetime.now().isoformat()


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------
def _safe_remove(path: Path) -> Tuple[bool, int]:
    """Remove a file safely; return (success, bytes_freed)."""
    try:
        size = path.stat().st_size if path.is_file() else _dir_size(path) if path.is_dir() else 0
        if path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        return True, size
    except Exception as exc:
        logger.debug("Could not remove %s: %s", path, exc)
        return False, 0

def _dir_size(path: Path) -> int:
    """Recursively compute directory size in bytes."""
    total = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                try:
                    total += p.stat().st_size
                except OSError:
                    pass
    except Exception:
        pass
    return total


def _default_downpour_db_path() -> Path:
    """Primary SQLite database used by the v29 application."""
    return Path(__file__).parent / "downpour_data" / "titanium.db"


def _is_hidden_path(path: Path) -> bool:
    """Best-effort hidden-file detection for Windows and dotfiles."""
    try:
        if path.name.startswith('.'):
            return True
        attrs = getattr(path.stat(), 'st_file_attributes', 0)
        return bool(attrs & getattr(stat, 'FILE_ATTRIBUTE_HIDDEN', 0))
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Core cleanup classes
# ---------------------------------------------------------------------------
class TempFileCleaner:
    """Remove downpour-generated temporary files from common locations."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path(__file__).parent

    def clean(self) -> CleanupResult:
        t0 = time.monotonic()
        result = CleanupResult(operation="temp_files", success=True)
        search_dirs = [
            self.base_dir,
            Path(os.environ.get("TEMP", "C:/Windows/Temp")),
            Path(os.environ.get("TMP",  "C:/Windows/Temp")),
        ]
        for directory in search_dirs:
            for pattern in TEMP_PATTERNS:
                for match in directory.glob(pattern):
                    ok, freed = _safe_remove(match)
                    if ok:
                        result.files_removed += 1
                        result.bytes_freed += freed
                    else:
                        result.errors.append(str(match))
        result.duration_seconds = time.monotonic() - t0
        logger.info("TempFileCleaner: removed %d files, freed %d bytes",
                    result.files_removed, result.bytes_freed)
        return result


class LogCleaner:
    """Rotate and prune old downpour log files."""

    def __init__(self, base_dir: Optional[Path] = None,
                 retention_days: int = LOG_RETENTION_DAYS,
                 max_size_mb: float = MAX_LOG_SIZE_MB):
        self.base_dir = base_dir or Path(__file__).parent
        self.retention_days = retention_days
        self.max_size_bytes = int(max_size_mb * 1024 * 1024)
        self.cutoff = datetime.now() - timedelta(days=retention_days)

    def clean(self) -> CleanupResult:
        t0 = time.monotonic()
        result = CleanupResult(operation="log_files", success=True)
        for log_path in self.base_dir.glob("*.log*"):
            try:
                mtime = datetime.fromtimestamp(log_path.stat().st_mtime)
                size  = log_path.stat().st_size
                if mtime < self.cutoff or size > self.max_size_bytes:
                    ok, freed = _safe_remove(log_path)
                    if ok:
                        result.files_removed += 1
                        result.bytes_freed += freed
                    else:
                        result.errors.append(str(log_path))
            except Exception as exc:
                result.errors.append(f"{log_path}: {exc}")
        result.duration_seconds = time.monotonic() - t0
        logger.info("LogCleaner: removed %d log files", result.files_removed)
        return result


class CacheCleaner:
    """Clear Python __pycache__ and downpour in-memory / on-disk caches."""

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path(__file__).parent

    def clean(self) -> CleanupResult:
        t0 = time.monotonic()
        result = CleanupResult(operation="cache", success=True)
        for cache_dir in self.base_dir.rglob("__pycache__"):
            freed = _dir_size(cache_dir)
            ok, _ = _safe_remove(cache_dir)
            if ok:
                result.files_removed += 1
                result.bytes_freed += freed
        for pkl in self.base_dir.glob("*.pkl"):
            ok, freed = _safe_remove(pkl)
            if ok:
                result.files_removed += 1
                result.bytes_freed += freed
        gc.collect()
        result.duration_seconds = time.monotonic() - t0
        logger.info("CacheCleaner: cleared %d items, freed %d bytes",
                    result.files_removed, result.bytes_freed)
        return result


class QuarantineCleaner:
    """Purge expired quarantine entries from the DB and disk."""

    def __init__(self, db_path: Optional[Path] = None,
                 retention_days: int = QUARANTINE_RETENTION_DAYS):
        self.db_path = db_path or _default_downpour_db_path()
        self.retention_days = retention_days


    def clean(self) -> CleanupResult:
        t0 = time.monotonic()
        result = CleanupResult(operation="quarantine", success=True)
        cutoff = (datetime.now() - timedelta(days=self.retention_days)).isoformat()
        if not self.db_path.exists():
            result.duration_seconds = time.monotonic() - t0
            return result
        try:
            with sqlite3.connect(str(self.db_path)) as conn:
                rows = conn.execute(
                    "SELECT quarantine_path FROM quarantine WHERE quarantined_at < ?",
                    (cutoff,)
                ).fetchall()
                for (qpath,) in rows:
                    if qpath:
                        p = Path(qpath)
                        ok, freed = _safe_remove(p)
                        if ok:
                            result.files_removed += 1
                            result.bytes_freed += freed
                conn.execute("DELETE FROM quarantine WHERE quarantined_at < ?", (cutoff,))
                conn.commit()
        except Exception as exc:
            result.errors.append(str(exc))
            result.success = False
        result.duration_seconds = time.monotonic() - t0
        logger.info("QuarantineCleaner: purged %d expired entries", result.files_removed)
        return result


class RegistryCleaner:
    """Remove leftover Downpour registry keys (used during uninstall)."""

    def clean(self) -> CleanupResult:
        t0 = time.monotonic()
        result = CleanupResult(operation="registry", success=True)
        for hive, key_path in DOWNPOUR_REG_KEYS:
            try:
                winreg.DeleteKey(hive, key_path)
                result.files_removed += 1
                logger.debug("Removed registry key: %s", key_path)
            except FileNotFoundError:
                pass  # Key doesn't exist - fine
            except PermissionError as exc:
                result.errors.append(f"Permission denied: {key_path} - {exc}")
            except Exception as exc:
                result.errors.append(f"{key_path}: {exc}")
        result.duration_seconds = time.monotonic() - t0
        return result


class DatabaseCleaner:
    """Vacuum and prune old records from the downpour SQLite database."""

    def __init__(self, db_path: Optional[Path] = None, max_age_days: int = 180):
        self.db_path = db_path or _default_downpour_db_path()
        self.max_age_days = max_age_days

    def clean(self) -> CleanupResult:
        t0 = time.monotonic()
        result = CleanupResult(operation="database", success=True)
        if not self.db_path.exists():
            result.duration_seconds = time.monotonic() - t0
            return result
        cutoff = (datetime.now() - timedelta(days=self.max_age_days)).isoformat()
        try:
            size_before = self.db_path.stat().st_size
            with sqlite3.connect(str(self.db_path)) as conn:
                for table, col in [
                    ("threat_history", "detected_at"),
                    ("network_events", "timestamp"),
                    ("behavioral_alerts", "timestamp"),
                    ("scan_history", "started_at"),
                    ("model_errors", "logged_at"),
                ]:
                    try:
                        cur = conn.execute(
                            f"DELETE FROM {table} WHERE {col} < ?", (cutoff,)
                        )
                        result.files_removed += cur.rowcount
                    except sqlite3.OperationalError:
                        pass  # Table may not exist yet
                conn.execute("VACUUM")
                conn.commit()
            size_after = self.db_path.stat().st_size
            result.bytes_freed = max(0, size_before - size_after)
        except Exception as exc:
            result.errors.append(str(exc))
            result.success = False
        result.duration_seconds = time.monotonic() - t0
        logger.info("DatabaseCleaner: removed %d rows, freed %d bytes",
                    result.files_removed, result.bytes_freed)
        return result


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------
class DownpourCleaner:
    """
    High-level cleanup orchestrator.
    Call run_full_cleanup() for a complete sweep, or individual methods
    for targeted operations.
    """

    def __init__(self, base_dir: Optional[Path] = None,
                 db_path: Optional[Path] = None):
        self.base_dir = base_dir or Path(__file__).parent
        self.db_path  = db_path
        self._lock    = threading.Lock()

    def run_full_cleanup(self, include_registry: bool = False) -> "_LegacyCleanupReport":
        with self._lock:
            report = _LegacyCleanupReport()
            tasks = [
                TempFileCleaner(self.base_dir).clean,
                LogCleaner(self.base_dir).clean,
                CacheCleaner(self.base_dir).clean,
                QuarantineCleaner(self.db_path).clean,
                DatabaseCleaner(self.db_path).clean,
            ]
            if include_registry:
                tasks.append(RegistryCleaner().clean)
            for task in tasks:
                try:
                    report.results.append(task())
                except Exception as exc:
                    report.results.append(CleanupResult(
                        operation=getattr(task, '__self__', task).__class__.__name__,
                        success=False,
                        errors=[str(exc)]
                    ))
            report.finish()
            self._log_report(report)
            return report

    def cleanup_temp_files(self) -> CleanupResult:
        return TempFileCleaner(self.base_dir).clean()

    def cleanup_logs(self) -> CleanupResult:
        return LogCleaner(self.base_dir).clean()

    def cleanup_caches(self) -> CleanupResult:
        return CacheCleaner(self.base_dir).clean()

    def cleanup_quarantine(self) -> CleanupResult:
        return QuarantineCleaner(self.db_path).clean()

    def cleanup_database(self) -> CleanupResult:
        return DatabaseCleaner(self.db_path).clean()

    def cleanup_registry(self) -> CleanupResult:
        return RegistryCleaner().clean()

    def graceful_shutdown(self, timeout: float = 10.0) -> None:
        try:
            gc.collect()
            TempFileCleaner(self.base_dir).clean()
            self._clean_stale_secure_dirs()
            logger.info("DownpourCleaner: graceful shutdown complete")
        except Exception as exc:
            logger.debug("Graceful shutdown cleanup error (non-fatal): %s", exc)

    def _clean_stale_secure_dirs(self, max_age_hours: float = 1.0) -> None:
        """Remove downpour_secure_* sandbox dirs older than max_age_hours.

        FIX: Each app run creates a new downpour_secure_* temp dir via
        tempfile.mkdtemp() but the app only cleaned files inside them,
        not the directories themselves.  After many runs these accumulate
        (108 dirs, 4.7 MB observed).  This method is called on every clean
        exit via atexit so stale dirs are removed automatically.
        Dirs locked by a running session are skipped silently.
        """
        import time as _time
        cutoff = _time.time() - max_age_hours * 3600
        tmp_dir = self.base_dir / "downpour_tmp"
        if not tmp_dir.is_dir():
            return
        removed = 0
        for d in tmp_dir.glob(SECURE_TMP_PATTERN):
            try:
                if d.is_dir() and d.stat().st_mtime < cutoff:
                    shutil.rmtree(d, ignore_errors=True)
                    removed += 1
            except Exception:
                pass  # Permission-locked dirs skipped silently
        if removed:
            logger.info("DownpourCleaner: removed %d stale secure temp dirs", removed)

    def _log_report(self, report: "_LegacyCleanupReport") -> None:
        total_mb = report.total_bytes_freed / (1024 * 1024)
        errors   = len(report.all_errors)
        logger.info(
            "Cleanup complete - freed %.2f MB, removed %d items, %d error(s)",
            total_mb, report.total_files_removed, errors
        )
        if errors:
            for e in report.all_errors[:10]:
                logger.debug("Cleanup error: %s", e)


# ---------------------------------------------------------------------------
# Module-level singleton + atexit hook
# ---------------------------------------------------------------------------
import atexit as _atexit

_cleaner = DownpourCleaner()
_atexit.register(_cleaner.graceful_shutdown)

# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------
__all__ = [
    "DownpourCleaner",
    "CleanupResult",
    "CleanupReport",
    "CleanupTarget",
    "CleanupEngine",
    "DuplicateFileFinder",
    "DuplicateGroup",
    "RiskLevel",
    "TempFileCleaner",
    "LogCleaner",
    "CacheCleaner",
    "QuarantineCleaner",
    "RegistryCleaner",
    "DatabaseCleaner",
    "size_fmt",
    "TEMP_PATTERNS",
    "LOG_RETENTION_DAYS",
    "QUARANTINE_RETENTION_DAYS",
]


# ---------------------------------------------------------------------------
# GUI-compatible classes expected by downpour_v29_titanium.py
# ---------------------------------------------------------------------------
import hashlib as _hashlib
from enum import Enum as _Enum


def size_fmt(num_bytes: int) -> str:
    """Human-readable byte size string (e.g. '1.4 MB')."""
    try:
        num_bytes = int(num_bytes)
    except (TypeError, ValueError):
        return "0 B"
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


class RiskLevel(_Enum):
    SAFE     = "safe"
    MODERATE = "moderate"
    HIGH     = "high"
    CRITICAL = "critical"


@dataclass
class _CleanupItem:
    """Individual file/directory found during a scan."""
    path:       Path
    size_bytes: int = 0


@dataclass
class CleanupTarget:
    """
    A named cleanup category. The GUI builds one row per CleanupTarget
    and scans lazily. Populated by CleanupEngine.scan().
    """
    key:          str
    label:        str
    icon:         str
    description:  str       = ""
    enabled:      bool      = True
    risk_level:   RiskLevel = RiskLevel.SAFE
    risk_note:    str       = ""
    confirm_msg:  str       = ""
    # Populated after scan():
    scanned_size: int  = 0
    item_count:   int  = 0
    items:        list = field(default_factory=list)  # list of _CleanupItem


@dataclass
class DuplicateGroup:
    """A group of files that are identical (same SHA-256 hash)."""
    file_hash:  str
    paths:      List[Path]
    size_bytes: int
    keep_path:  Optional[Path] = None

    @property
    def files(self) -> List[Path]:
        """Alias for paths — used by the main UI."""
        return self.paths

    @property
    def wasted_bytes(self) -> int:
        return self.size_bytes * max(0, len(self.paths) - 1)


@dataclass
class CleanupReport:
    """
    Aggregated cleanup execution report — GUI-compatible version.
    Fields match what downpour_v29_titanium.py reads after execute_cleanup().
    """
    started_at:    str   = field(default_factory=lambda: datetime.now().isoformat())
    completed_at:  str   = ""
    bytes_freed:   int   = 0
    files_deleted: int   = 0
    dirs_deleted:  int   = 0
    skipped:       int   = 0
    duration_s:    float = 0.0
    errors:        list  = field(default_factory=list)
    results:       list  = field(default_factory=list)

    def finish(self, t0: float = 0.0) -> None:
        self.completed_at = datetime.now().isoformat()
        if t0:
            self.duration_s = time.monotonic() - t0

    # Legacy compat properties (used by DownpourCleaner internals)
    @property
    def total_bytes_freed(self) -> int:
        return self.bytes_freed + sum(getattr(r, 'bytes_freed', 0) for r in self.results)

    @property
    def total_files_removed(self) -> int:
        return self.files_deleted + sum(getattr(r, 'files_removed', 0) for r in self.results)

    @property
    def all_errors(self) -> List[str]:
        return list(self.errors) + [e for r in self.results for e in getattr(r, 'errors', [])]


# ---------------------------------------------------------------------------
# DuplicateFileFinder
# ---------------------------------------------------------------------------
class DuplicateFileFinder:
    """Finds duplicate files by SHA-256 hash across one or more directories."""

    def __init__(self, min_size_bytes: int = 1024):
        self.min_size_bytes = min_size_bytes
        self._stop = threading.Event()
        self.targets: List[CleanupTarget] = []

    def stop(self) -> None:
        self._stop.set()

    def find_duplicates(
        self,
        paths: List[Path],
        extensions: Optional[Set[str]] = None,
        include_hidden: bool = False,
        progress_callback: Optional[Callable] = None,
    ) -> List[DuplicateGroup]:
        """Scan paths for duplicate files. progress_callback(current, total) called periodically."""
        self._stop.clear()
        candidates: List[Path] = []
        for root in paths:
            for p in Path(root).rglob("*"):
                if self._stop.is_set():
                    return []
                if not p.is_file():
                    continue
                if not include_hidden and _is_hidden_path(p):
                    continue
                if extensions and p.suffix.lower() not in extensions:
                    continue
                try:
                    if p.stat().st_size >= self.min_size_bytes:
                        candidates.append(p)
                except OSError:
                    pass

        # Group by size first (cheap), then hash (expensive)
        size_groups: Dict[int, List[Path]] = {}
        for p in candidates:
            try:
                sz = p.stat().st_size
                size_groups.setdefault(sz, []).append(p)
            except OSError:
                pass

        total = sum(len(v) for v in size_groups.values() if len(v) > 1)
        done  = 0
        hash_groups: Dict[str, List[Path]] = {}

        for sz, files in size_groups.items():
            if len(files) < 2:
                continue
            for p in files:
                if self._stop.is_set():
                    return []
                h = self._hash_file(p)
                if h:
                    hash_groups.setdefault(h, []).append(p)
                done += 1
                if progress_callback and done % 50 == 0:
                    try:
                        progress_callback(done, total)
                    except Exception:
                        pass

        groups: List[DuplicateGroup] = []
        for file_hash, paths_list in hash_groups.items():
            if len(paths_list) < 2:
                continue
            try:
                sz = paths_list[0].stat().st_size
            except OSError:
                sz = 0
            groups.append(DuplicateGroup(
                file_hash=file_hash,
                paths=paths_list,
                size_bytes=sz,
            ))
        return sorted(groups, key=lambda g: g.wasted_bytes, reverse=True)

    def delete_duplicates(
        self,
        groups: List['DuplicateGroup'],
        progress_cb: Optional[Callable] = None,
    ) -> tuple:
        """Delete duplicate files, keeping the designated keep_path in each group.

        Returns (deleted_count, freed_bytes, error_list).
        """
        deleted = 0
        freed = 0
        errors: List[str] = []
        total = sum(max(0, len(g.paths) - 1) for g in groups)
        done = 0
        for grp in groups:
            if not grp.keep_path:
                continue
            for fp in grp.paths:
                if fp == grp.keep_path:
                    continue
                try:
                    sz = fp.stat().st_size
                    fp.unlink()
                    deleted += 1
                    freed += sz
                except Exception as exc:
                    errors.append(f'{fp}: {exc}')
                done += 1
                if progress_cb and done % 10 == 0:
                    try:
                        progress_cb(f'Deleted {deleted:,}/{total:,} files…')
                    except Exception:
                        pass
        return deleted, freed, errors

    @staticmethod
    def _hash_file(path: Path) -> Optional[str]:
        try:
            h = _hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Default category definitions (used to pre-populate CleanupEngine.targets)
# ---------------------------------------------------------------------------
_DEFAULT_CATEGORIES: List[Dict] = [
    # ── Windows System Temp ───────────────────────────────────────────────
    {
        "key": "win_temp",
        "label": "Windows Temp",
        "icon": "🗑",
        "description": "C:\\Windows\\Temp — system-wide temporary files created by Windows and installers.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "user_temp",
        "label": "User Temp (%TEMP%)",
        "icon": "📂",
        "description": "%TEMP% and %LOCALAPPDATA%\\Temp — per-user temporary files from apps and Windows.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "prefetch",
        "label": "Prefetch Files",
        "icon": "⚡",
        "description": "C:\\Windows\\Prefetch — *.pf launch-accelerator files. Safe to delete; Windows rebuilds them.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "thumbnails",
        "label": "Thumbnail Cache",
        "icon": "🖼",
        "description": "Explorer thumbcache_*.db files in %LOCALAPPDATA%\\Microsoft\\Windows\\Explorer.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "win_error_reports",
        "label": "Windows Error Reports",
        "icon": "💥",
        "description": "%LOCALAPPDATA%\\Microsoft\\Windows\\WER — crash dump and error report files.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "recent_files",
        "label": "Recent File Links",
        "icon": "🕐",
        "description": "%APPDATA%\\Microsoft\\Windows\\Recent — .lnk shortcut files tracking recent file access.",
        "risk_level": RiskLevel.SAFE,
        "enabled": False,
    },
    {
        "key": "delivery_opt",
        "label": "Delivery Optimisation",
        "icon": "📦",
        "description": "C:\\Windows\\SoftwareDistribution\\DeliveryOptimization — Windows Update peer cache.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "win_update_cache",
        "label": "Windows Update Cache",
        "icon": "🔄",
        "description": "C:\\Windows\\SoftwareDistribution\\Download — downloaded update packages (re-downloaded on next update).",
        "risk_level": RiskLevel.MODERATE,
        "risk_note": "Deleting forces Windows to re-download pending updates.",
        "enabled": False,
    },
    {
        "key": "font_cache",
        "label": "Font Cache",
        "icon": "🔤",
        "description": "Windows font cache files (FNTCACHE.DAT, FontDPI.log). Rebuilt automatically on next boot.",
        "risk_level": RiskLevel.SAFE,
        "enabled": False,
    },
    {
        "key": "recycle_bin",
        "label": "Recycle Bin",
        "icon": "♻",
        "description": "Files currently in the Windows Recycle Bin across all drives.",
        "risk_level": RiskLevel.MODERATE,
        "risk_note": "Permanently deletes all recycled files — cannot be recovered.",
        "enabled": False,
    },
    # ── Browser Caches ────────────────────────────────────────────────────
    {
        "key": "chrome_cache",
        "label": "Chrome Cache",
        "icon": "🌐",
        "description": "Google Chrome cache, code cache, and GPU cache for all profiles.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "edge_cache",
        "label": "Edge Cache",
        "icon": "🌐",
        "description": "Microsoft Edge cache, code cache, and GPU cache for all profiles.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "firefox_cache",
        "label": "Firefox Cache",
        "icon": "🌐",
        "description": "Mozilla Firefox cache2 and startupCache for all profiles.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "opera_cache",
        "label": "Opera Cache",
        "icon": "🌐",
        "description": "Opera browser cache files.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "brave_cache",
        "label": "Brave Cache",
        "icon": "🌐",
        "description": "Brave browser cache files.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "vivaldi_cache",
        "label": "Vivaldi Cache",
        "icon": "🌐",
        "description": "Vivaldi browser cache files.",
        "risk_level": RiskLevel.SAFE,
        "enabled": False,
    },
    # ── App Caches ────────────────────────────────────────────────────────
    {
        "key": "ms_teams_cache",
        "label": "Teams Cache",
        "icon": "💬",
        "description": "Microsoft Teams cache (blob_storage, Cache, GPUCache, Code Cache).",
        "risk_level": RiskLevel.SAFE,
        "enabled": False,
    },
    {
        "key": "discord_cache",
        "label": "Discord Cache",
        "icon": "💬",
        "description": "Discord cache and code cache folders.",
        "risk_level": RiskLevel.SAFE,
        "enabled": False,
    },
    {
        "key": "spotify_cache",
        "label": "Spotify Cache",
        "icon": "🎵",
        "description": "Spotify cached tracks and data files.",
        "risk_level": RiskLevel.SAFE,
        "enabled": False,
    },
    {
        "key": "steam_cache",
        "label": "Steam Download Cache",
        "icon": "🎮",
        "description": "Steam\\appcache and depotcache (not game files).",
        "risk_level": RiskLevel.SAFE,
        "enabled": False,
    },
    # ── Logs ──────────────────────────────────────────────────────────────
    {
        "key": "iis_logs",
        "label": "IIS Logs",
        "icon": "📄",
        "description": "C:\\inetpub\\logs — IIS web server log files.",
        "risk_level": RiskLevel.SAFE,
        "enabled": False,
    },
    {
        "key": "win_logs",
        "label": "Windows Event Logs",
        "icon": "📋",
        "description": "C:\\Windows\\System32\\winevt\\Logs — Windows event log files (.evtx). Security logs cleared.",
        "risk_level": RiskLevel.HIGH,
        "risk_note": "Clearing event logs removes audit trail and forensic evidence.",
        "enabled": False,
    },
    {
        "key": "logs",
        "label": "Downpour Logs",
        "icon": "📝",
        "description": f"Downpour log files older than {LOG_RETENTION_DAYS} days or larger than {MAX_LOG_SIZE_MB} MB.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    # ── Downpour-specific ────────────────────────────────────────────────
    {
        "key": "temp",
        "label": "Downpour Temp",
        "icon": "🛡",
        "description": "Downpour-generated temp files matching downpour_*.tmp, dp_cache_*.pkl patterns.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "cache",
        "label": "Python Cache",
        "icon": "⚡",
        "description": "__pycache__ directories and compiled .pyc bytecode files in the Downpour folder.",
        "risk_level": RiskLevel.SAFE,
        "enabled": True,
    },
    {
        "key": "quarantine",
        "label": "Expired Quarantine",
        "icon": "🔒",
        "description": f"Quarantined threat files older than {QUARANTINE_RETENTION_DAYS} days.",
        "risk_level": RiskLevel.MODERATE,
        "risk_note": "Permanently removes old quarantine samples.",
        "enabled": False,
    },
    {
        "key": "database",
        "label": "Database Records",
        "icon": "🗄",
        "description": "Old scan records, network events, and behavioral alerts from the Downpour database.",
        "risk_level": RiskLevel.MODERATE,
        "risk_note": "Removes historical threat detection records.",
        "enabled": False,
    },
]


# ---------------------------------------------------------------------------
# CleanupEngine — full GUI-compatible implementation
# ---------------------------------------------------------------------------
class CleanupEngine:
    """
    Main cleanup engine used by the Downpour GUI Cleanup tab.
    Provides a keyed category system fully compatible with downpour_v29_titanium.py.
    """

    def __init__(self, base_dir: Optional[Path] = None,
                 db_path: Optional[Path] = None):
        self.cleaner    = DownpourCleaner(base_dir, db_path)
        self.dup_finder = DuplicateFileFinder()
        self._stop      = threading.Event()
        self._lock      = threading.Lock()

        # Pre-build category targets so the GUI can iterate .targets immediately
        # without needing to call scan() first (fixes "no attribute 'targets'" error)
        self.targets: List[CleanupTarget] = [
            CleanupTarget(
                key=c["key"],
                label=c["label"],
                icon=c["icon"],
                description=c.get("description", ""),
                risk_level=c.get("risk_level", RiskLevel.SAFE),
                risk_note=c.get("risk_note", ""),
                confirm_msg=c.get("confirm_msg", ""),
                enabled=c.get("enabled", True),
            )
            for c in _DEFAULT_CATEGORIES
        ]
        self._target_map: Dict[str, CleanupTarget] = {t.key: t for t in self.targets}

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------
    def get_target(self, key: str) -> Optional[CleanupTarget]:
        """Return the CleanupTarget for a given key, or None if not found."""
        return self._target_map.get(key)

    def stop(self) -> None:
        self._stop.set()
        self.dup_finder.stop()


    # ------------------------------------------------------------------
    # scan() — GUI calls: scan(keys=checked, progress_cb=_prog, all_drives=True)
    #          returns dict[key -> CleanupTarget] with items populated
    # ------------------------------------------------------------------
    def scan(
        self,
        keys: Optional[List[str]] = None,
        progress_cb: Optional[Callable] = None,
        all_drives: bool = False,
    ) -> Dict[str, CleanupTarget]:
        """
        Scan selected categories. Returns dict mapping key -> CleanupTarget.
        progress_cb(message: str, percent: float) is called with status updates.
        """
        self._stop.clear()
        base = self.cleaner.base_dir

        def _cb(msg: str, pct: float = 0.0) -> None:
            if progress_cb:
                try:
                    progress_cb(msg, pct)
                except Exception:
                    pass

        active_keys = set(keys) if keys else {t.key for t in self.targets}
        ordered_targets = [t for t in self.targets if t.key in active_keys]
        results: Dict[str, CleanupTarget] = {}
        n = max(len(ordered_targets), 1)

        for step_i, target in enumerate(ordered_targets, 1):
            if self._stop.is_set():
                break
            key = target.key
            # Reset from any previous scan
            target.scanned_size = 0
            target.item_count   = 0
            target.items        = []

            pct_start = (step_i - 1) / n * 100
            pct_end   = step_i / n * 100
            _cb(f"Scanning {target.label}...", pct_start)

            try:
                # ── Windows system categories ──────────────────────────────
                if key == "win_temp":
                    self._scan_win_temp(target)
                elif key == "user_temp":
                    self._scan_user_temp(target)
                elif key == "prefetch":
                    self._scan_prefetch(target)
                elif key == "thumbnails":
                    self._scan_thumbnails(target)
                elif key == "win_error_reports":
                    self._scan_win_error_reports(target)
                elif key == "recent_files":
                    self._scan_recent_files(target)
                elif key == "delivery_opt":
                    self._scan_delivery_opt(target)
                elif key == "win_update_cache":
                    self._scan_win_update_cache(target)
                elif key == "font_cache":
                    self._scan_font_cache(target)
                elif key == "recycle_bin":
                    self._scan_recycle_bin(target)
                # ── Browser caches ─────────────────────────────────────────
                elif key == "chrome_cache":
                    self._scan_browser_cache(target,
                        r"Google\Chrome\User Data",
                        ["Cache", "Code Cache", "GPUCache", "Service Worker\\CacheStorage"])
                elif key == "edge_cache":
                    self._scan_browser_cache(target,
                        r"Microsoft\Edge\User Data",
                        ["Cache", "Code Cache", "GPUCache", "Service Worker\\CacheStorage"])
                elif key == "firefox_cache":
                    self._scan_firefox_cache(target)
                elif key == "opera_cache":
                    self._scan_browser_cache(target,
                        r"Opera Software\Opera Stable",
                        ["Cache", "Code Cache", "GPUCache"],
                        roaming=True)
                elif key == "brave_cache":
                    self._scan_browser_cache(target,
                        r"BraveSoftware\Brave-Browser\User Data",
                        ["Cache", "Code Cache", "GPUCache", "Service Worker\\CacheStorage"])
                elif key == "vivaldi_cache":
                    self._scan_browser_cache(target,
                        r"Vivaldi\User Data",
                        ["Cache", "Code Cache", "GPUCache"])
                # ── App caches ─────────────────────────────────────────────
                elif key == "ms_teams_cache":
                    self._scan_app_cache_dirs(target, [
                        r"Microsoft\Teams\Cache",
                        r"Microsoft\Teams\blob_storage",
                        r"Microsoft\Teams\GPUCache",
                        r"Microsoft\Teams\Code Cache",
                        r"Microsoft\Teams\databases",
                        r"Microsoft\Teams\Local Storage",
                    ])
                elif key == "discord_cache":
                    self._scan_app_cache_dirs(target, [
                        r"discord\Cache",
                        r"discord\Code Cache",
                        r"discord\GPUCache",
                    ])
                elif key == "spotify_cache":
                    self._scan_app_cache_dirs(target, [
                        r"Spotify\Data",
                        r"Spotify\Browser\Cache",
                    ], roaming=True)
                elif key == "steam_cache":
                    self._scan_steam_cache(target)
                # ── Logs ───────────────────────────────────────────────────
                elif key == "iis_logs":
                    self._scan_dir_all_files(target, Path(r"C:\inetpub\logs"), max_age_days=30)
                elif key == "win_logs":
                    self._scan_dir_all_files(target,
                        Path(r"C:\Windows\System32\winevt\Logs"), pattern="*.evtx")
                # ── Downpour-specific ──────────────────────────────────────
                elif key == "temp":
                    self._scan_temp(target, base)
                elif key == "logs":
                    self._scan_logs(target, base)
                elif key == "cache":
                    self._scan_cache(target, base)
                elif key == "quarantine":
                    self._scan_quarantine(target)
                elif key == "database":
                    self._scan_database(target)
            except Exception as exc:
                logger.warning("CleanupEngine scan error for '%s': %s", key, exc)

            _cb(f"Scanned {target.label} - {size_fmt(target.scanned_size)}", pct_end)
            results[key] = target

        return results


    # ------------------------------------------------------------------
    # Per-category scan helpers
    # ------------------------------------------------------------------
    def _scan_temp(self, target: CleanupTarget, base: Path) -> None:
        search_dirs = [
            base,
            Path(os.environ.get("TEMP", "C:/Windows/Temp")),
            Path(os.environ.get("TMP",  "C:/Windows/Temp")),
        ]
        for directory in search_dirs:
            if not directory.is_dir():
                continue
            for pattern in TEMP_PATTERNS:
                for p in directory.glob(pattern):
                    if self._stop.is_set():
                        return
                    try:
                        sz = p.stat().st_size
                        target.items.append(_CleanupItem(path=p, size_bytes=sz))
                        target.scanned_size += sz
                        target.item_count   += 1
                    except OSError:
                        pass

    def _scan_logs(self, target: CleanupTarget, base: Path) -> None:
        cutoff    = datetime.now() - timedelta(days=LOG_RETENTION_DAYS)
        max_bytes = int(MAX_LOG_SIZE_MB * 1024 * 1024)
        log_dirs  = [base, base / "downpour_data" / "logs"]
        for log_dir in log_dirs:
            if not log_dir.is_dir():
                continue
            for p in log_dir.glob("*.log*"):
                if self._stop.is_set():
                    return
                try:
                    sz    = p.stat().st_size
                    mtime = datetime.fromtimestamp(p.stat().st_mtime)
                    if mtime < cutoff or sz > max_bytes:
                        target.items.append(_CleanupItem(path=p, size_bytes=sz))
                        target.scanned_size += sz
                        target.item_count   += 1
                except OSError:
                    pass


    def _scan_cache(self, target: CleanupTarget, base: Path) -> None:
        for cache_dir in base.rglob("__pycache__"):
            if self._stop.is_set():
                return
            sz = _dir_size(cache_dir)
            target.items.append(_CleanupItem(path=cache_dir, size_bytes=sz))
            target.scanned_size += sz
            target.item_count   += 1
        for pkl in base.glob("*.pkl"):
            if self._stop.is_set():
                return
            try:
                sz = pkl.stat().st_size
                target.items.append(_CleanupItem(path=pkl, size_bytes=sz))
                target.scanned_size += sz
                target.item_count   += 1
            except OSError:
                pass

    def _scan_quarantine(self, target: CleanupTarget) -> None:
        q_dir = self.cleaner.base_dir / "downpour_data" / "quarantine"
        if not q_dir.is_dir():
            return
        cutoff = datetime.now() - timedelta(days=QUARANTINE_RETENTION_DAYS)
        for p in q_dir.rglob("*"):
            if self._stop.is_set():
                return
            try:
                if p.is_file():
                    mtime = datetime.fromtimestamp(p.stat().st_mtime)
                    if mtime < cutoff:
                        sz = p.stat().st_size
                        target.items.append(_CleanupItem(path=p, size_bytes=sz))
                        target.scanned_size += sz
                        target.item_count   += 1
            except OSError:
                pass


    def _scan_database(self, target: CleanupTarget) -> None:
        db_path = (self.cleaner.db_path
                   or self.cleaner.base_dir / "downpour_data" / "titanium.db")
        if not db_path or not Path(db_path).exists():
            return
        try:
            cutoff = (datetime.now() - timedelta(days=180)).isoformat()
            with sqlite3.connect(str(db_path)) as conn:
                for table, col in [
                    ("threat_history",    "detected_at"),
                    ("network_events",    "timestamp"),
                    ("behavioral_alerts", "timestamp"),
                    ("scan_history",      "started_at"),
                ]:
                    try:
                        row = conn.execute(
                            f"SELECT COUNT(*) FROM {table} WHERE {col} < ?",
                            (cutoff,)
                        ).fetchone()
                        if row and row[0]:
                            target.item_count   += row[0]
                            target.scanned_size += row[0] * 512  # ~512 B/row estimate
                    except Exception:
                        pass
        except Exception as exc:
            logger.debug("CleanupEngine._scan_database: %s", exc)

    # ------------------------------------------------------------------
    # New system scan helpers
    # ------------------------------------------------------------------

    def _add_dir(self, target: CleanupTarget, directory: Path,
                 pattern: str = "*", max_age_days: int = 0) -> None:
        """Recursively add all files in *directory* to target.items.
        If max_age_days > 0, only include files older than that many days."""
        if not directory.is_dir():
            return
        cutoff = (datetime.now() - timedelta(days=max_age_days)) if max_age_days else None
        try:
            for p in directory.rglob(pattern):
                if self._stop.is_set():
                    return
                if not p.is_file():
                    continue
                try:
                    st = p.stat()
                    if cutoff and datetime.fromtimestamp(st.st_mtime) > cutoff:
                        continue
                    sz = st.st_size
                    target.items.append(_CleanupItem(path=p, size_bytes=sz))
                    target.scanned_size += sz
                    target.item_count += 1
                except OSError:
                    pass
        except (OSError, PermissionError):
            pass

    def _add_dir_toplevel(self, target: CleanupTarget, directory: Path) -> None:
        """Add only the immediate children of *directory* (files + subdirs)."""
        if not directory.is_dir():
            return
        try:
            for p in directory.iterdir():
                if self._stop.is_set():
                    return
                try:
                    if p.is_file():
                        sz = p.stat().st_size
                        target.items.append(_CleanupItem(path=p, size_bytes=sz))
                        target.scanned_size += sz
                        target.item_count += 1
                    elif p.is_dir():
                        sz = _dir_size(p)
                        target.items.append(_CleanupItem(path=p, size_bytes=sz))
                        target.scanned_size += sz
                        target.item_count += 1
                except OSError:
                    pass
        except (OSError, PermissionError):
            pass

    def _scan_win_temp(self, target: CleanupTarget) -> None:
        """C:\\Windows\\Temp — skip files younger than 1 day (may be in use)."""
        self._add_dir(target, Path(r"C:\Windows\Temp"), max_age_days=1)

    def _scan_user_temp(self, target: CleanupTarget) -> None:
        """All per-user temp directories."""
        seen: set = set()
        for env_var in ("TEMP", "TMP", "LOCALAPPDATA"):
            raw = os.environ.get(env_var, "")
            if not raw:
                continue
            base = Path(raw)
            # LOCALAPPDATA\Temp
            candidate = base / "Temp" if env_var == "LOCALAPPDATA" else base
            resolved = str(candidate.resolve()) if candidate.exists() else str(candidate)
            if resolved in seen:
                continue
            seen.add(resolved)
            self._add_dir(target, candidate, max_age_days=1)

    def _scan_prefetch(self, target: CleanupTarget) -> None:
        self._add_dir(target, Path(r"C:\Windows\Prefetch"), pattern="*.pf")

    def _scan_thumbnails(self, target: CleanupTarget) -> None:
        local_app = os.environ.get("LOCALAPPDATA", "")
        if local_app:
            thumb_dir = Path(local_app) / "Microsoft" / "Windows" / "Explorer"
            self._add_dir(target, thumb_dir, pattern="thumbcache_*.db")
            self._add_dir(target, thumb_dir, pattern="iconcache_*.db")

    def _scan_win_error_reports(self, target: CleanupTarget) -> None:
        local_app = os.environ.get("LOCALAPPDATA", "")
        appdata   = os.environ.get("APPDATA", "")
        candidates = []
        if local_app:
            candidates += [
                Path(local_app) / "Microsoft" / "Windows" / "WER",
                Path(local_app) / "CrashDumps",
            ]
        if appdata:
            candidates.append(Path(appdata) / "Microsoft" / "Windows" / "WER")
        # Also system WER
        candidates.append(Path(r"C:\ProgramData\Microsoft\Windows\WER"))
        for d in candidates:
            self._add_dir(target, d)

    def _scan_recent_files(self, target: CleanupTarget) -> None:
        appdata = os.environ.get("APPDATA", "")
        if appdata:
            recent = Path(appdata) / "Microsoft" / "Windows" / "Recent"
            self._add_dir(target, recent, pattern="*.lnk")
            self._add_dir(target, recent / "AutomaticDestinations")
            self._add_dir(target, recent / "CustomDestinations")

    def _scan_delivery_opt(self, target: CleanupTarget) -> None:
        do_dir = Path(r"C:\Windows\SoftwareDistribution\DeliveryOptimization")
        self._add_dir(target, do_dir)

    def _scan_win_update_cache(self, target: CleanupTarget) -> None:
        dl_dir = Path(r"C:\Windows\SoftwareDistribution\Download")
        self._add_dir(target, dl_dir)

    def _scan_font_cache(self, target: CleanupTarget) -> None:
        candidates = [
            Path(r"C:\Windows\System32\FNTCACHE.DAT"),
            Path(r"C:\Windows\SysWOW64\FNTCACHE.DAT"),
            Path(r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache"),
        ]
        for c in candidates:
            if c.is_file():
                try:
                    sz = c.stat().st_size
                    target.items.append(_CleanupItem(path=c, size_bytes=sz))
                    target.scanned_size += sz
                    target.item_count += 1
                except OSError:
                    pass
            elif c.is_dir():
                self._add_dir(target, c)

    def _scan_recycle_bin(self, target: CleanupTarget) -> None:
        import string
        for letter in string.ascii_uppercase:
            rb = Path(f"{letter}:\\$Recycle.Bin")
            if not rb.is_dir():
                continue
            try:
                for user_dir in rb.iterdir():
                    self._add_dir(target, user_dir)
            except (OSError, PermissionError):
                pass

    def _scan_browser_cache(self, target: CleanupTarget,
                             rel_path: str,
                             cache_subdirs: List[str],
                             roaming: bool = False) -> None:
        """Generic Chromium-based browser cache scanner.
        Looks in all profile folders (Default, Profile 1, Profile 2, …)."""
        base_env = "APPDATA" if roaming else "LOCALAPPDATA"
        base = os.environ.get(base_env, "")
        if not base:
            return
        browser_root = Path(base) / rel_path
        if not browser_root.is_dir():
            return
        # Scan named profiles and root-level cache dirs
        profile_dirs = [browser_root]
        try:
            for child in browser_root.iterdir():
                if child.is_dir() and (
                    child.name == "Default" or child.name.startswith("Profile ")
                ):
                    profile_dirs.append(child)
        except (OSError, PermissionError):
            pass
        for profile in profile_dirs:
            for sub in cache_subdirs:
                self._add_dir_toplevel(target, profile / sub)

    def _scan_firefox_cache(self, target: CleanupTarget) -> None:
        local_app = os.environ.get("LOCALAPPDATA", "")
        appdata   = os.environ.get("APPDATA", "")
        ff_roots = []
        if local_app:
            ff_roots.append(Path(local_app) / "Mozilla" / "Firefox" / "Profiles")
        if appdata:
            ff_roots.append(Path(appdata) / "Mozilla" / "Firefox" / "Profiles")
        for ff_root in ff_roots:
            if not ff_root.is_dir():
                continue
            try:
                for profile in ff_root.iterdir():
                    if not profile.is_dir():
                        continue
                    for sub in ["cache2", "startupCache", "thumbnails",
                                "storage\\default", "shader-cache"]:
                        self._add_dir(target, profile / sub)
            except (OSError, PermissionError):
                pass

    def _scan_app_cache_dirs(self, target: CleanupTarget,
                              rel_paths: List[str],
                              roaming: bool = False) -> None:
        """Scan one or more LOCALAPPDATA/APPDATA relative cache paths."""
        base = os.environ.get("APPDATA" if roaming else "LOCALAPPDATA", "")
        if not base:
            return
        for rel in rel_paths:
            self._add_dir(target, Path(base) / rel)

    def _scan_steam_cache(self, target: CleanupTarget) -> None:
        steam_roots = [
            Path(r"C:\Program Files (x86)\Steam"),
            Path(r"C:\Program Files\Steam"),
        ]
        local_app = os.environ.get("LOCALAPPDATA", "")
        if local_app:
            steam_roots.append(Path(local_app) / "Steam")
        for root in steam_roots:
            if root.is_dir():
                self._add_dir(target, root / "appcache")
                self._add_dir(target, root / "depotcache")

    def _scan_dir_all_files(self, target: CleanupTarget, directory: Path,
                             pattern: str = "*", max_age_days: int = 0) -> None:
        self._add_dir(target, directory, pattern=pattern, max_age_days=max_age_days)

    # ------------------------------------------------------------------
    # execute_cleanup() — GUI calls: execute_cleanup(keys=keys, progress_cb=_prog, flush_dns=True)
    # ------------------------------------------------------------------
    def execute_cleanup(
        self,
        keys: Optional[List[str]] = None,
        progress_cb: Optional[Callable] = None,
        flush_dns: bool = False,
    ) -> CleanupReport:
        """
        Delete all scanned items in the selected categories.
        Returns a CleanupReport with files_deleted, dirs_deleted, skipped, bytes_freed, duration_s.
        """
        t0 = time.monotonic()
        report = CleanupReport()

        def _cb(msg: str, pct: float = 0.0) -> None:
            if progress_cb:
                try:
                    progress_cb(msg, pct)
                except Exception:
                    pass

        active_keys      = set(keys) if keys else {t.key for t in self.targets}
        targets_to_clean = [t for t in self.targets if t.key in active_keys]
        total_items     = max(sum(t.item_count for t in targets_to_clean), 1)
        done            = 0


        for target in targets_to_clean:
            if self._stop.is_set():
                break

            # Recycle Bin: use PowerShell to empty all drives cleanly
            if target.key == "recycle_bin":
                try:
                    import subprocess
                    r = subprocess.run(
                        ["powershell", "-NoProfile", "-Command",
                         "Clear-RecycleBin -Force -ErrorAction SilentlyContinue"],
                        capture_output=True, timeout=30)
                    report.files_deleted += target.item_count
                    report.bytes_freed   += target.scanned_size
                except Exception as exc:
                    logger.warning("Recycle bin empty error: %s", exc)
                    report.errors.append(f"Recycle Bin: {exc}")
                target.scanned_size = 0; target.item_count = 0; target.items = []
                continue

            # Windows event logs: use wevtutil
            if target.key == "win_logs":
                try:
                    import subprocess
                    logs = ["Application", "System", "Security", "Setup",
                            "Microsoft-Windows-PowerShell/Operational"]
                    for log in logs:
                        try:
                            subprocess.run(
                                ["wevtutil", "cl", log],
                                capture_output=True, timeout=10)
                        except Exception:
                            pass
                    report.files_deleted += target.item_count
                    report.bytes_freed   += target.scanned_size
                except Exception as exc:
                    logger.warning("Win log clear error: %s", exc)
                    report.errors.append(f"Windows Event Logs: {exc}")
                target.scanned_size = 0; target.item_count = 0; target.items = []
                continue

            # Database: delegate to DatabaseCleaner
            if target.key == "database":
                try:
                    res = DatabaseCleaner(self.cleaner.db_path).clean()
                    report.files_deleted += res.files_removed
                    report.bytes_freed   += res.bytes_freed
                    report.errors.extend(res.errors)
                    report.results.append(res)
                except Exception as exc:
                    logger.warning("DB cleanup error: %s", exc)
                    report.errors.append(f"Database: {exc}")
                target.scanned_size = 0; target.item_count = 0; target.items = []
                continue

            # Quarantine: prefer the DB-aware cleaner when the main DB exists
            if target.key == "quarantine" and Path(self.cleaner.db_path or _default_downpour_db_path()).exists():
                try:
                    res = QuarantineCleaner(self.cleaner.db_path).clean()
                    report.files_deleted += res.files_removed
                    report.bytes_freed   += res.bytes_freed
                    report.errors.extend(res.errors)
                    report.results.append(res)
                except Exception as exc:
                    logger.warning("Quarantine cleanup error: %s", exc)
                    report.errors.append(f"Quarantine: {exc}")
                target.scanned_size = 0; target.item_count = 0; target.items = []
                continue

            for item in list(target.items):
                if self._stop.is_set():
                    break
                done += 1
                pct = done / total_items * 100
                _cb(f"Deleting {item.path.name}...", pct)
                try:
                    if item.path.is_dir():
                        ok, freed = _safe_remove(item.path)
                        if ok:
                            report.dirs_deleted += 1
                            report.bytes_freed  += freed
                        else:
                            report.skipped += 1
                            report.errors.append(f"Could not remove directory: {item.path}")
                    elif item.path.exists():
                        ok, freed = _safe_remove(item.path)
                        if ok:
                            report.files_deleted += 1
                            report.bytes_freed   += freed
                        else:
                            report.skipped += 1
                            report.errors.append(f"Could not remove file: {item.path}")
                    else:
                        report.skipped += 1
                        report.errors.append(f"Path no longer exists: {item.path}")
                except Exception as exc:
                    report.skipped += 1
                    report.errors.append(f"{item.path}: {exc}")
                    logger.debug("Cleanup item error %s: %s", item.path, exc)

            # Reset target after cleanup
            target.scanned_size = 0
            target.item_count   = 0
            target.items        = []


        if flush_dns:
            try:
                import subprocess
                subprocess.run(["ipconfig", "/flushdns"],
                               capture_output=True, timeout=5)
            except Exception:
                pass

        report.finish(t0)
        return report

    # ------------------------------------------------------------------
    # Legacy / convenience pass-throughs
    # ------------------------------------------------------------------
    def clean_targets(self, targets: List[CleanupTarget]) -> CleanupReport:
        """Delete an explicit list of CleanupTarget objects and return a report."""
        t0 = time.monotonic()
        report = CleanupReport()
        for t in targets:
            for item in getattr(t, "items", []):
                ok, freed = _safe_remove(item.path)
                if ok:
                    report.files_deleted += 1
                    report.bytes_freed   += freed
                else:
                    report.skipped += 1
        report.finish(t0)
        return report

    def run_full_cleanup(self, include_registry: bool = False) -> CleanupReport:
        """Run all cleanup tasks via DownpourCleaner and return a GUI-compatible report."""
        legacy = self.cleaner.run_full_cleanup(include_registry=include_registry)
        report = CleanupReport()
        report.bytes_freed   = legacy.total_bytes_freed
        report.files_deleted = legacy.total_files_removed
        report.results       = legacy.results
        report.finish()
        return report


# ---------------------------------------------------------------------------
# DiskAnalyzer — used by the Disk Analyzer tab in the GUI
# ---------------------------------------------------------------------------

@dataclass
class _DiskEntry:
    """Single directory entry returned by DiskAnalyzer.analyze()."""
    path:         str
    size_bytes:   int   = 0
    file_count:   int   = 0
    pct_of_total: float = 0.0


def _get_all_drives() -> List[str]:
    """Return a list of available drive root paths (e.g. ['C:\\\\', 'D:\\\\'])."""
    import string
    drives = []
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        if os.path.isdir(root):
            drives.append(root)
    return drives


class DiskAnalyzer:
    """Analyze disk usage by directory, returning the top-N largest folders."""

    @staticmethod
    def get_drive_info(drive: str) -> dict:
        """Return {'total': int, 'used': int, 'free': int} for a drive."""
        try:
            usage = shutil.disk_usage(drive)
            return {'total': usage.total, 'used': usage.used, 'free': usage.free}
        except Exception:
            return {}

    def analyze(
        self,
        root: str,
        max_depth: int = 1,
        top_n: int = 40,
        progress_cb: Optional[Callable] = None,
    ) -> List[_DiskEntry]:
        """Walk *root* up to *max_depth* levels and return the largest entries."""
        entries: List[_DiskEntry] = []
        root = os.path.abspath(root)

        try:
            children = sorted(os.listdir(root))
        except PermissionError:
            return entries

        total_scanned = 0
        for i, name in enumerate(children):
            child = os.path.join(root, name)
            if not os.path.isdir(child):
                # Single file at root level
                try:
                    sz = os.path.getsize(child)
                    entries.append(_DiskEntry(path=child, size_bytes=sz, file_count=1))
                    total_scanned += sz
                except (OSError, PermissionError):
                    pass
                continue

            if progress_cb:
                try:
                    progress_cb(f"Scanning {name}... ({i+1}/{len(children)})")
                except Exception:
                    pass

            dir_size = 0
            file_count = 0
            try:
                for dirpath, _dirs, files in os.walk(child):
                    # Respect max_depth
                    depth = dirpath.replace(child, '').count(os.sep)
                    if depth >= max_depth:
                        _dirs.clear()
                    for f in files:
                        try:
                            dir_size += os.path.getsize(os.path.join(dirpath, f))
                            file_count += 1
                        except (OSError, PermissionError):
                            pass
            except (OSError, PermissionError):
                pass

            entries.append(_DiskEntry(path=child, size_bytes=dir_size, file_count=file_count))
            total_scanned += dir_size

        # Compute percentages
        grand_total = max(total_scanned, 1)
        for e in entries:
            e.pct_of_total = e.size_bytes / grand_total * 100

        # Sort descending by size, return top N
        entries.sort(key=lambda e: e.size_bytes, reverse=True)
        return entries[:top_n]


# ---------------------------------------------------------------------------
# LargeFileFinder — used by the Large Files tab in the GUI
# ---------------------------------------------------------------------------

@dataclass
class _LargeFileEntry:
    """Single file returned by LargeFileFinder.find()."""
    path:       str
    size_bytes: int   = 0
    mtime:      float = 0.0
    drive:      str   = ''
    extension:  str   = ''
    age_days:   float = 0.0


class LargeFileFinder:
    """Scan directories for files exceeding a size threshold."""

    def __init__(self):
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def find(
        self,
        paths: List[str],
        threshold_bytes: int = 100 * 1024 * 1024,
        extensions: Optional[set] = None,
        progress_cb: Optional[Callable] = None,
        max_results: int = 500,
    ) -> List[_LargeFileEntry]:
        self._stop.clear()
        results: List[_LargeFileEntry] = []
        now = time.time()

        for base_path in paths:
            if self._stop.is_set():
                break
            drive = os.path.splitdrive(base_path)[0] + '\\'
            try:
                for dirpath, _dirs, files in os.walk(base_path):
                    if self._stop.is_set():
                        break
                    for fname in files:
                        fpath = os.path.join(dirpath, fname)
                        try:
                            st = os.stat(fpath)
                            if st.st_size < threshold_bytes:
                                continue
                            ext = os.path.splitext(fname)[1].lstrip('.').lower()
                            if extensions and ext not in extensions:
                                continue
                            results.append(_LargeFileEntry(
                                path=fpath,
                                size_bytes=st.st_size,
                                mtime=st.st_mtime,
                                drive=drive,
                                extension=ext,
                                age_days=(now - st.st_mtime) / 86400,
                            ))
                            if progress_cb and len(results) % 50 == 0:
                                try:
                                    progress_cb(f"Found {len(results):,} large files...", len(results))
                                except Exception:
                                    pass
                            if len(results) >= max_results:
                                break
                        except (OSError, PermissionError):
                            pass
                    if len(results) >= max_results:
                        break
            except (OSError, PermissionError):
                pass

        results.sort(key=lambda e: e.size_bytes, reverse=True)
        return results


# ---------------------------------------------------------------------------
# EmptyFolderFinder — used by the Empty Folders tab in the GUI
# ---------------------------------------------------------------------------

class EmptyFolderFinder:
    """Find and optionally delete empty directories."""

    def __init__(self):
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def find(
        self,
        paths: List[str],
        progress_cb: Optional[Callable] = None,
    ) -> List[str]:
        self._stop.clear()
        empty: List[str] = []

        for base_path in paths:
            if self._stop.is_set():
                break
            try:
                for dirpath, dirs, files in os.walk(base_path, topdown=False):
                    if self._stop.is_set():
                        break
                    if not dirs and not files:
                        empty.append(dirpath)
                        if progress_cb and len(empty) % 20 == 0:
                            try:
                                progress_cb(f"Found {len(empty):,} empty folders...", len(empty))
                            except Exception:
                                pass
            except (OSError, PermissionError):
                pass

        return empty

    @staticmethod
    def delete_empty_folders(paths: List[str]) -> Tuple[int, List[str]]:
        deleted = 0
        errors: List[str] = []
        for p in paths:
            try:
                os.rmdir(p)
                deleted += 1
            except Exception as e:
                errors.append(f"{p}: {e}")
        return deleted, errors


# ---------------------------------------------------------------------------
# StartupItemManager — used by the Startup Items tab in the GUI
# ---------------------------------------------------------------------------

@dataclass
class StartupItem:
    """A single startup entry from the registry or startup folder."""
    name:        str
    command:     str   = ''
    source:      str   = ''   # e.g. 'HKCU\\Run', 'Startup Folder'
    risk_score:  int   = 0
    risk_reason: str   = ''
    reg_key:     str   = ''
    reg_val:     str   = ''
    folder_path: str   = ''
    disabled:    bool  = False


class StartupItemManager:
    """Scan, disable, and re-enable Windows startup items."""

    _RUN_KEYS = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Run",  "HKCU\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run",  "HKLM\\Run"),
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
    ]

    _SUSPICIOUS_KEYWORDS = {
        'temp', 'tmp', 'appdata\\local\\temp', 'cmd.exe /c', 'powershell',
        'wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32',
    }

    def scan(self) -> List[StartupItem]:
        items: List[StartupItem] = []
        # Registry entries
        for hive, subkey, label in self._RUN_KEYS:
            self._scan_registry_entries(items, hive, subkey, label, disabled=False)
            self._scan_registry_entries(items, hive, subkey + "\\AutorunsDisabled",
                                        f"{label} (Disabled)", disabled=True,
                                        reg_key=subkey)

        # Startup folders
        for folder in self._get_startup_folders():
            if not os.path.isdir(folder):
                continue
            for fname in os.listdir(folder):
                fpath = os.path.join(folder, fname)
                disabled = fname.lower().endswith('.disabled')
                display_name = fname[:-9] if disabled else fname
                risk, reason = self._assess_risk(display_name, fpath)
                items.append(StartupItem(
                    name=display_name,
                    command=fpath,
                    source='Startup Folder (Disabled)' if disabled else 'Startup Folder',
                    risk_score=risk,
                    risk_reason=reason,
                    folder_path=fpath,
                    disabled=disabled,
                ))

        items.sort(key=lambda x: x.risk_score, reverse=True)
        return items

    def _scan_registry_entries(
        self,
        items: List[StartupItem],
        hive: int,
        subkey: str,
        label: str,
        disabled: bool = False,
        reg_key: str = '',
    ) -> None:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        risk, reason = self._assess_risk(name, str(value))
                        items.append(StartupItem(
                            name=name,
                            command=str(value),
                            source=label,
                            risk_score=risk,
                            risk_reason=reason,
                            reg_key=reg_key or subkey,
                            reg_val=name,
                            disabled=disabled,
                        ))
                        i += 1
                    except OSError:
                        break
        except OSError:
            pass

    def _assess_risk(self, name: str, command: str) -> Tuple[int, str]:
        score = 0
        reasons = []
        cmd_lower = command.lower()
        name_lower = name.lower()

        for kw in self._SUSPICIOUS_KEYWORDS:
            if kw in cmd_lower:
                score += 30
                reasons.append(f"Suspicious keyword: {kw}")
                break

        if '\\temp\\' in cmd_lower or '\\tmp\\' in cmd_lower:
            score += 25
            reasons.append("Runs from temp directory")

        if not os.path.exists(command.strip('"').split(' ')[0]):
            if not command.startswith('reg') and not command.startswith('"'):
                score += 15
                reasons.append("Executable not found")

        return min(score, 100), '; '.join(reasons) if reasons else 'No issues detected'

    @staticmethod
    def _get_startup_folders() -> List[str]:
        folders = []
        appdata = os.environ.get('APPDATA', '')
        if appdata:
            folders.append(os.path.join(
                appdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'))
        programdata = os.environ.get('PROGRAMDATA', '')
        if programdata:
            folders.append(os.path.join(
                programdata, 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'))
        return folders

    def disable_registry(self, item: StartupItem) -> Tuple[bool, str]:
        """Move a registry startup entry to a Disabled subkey."""
        if not item.reg_key or not item.reg_val:
            return False, "No registry info"
        for hive, subkey, label in self._RUN_KEYS:
            if subkey == item.reg_key:
                try:
                    disabled_key = subkey + "\\AutorunsDisabled"
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                        value, vtype = winreg.QueryValueEx(key, item.reg_val)
                    winreg.CreateKey(hive, disabled_key)
                    with winreg.OpenKey(hive, disabled_key, 0, winreg.KEY_SET_VALUE) as dkey:
                        winreg.SetValueEx(dkey, item.reg_val, 0, vtype, value)
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.DeleteValue(key, item.reg_val)
                    return True, f"Disabled {item.name}"
                except Exception as e:
                    return False, str(e)
        return False, "Registry key not found"

    def enable_registry(self, item: StartupItem) -> Tuple[bool, str]:
        """Move a startup entry back from the Disabled subkey."""
        if not item.reg_key or not item.reg_val:
            return False, "No registry info"
        for hive, subkey, label in self._RUN_KEYS:
            if subkey == item.reg_key:
                try:
                    disabled_key = subkey + "\\AutorunsDisabled"
                    with winreg.OpenKey(hive, disabled_key, 0, winreg.KEY_READ) as dkey:
                        value, vtype = winreg.QueryValueEx(dkey, item.reg_val)
                    with winreg.OpenKey(hive, subkey, 0, winreg.KEY_SET_VALUE) as key:
                        winreg.SetValueEx(key, item.reg_val, 0, vtype, value)
                    with winreg.OpenKey(hive, disabled_key, 0, winreg.KEY_SET_VALUE) as dkey:
                        winreg.DeleteValue(dkey, item.reg_val)
                    return True, f"Re-enabled {item.name}"
                except Exception as e:
                    return False, str(e)
        return False, "Registry key not found"

    def disable_folder_item(self, item: StartupItem) -> Tuple[bool, str]:
        """Rename a startup folder item with .disabled extension."""
        if not item.folder_path or not os.path.exists(item.folder_path):
            return False, "File not found"
        try:
            if item.folder_path.lower().endswith('.disabled'):
                return True, f"{item.name} is already disabled"
            new_path = item.folder_path + '.disabled'
            os.rename(item.folder_path, new_path)
            return True, f"Renamed to {os.path.basename(new_path)}"
        except Exception as e:
            return False, str(e)

    def enable_folder_item(self, item: StartupItem) -> Tuple[bool, str]:
        """Restore a startup folder item that was previously renamed to .disabled."""
        if not item.folder_path or not os.path.exists(item.folder_path):
            return False, "File not found"
        if not item.folder_path.lower().endswith('.disabled'):
            return False, "Item is not disabled"
        try:
            new_path = item.folder_path[:-9]
            if os.path.exists(new_path):
                return False, "Target path already exists"
            os.rename(item.folder_path, new_path)
            return True, f"Restored {os.path.basename(new_path)}"
        except Exception as e:
            return False, str(e)
