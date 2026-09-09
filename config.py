#!/usr/bin/env python3
"""Centralized runtime configuration for Downpour v29 Titanium."""

__version__ = "29.0.0"

import json
import os
import hashlib
import hmac
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

CONFIG = {
  "AI": {
    "LEARNING_CYCLE_SECONDS": 300
  },
  "HARDWARE": {
    "UPDATE_INTERVAL": 0.5,
    "HISTORY_SIZE": 100,
    "SMOOTHING_FACTOR": 0.3,
    "ALERT_THRESHOLDS": {
      "CPU": 80.0,
      "MEMORY": 85.0,
      "DISK": 90.0,
      "TEMP": 75.0
    }
  },
  "UI": {
    "ASCII_ONLY": True,
    "PREFIX": "DOWNPOUR"
  },
  "GEOIP": {
    "PROVIDER": "ip-api",
    "ENABLED": True
  },
  "LOGGING": {
    "LEVEL": "INFO"
  },
  "FEEDS": {
    "threatfox": {"enabled": True, "update_interval": 900},
    "urlhaus": {"enabled": True, "update_interval": 900},
    "phishtank": {"enabled": True, "update_interval": 3600},
    "emerging_threats": {"enabled": True, "update_interval": 3600}
  },
  "KEV": {
    "ENABLED": True,
    "UPDATE_INTERVAL_HOURS": 24,
    "CRITICAL_THRESHOLD": 9.0
  },
  "EPSS": {
    "ENABLED": True,
    "UPDATE_INTERVAL_HOURS": 12,
    "EXPLOIT_THRESHOLD": 0.5
  },
  "YARA": {
    "ENABLED": True,
    "RULES_PATH": "yara_rules",
    "SCAN_TIMEOUT_SECONDS": 30
  },
  "VULNERABILITY": {
    "SCAN_ON_STARTUP": True,
    "SCAN_INTERVAL_HOURS": 24,
    "ALERT_ON_CRITICAL": True
  }
}


class ConfigChangeHandler(FileSystemEventHandler):
    """File system event handler for config file changes."""
    
    def __init__(self, config_manager: 'ConfigManager'):
        self.config_manager = config_manager
        self._last_reload = 0
        self._debounce_seconds = 1.0
    
    def on_modified(self, event):
        if event.is_directory:
            return
        if event.src_path.endswith(('.json', '.yaml', '.yml')):
            now = time.time()
            if now - self._last_reload > self._debounce_seconds:
                self._last_reload = now
                self.config_manager._trigger_reload()


class ConfigManager:
    """Thread-safe configuration manager with hot-reload support."""
    
    def __init__(self, config_path: str = 'config.json', initial_config: Optional[Dict] = None):
        self.config_path = Path(config_path).resolve()
        self._config: Dict = initial_config or CONFIG
        self._lock = threading.RLock()
        self._callbacks: List[Callable[[Dict], None]] = []
        self._observer: Optional[Observer] = None
        self._handler: Optional[ConfigChangeHandler] = None
        self._watching = False
        self._last_modified = 0
        # v29.42w (TASK-014): config tamper detection. config.json is
        # hot-reloaded on ANY file change; without integrity verification,
        # same-user malware could disable sensors by editing it. Every save
        # writes an HMAC-SHA256 signature next to the file (key generated
        # once on first save, DPAPI-protected when pywin32 is available).
        # Loads verify the signature: a mismatch keeps the previous config
        # and raises the tamper flag/callbacks. First-run adoption: an
        # unsigned file is accepted (and signed on the next save); once a
        # signature exists, an unsigned or mismatched edit is tamper.
        self._sig_path: Path = Path(str(self.config_path) + '.sig')
        self._key_path: Path = Path(str(self.config_path) + '.key')
        self._sig_key: Optional[bytes] = self._load_key()
        self._have_signature: bool = self._sig_path.exists()
        self._tamper_flag: bool = False
        self._tamper_callbacks: List[Callable[[str], None]] = []
        self._load_from_file()
        self._start_watching()
    
    def _load_from_file(self):
        """Load configuration from file, verifying its signature (v29.42w)."""
        try:
            if self.config_path.exists():
                stat = self.config_path.stat()
                self._last_modified = stat.st_mtime
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                verdict = self._verify_signature(loaded)
                if verdict is False:
                    self._raise_tamper(
                        f"config signature mismatch for {self.config_path.name}"
                        " — keeping previous configuration")
                    return
                if verdict is None and self._have_signature:
                    self._raise_tamper(
                        f"config signature missing for {self.config_path.name}"
                        " — keeping previous configuration")
                    return
                with self._lock:
                    self._config = loaded
                    if verdict is None:
                        # First-run adoption of an unsigned file. It is signed
                        # automatically on the next save; from then on,
                        # unsigned edits are treated as tamper.
                        logging.getLogger(__name__).info(
                            "ConfigManager: unsigned config adopted (%s)",
                            self.config_path.name)
        except (FileNotFoundError, json.JSONDecodeError):
            with self._lock:
                self._config = self._config or CONFIG

    # -- tamper detection helpers (v29.42w, TASK-014) ------------------------

    def _load_key(self) -> Optional[bytes]:
        """Load the HMAC signing key if it exists (never creates files)."""
        try:
            if not self._key_path.exists():
                return None
            blob = self._key_path.read_bytes().strip()
            if blob.startswith(b'DPAPI:'):
                import base64
                import win32crypt
                protected = base64.b64decode(blob[6:])
                _desc, key = win32crypt.CryptUnprotectData(
                    protected, None, None, None, 0)
                return key
            if blob.startswith(b'RAW:'):
                import base64
                return base64.b64decode(blob[4:])
            return None
        except Exception:
            return None

    def _create_key(self) -> Optional[bytes]:
        """Create and persist a fresh HMAC key (DPAPI-protected if possible)."""
        try:
            import base64
            import secrets
            key = secrets.token_bytes(32)
            try:
                import win32crypt
                protected = win32crypt.CryptProtectData(
                    key, 'downpour-config-key', None, None, None, 0)
                self._key_path.write_bytes(b'DPAPI:' + base64.b64encode(protected))
            except Exception:
                # DPAPI unavailable: fall back to a plain random key file.
                self._key_path.write_bytes(b'RAW:' + base64.b64encode(key))
            return key
        except Exception:
            return None

    def _compute_sig(self, cfg: Dict) -> str:
        """HMAC-SHA256 over the canonical JSON form of the config."""
        canonical = json.dumps(cfg, sort_keys=True).encode('utf-8')
        return hmac.new(self._sig_key or b'', canonical, hashlib.sha256).hexdigest()

    def _verify_signature(self, cfg: Dict) -> Optional[bool]:
        """Verify the on-disk signature for the given config dict.

        Returns True (valid), False (mismatch = tamper), or None when there is
        no signature file or no key available (cannot verify — adoption mode).
        """
        try:
            if self._sig_key is None or not self._sig_path.exists():
                return None
            expected = self._sig_path.read_text(encoding='utf-8').strip()
            return hmac.compare_digest(expected, self._compute_sig(cfg))
        except Exception:
            return None

    def _write_signature(self) -> None:
        """Sign the current config (best effort; creates the key once)."""
        try:
            if self._sig_key is None:
                self._sig_key = self._create_key()
            if self._sig_key is None:
                return
            self._sig_path.write_text(self._compute_sig(self._config),
                                      encoding='utf-8')
            self._have_signature = True
        except Exception:
            pass

    def _raise_tamper(self, message: str) -> None:
        """Record a tamper event and notify tamper callbacks."""
        with self._lock:
            self._tamper_flag = True
        logging.getLogger(__name__).error("ConfigManager TAMPER: %s", message)
        for callback in self._tamper_callbacks:
            try:
                callback(message)
            except Exception:
                pass

    def register_tamper_callback(self, callback: Callable[[str], None]) -> None:
        """Register a callback invoked when config tamper is detected."""
        with self._lock:
            self._tamper_callbacks.append(callback)

    @property
    def tamper_detected(self) -> bool:
        """True if a signature mismatch / missing-signature event was seen."""
        with self._lock:
            return self._tamper_flag
    
    def _start_watching(self):
        """Start file system watcher for hot-reload."""
        try:
            self._handler = ConfigChangeHandler(self)
            self._observer = Observer()
            self._observer.schedule(
                self._handler,
                str(self.config_path.parent),
                recursive=False
            )
            self._observer.start()
            self._watching = True
        except Exception:
            # Watchdog not available or other error - hot-reload disabled
            self._watching = False
    
    def _trigger_reload(self):
        """Trigger configuration reload and notify callbacks.

        v29.42w: delegates to _load_from_file() so hot-reloads go through the
        same signature verification as startup loads — an out-of-band edit
        without a matching signature is rejected (tamper) instead of applied,
        and callbacks only fire when the config actually changed.
        """
        try:
            if self.config_path.exists():
                stat = self.config_path.stat()
                if stat.st_mtime > self._last_modified:
                    previous = self.get_all()
                    self._load_from_file()
                    if self.get_all() != previous:
                        # Notify callbacks outside lock to avoid deadlocks
                        for callback in self._callbacks:
                            try:
                                callback(self.get_all())
                            except Exception:
                                pass
        except Exception:
            pass
    
    def register_callback(self, callback: Callable[[Dict], None]):
        """Register a callback to be called when config changes."""
        with self._lock:
            self._callbacks.append(callback)
    
    def unregister_callback(self, callback: Callable[[Dict], None]):
        """Unregister a callback."""
        with self._lock:
            if callback in self._callbacks:
                self._callbacks.remove(callback)
    
    def get(self, section: str, key: str, fallback: Any = None) -> Any:
        """Get a configuration value."""
        with self._lock:
            return self._config.get(section, {}).get(key, fallback)
    
    def get_section(self, section: str) -> Dict:
        """Get entire section."""
        with self._lock:
            return self._config.get(section, {}).copy()
    
    def set(self, section: str, key: str, value: Any) -> bool:
        """Set a configuration value and save."""
        with self._lock:
            if section not in self._config:
                self._config[section] = {}
            self._config[section][key] = value
            try:
                self.save()
                return True
            except Exception:
                return False
    
    def save(self) -> bool:
        """Save current configuration to file and refresh its signature (v29.42w)."""
        try:
            with self._lock:
                with open(self.config_path, 'w', encoding='utf-8') as f:
                    json.dump(self._config, f, indent=2)
                self._write_signature()
            return True
        except Exception:
            return False
    
    def get_all(self) -> Dict:
        """Get complete configuration."""
        with self._lock:
            return self._config.copy()
    
    def update(self, updates: Dict) -> bool:
        """Update multiple values at once."""
        with self._lock:
            for section, values in updates.items():
                if section not in self._config:
                    self._config[section] = {}
                self._config[section].update(values)
            try:
                self.save()
                return True
            except Exception:
                return False
    
    def stop_watching(self):
        """Stop file system watcher."""
        if self._observer and self._watching:
            self._observer.stop()
            self._observer.join(timeout=2)
            self._watching = False
    
    def is_watching(self) -> bool:
        """Check if hot-reload is active."""
        return self._watching
    
    # ConfigParser-compatible interface for backward compatibility
    def has_option(self, section: str, key: str) -> bool:
        with self._lock:
            return key in self._config.get(section, {})
    
    def has_section(self, section: str) -> bool:
        with self._lock:
            return section in self._config
    
    def getint(self, section: str, key: str, fallback: int = 0) -> int:
        return int(self.get(section, key, fallback))
    
    def getfloat(self, section: str, key: str, fallback: float = 0.0) -> float:
        return float(self.get(section, key, fallback))
    
    def getboolean(self, section: str, key: str, fallback: bool = False) -> bool:
        v = self.get(section, key, fallback)
        if isinstance(v, bool):
            return v
        return str(v).lower() in ('true', '1', 'yes')
    
    def sections(self):
        with self._lock:
            return list(self._config.keys())
    
    def __getitem__(self, key):
        with self._lock:
            return self._config[key]
    
    def __contains__(self, key):
        with self._lock:
            return key in self._config
    
    def __iter__(self):
        with self._lock:
            return iter(self._config)
    
    def keys(self):
        with self._lock:
            return self._config.keys()
    
    def values(self):
        with self._lock:
            return self._config.values()
    
    def items(self):
        with self._lock:
            return self._config.items()


# Wrap the raw dict for use across the application
config = ConfigManager(initial_config=CONFIG)

# Lightweight global logging configuration to ensure consistent observability
try:
    import logging
    if not logging.getLogger().hasHandlers():
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
except Exception:
    pass
