#!/usr/bin/env python3
"""Centralized runtime configuration for Downpour v29 Titanium."""

__version__ = "29.0.0"

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


class ConfigWrapper:
    """FIX-v29.42: ConfigParser-compatible wrapper around the CONFIG dict.

    Modules like network_monitor.py and process_monitor.py call
    ``config.has_option('SECTION', 'key')`` and ``config.get('SECTION', 'key')``,
    expecting a configparser.ConfigParser interface. The raw dict lacks those
    methods, causing AttributeError. This wrapper provides both dictionary-style
    access and ConfigParser-compatible ``.get()`` / ``.has_option()`` methods.
    """

    def __init__(self, data: dict):
        self._data = data

    # --- ConfigParser-compatible interface ---
    def has_option(self, section: str, key: str) -> bool:
        return key in self._data.get(section, {})

    def has_section(self, section: str) -> bool:
        return section in self._data

    def get(self, section_or_key, key=None, fallback=None):
        """Dual-mode get: (section, key) or (key) with optional fallback."""
        if key is not None:
            return self._data.get(section_or_key, {}).get(key, fallback)
        return self._data.get(section_or_key, fallback)

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
        return list(self._data.keys())

    # --- dict-style interface ---
    def __getitem__(self, key):
        return self._data[key]

    def __contains__(self, key):
        return key in self._data

    def __iter__(self):
        return iter(self._data)

    def keys(self):
        return self._data.keys()

    def values(self):
        return self._data.values()

    def items(self):
        return self._data.items()

    # --- Persistence ---
    def save(self, path: str = 'config.json') -> None:
        import json
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(self._data, f, indent=2)

    @classmethod
    def load(cls, path: str = 'config.json') -> 'ConfigWrapper':
        import json
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return cls(json.load(f))
        except FileNotFoundError:
            return cls(CONFIG)


# Wrap the raw dict for use across the application
config = ConfigWrapper(CONFIG)

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
