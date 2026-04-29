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
