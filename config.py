#!/usr/bin/env python3
"""Centralized runtime configuration for Downpour v29 Titanium."""

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
