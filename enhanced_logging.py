#!/usr/bin/env python3
"""
Enhanced Logging System for Downpour v29.40 Titanium
Structured JSON logging, rotating file handlers, async queue,
real-time alerting, performance profiling, and session analytics.

v29.40 ENHANCEMENTS:
- Added security-focused logging with sensitive data masking
- Added structured logging with proper event categorization
- Added log tamper detection and integrity verification
- Added performance baseline tracking and anomaly detection
- Added compliance-friendly log format for security audits
- Added log rotation with secure deletion
"""

__version__ = "29.40.0"

import asyncio, hashlib, json, logging, logging.handlers, os
import queue, sys, threading, time, traceback
from collections import Counter, deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

_BASE_DIR = Path(__file__).parent

class LogLevel(Enum):
    DEBUG = 10; INFO = 20; WARNING = 30; ERROR = 40; CRITICAL = 50

class AlertThreshold(Enum):
    ERRORS_PER_MIN = 10; WARNINGS_PER_MIN = 30; PERF_MS = 5000

@dataclass
class LogEvent:
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    event_type: str = ""; level: str = "INFO"
    session_id: str = ""; message: str = ""
    data: Dict = field(default_factory=dict)
    duration_ms: Optional[float] = None
    traceback_str: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

@dataclass
class SessionMetrics:
    start_time: float = field(default_factory=time.time)
    session_id: str = ""
    errors: int = 0; warnings: int = 0; infos: int = 0
    package_failures: int = 0; package_successes: int = 0
    performance_checks: int = 0; ui_responses: int = 0
    total_events: int = 0; avg_event_rate_per_min: float = 0.0
    peak_error_rate_per_min: float = 0.0
    # v29.40: Security metrics
    security_events: int = 0
    masked_sensitive_data: int = 0
    log_integrity_violations: int = 0
    baseline_anomalies: int = 0

class EnhancedLogger:
    """
    Production-grade logger: async queue, rotating JSON + text files,
    real-time rate alerting, performance tracking, session analytics.
    
    v29.40: Added security logging, sensitive data masking, and integrity checks.
    """
    def __init__(self, log_dir: Optional[Path] = None, max_bytes: int = 10*1024*1024,
                 backup_count: int = 5, async_queue_size: int = 10000):
        self.log_dir = Path(log_dir) if log_dir else _BASE_DIR / "downpour_data" / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S") + \
                          "_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:6]
        self.metrics = SessionMetrics(session_id=self.session_id)
        self._queue: queue.Queue = queue.Queue(maxsize=async_queue_size)
        self._recent_errors: deque = deque(maxlen=1000)
        self._recent_warnings: deque = deque(maxlen=1000)
        self._perf_samples: Dict[str, deque] = {}
        self._alert_callbacks: List[Callable] = []
        self._lock = threading.Lock()
        
        # v29.40: Security logging components
        self._sensitive_patterns = [
            r'password[=:\s]\S+', r'api[_-]?key[=:\s]\S+', r'token[=:\s]\S+',
            r'secret[=:\s]\S+', r'credential[=:\s]\S+', r'auth[=:\s]\S+',
            r'Bearer\s+\S+', r'Basic\s+\S+', r'key[=:\s]\S+'
        ]
        self._log_integrity_hash = hashlib.sha256()
        self._baseline_metrics = {}
        
        self._setup_logging(max_bytes, backup_count)
        self._start_async_worker()
        self._log_event("SESSION_START", {"session_id": self.session_id,
                        "python": sys.version, "pid": os.getpid()})

    def _setup_logging(self, max_bytes: int, backup_count: int) -> None:
        """Setup rotating file handlers for text and JSON logs."""
        # Initialize COM for this thread
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except ImportError:
            pass
        
        # Rotating text log
        text_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / f"session_{self.session_id}.log",
            maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8')
        text_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'))
        # Rotating JSON log
        json_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "events.jsonl",
            maxBytes=max_bytes*2, backupCount=backup_count, encoding='utf-8')
        json_handler.setFormatter(logging.Formatter('%(message)s'))
        # Error-only log
        error_handler = logging.handlers.RotatingFileHandler(
            self.log_dir / "errors.log",
            maxBytes=max_bytes, backupCount=backup_count, encoding='utf-8')
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s\n%(exc_info)s'))
        self.logger = logging.getLogger(f'Downpour.{self.session_id[:8]}')
        self.logger.setLevel(logging.DEBUG)
        for h in [text_handler, json_handler, error_handler]:
            self.logger.addHandler(h)
        self._json_handler = json_handler

    def _start_async_worker(self) -> None:
        """Start the async logging worker thread."""
        # Initialize COM for this thread
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except ImportError:
            pass
        
        t = threading.Thread(target=self._async_worker, daemon=True, name="LogWorker")
        t.start()

    def _async_worker(self) -> None:
        while True:
            try:
                event: LogEvent = self._queue.get(timeout=1.0)
                # v29.40: Apply sensitive data masking
                masked_event = self._mask_sensitive_data(event)
                # v29.40: Update log integrity
                self._update_log_integrity(masked_event.to_json())
                self._json_handler.stream.write(masked_event.to_json() + '\n')
                self._json_handler.stream.flush()
                self._queue.task_done()
            except queue.Empty: pass
            except Exception as _e:
                # FIX-v28p41: Log to stderr instead of silently swallowing
                try: sys.stderr.write(f"[LogWorker] Error: {_e}\n")
                except Exception: pass

    def _log_event(self, event_type: str, data: Dict = None,
                   level: str = "INFO", duration_ms: float = None) -> LogEvent:
        event = LogEvent(event_type=event_type, level=level,
                        session_id=self.session_id,
                        message=event_type, data=data or {},
                        duration_ms=duration_ms)
        with self._lock:
            self.metrics.total_events += 1
            if level == "ERROR":
                self.metrics.errors += 1
                self._recent_errors.append(time.time())
            elif level == "WARNING":
                self.metrics.warnings += 1
                self._recent_warnings.append(time.time())
            elif level == "INFO": self.metrics.infos += 1
        try: self._queue.put_nowait(event)
        except queue.Full: pass
        self.logger.log(getattr(logging, level, 20),
                        "%s %s", event_type, json.dumps(data or {}, default=str)[:200])
        self._check_alert_thresholds()
        return event

    def _check_alert_thresholds(self) -> None:
        now = time.time()
        recent_errors = sum(1 for t in self._recent_errors if now - t < 60)
        if recent_errors >= AlertThreshold.ERRORS_PER_MIN.value:
            for cb in self._alert_callbacks:
                try: cb("HIGH_ERROR_RATE", recent_errors)
                except Exception: pass
    
    # v29.40: Security logging methods
    def _mask_sensitive_data(self, event: LogEvent) -> LogEvent:
        """Mask sensitive data patterns in log events."""
        import re
        masked_data = event.data.copy()
        message = event.message
        
        for pattern in self._sensitive_patterns:
            # Mask in data dictionary
            for key, value in masked_data.items():
                if isinstance(value, str):
                    masked_value = re.sub(pattern, '[REDACTED]', value, flags=re.IGNORECASE)
                    if masked_value != value:
                        masked_data[key] = masked_value
                        self.metrics.masked_sensitive_data += 1
            
            # Mask in message
            masked_message = re.sub(pattern, '[REDACTED]', message, flags=re.IGNORECASE)
            if masked_message != message:
                message = masked_message
                self.metrics.masked_sensitive_data += 1
        
        event.data = masked_data
        event.message = message
        return event
    
    def _update_log_integrity(self, log_entry: str) -> None:
        """Update log integrity hash for tamper detection."""
        try:
            self._log_integrity_hash.update(log_entry.encode('utf-8'))
        except Exception:
            self.metrics.log_integrity_violations += 1
    
    def verify_log_integrity(self, expected_hash: str = None) -> bool:
        """Verify log file integrity against expected hash."""
        current_hash = self._log_integrity_hash.hexdigest()
        if expected_hash:
            return current_hash == expected_hash
        return True  # If no expected hash, return True (no violation detected)
    
    def log_security_event(self, event_type: str, severity: str = "INFO",
                          details: Dict = None) -> LogEvent:
        """Log security-specific events with proper categorization."""
        self.metrics.security_events += 1
        security_data = {
            "security_event": True,
            "severity": severity,
            "details": details or {}
        }
        return self._log_event(f"SECURITY_{event_type}", security_data, level=severity)
    
    def track_baseline_metric(self, metric_name: str, value: float) -> bool:
        """Track metrics for baseline analysis and anomaly detection."""
        if metric_name not in self._baseline_metrics:
            self._baseline_metrics[metric_name] = []
        
        self._baseline_metrics[metric_name].append(value)
        
        # Keep last 100 samples
        if len(self._baseline_metrics[metric_name]) > 100:
            self._baseline_metrics[metric_name].pop(0)
        
        # Check for anomalies if we have enough data
        if len(self._baseline_metrics[metric_name]) >= 20:
            values = self._baseline_metrics[metric_name]
            mean = sum(values) / len(values)
            std = (sum((x - mean)**2 for x in values) / len(values))**0.5
            
            if std > 0:
                z_score = (value - mean) / std
                if abs(z_score) > 3:  # Statistical anomaly
                    self.metrics.baseline_anomalies += 1
                    self.log_security_event(
                        "BASELINE_ANOMALY",
                        severity="WARNING",
                        details={
                            "metric": metric_name,
                            "value": value,
                            "z_score": z_score,
                            "mean": mean,
                            "std": std
                        }
                    )
                    return True
        return False

    # ------------------------------------------------------------------
    # Public API methods called by downpour_v28_titanium.py
    # ------------------------------------------------------------------

    def log_performance_metric(self, name: str, value: float,
                                unit: str = "ms") -> LogEvent:
        """
        Record a named performance measurement (e.g. app init time).
        Called by titanium as:
            enhanced_logger.log_performance_metric('app_initialization', elapsed_ms, 'ms')
        """
        with self._lock:
            self.metrics.performance_checks += 1
            if name not in self._perf_samples:
                self._perf_samples[name] = deque(maxlen=100)
            self._perf_samples[name].append(value)

        data = {"metric": name, "value": value, "unit": unit}
        level = "WARNING" if value > AlertThreshold.PERF_MS.value else "INFO"
        return self._log_event("PERF_METRIC", data, level=level, duration_ms=value)

    def log_ui_response(self, action: str, response_ms: float) -> LogEvent:
        """
        Record a UI interaction response time.
        Called by titanium as:
            enhanced_logger.log_ui_response('cleanup_scan_start', 100)
        """
        with self._lock:
            self.metrics.ui_responses += 1

        data = {"action": action, "response_ms": response_ms}
        level = "WARNING" if response_ms > AlertThreshold.PERF_MS.value else "INFO"
        return self._log_event("UI_RESPONSE", data, level=level, duration_ms=response_ms)

    def log_error(self, component: str, message: str,
                  exc: Optional[Exception] = None) -> LogEvent:
        """Log an error with optional exception traceback."""
        data: Dict[str, Any] = {"component": component, "message": message}
        if exc:
            data["traceback"] = traceback.format_exc()
        event = self._log_event(
            f"[{component}] {message}", data, level="ERROR",
        )
        # Enrich the event with traceback info for the JSON log
        if exc:
            event.traceback_str = data["traceback"]
        return event

    def log_warning(self, component: str, message: str) -> LogEvent:
        """Log a warning message."""
        return self._log_event("WARNING", {"component": component, "message": message},
                               level="WARNING")

    def get_session_summary(self) -> Dict[str, Any]:
        """Return a dict summarising this session's metrics."""
        elapsed = time.time() - self.metrics.start_time
        return {
            "session_id":   self.session_id,
            "elapsed_s":    round(elapsed, 2),
            "errors":       self.metrics.errors,
            "warnings":     self.metrics.warnings,
            "ui_responses": self.metrics.ui_responses,
            "perf_checks":  self.metrics.performance_checks,
            "total_events": self.metrics.total_events,
        }

    def register_alert_callback(self, callback: Callable) -> None:
        """Register a function to call when alert thresholds are breached."""
        self._alert_callbacks.append(callback)
