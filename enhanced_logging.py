#!/usr/bin/env python3
"""
Enhanced Logging System for Downpour v29 Titanium
Structured JSON logging, rotating file handlers, async queue,
real-time alerting, performance profiling, and session analytics.
"""
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

class EnhancedLogger:
    """
    Production-grade logger: async queue, rotating JSON + text files,
    real-time rate alerting, performance tracking, session analytics.
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
        self._setup_logging(max_bytes, backup_count)
        self._start_async_worker()
        self._log_event("SESSION_START", {"session_id": self.session_id,
                        "python": sys.version, "pid": os.getpid()})

    def _setup_logging(self, max_bytes: int, backup_count: int) -> None:
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
        t = threading.Thread(target=self._async_worker, daemon=True, name="LogWorker")
        t.start()

    def _async_worker(self) -> None:
        while True:
            try:
                event: LogEvent = self._queue.get(timeout=1.0)
                self._json_handler.stream.write(event.to_json() + '\n')
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
        tb = traceback.format_exc() if exc else None
        event = LogEvent(
            event_type="ERROR", level="ERROR",
            session_id=self.session_id,
            message=f"[{component}] {message}",
            data=data, traceback_str=tb,
        )
        with self._lock:
            self.metrics.errors += 1
            self._recent_errors.append(time.time())
            self.metrics.total_events += 1
        try: self._queue.put_nowait(event)
        except queue.Full: pass
        self.logger.error("[%s] %s", component, message, exc_info=exc is not None)
        self._check_alert_thresholds()
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
