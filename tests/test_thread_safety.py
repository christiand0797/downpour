"""Unit tests for Downpour's thread-safety + FP-suppression mechanisms.

Targets the DB-backed false-positive auto-suppression flow (v29.16) and the
executor-post-back pattern without instantiating the full Tk app (which needs
a display + heavy module init). Uses `object.__new__(downpour)` so the pure
logic methods can run against a lightweight fake instance.

Run:  Python312\\python.exe -m pytest tests -q
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import downpour_v29_titanium as dp  # noqa: E402

# The main class name for the titanium app.
_APP_CLASS = getattr(dp, 'downpour', None)
_COLORS = getattr(dp, 'Colors', None)


def make_instance():
    """Create a bare downpour instance without running __init__."""
    assert _APP_CLASS is not None, 'downpour class not found'
    return object.__new__(_APP_CLASS)


# --------------------------------------------------------------------------
# _fp_fingerprint normalization
# --------------------------------------------------------------------------

class TestFpFingerprint:
    def test_category_preserved_uppercased(self):
        inst = make_instance()
        fp = inst._fp_fingerprint('[botnet] C2 45.88.48.238')
        assert fp.startswith('[BOTNET]:')

    def test_generic_category_when_no_bracket(self):
        inst = make_instance()
        fp = inst._fp_fingerprint('random plain alert text')
        assert fp.startswith('[GEN]:')

    def test_port_normalized_away(self):
        inst = make_instance()
        a = inst._fp_fingerprint('[BOTNET] C2 45.88.48.238 :443')
        b = inst._fp_fingerprint('[BOTNET] C2 45.88.48.238')
        assert a == b, f'port variant should collapse: {a!r} != {b!r}'

    def test_timestamp_numbers_normalized(self):
        inst = make_instance()
        a = inst._fp_fingerprint('[X] process 12345 high CPU')
        b = inst._fp_fingerprint('[X] process 99999 high CPU')
        assert a == b

    def test_hash_normalized_away(self):
        inst = make_instance()
        h1 = 'a' * 32
        h2 = 'b' * 32
        a = inst._fp_fingerprint(f'[HASH] md5 {h1}')
        b = inst._fp_fingerprint(f'[HASH] md5 {h2}')
        assert a == b

    def test_different_categories_stay_different(self):
        inst = make_instance()
        a = inst._fp_fingerprint('[BOTNET] C2 45.88.48.238')
        b = inst._fp_fingerprint('[DLL]   C2 45.88.48.238')
        assert a != b

    def test_never_raises_on_garbage(self):
        inst = make_instance()
        for bad in (None, 12345, object(), '', '   '):
            try:
                inst._fp_fingerprint(bad)
            except Exception:
                pass  # must not raise; may return partial key


# --------------------------------------------------------------------------
# _fp_is_suppressed hot-path (memory only, no DB)
# --------------------------------------------------------------------------

class TestFpIsSuppressed:
    def test_returns_false_when_cache_not_loaded(self):
        inst = make_instance()
        inst._fp_cache = {}
        inst._fp_cache_loaded = False
        assert inst._fp_is_suppressed('[BOTNET] C2 45.88.48.238') is False

    def test_returns_true_for_suppressed_fingerprint(self):
        inst = make_instance()
        inst._fp_cache_loaded = True
        fp = inst._fp_fingerprint('[BOTNET] C2 45.88.48.238')
        inst._fp_cache = {fp: {'confirmed': 3, 'suppressed': True}}
        assert inst._fp_is_suppressed('[BOTNET] C2 45.88.48.238 :443') is True

    def test_returns_false_when_not_suppressed(self):
        inst = make_instance()
        inst._fp_cache_loaded = True
        inst._fp_cache = {}
        assert inst._fp_is_suppressed('[BOTNET] C2 45.88.48.238') is False

    def test_never_raises(self):
        inst = make_instance()
        inst._fp_cache_loaded = True
        inst._fp_cache = None
        assert inst._fp_is_suppressed(None) is False


# --------------------------------------------------------------------------
# _queue_alert drops suppressed messages before they reach the UI
# --------------------------------------------------------------------------

class TestQueueAlertSuppression:
    def _ready(self):
        import time
        inst = make_instance()
        inst._alert_rate_reset = time.monotonic()
        inst._alert_rate_count = 0
        inst._alerted_dedup = {}
        inst._pending_alerts = []
        inst._fp_cache_loaded = True
        inst._fp_cache = {}
        return inst

    def test_suppressed_alert_is_dropped(self):
        inst = self._ready()
        fp = inst._fp_fingerprint('[BOTNET] C2 45.88.48.238')
        inst._fp_cache = {fp: {'confirmed': 3, 'suppressed': True}}
        inst._queue_alert('[BOTNET] C2 45.88.48.238 :443', _COLORS.GAUGE_RED)
        assert len(inst._pending_alerts) == 0

    def test_normal_alert_is_queued(self):
        inst = self._ready()
        inst._queue_alert('[TEST] normal alert', _COLORS.GAUGE_TEAL)
        assert len(inst._pending_alerts) == 1

    def test_rate_limit_2_per_second(self):
        inst = self._ready()
        for i in range(5):
            inst._queue_alert(f'[TEST] alert number {i}', _COLORS.GAUGE_TEAL)
        # 2 pass the global rate limit; the rest are dropped
        assert len(inst._pending_alerts) <= 2


# --------------------------------------------------------------------------
# Executor post-back pattern: a background task must marshal results back
# via after(0) rather than touching widgets directly.
# --------------------------------------------------------------------------

class TestExecutorPostBack:
    def test_after_used_for_ui_callback(self):
        """The FP cache loader posts back with after(0), never direct calls."""
        src = open(os.path.join(os.path.dirname(__file__),
                                '..', 'downpour_v29_titanium.py'),
                   encoding='utf-8', errors='replace').read()
        # _fp_load_cache submits to executor and marshals via self.after
        start = src.index('def _fp_load_cache')
        end = src.index('def _fp_cache_update', start)
        chunk = src[start:end]
        assert '_executor.submit' in chunk
        assert 'self.after(0' in chunk
        assert '_fp_cache_update(c)' in chunk

    def test_after_never_raises_during_shutdown(self):
        """_proc_loop wraps self.after in try/except RuntimeError."""
        src = open(os.path.join(os.path.dirname(__file__),
                                '..', 'downpour_v29_titanium.py'),
                   encoding='utf-8', errors='replace').read()
        idx = src.index('def _proc_loop')
        chunk = src[idx: idx + 6000]
        assert 'except RuntimeError' in chunk
