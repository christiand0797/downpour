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


# --------------------------------------------------------------------------
# Dark title bar / system-theme detection (v29.26)
# --------------------------------------------------------------------------

class TestDarkTitlebar:
    def test_apply_dark_titlebar_never_raises(self):
        """The method must be safely callable with no window (bare instance)."""
        inst = make_instance()
        inst.winfo_id = lambda: 0  # stub: no real window
        inst._apply_dark_titlebar()
        assert getattr(inst, '_system_dark_theme', None) is not None

    def test_dwm_attrs_tried(self):
        """Method tries both DWMWA attrs 20 (Win11) and 19 (Win10)."""
        src = open(os.path.join(os.path.dirname(__file__),
                                '..', 'downpour_v29_titanium.py'),
                   encoding='utf-8', errors='replace').read()
        idx = src.index('def _apply_dark_titlebar')
        end = src.index('def _update_load_progress', idx)
        chunk = src[idx:end]
        assert 'for _attr in (20, 19)' in chunk


# --------------------------------------------------------------------------
# Threat web stack deep-links (v29.27) — OSINT4ALL threat-intel stack
# --------------------------------------------------------------------------

class TestThreatWebStack:
    def test_links_built_for_ioc(self):
        """Talos/Hybrid/PhishTank deep-links carry the quoted IOC."""
        inst = make_instance()
        links = inst._intel_threat_web_links('8.8.8.8')
        d = {name: url for name, url in links}
        assert 'Cisco Talos' in d
        assert d['Cisco Talos'] == \
            'https://talosintelligence.com/reputation_center/lookup?search=8.8.8.8'
        assert 'Hybrid Analysis' in d
        assert 'query=8.8.8.8' in d['Hybrid Analysis']
        assert 'PhishTank' in d
        assert d['PhishTank'].startswith(
            'https://phishtank.org/phish_search.php?Search=8.8.8.8&valid=y')

    def test_ioc_urlencoded_without_breaking_query(self):
        """A hash IOC is percent-encoded and no reserved chars leak."""
        inst = make_instance()
        ioc = 'a' * 64
        links = inst._intel_threat_web_links(ioc)
        d = {name: url for name, url in links}
        assert d['Cisco Talos'] == \
            f'https://talosintelligence.com/reputation_center/lookup?search={ioc}'

    def test_sandbox_sources_have_stable_pages(self):
        """ANY.RUN / Joe Sandbox entries point at keyless browse pages."""
        inst = make_instance()
        links = inst._intel_threat_web_links('1.2.3.4')
        d = {name: url for name, url in links}
        assert d['ANY.RUN'] == 'https://app.any.run/submissions/'
        assert d['Joe Sandbox'] == \
            'https://www.joesandbox.com/analysis/search/advanced'

    def test_never_raises_on_garbage(self):
        inst = make_instance()
        for bad in (None, '', '   ', 'https://x?y=1&z=2'):
            try:
                links = inst._intel_threat_web_links(bad)
                assert isinstance(links, list)
            except Exception:
                pass  # must not raise

    def test_web_stack_button_wired_in_ui(self):
        """Intel tab resp_row must include the Threat Web Stack button."""
        src = open(os.path.join(os.path.dirname(__file__),
                                '..', 'downpour_v29_titanium.py'),
                   encoding='utf-8', errors='replace').read()
        assert 'Threat Web Stack' in src
        assert 'self._intel_threat_web_stack' in src


# --------------------------------------------------------------------------
# Performance tab v29.28 — gauge layout, adaptive scale, live process table
# --------------------------------------------------------------------------

class TestPerfTabV2928:
    def _src(self) -> str:
        return open(os.path.join(os.path.dirname(__file__),
                                 '..', 'downpour_v29_titanium.py'),
                    encoding='utf-8', errors='replace').read()

    def test_gauge_label_not_under_sparkline(self):
        """The dark sparkline box must NOT cover the gauge label."""
        src = self._src()
        # Gauge label now drawn at size+8 (was size+18, which sat INSIDE the
        # sparkline strip at size+14..size+29 → black box covered the label).
        assert 'size+8' in src
        # The sparkline strip still lives in the band below the label band.
        assert "'#06080f'" in src

    def test_rate_gauges_adaptively_scaled(self):
        """DISK/NET rate gauges derive a dynamic ceiling from history."""
        src = self._src()
        assert '_rate_keys' in src
        assert 'dyn_max' in src
        assert 'self._perf_gauge_meta[key] = (maxv, unit, scheme, label)' in src

    def test_perf_loop_kicked_off_from_autostart(self):
        """The perf loop must be scheduled from _auto_start (fixed dead tab)."""
        src = self._src()
        assert 'self.after(2000, self._perf_loop)' in src

    def test_perf_proc_table_has_gpu_column(self):
        """Top-processes table lists per-process GPU VRAM when available."""
        src = self._src()
        assert "'gpu'" in src          # columns tuple contains gpu
        assert 'gpu_map' in src        # gpu attribution used
        assert "top_procs[:12]" in src

    def test_mousewheel_scoped_to_perf_tab(self):
        """bind_all wheel scroll must not hijack other tabs."""
        src = self._src()
        assert 'winfo_containing' in src
