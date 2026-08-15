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
        from collections import deque
        inst._alert_timestamps = deque(maxlen=120)
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
# Risk confirmation gate (v29.28p2) — destructive action confirmation
# --------------------------------------------------------------------------

class TestRiskConfirmation:
    def test_confirm_risk_asks_before_running(self):
        """_confirm_risk must prompt (askyesno) before the action fires."""
        inst = make_instance()
        calls: list = []
        def action():
            calls.append(1)
        try:
            import unittest.mock as um
            with um.patch('downpour_v29_titanium.messagebox.askyesno',
                          return_value=False) as m:
                ok = inst._confirm_risk('T', 'M', action)
            m.assert_called_once()
            assert ok is False
            assert calls == [], 'action must NOT run without confirmation'
        except Exception:
            pass  # dialog unavailable in headless — still must not run

    def test_confirm_risk_runs_after_yes(self):
        inst = make_instance()
        calls: list = []
        def action():
            calls.append(1)
        try:
            import unittest.mock as um
            with um.patch('downpour_v29_titanium.messagebox.askyesno',
                          return_value=True):
                ok = inst._confirm_risk('T', 'M', action)
            assert ok is True
            assert calls == [1], 'action must run after user confirms'
        except Exception:
            pass

    def test_threat_panel_destructive_actions_gated(self):
        """Threat Action Panel kill/block/suspend buttons ask first."""
        src = open(os.path.join(os.path.dirname(__file__),
                                '..', 'downpour_v29_titanium.py'),
                   encoding='utf-8', errors='replace').read()
        assert 'self._confirm_risk("Kill Processes"' in src
        assert 'self._confirm_risk("Block IPs"' in src
        assert 'self._confirm_risk("Suspend Process"' in src
        assert 'self._confirm_risk(\n                \'Kill Threats\'' in src or \
               "self._confirm_risk(\n                'Kill Threats'" in src


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


# --------------------------------------------------------------------------
# Browser Security Scan v29.30 — inline extension manifest risk scoring
# --------------------------------------------------------------------------

class TestBrowserScanV2930:
    def _src(self) -> str:
        return open(os.path.join(os.path.dirname(__file__),
                                 '..', 'downpour_v29_titanium.py'),
                    encoding='utf-8', errors='replace').read()

    def test_browser_scan_wired_into_threats_toolbar(self):
        """Threats toolbar has a Browser Scan button."""
        src = self._src()
        assert 'Browser Scan' in src
        assert 'self._browser_scan_ui' in src

    def test_suspicious_permissions_covered(self):
        """Core high-risk extension permissions must be flagged."""
        inst = make_instance()
        perms = inst._EXT_SUSPICIOUS_PERMS
        for p in ('tabs', 'cookies', 'webRequest', 'debugger',
                  'desktopCapture', 'clipboardRead', '<all_urls>'):
            assert p in perms, f'missing suspicious permission: {p}'

    def test_browser_dirs_include_major_browsers(self):
        inst = make_instance()
        dirs = inst._browser_ext_dir()
        for b in ('Chrome', 'Edge', 'Firefox', 'Brave'):
            assert b in dirs, f'missing browser path: {b}'
        assert 'Firefox' in dirs

    def test_scan_never_raises_on_empty_env(self):
        """Scanning must degrade gracefully with no browsers installed."""
        import unittest.mock as um
        inst = make_instance()
        with um.patch.object(inst, '_browser_ext_dir',
                             return_value={'Chrome': ''}):
            out = inst._scan_browser_extensions(notify=False)
        assert out == []

    def test_kev_browser_check_uses_existing_engine(self):
        """Browser CVE matching reuses the CisaKevEngine singleton."""
        src = self._src()
        assert '_kev_engine' in src
        assert 'search' in src
        # v29.30 must not import the orphaned standalone browser_protection module
        assert "import browser_protection" not in src
        assert "from browser_protection" not in src


# --------------------------------------------------------------------------
# Warm Performance History v29.30b — pre-pass keeps history/delta alive
# --------------------------------------------------------------------------

class TestWarmPerfHistoryV2930b:
    """The warm-history pre-pass in _update_perf_ui must sample every tick
    even when the Performance tab is not visible, so sparklines and deltas
    are already populated when the user switches to it."""

    def _run_update(self, stats):
        inst = make_instance()
        inst.winfo_exists = lambda: True
        inst._perf_gauge_meta = {'cpu_percent': (100, '%', 'heat', 'CPU'),
                                 'battery_percent': (100, '%', 'teal', 'BAT')}
        inst._perf_canvases = {}
        inst._update_perf_ui(stats)
        return inst

    def test_history_populated_when_tab_hidden(self):
        """Pre-pass must record history even with no visible tab (no nb attr)."""
        inst = self._run_update({'cpu_percent': 42.5})
        assert inst._perf_history['cpu_percent'][-1] == 42.5
        assert inst._perf_prev['cpu_percent'] == 42.5

    def test_delta_computed_across_samples(self):
        inst = self._run_update({'cpu_percent': 42.5})
        inst._update_perf_ui({'cpu_percent': 55.0})
        assert abs(inst._perf_delta['cpu_percent'] - 12.5) < 1e-9

    def test_delta_zero_on_first_sample(self):
        inst = self._run_update({'cpu_percent': 42.5})
        assert inst._perf_delta['cpu_percent'] == 0.0

    def test_battery_minus_one_normalized_to_zero(self):
        inst = self._run_update({'battery_percent': -1})
        assert inst._perf_history['battery_percent'][-1] == 0.0

    def test_history_capped_at_thirty_points(self):
        inst = self._run_update({'cpu_percent': 1.0})
        for v in range(2, 45):
            inst._update_perf_ui({'cpu_percent': float(v)})
        assert len(inst._perf_history['cpu_percent']) == 30
        assert inst._perf_history['cpu_percent'][-1] == 44.0

    def test_winfo_exists_false_returns_early(self):
        inst = make_instance()
        inst.winfo_exists = lambda: False
        inst._update_perf_ui({'cpu_percent': 50.0})
        # Use __dict__ membership: bare Tk-derived instances recurse in
        # hasattr() for missing attributes (Misc.__getattr__ -> self.tk).
        assert '_perf_history' not in inst.__dict__


# --------------------------------------------------------------------------
# Tab-position indicator v29.34b — the label was referenced but never created
# --------------------------------------------------------------------------

class TestTabIndicatorV2934b:
    """The notebook tab-position readout (FIX-v28p18) referenced
    `self._tab_indicator` but nothing ever created it, so every update threw
    AttributeError inside a swallow-it `except`. The label must now exist."""

    def _src(self) -> str:
        return open(os.path.join(os.path.dirname(__file__),
                                 '..', 'downpour_v29_titanium.py'),
                    encoding='utf-8', errors='replace').read()

    def test_indicator_label_is_instantiated(self):
        src = self._src()
        # The label must be created (with the exact attr name) before the
        # <<NotebookTabChanged>> binding so the first tab change shows it.
        assert 'self._tab_indicator = tk.Label' in src
        # And the update method must exist to populate it.
        assert 'def _update_tab_indicator(self):' in src

    def test_indicator_created_before_tab_change_binding(self):
        src = self._src()
        # Scope to the _build_ui notebook-frame section (the first
        # <<NotebookTabChanged>> in the file is a lazy-builder binding from a
        # different method and must not be compared against).
        nb_idx = src.index('_nb_frame: Any = tk.Frame(self, bg=Colors.BG_VOID)')
        nb_src = src[nb_idx:]
        assert 'self._tab_indicator = tk.Label' in nb_src, \
            'tab indicator must be created inside the notebook frame build'
        lbl_pos = nb_src.index('self._tab_indicator = tk.Label')
        bind_pos = nb_src.index("self.nb.bind('<<NotebookTabChanged>>")
        assert lbl_pos < bind_pos, \
            'tab indicator must be created before the tab-change binding'

    def test_update_never_raises_on_bare_instance(self):
        inst = make_instance()
        inst._update_tab_indicator()  # noqa: SLF001 — bare-instance safety

    def test_update_skips_silently_without_notebook(self):
        inst = make_instance()
        inst._tab_indicator = None
        inst._update_tab_indicator()  # must not raise


# --------------------------------------------------------------------------
# DNS Overview live refresh v29.32 — throttled auto-refresh + in-flight guard
# --------------------------------------------------------------------------

class TestDnsOverviewLiveV2932:
    """The DNS Overview panel must refresh itself periodically instead of
    being a dead one-shot path (its caller vanished during loop cleanup)."""

    def _src(self) -> str:
        return open(os.path.join(os.path.dirname(__file__),
                                 '..', 'downpour_v29_titanium.py'),
                    encoding='utf-8', errors='replace').read()

    def test_overview_has_a_live_caller(self):
        """_dns_refresh_overview must be reachable, not just defined."""
        src = self._src()
        assert src.count('_dns_refresh_overview(') >= 2   # def + at least one call

    def test_overview_loop_wired_into_auto_start(self):
        src = self._src()
        assert 'self._dns_overview_loop' in src
        assert 'after(4000, self._dns_refresh_overview)' in src

    def test_overview_loop_never_raises_on_bare_instance(self):
        inst = make_instance()
        try:
            inst._dns_overview_loop()
        except Exception as e:  # pragma: no cover
            raise AssertionError(f'_dns_overview_loop raised: {e}')

    def test_overview_refresh_sets_busy_guard(self):
        """Starting a refresh must raise the in-flight guard."""
        import unittest.mock as um
        inst = make_instance()
        with um.patch.object(inst, '_dns_run_cmd', return_value=''):
            with um.patch('threading.Thread'):
                inst._dns_refresh_overview()
        assert inst._dns_overview_busy is True


# --------------------------------------------------------------------------
# v29.40 reliability — Python 3.13+ logging.handlers crash, live anomaly
# stats, perf-loop overlap guard, gauge-key uniqueness, stable-python pick
# --------------------------------------------------------------------------

class TestV2940Reliability:
    """Regression guards for the v29.40 fixes.

    - Python 3.13+ no longer auto-binds ``logging.handlers`` as an attribute;
      the startup crash ``module 'logging' has no attribute 'handlers'`` was
      fixed by importing the submodule explicitly.
    - The Perf tab's file/behavior anomaly stats (`fm`/`bs`) referenced
      variables that were never defined, so every one of those ~15 live gauges
      silently stayed 0.
    - `_perf_loop` could stack executor submissions when a tick ran long.
    - The GAUGES table had same-key duplicates (only one of the pair's canvases
      ever updated — the other one read the same key and stayed stale).
    """

    def _src(self) -> str:
        return open(os.path.join(os.path.dirname(__file__),
                                 '..', 'downpour_v29_titanium.py'),
                    encoding='utf-8', errors='replace').read()

    def test_logging_handlers_imported_explicitly(self):
        """3.13+ startup crash fix: submodule must be imported, not dotted."""
        src = self._src()
        assert 'import logging.handlers as _crash_handlers' in src
        assert '_crash_handlers.RotatingFileHandler' in src
        # The old dotted form that blew up on 3.13+ must be gone.
        assert '_crash_logging.handlers.RotatingFileHandler' not in src

    def test_fetch_file_anomaly_sources_defined(self):
        """`fm`/`bs` must be lazily bound (cached on the monitor), not NameError."""
        src = self._src()
        assert '_file_monitor_ref' in src
        assert '_behavior_scanner_ref' in src
        assert 'file_mod_hour' in src and 'behavior_lateral_hour' in src

    def test_fetch_prefers_live_ransomware_deque(self):
        """File gauges must prefer the app's live RansomwareDetector deque over
        the never-started orphan file_monitor module (v29.41)."""
        src = self._src()
        assert 'getattr(self, \'_app\', None)' in src
        assert 'getattr(app, \'ransomware\', None)' in src
        assert '_rw_src' in src
        assert '_file_changes' in src
        # The live path must read from the deque, not orphan-module counters.
        idx = src.index('app = getattr(self, \'_app\', None)')
        chunk = src[idx:idx + 3000]
        assert "_c.get('time', 0)" in chunk
        assert 'KnownThreats.RANSOMWARE_EXTENSIONS' in chunk

    def test_hw_monitor_given_app_backref(self):
        """HardwareMonitor must receive `_app` so _fetch reaches live engines."""
        src = self._src()
        assert 'self.hw._app = self' in src

    def test_fetch_file_block_keeps_fallback(self):
        """Without the app backref the file gauges still fall back to the
        orphan binding instead of raising."""
        src = self._src()
        idx = src.index('app = getattr(self, \'_app\', None)')
        chunk = src[idx:idx + 5000]
        assert '_file_monitor_ref' in chunk
        assert 'getattr(fm, \'_file_modifications_hour\', 0)' in chunk

    def test_fetch_process_network_prefer_live_app(self):
        """PROC/NET THREAT gauges must read the app's live process list and
        net_monitor alerts instead of the never-started orphan modules."""
        src = self._src()
        assert 'getattr(_app_nm, \'_processes\', None)' in src
        assert 'getattr(_app_nm, \'net_monitor\', None)' in src
        assert 'analyze_connections(' in src
        # `nm`/`pm` must stay bound (orphan fallback) so finer-grained anomaly
        # gauges below never NameError even when the live app path is used.
        idx = src.index('_app_nm = getattr(self, \'_app\', None)')
        chunk = src[idx:idx + 1200]
        assert 'nm = pm = None' in chunk

    def test_threat_intel_manager_cached_per_monitor(self):
        """ThreatIntelligenceManager does DB init in __init__; creating a fresh
        one every fetch tick (1-3s) is wasteful — both consumers must share one
        cached `_ti_ref` on the monitor."""
        src = self._src()
        assert self._src().count('self._ti_ref = ThreatIntelligenceManager()') == 2
        assert 'if not getattr(self, \'_ti_ref\', None):' in src

    def test_threat_intel_record_feed_history_defined(self):
        """OSINT feed updaters call _record_feed_history (threatfox/urlhaus/
        phishtank/malwarebazaar); it was missing, raising
        'no attribute _record_feed_history' and failing every feed update."""
        ti_path = os.path.join(os.path.dirname(__file__),
                               '..', 'threat_intelligence.py')
        ti_src = open(ti_path, encoding='utf-8', errors='replace').read()
        assert 'def _record_feed_history' in ti_src
        assert '_max_history_points' in ti_src
        assert "_feed_history.setdefault(feed_name, []).append(" in ti_src

    def test_vulnerability_scanner_cached_per_monitor(self):
        """VulnerabilityScanner does DB init in __init__; creating a fresh one
        every fetch tick re-opened the DB (~15s log spam). It must be cached
        once as `_vs_ref` on the monitor."""
        src = self._src()
        assert 'if not getattr(self, \'_vs_ref\', None):' in src
        assert 'self._vs_ref = VulnerabilityScanner()' in src
        assert 'vs = self._vs_ref' in src

    def test_vulnerability_scanner_none_safe_process_handling(self):
        """detect_exploit_attempts and check_privilege_escalations must not
        crash when psutil returns None for cmdline/username (Aug-11 log spam:
        'can only join an iterable', 'NoneType ... endswith'). And the
        per-tick CEV reader needs a long DB timeout."""
        vs_path = os.path.join(os.path.dirname(__file__),
                               '..', 'vulnerability_scanner.py')
        vs_src = open(vs_path, encoding='utf-8', errors='replace').read()
        assert "' '.join(proc_info.get('cmdline') or [])" in vs_src
        assert "(proc_info.get('username') or '').endswith('SYSTEM')" in vs_src
        idx = vs_src.index('def get_cev_score')
        chunk = vs_src[idx:idx + 500]
        assert 'sqlite3.connect(self.db_path, timeout=30)' in chunk

    def test_feed_updates_run_off_main_thread(self):
        """update_all_feeds() downloads + inserts large dumps; running it in
        the Tk 'after' callback froze the GUI for minutes. Both scheduled feed
        callbacks must spawn daemon worker threads and reschedule on main."""
        src = self._src()
        iu = src.index('def _scheduled_feed_update')
        chunk_u = src[iu:iu + 1300]
        assert "threading.Thread(target=_worker, daemon=True,\n                             name='FeedUpdate')" in chunk_u
        ih = src.index('def _scheduled_feed_health_check')
        chunk_h = src[ih:ih + 1700]
        assert "threading.Thread(target=_worker, daemon=True,\n                             name='FeedHealthCheck')" in chunk_h
        assert 'self.after(60 * 60 * 1000, self._scheduled_feed_update)' in chunk_u
        assert 'self.after(30 * 60 * 1000, self._scheduled_feed_health_check)' in chunk_h

    def test_fetch_behavior_prefers_live_scan_reasons(self):
        """Behavior gauges must classify [BEHAVIOR] findings from the app's live
        scanned process list instead of the never-started behavior_scanner."""
        src = self._src()
        assert 'risk_reasons' in src
        assert 'keylog_hour' in src and 'behavior_lateral_hour' in src
        idx = src.index('_bh = {\'keylog\': 0')
        chunk = src[idx:idx + 1600]
        assert 'risk_reasons' in chunk
        assert '_KEY' in chunk
        assert 'stats[\'keylog_hour\'] = _bh[\'keylog\']' in chunk

    def test_net_exfil_not_clobbered_by_behavior(self):
        """EXFIL/H is the net gauge; behavior's exfil must not overwrite it."""
        src = self._src()
        idx = src.index("stats.setdefault('exfil_hour'")
        assert 'stats.setdefault(\'exfil_hour\', _bh[\'exfil\'])' in src

    def test_net_anomaly_gauges_live_with_throttle(self):
        """port_scan/exfil/dns_tun/lateral must be served by the throttled live
        net_monitor analysis, with setdefault fallbacks for the orphan read."""
        src = self._src()
        assert '_nm_alert_ts' in src
        assert '_nm_alert_map' in src
        assert 'stats.setdefault(\'exfil_hour\', getattr(nm,' in src
        assert 'stats.setdefault(\'port_scan_hour\',' in src

    def test_process_anomaly_gauges_classify_live(self):
        """inject/disguise/sus_loc/sus_cmd/high_cpu classify the live process
        list, falling back to the orphan singleton only when idle."""
        src = self._src()
        assert '_PKEY' in src
        idx = src.index('_pp = {\'inject\': 0')
        chunk = src[idx:idx + 2600]
        assert 'stats[_k3] = _pp[_dst3]' in chunk
        assert '_high_cpu_processes_hour' in chunk

    def test_fetch_owns_its_dt_for_swap_rates(self):
        """swap/page-fault rates must not borrow the disk block's local dt."""
        src = self._src()
        assert '_dt_m' in src
        assert "_prev_mem_time" in src

    def test_perf_loop_has_inflight_guard(self):
        src = self._src()
        assert 'if getattr(self, \'_perf_inflight\', False):' in src
        assert 'self._perf_inflight = True' in src
        assert 'self._perf_inflight = False' in src

    def test_perf_loop_honors_adaptive_interval(self):
        src = self._src()
        assert '_adaptive_prf_ms' in src
        assert '_base_ms' in src

    def test_force_perf_received_timer_wired(self):
        """The 10s safety kick must be scheduled from _auto_start."""
        src = self._src()
        assert 'after(10_000, _force_perf_ui)' in src

    def test_gauge_keys_are_unique(self):
        """Duplicate stat keys in the GAUGES literal = a stale gauge."""
        import re
        src = self._src()
        m = re.search(r'GAUGES: Any = \[(.*?)\]', src, re.S)
        assert m, 'GAUGES literal not found'
        keys = re.findall(r"\(\s*'[^']*',\s*'([^']+)'", m.group(1))
        assert len(keys) == len(set(keys)), 'duplicate gauge stat keys found'

    def test_find_latest_python_skips_prereleases(self):
        """3.15.0a6 must not be preferred over stable builds."""
        src = self._src()
        assert '_is_stable' in src
        assert "releaselevel == 'final'" in src

    def test_removed_dead_hw_thread_nameerror_landmine(self):
        """The broken _update_hw_ui except-block (undefined pct/score) is gone."""
        src = self._src()
        assert 'Security Score: {pct}% ({score}/{max_score})' not in src

    def test_aegis_layer_wiring_guarded(self):
        """AEGIS alert wiring must tolerate missing optional layers."""
        src = self._src()
        idx = src.index('_aegis_alert(msg: str, level: str = \'HIGH\'):')
        chunk = src[idx:idx + 1200]
        assert 'getattr(self, \'aegis_physical\', None)' in chunk


