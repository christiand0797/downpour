"""Tests for v29.47: dns_cache_watch, misp_feed, child_process_guard +
main-file wiring."""
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

dns_cache_watch = importlib.import_module('dns_cache_watch')
misp_feed = importlib.import_module('misp_feed')
child_process_guard = importlib.import_module('child_process_guard')
native_probes = importlib.import_module('native_probes')


class TestDnsCacheWatch(unittest.TestCase):
    def test_known_good_scores_zero(self):
        self.assertEqual(dns_cache_watch.score_domain(
            'www.microsoft.com')['score'], 0)
        self.assertEqual(dns_cache_watch.score_domain(
            'api.github.com')['score'], 0)

    def test_dga_scores_high(self):
        scored = dns_cache_watch.score_domain('xk4j2h9qz8v1m3w7p6r2.tk')
        self.assertGreaterEqual(scored['score'],
                                dns_cache_watch._ALERT_THRESHOLD)
        self.assertIn('high entropy', ' '.join(scored['factors']))

    def test_dictionary_words_discount(self):
        plain = dns_cache_watch.score_domain('mikrotik-router-config'
                                             '.example-server.net')
        # dictionary-ish words discount keeps benign infra quiet
        self.assertLess(plain['score'],
                        dns_cache_watch._ALERT_THRESHOLD)

    def test_not_a_domain(self):
        self.assertEqual(dns_cache_watch.score_domain('localhost')
                         ['score'], 0)

    def _canned_native(self, pages):
        """native_probes stub serving per-call canned (name, data) lists
        (list cycles last). v29.60: collect_dns_cache is native now."""
        calls = {'n': 0}

        def fake_walk():
            idx = min(calls['n'], len(pages) - 1)
            calls['n'] += 1
            return pages[idx]
        return mock.patch.object(native_probes, 'get_dns_cache_entries',
                                 fake_walk)

    def test_tofu_then_alert_then_quiet(self):
        tmp = tempfile.mkdtemp(prefix='dp_dns_')
        orig = dns_cache_watch.BASELINE_PATH
        dns_cache_watch.BASELINE_PATH = os.path.join(tmp, 'dns.json')
        good = [('www.google.com', '142.250.0.1')]
        with_dga = [('www.google.com', '142.250.0.1'),
                    ('xk4j2h9qz8v1m3w7p6r2.tk', '1.2.3.4')]
        try:
            with self._canned_native([good]):
                self.assertEqual(dns_cache_watch.run_dns_cache_check(), [])
            with self._canned_native([with_dga]):
                alerts = dns_cache_watch.run_dns_cache_check()
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0].source, 'dns_cache')
            self.assertIn(alerts[0].severity, ('MEDIUM', 'HIGH'))
            self.assertIn(alerts[0].technique, ('T1568', 'T1071.004'))
            self.assertIn('.tk', alerts[0].detail)
            with self._canned_native([with_dga]):
                self.assertEqual(dns_cache_watch.run_dns_cache_check(), [])
        finally:
            dns_cache_watch.BASELINE_PATH = orig

    def test_collect_never_raises(self):
        # Native walker failing (or missing) must degrade to [] silently
        with mock.patch.object(native_probes, 'get_dns_cache_entries',
                               side_effect=OSError('boom')):
            self.assertEqual(dns_cache_watch.collect_dns_cache(), [])


class TestMispFeed(unittest.TestCase):
    def test_extraction_and_domain_ip_split(self):
        attrs = [
            {'type': 'sha256', 'value': 'a' * 64, 'comment': 'dropper',
             'event_id': '42'},
            {'type': 'ip-dst', 'value': '8.8.8.8'},
            {'type': 'domain|ip', 'value': 'evil.test|1.1.1.1'},
            {'type': 'url', 'value': 'http://x/y'},
            {'type': 'text', 'value': 'ignored-type'},
            {'type': 'sha256', 'value': 'a' * 64, 'deleted': '1'},
            {'type': 'sha256', 'value': 'a' * 64},   # dedupe vs first
        ]
        inds = misp_feed.extract_indicators(attrs, 't')
        self.assertEqual(len(inds), 5)
        types = {i['type'] for i in inds}
        self.assertEqual(types, {'hash', 'ip', 'domain', 'url'})
        self.assertIn('event 42', next(
            i['name'] for i in inds if i['type'] == 'hash'))

    def test_disabled_by_default(self):
        self.assertFalse(misp_feed.sync_once(config={'enabled': False})
                         ['enabled'])

    def test_config_round_trip(self):
        tmp = tempfile.mkdtemp(prefix='dp_misp_')
        p = Path(tmp) / 'misp_config.json'
        self.assertTrue(misp_feed.save_config(misp_feed.default_config(),
                                              path=p))
        self.assertFalse(misp_feed.load_config(path=p)['enabled'])

    def _fake_requests(self, payload, status=200):
        class FakeResp:
            status_code = status

            def json(self):
                return payload

            def raise_for_status(self):
                pass
        fake = mock.MagicMock()
        fake.post.return_value = FakeResp()
        return fake

    def test_response_shape_new(self):
        payload = {'response': {'Attribute': [
            {'type': 'domain', 'value': 'a.test', 'event_id': '7'}]}}
        with mock.patch.object(misp_feed, 'requests',
                               self._fake_requests(payload)):
            attrs, err = misp_feed._request_attributes(
                {'url': 'https://m', 'api_key': 'k'}, '')
        self.assertEqual(err, '')
        self.assertEqual(len(attrs), 1)

    def test_response_shape_old(self):
        payload = {'response': [
            {'type': 'domain', 'value': 'b.test', 'event_id': '7'}]}
        with mock.patch.object(misp_feed, 'requests',
                               self._fake_requests(payload)):
            attrs, err = misp_feed._request_attributes(
                {'url': 'https://m', 'api_key': 'k'}, '')
        self.assertEqual(err, '')
        self.assertEqual(len(attrs), 1)

    def test_auth_failure_surface(self):
        with mock.patch.object(misp_feed, 'requests',
                               self._fake_requests({}, status=403)):
            _attrs, err = misp_feed._request_attributes(
                {'url': 'https://m', 'api_key': 'k'}, '')
        self.assertIn('403', err)


class TestChildProcessGuard(unittest.TestCase):
    """Live job install (safe: contains only this test process)."""

    def test_install_idempotent(self):
        if not child_process_guard._WIN32JOB_AVAILABLE:
            self.skipTest('pywin32 unavailable')
        guard = child_process_guard.ChildProcessGuard()
        st = guard.install()
        if not st['installed']:
            # v29.60: non-elevated shells get ERROR_ACCESS_DENIED from
            # CreateJobObject on hardened builds — the feature is fine;
            # only the live-install assertion needs elevation.
            self.skipTest(f"job install unavailable here: {st['reason']}")
        self.assertTrue(st['kill_on_close'])
        self.assertTrue(st['breakaway_blocked'])
        # our own process must now be a member of the job
        pids = guard.list_job_pids()
        self.assertIsInstance(pids, list)
        self.assertGreaterEqual(len(pids), 1)
        # second install reports already-installed without duplicating
        st2 = child_process_guard.install_job_guard() if \
            child_process_guard._module_guard else st
        self.assertIn(st2.get('reason'), ('ok', 'already installed'))
        # FIX (v29.60): this test assigned the PYTEST PROCESS ITSELF to a
        # KILL_ON_JOB_CLOSE job. When the guard's handle was later garbage
        # collected, the kernel terminated the entire pytest run mid-suite
        # (the silent "no summary, dead at ~73%" full-suite symptom). Strip
        # the kill-on-close flag so the leftover job is inert: it ends when
        # this process exits anyway, which is exactly what we want here.
        try:
            import win32job as _wj
            _limits = _wj.QueryInformationJobObject(
                guard.handle, _wj.JobObjectExtendedLimitInformation)
            _limits['BasicLimitInformation']['LimitFlags'] = 0
            _wj.SetInformationJobObject(
                guard.handle, _wj.JobObjectExtendedLimitInformation, _limits)
        except Exception:
            pass

    def test_module_guard_status_shape(self):
        st = child_process_guard.get_guard_status()
        for key in ('installed', 'kill_on_close', 'breakaway_blocked',
                    'reason'):
            self.assertIn(key, st)

    def test_terminate_guarded_when_not_installed(self):
        # must never terminate anything when there is no handle
        g = child_process_guard.ChildProcessGuard()
        self.assertFalse(g.terminate_all_children())

    def test_terminate_guarded_when_pywin32_missing(self):
        g = child_process_guard.ChildProcessGuard()
        g._handle = 1234                      # fake handle
        with mock.patch.object(child_process_guard,
                               '_WIN32JOB_AVAILABLE', False):
            self.assertFalse(g.terminate_all_children())

    def test_never_raises_on_install_garbage(self):
        with mock.patch.object(child_process_guard, 'win32job', None), \
                mock.patch.object(child_process_guard,
                                  '_WIN32JOB_AVAILABLE', False):
            st = child_process_guard.ChildProcessGuard().install()
        self.assertFalse(st['installed'])
        self.assertIn('unavailable', st['reason'])


class TestV2947Wiring(unittest.TestCase):
    """Source-structure tests — main file read as text, never imported."""
    MAIN = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'downpour_v29_titanium.py')

    @classmethod
    def setUpClass(cls):
        with open(cls.MAIN, encoding='utf-8', errors='replace') as f:
            cls.src = f.read()

    def test_dns_watch_wired(self):
        self.assertIn('import dns_cache_watch', self.src)
        self.assertIn('DNS_CACHE_WATCH_AVAILABLE', self.src)
        self.assertIn('_dns_cache_alert_bridge', self.src)
        self.assertIn('_dns_cache_loop', self.src)
        self.assertIn('[DNS-CACHE]', self.src)
        self.assertIn('_dns_cache_started', self.src)

    def test_misp_wired(self):
        self.assertIn('import misp_feed', self.src)
        self.assertIn('MISP_FEED_AVAILABLE', self.src)
        self.assertIn('_misp_sync_oneshot', self.src)
        self.assertIn('[MISP]', self.src)
        self.assertIn('_misp_started', self.src)

    def test_job_guard_wired(self):
        self.assertIn('import child_process_guard', self.src)
        self.assertIn('CHILD_PROCESS_GUARD_AVAILABLE', self.src)
        self.assertIn('install_job_guard', self.src)
        self.assertIn('[JOB-GUARD]', self.src)
        self.assertIn('_job_guard_started', self.src)

    def test_guard_installs_before_probes(self):
        # the job-guard block must appear BEFORE the USB monitor start so
        # every subsequent spawned probe is contained
        guard_pos = self.src.find('_job_guard_started')
        usb_pos = self.src.find('_usb_monitor_loop')
        self.assertGreater(guard_pos, 0)
        self.assertLess(guard_pos, usb_pos)


if __name__ == '__main__':
    unittest.main()
