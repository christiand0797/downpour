"""Tests for pe_analyzer and event_log_monitor (v29.44b)."""
import os
import sys
import time
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pe_analyzer import (  # noqa: E402
    SUSPICIOUS_IMPORTS, PACKER_SIGNATURES, _shannon_entropy, analyze_pe)

NOTEPAD = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                       'System32', 'notepad.exe')


class TestPEAnalyzer(unittest.TestCase):
    def test_entropy_empty_and_uniform(self):
        self.assertEqual(_shannon_entropy(b''), 0.0)
        self.assertEqual(_shannon_entropy(b'\x00' * 1000), 0.0)
        self.assertAlmostEqual(_shannon_entropy(bytes(range(256))), 8.0, 1)

    def test_notepad_analyzes_clean(self):
        if not os.path.isfile(NOTEPAD):
            self.skipTest('notepad.exe not available')
        r = analyze_pe(NOTEPAD)
        self.assertTrue(r.is_pe)
        self.assertFalse(r.is_dll)
        self.assertEqual(len(r.sha256), 64)
        self.assertGreater(len(r.sections), 0)
        self.assertLess(r.risk_score, 30, 'clean system binary must score low')
        self.assertNotIn('UPX', r.packers_detected)

    def test_nonpe_file(self):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
            f.write(b'plain text, not a PE at all')
            path = f.name
        try:
            r = analyze_pe(path)
            self.assertFalse(r.is_pe)
            self.assertIsNotNone(r.error)
        finally:
            os.unlink(path)

    def test_missing_file(self):
        r = analyze_pe('Z:/definitely/not/there.exe')
        self.assertFalse(r.is_pe)
        self.assertIn('hash failed', (r.error or ''))

    def test_packer_table_covers_major_families(self):
        for family in ('UPX', 'Themida', 'VMProtect', 'MPRESS'):
            self.assertIn(family, PACKER_SIGNATURES.values())

    def test_injection_apis_listed(self):
        for api in ('VirtualAllocEx', 'WriteProcessMemory',
                    'CreateRemoteThread'):
            self.assertIn(api, SUSPICIOUS_IMPORTS['process_injection'])


if __name__ == '__main__':
    unittest.main()


class _FakeEvent:
    def __init__(self, eid, record, inserts=None):
        self.EventID = eid
        self.RecordNumber = record
        self.StringInserts = inserts or []
        self.TimeGenerated = None


class _FakeEvt(types.SimpleNamespace):
    """Fake win32evtlog module with the flag constants the monitor uses."""
    EVENTLOG_BACKWARDS_READ = 8
    EVENTLOG_SEQUENTIAL_READ = 1


class TestEventLogMonitor(unittest.TestCase):
    def _monitor(self):
        from event_log_monitor import EventLogMonitor
        return EventLogMonitor()

    @staticmethod
    def _fake(events, log_name='System'):
        """Fake win32evtlog: events only for `log_name`, empty for others."""
        return _FakeEvt(
            ReadEventLog=lambda h, f, b: (
                list(events) if getattr(h, '_log', None) == log_name else []),
            OpenEventLog=lambda machine, name: types.SimpleNamespace(
                _log=name),
            CloseEventLog=lambda h: None)

    def test_service_install_alerts(self):
        m = self._monitor()
        fake = self._fake([
            _FakeEvent(7045, 5, ['evilsvc', 'C:\\tmp\\x.exe', '4']),
            _FakeEvent(1000, 4, ['noise'])])
        with mock.patch('event_log_monitor.win32evtlog', fake):
            alerts = m.check_once()
        svc = [a for a in alerts if a.event_id == 7045]
        self.assertEqual(len(svc), 1)
        self.assertEqual(svc[0].technique, 'T1543.003')
        self.assertEqual(svc[0].severity, 'HIGH')
        self.assertIn('evilsvc', svc[0].detail)
        # bookmark prevents re-alerting the same record
        with mock.patch('event_log_monitor.win32evtlog', fake):
            self.assertEqual(
                len([a for a in m.check_once() if a.event_id == 7045]), 0)

    def test_log_clear_is_critical(self):
        m = self._monitor()
        with mock.patch('event_log_monitor.win32evtlog',
                        self._fake([_FakeEvent(1102, 7)])):
            alerts = m.check_once()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'CRITICAL')
        self.assertIn('TAMPER', alerts[0].description)

    def test_ps_block_filtering(self):
        m = self._monitor()
        self.assertTrue(m._ps_block_suspicious(
            'IEX (New-Object Net.WebClient).DownloadString(...)'))
        self.assertFalse(m._ps_block_suspicious(
            'Write-Host hello world'))
        fake = self._fake([
            _FakeEvent(4104, 9, ['Write-Host benign']),
            _FakeEvent(4104, 10, ['iex downloaded payload'])])
        with mock.patch('event_log_monitor.win32evtlog', fake):
            alerts = [a for a in m.check_once() if a.event_id == 4104]
        self.assertEqual(len(alerts), 1)
        self.assertIn('payload', alerts[0].detail)

    def test_brute_force_burst(self):
        m = self._monitor()
        now = time.time()
        with m._lock:
            m._failed_logons = [now - 5] * 12
        alerts = m.check_once()  # no win32evtlog read needed
        bf = [a for a in alerts if a.event_id == 4625]
        self.assertEqual(len(bf), 1)
        self.assertIn('12 failed logons', bf[0].detail)

    def test_brute_force_old_events_expire(self):
        m = self._monitor()
        with m._lock:
            m._failed_logons = [time.time() - 4000] * 30
        self.assertEqual(
            len([a for a in m.check_once() if a.event_id == 4625]), 0)

    def test_unavailable_evt_returns_empty(self):
        m = self._monitor()
        with mock.patch('event_log_monitor._EVT_AVAILABLE', False):
            self.assertEqual(m.check_once(), [])

    def test_callback_receives_alerts(self):
        m = self._monitor()
        got = []
        m.callback = got.append
        with mock.patch('event_log_monitor.win32evtlog',
                        self._fake([_FakeEvent(4698, 3, ['task1'])])):
            m.check_once()
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].event_id, 4698)


class TestMainWiring(unittest.TestCase):
    """Source-structure assertions (main file is never imported)."""

    MAIN = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'downpour_v29_titanium.py')

    @classmethod
    def setUpClass(cls):
        with open(cls.MAIN, encoding='utf-8', errors='replace') as f:
            cls.src = f.read()

    def test_monitor_imported_and_started(self):
        self.assertIn('from event_log_monitor import', self.src)
        self.assertIn('EVENT_LOG_MONITOR_AVAILABLE', self.src)
        self.assertIn('_event_log_alert_bridge', self.src)
        # started from the security-monitors engine, not just defined
        call_site = self.src.find(
            'get_event_log_monitor(\n                        callback=')
        self.assertGreater(call_site, 0)
        self.assertGreater(
            call_site,
            self.src.index('def _manual_start_security_monitors'))

    def test_bridge_uses_real_color_attrs(self):
        self.assertNotIn('Colors.ALERT_RED', self.src)
        self.assertIn('Colors.GAUGE_RED', self.src)