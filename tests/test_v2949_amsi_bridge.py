"""Tests for v29.49: AMSI bridge into push-delivered 4104 events."""
import importlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

event_push_monitor = importlib.import_module('event_push_monitor')

XML_4104 = ("<Event><System><EventID>4104</EventID></System><EventData>"
            "<Data Name='ScriptBlockText'>{}</Data></EventData></Event>")


class TestAmsiBridge(unittest.TestCase):
    def setUp(self):
        self.alerts = []
        self.mon = event_push_monitor.EventPushMonitor(self.alerts.append)

    def _fake_amsi_module(self, analyze_result=None, scan_result=None,
                          initialized=True):
        """Build a fake amsi_integration module for patching."""
        fake = mock.MagicMock()
        fake.PowerShellEvent = mock.MagicMock()
        integration = mock.MagicMock()
        integration.amsi_initialized = initialized
        integration.scan_string.return_value = scan_result
        if analyze_result is not None:
            def fake_analyze(event):
                event.is_suspicious = analyze_result.get('suspicious', False)
                event.severity = analyze_result.get('severity', 'LOW')
                event.mitre_techniques = analyze_result.get(
                    'mitre', ['T1059.001'])
                event.suspicious_patterns = analyze_result.get(
                    'patterns', ['x'])
            integration._analyze_script.side_effect = fake_analyze
        fake.get_amsi_integration.return_value = integration
        return fake, integration

    def test_suspicious_pattern_emits_alert(self):
        fake, _ = self._fake_amsi_module(analyze_result={
            'suspicious': True, 'severity': 'CRITICAL',
            'mitre': ['T1003.001'], 'patterns': ['Mimikatz']})
        with mock.patch.object(event_push_monitor, 'amsi_integration', fake), \
                mock.patch.object(event_push_monitor,
                                  '_AMSI_AVAILABLE', True):
            self.mon._handle_event(4104, XML_4104.format('evil script'))
        amsi_alerts = [a for a in self.alerts
                       if a.description.startswith('[AMSI-PS]')]
        self.assertEqual(len(amsi_alerts), 1)
        a = amsi_alerts[0]
        self.assertEqual(a.severity, 'CRITICAL')
        self.assertEqual(a.technique, 'T1003.001')
        self.assertIn('Mimikatz', a.detail)

    def test_av_engine_verdict_emits_critical(self):
        scan = mock.MagicMock()
        scan.result = event_push_monitor._AMSI_MALICIOUS_RESULT
        scan.content_name = 'downpour-4104'
        fake, _ = self._fake_amsi_module(
            analyze_result={'suspicious': False, 'severity': 'LOW',
                            'mitre': [], 'patterns': []},
            scan_result=scan)
        with mock.patch.object(event_push_monitor, 'amsi_integration', fake), \
                mock.patch.object(event_push_monitor,
                                  '_AMSI_AVAILABLE', True):
            self.mon._handle_event(4104, XML_4104.format('some payload'))
        verdicts = [a for a in self.alerts
                    if a.description.startswith('[AMSI]')]
        self.assertEqual(len(verdicts), 1)
        self.assertEqual(verdicts[0].severity, 'CRITICAL')

    def test_clean_script_is_silent(self):
        scan = mock.MagicMock()
        scan.result = 1                        # NOT_DETECTED
        fake, _ = self._fake_amsi_module(
            analyze_result={'suspicious': False, 'severity': 'LOW',
                            'mitre': [], 'patterns': []},
            scan_result=scan)
        with mock.patch.object(event_push_monitor, 'amsi_integration', fake), \
                mock.patch.object(event_push_monitor,
                                  '_AMSI_AVAILABLE', True):
            self.mon._handle_event(4104, XML_4104.format("Write-Host 'hi'"))
        self.assertEqual([a for a in self.alerts
                          if 'AMSI' in a.description], [])

    def test_amsi_exception_is_contained(self):
        fake = mock.MagicMock()
        fake.get_amsi_integration.side_effect = RuntimeError('boom')
        with mock.patch.object(event_push_monitor, 'amsi_integration', fake), \
                mock.patch.object(event_push_monitor,
                                  '_AMSI_AVAILABLE', True):
            try:
                self.mon._handle_event(4104, XML_4104.format('anything'))
            except RuntimeError:
                self.fail('AMSI exception leaked into the event thread')

    def test_unavailable_amsi_is_skipped(self):
        with mock.patch.object(event_push_monitor, 'amsi_integration', None), \
                mock.patch.object(event_push_monitor,
                                  '_AMSI_AVAILABLE', False):
            self.mon._handle_event(4104, XML_4104.format('anything'))
        # informational 4104 only — no AMSI alerts, no crash
        self.assertTrue(all('AMSI' not in a.description
                            for a in self.alerts))

    def test_scan_result_below_threshold_is_silent(self):
        scan = mock.MagicMock()
        scan.result = 1                        # clean/not-detected
        fake, _ = self._fake_amsi_module(
            analyze_result={'suspicious': False, 'severity': 'LOW',
                            'mitre': [], 'patterns': []},
            scan_result=scan)
        with mock.patch.object(event_push_monitor, 'amsi_integration', fake), \
                mock.patch.object(event_push_monitor,
                                  '_AMSI_AVAILABLE', True):
            self.mon._handle_event(4104, XML_4104.format('x'))
        self.assertEqual([a for a in self.alerts
                          if a.description.startswith('[AMSI]')], [])

    def test_amsi_module_bugs_fixed(self):
        """The never-wired module had two crash bugs (wintypes.HRESULT,
        missing math import) — both must be fixed for the bridge to work."""
        self.assertTrue(event_push_monitor._AMSI_AVAILABLE)
        integration = event_push_monitor.amsi_integration \
            .get_amsi_integration()
        # live AMSI context init (Windows AV provider) — on non-Windows or
        # hardened CI this degrades gracefully, so only assert no-crash
        self.assertIsNotNone(integration)
        evt = event_push_monitor.amsi_integration.PowerShellEvent(
            timestamp=0.0, event_id=4104, sequence_number=0,
            script_block_text='Invoke-Mimikatz', script_block_id='')
        integration._analyze_script(evt)     # must not raise NameError
        self.assertTrue(evt.is_suspicious)   # mimikatz keyword → flagged
        self.assertEqual(evt.severity, 'CRITICAL')


if __name__ == '__main__':
    unittest.main()
