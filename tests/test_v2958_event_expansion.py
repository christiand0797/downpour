"""Tests for v29.58: expanded event push coverage (7 channels, 35 event IDs)."""
import importlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

event_push_monitor = importlib.import_module('event_push_monitor')

XML_5001 = ("<Event><System><Provider Name='Microsoft-Windows-Windows Defender'/>"
            "<EventID>5001</EventID></System><EventData>"
            "<Data>Real-time protection is disabled</Data></EventData></Event>")
XML_1149 = ("<Event><System><Provider Name='Microsoft-Windows-TerminalServices-RemoteConnectionManager'/>"
            "<EventID>1149</EventID></System><EventData>"
            "<Data Name='User'>evil_admin</Data>"
            "<Data Name='Address'>10.0.0.5</Data></EventData></Event>")
XML_5157 = ("<Event><System><Provider Name='Microsoft-Windows-Windows Firewall With Advanced Security'/>"
            "<EventID>5157</EventID></System><EventData>"
            "<Data Name='Application'>C:\\Users\\evil\\c2.exe</Data>"
            "<Data Name='RemotePort'>4444</Data></EventData></Event>")


class TestExpandedEventCoverage(unittest.TestCase):
    def setUp(self):
        self.alerts = []
        self.mon = event_push_monitor.EventPushMonitor(self.alerts.append)

    def test_channel_count(self):
        self.assertEqual(len(event_push_monitor.CHANNELS), 7)
        self.assertIn('Microsoft-Windows-Windows Defender/Operational',
                      event_push_monitor.CHANNELS)
        self.assertIn('Microsoft-Windows-TerminalServices-LocalSessionManager'
                      '/Operational', event_push_monitor.CHANNELS)
        self.assertIn('Microsoft-Windows-Windows Firewall With Advanced '
                      'Security/Firewall', event_push_monitor.CHANNELS)

    def test_event_id_count(self):
        self.assertGreaterEqual(len(event_push_monitor.EVENT_MAP), 35)

    def test_t1562_defender_tamper(self):
        self.assertIn(5001, event_push_monitor.EVENT_MAP)
        tech, sev, desc = event_push_monitor.EVENT_MAP[5001]
        self.assertEqual(tech, 'T1562.001')
        self.assertEqual(sev, 'CRITICAL')
        self.assertIn('TAMPER', desc)

    def test_t1021_rdp(self):
        self.assertIn(1149, event_push_monitor.EVENT_MAP)
        tech, sev, _ = event_push_monitor.EVENT_MAP[1149]
        self.assertEqual(tech, 'T1021.001')
        self.assertEqual(sev, 'HIGH')

    def test_t1071_firewall(self):
        self.assertIn(5157, event_push_monitor.EVENT_MAP)
        tech, sev, desc = event_push_monitor.EVENT_MAP[5157]
        self.assertEqual(tech, 'T1071')
        self.assertEqual(sev, 'MEDIUM')
        self.assertIn('BLOCKED', desc)

    def test_t1136_account(self):
        for eid in (4720, 4738):
            self.assertIn(eid, event_push_monitor.EVENT_MAP)
            tech, _, _ = event_push_monitor.EVENT_MAP[eid]
            self.assertIn('T1136', tech)
        # 4726 = account deleted (T1531, a related but different technique)
        self.assertIn(4726, event_push_monitor.EVENT_MAP)
        self.assertEqual(event_push_monitor.EVENT_MAP[4726][0], 'T1531')

    def test_defender_tamper_alert(self):
        self.mon._handle_event(5001, XML_5001)
        self.assertEqual(len(self.alerts), 1)
        a = self.alerts[0]
        self.assertEqual(a.severity, 'CRITICAL')
        self.assertEqual(a.technique, 'T1562.001')
        self.assertIn('TAMPER', a.description)

    def test_rdp_lateral_movement_alert(self):
        self.mon._handle_event(1149, XML_1149)
        self.assertEqual(len(self.alerts), 1)
        a = self.alerts[0]
        self.assertEqual(a.technique, 'T1021.001')
        self.assertEqual(a.severity, 'HIGH')

    def test_firewall_blocked_alert(self):
        self.mon._handle_event(5157, XML_5157)
        self.assertEqual(len(self.alerts), 1)
        a = self.alerts[0]
        self.assertEqual(a.technique, 'T1071')
        self.assertEqual(a.severity, 'MEDIUM')

    def test_malware_detected_alert(self):
        self.mon._handle_event(1116, XML_5001)  # reuse XML (event_id override)
        self.assertEqual(len(self.alerts), 1)
        a = self.alerts[0]
        self.assertEqual(a.technique, 'T1204')
        self.assertEqual(a.severity, 'HIGH')

    def test_tolerated_channels(self):
        self.assertTrue(hasattr(event_push_monitor, '_TOLERATED_CHANNELS'))
        self.assertGreaterEqual(
            len(event_push_monitor._TOLERATED_CHANNELS), 3)


if __name__ == '__main__':
    unittest.main()
