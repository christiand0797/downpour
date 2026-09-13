"""Tests for v29.59: forensic report module + tab wiring."""
import importlib
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

fr = importlib.import_module('forensic_report')

MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'downpour_v29_titanium.py')
with open(MAIN, encoding='utf-8', errors='replace') as f:
    main_src = f.read()


class TestForensicReportModule(unittest.TestCase):
    def test_collect_all_evidence_structure(self):
        # v29.60: the collectors are native now (native_probes / _run_cmd);
        # stub the native event walker + native cmd runner to keep the test
        # offline-deterministic.
        import native_probes
        with mock.patch.object(native_probes, 'evt_query_events',
                               return_value=[]), \
                mock.patch.object(fr, '_run_cmd', return_value=None):
            evidence = fr.collect_all_evidence()
        for key in ('chain_of_custody', 'attacker_ips', 'rdp_sessions',
                    'account_events', 'defender_tamper', 'firewall_events',
                    'suspicious_tasks', 'total_evidence'):
            self.assertIn(key, evidence)
        coc = evidence['chain_of_custody']
        self.assertIn('hostname', coc)
        self.assertIn('collected_at', coc)

    def test_generate_html_report(self):
        evidence = {
            'chain_of_custody': {'hostname': 'test-pc',
                                 'collected_at': '2026-01-01T00:00:00Z'},
            'attacker_ips': [{'ip': '1.2.3.4', 'reason': 'DDoS',
                              'blocked_at': '2026-01-01'}],
            'rdp_sessions': [], 'account_events': [],
            'defender_tamper': [], 'firewall_events': [],
            'suspicious_tasks': [], 'total_evidence': 1,
        }
        html = fr.generate_html_report(evidence)
        self.assertIn('Downpour Forensic Investigation Report', html)
        self.assertIn('1.2.3.4', html)
        self.assertIn('Chain of Custody', html)
        self.assertIn('test-pc', html)
        self.assertIn('ic3.gov', html)

    def test_save_report(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix='dp_forensic_')
        evidence = {'chain_of_custody': {'hostname': 'pc'},
                    'total_evidence': 0, 'attacker_ips': [],
                    'rdp_sessions': [], 'account_events': [],
                    'defender_tamper': [], 'firewall_events': [],
                    'suspicious_tasks': []}
        html_path, json_path = fr.save_report(evidence, output_dir=tmp)
        self.assertTrue(os.path.isfile(html_path))
        self.assertTrue(os.path.isfile(json_path))
        self.assertIn('forensic', html_path)


class TestForensicTabWiring(unittest.TestCase):
    def test_tab_registered(self):
        self.assertIn('_tab_forensic', main_src)
        self.assertIn('_build_forensic_tab', main_src)

    def test_collect_method(self):
        self.assertIn('def _forensic_collect', main_src)
        self.assertIn('from forensic_report import collect_all_evidence',
                      main_src)

    def test_report_method(self):
        self.assertIn('def _forensic_report', main_src)
        self.assertIn('from forensic_report import save_report', main_src)

    def test_fbi_ic3_button(self):
        self.assertIn('ic3.gov', main_src)

    def test_alert_tag(self):
        self.assertIn('[FORENSIC]', main_src)


if __name__ == '__main__':
    unittest.main()
