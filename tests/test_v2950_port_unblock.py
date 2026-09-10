"""Tests for port_firewall_unblock (v29.50)."""
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pfu = importlib.import_module('port_firewall_unblock')

# Simulated netsh output with 2 Downpour rules + 1 non-Downpour rule
FAKE_OUT_IN = (
    "==========================================================================\n"
    "Rule Name:            Downpour_DDoS_Block_1_2_3_4\n"
    "--------------------------------------------------------------------------\n"
    "Description:          DDoS block\n"
    "Enabled:              Yes\n"
    "Direction:            In\n"
    "Profiles:             Domain,Private,Public\n"
    "Grouping:             \n"
    "LocalIP:              Any\n"
    "RemoteIP:             1.2.3.4\n"
    "Protocol:             Any\n"
    "Edge traversal:       No\n"
    "Action:               Block\n"
    "\n"
    "Ok.\n"
)
FAKE_OUT_OUT = (
    "==========================================================================\n"
    "Rule Name:            Downpour_VPN_KillSwitch_BlockAll\n"
    "--------------------------------------------------------------------------\n"
    "Enabled:              Yes\n"
    "Direction:            Out\n"
    "Profiles:             Domain,Private,Public\n"
    "LocalIP:              Any\n"
    "RemoteIP:             Any\n"
    "Protocol:             Any\n"
    "Action:               Block\n"
    "\n"
    "Rule Name:            Windows_Media_Player\n"
    "--------------------------------------------------------------------------\n"
    "Enabled:              Yes\n"
    "Direction:            Out\n"
    "Action:               Allow\n"
    "\n"
    "Ok.\n"
)
class TestListDownpourRules(unittest.TestCase):
    def test_parses_and_filters(self):
        with mock.patch.object(pfu, '_run',
                               side_effect=[(0, FAKE_OUT_IN),
                                            (0, FAKE_OUT_OUT)]):
            rules = pfu.list_downpour_rules()
        names = sorted(r['name'] for r in rules)
        self.assertEqual(
            names, ['Downpour_DDoS_Block_1_2_3_4',
                    'Downpour_VPN_KillSwitch_BlockAll'])

    def test_netsh_failure_is_tolerated(self):
        with mock.patch.object(pfu, '_run',
                               side_effect=[(-1, 'netsh unavailable'),
                                            (-1, 'netsh unavailable')]):
            self.assertEqual(pfu.list_downpour_rules(), [])


class TestCategorize(unittest.TestCase):
    def test_categories(self):
        self.assertIn('DDoS', pfu.categorize(
            {'name': 'Downpour_DDoS_Block_1_2_3_4', 'action': 'Block'}))
        self.assertIn('kill-switch', pfu.categorize(
            {'name': 'Downpour_VPN_KillSwitch_BlockAll',
             'action': 'Block'}))
        self.assertIn('Emergency', pfu.categorize(
            {'name': 'DOWNPOUR_EMERGENCY_BLOCK', 'action': 'Block'}))
        self.assertIn('C2', pfu.categorize(
            {'name': 'Downpour_C2_Block_1_2_3_4', 'action': 'Block'}))


class TestUnblock(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix='dp_pfu_')
        self._orig_audit = pfu.AUDIT_PATH
        pfu.AUDIT_PATH = Path(self._tmp) / 'port_unblock_audit.json'

    def tearDown(self):
        pfu.AUDIT_PATH = self._orig_audit

    def test_dry_run_no_mutation(self):
        rules = [{'name': 'Downpour_DDoS_Block_1_2_3_4',
                  'dir': 'in', 'action': 'Block'}]
        with mock.patch.object(pfu, '_run', side_effect=[
                AssertionError('netsh must not run in dry-run')]):
            result = pfu.unblock(rules=rules, dry_run=True, audit=True)
        self.assertEqual(len(result['removed']), 1)
        self.assertEqual(result['dry_run'], True)
        self.assertEqual(result['errors'], [])
        self.assertTrue(pfu.AUDIT_PATH.exists())

    def test_real_run_deletes_rules(self):
        rules = [
            {'name': 'Downpour_DDoS_Block_1_2_3_4', 'dir': 'in',
             'action': 'Block'},
            {'name': 'Downpour_VPN_KillSwitch_BlockAll', 'dir': 'out',
             'action': 'Block'},
        ]
        calls = []

        def fake_run(cmd):
            calls.append(cmd)
            return (0, 'Ok.')
        with mock.patch.object(pfu, '_run', side_effect=fake_run):
            result = pfu.unblock(rules=rules, dry_run=False, audit=True)
        self.assertEqual(len(result['removed']), 2)
        self.assertEqual(result['errors'], [])
        self.assertEqual(len(calls), 2)
        for cmd in calls:
            self.assertEqual(cmd[0], 'netsh')
            self.assertIn('delete', cmd)

    def test_error_contained(self):
        rules = [{'name': 'Downpour_C2_Block_1_2_3_4', 'dir': 'in',
                  'action': 'Block'}]

        def fake_run(cmd):
            return (1, 'access denied')
        with mock.patch.object(pfu, '_run', side_effect=fake_run):
            result = pfu.unblock(rules=rules, dry_run=False, audit=False)
        self.assertEqual(result['removed'], [])
        self.assertEqual(len(result['errors']), 1)
        self.assertIn('access denied', result['errors'][0])

    def test_audit_trail_written(self):
        rules = [{'name': 'Downpour_X', 'dir': 'in', 'action': 'Block'}]
        with mock.patch.object(pfu, '_run', side_effect=[(0, 'Ok.')]):
            pfu.unblock(rules=rules, dry_run=False, audit=True)
        trail = pfu.audit_trail()
        self.assertEqual(len(trail), 1)
        self.assertEqual(trail[0]['removed'], ['Downpour_X'])

    def test_audit_trail_keeps_last_50(self):
        for i in range(55):
            rules = [{'name': f'Downpour_{i}', 'dir': 'in',
                      'action': 'Block'}]
            pfu.unblock(rules=rules, dry_run=True, audit=True)
        trail = pfu.audit_trail()
        self.assertEqual(len(trail), 50)
        self.assertEqual(trail[-1]['rules'][0]['name'], 'Downpour_54')

    def test_non_downpour_rules_never_touched(self):
        rules = [{'name': 'Windows_Media_Player', 'dir': 'in',
                  'action': 'Block'},
                 {'name': 'MyFirewall_Block', 'dir': 'in',
                  'action': 'Block'}]
        with mock.patch.object(pfu, '_run', side_effect=[
                AssertionError('non-Downpour rules must not be deleted')]):
            result = pfu.unblock(rules=rules, dry_run=False, audit=False)
        self.assertEqual(result['removed'], [])


class TestStatus(unittest.TestCase):
    def test_status_shape(self):
        with mock.patch.object(pfu, 'list_downpour_rules',
                               return_value=[
                {'name': 'Downpour_A', 'dir': 'in', 'action': 'Block'}]):
            st = pfu.status()
        self.assertIn('total', st)
        self.assertIn('blocking', st)
        self.assertIn('categories', st)
        self.assertEqual(st['total'], 1)
        self.assertEqual(st['blocking'], 1)


if __name__ == '__main__':
    unittest.main()
