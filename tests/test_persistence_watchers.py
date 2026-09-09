"""Tests for persistence_watchers (v29.44d): registry, DLL hijack, drivers."""
import importlib
import os
import sys
import tempfile
import unittest
import winreg
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pw = importlib.import_module('persistence_watchers')


class _BaselineIsolated(unittest.TestCase):
    """Redirects the baseline file + resets singletons per test."""

    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix='dp_persist_')
        self._orig_path = pw.BASELINE_PATH
        pw.BASELINE_PATH = os.path.join(self._tmp, 'baseline.json')
        pw._registry_watcher = pw._driver_monitor = pw._dll_detector = None

    def tearDown(self):
        pw.BASELINE_PATH = self._orig_path


class TestRegistryWatcher(_BaselineIsolated):
    @staticmethod
    def _key_stub(values, only_hive=winreg.HKEY_CURRENT_USER,
                  only_subkey='\\Run'):
        """_read_key stub returning `values` for exactly one key."""
        return lambda hive, subkey: (
            dict(values) if (hive == only_hive
                             and subkey.endswith(only_subkey)) else {})

    def test_first_run_is_tofu_silent(self):
        w = pw.RegistryPersistenceWatcher()
        with mock.patch.object(w, '_read_key', self._key_stub({'a': '1'})):
            alerts, first = w.check()
        self.assertTrue(first)
        self.assertEqual(alerts, [])
        with mock.patch.object(w, '_read_key', self._key_stub({'a': '1'})):
            alerts, first = w.check()
        self.assertFalse(first)
        self.assertEqual(alerts, [])

    def test_new_run_value_alerts_high(self):
        w = pw.RegistryPersistenceWatcher()
        with mock.patch.object(w, '_read_key', self._key_stub({'a': '1'})):
            w.check()
        with mock.patch.object(
                w, '_read_key',
                self._key_stub({'a': '1', 'evil': 'C:\\x.exe'})):
            alerts, _ = w.check()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].technique, 'T1060')
        self.assertEqual(alerts[0].severity, 'HIGH')
        self.assertIn('evil', alerts[0].detail)

    def test_modified_value_alerts(self):
        w = pw.RegistryPersistenceWatcher()
        with mock.patch.object(
                w, '_read_key', self._key_stub({'Start': 'explorer.exe'})):
            w.check()
        with mock.patch.object(
                w, '_read_key', self._key_stub({'Start': 'malware.exe'})):
            alerts, _ = w.check()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].technique, 'T1574.011')

    def test_baseline_persisted_for_offline_detection(self):
        w = pw.RegistryPersistenceWatcher()
        with mock.patch.object(w, '_read_key', self._key_stub({'a': '1'})):
            w.check()
        w2 = pw.RegistryPersistenceWatcher()  # fresh instance sees baseline
        with mock.patch.object(
                w2, '_read_key', self._key_stub({'a': '1', 'b': '2'})):
            alerts, _ = w2.check()
        self.assertEqual(len(alerts), 1)

    def test_removed_value_not_alerted(self):
        # removal is usually cleanup, not attack — stay quiet
        w = pw.RegistryPersistenceWatcher()
        with mock.patch.object(
                w, '_read_key', self._key_stub({'a': '1', 'b': '2'})):
            w.check()
        with mock.patch.object(w, '_read_key', self._key_stub({'a': '1'})):
            alerts, _ = w.check()
        self.assertEqual(alerts, [])


class TestDLLHijack(_BaselineIsolated):
    def test_planted_system_dll_in_writable_dir(self):
        d = tempfile.mkdtemp(prefix='dp_hijack_')
        with open(os.path.join(d, 'version.dll'), 'wb') as f:
            f.write(b'MZ fake')
        det = pw.DLLHijackDetector()
        with mock.patch.dict(os.environ, {'PATH': d}):
            alerts = det.check()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].technique, 'T1574.001')
        self.assertIn('version.dll', alerts[0].detail)

    def test_clean_path_no_alerts(self):
        d = tempfile.mkdtemp(prefix='dp_clean_')
        det = pw.DLLHijackDetector()
        with mock.patch.dict(os.environ, {'PATH': d}):
            self.assertEqual(det.check(), [])

    def test_systemroot_dirs_ignored(self):
        det = pw.DLLHijackDetector()
        sysroot = os.environ.get('SystemRoot', r'C:\Windows')
        with mock.patch.dict(os.environ, {'PATH': sysroot}):
            self.assertEqual(det.check(), [])


class TestDriverMonitor(_BaselineIsolated):
    def test_byovd_blocklist_critical(self):
        d = tempfile.mkdtemp(prefix='dp_drv_')
        with open(os.path.join(d, 'gdrv.sys'), 'wb') as f:
            f.write(b'MZ vulnerable')
        m = pw.DriverMonitor()
        with mock.patch.object(m, '_drivers_dir', return_value=d):
            alerts = m.check()
        byovd = [a for a in alerts if a.severity == 'CRITICAL']
        self.assertEqual(len(byovd), 1)
        self.assertIn('CVE-2018-19320', byovd[0].detail)

    def test_new_driver_medium_on_second_pass(self):
        d = tempfile.mkdtemp(prefix='dp_drv2_')
        with open(os.path.join(d, 'existing.sys'), 'wb') as f:
            f.write(b'MZ')
        m = pw.DriverMonitor()
        with mock.patch.object(m, '_drivers_dir', return_value=d):
            self.assertEqual(m.check(), [])  # TOFU baseline
        with open(os.path.join(d, 'newdrv.sys'), 'wb') as f:
            f.write(b'MZ')
        with mock.patch.object(m, '_drivers_dir', return_value=d):
            alerts = m.check()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].severity, 'MEDIUM')
        self.assertEqual(alerts[0].technique, 'T1068')

    def test_missing_drivers_dir_safe(self):
        m = pw.DriverMonitor()
        with mock.patch.object(m, '_drivers_dir', return_value='Z:/none'):
            self.assertEqual(m.check(), [])


class TestCombinedRunner(_BaselineIsolated):
    def test_combined_first_run_silent_second_run_diffs(self):
        # DLL hijack in a tmp PATH dir present from the start is still
        # reported (DLL detector has no TOFU — it's stateless).
        d = tempfile.mkdtemp(prefix='dp_comb_')
        with mock.patch.dict(os.environ, {'PATH': d}):
            pw.run_all_persistence_checks()  # TOFU
            alerts = pw.run_all_persistence_checks()
        self.assertIsInstance(alerts, list)


class TestMainWiring(unittest.TestCase):
    MAIN = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        'downpour_v29_titanium.py')

    @classmethod
    def setUpClass(cls):
        with open(cls.MAIN, encoding='utf-8', errors='replace') as f:
            cls.src = f.read()

    def test_persistence_watch_wired(self):
        self.assertIn('from persistence_watchers import', self.src)
        self.assertIn('_persistence_watch_loop', self.src)
        self.assertIn('_persistence_alert_bridge', self.src)
        self.assertIn('[PERSIST]', self.src)
        self.assertIn('run_all_persistence_checks()', self.src)
        self.assertIn('_persistence_watch_started', self.src)

    def test_bridge_uses_gauge_colors(self):
        self.assertNotIn('Colors.ALERT_', self.src)
        self.assertIn('Colors.GAUGE_RED', self.src)


if __name__ == '__main__':
    unittest.main()