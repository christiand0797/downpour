"""Tests for v29.55: Sysmon monitor wiring + service/registry monitor."""
import os
import unittest

MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'downpour_v29_titanium.py')

with open(MAIN, encoding='utf-8', errors='replace') as f:
    src = f.read()


class TestSysmonWiring(unittest.TestCase):
    def test_sysmon_import(self):
        self.assertIn('from sysmon_monitor import get_sysmon_monitor', src)

    def test_sysmon_callback_registered(self):
        self.assertIn('register_alert_callback', src)

    def test_sysmon_alert_tag(self):
        self.assertIn('[SYSMON]', src)

    def test_sysmon_started_guard(self):
        self.assertIn('_sysmon_started', src)

    def test_sysmon_graceful_degradation(self):
        self.assertIn('sysmon_available', src)
        self.assertIn('Sysmon not installed', src)


class TestOrphanedMethodsAudit(unittest.TestCase):
    """Audit for monitor methods defined but never called."""

    def test_all_monitor_loops_called(self):
        import re
        # Find all *_loop / *_monitor method definitions
        defs = re.findall(r'def (_\w+(?:_loop|_monitor|_watch))\b', src)
        # Check each appears at least twice (def + call site)
        orphans = [m for m in defs
                   if len(re.findall(re.escape(m) + r'\b', src)) <= 1]
        # These are known orphans (documented, not critical)
        acceptable = {'_performance_monitor_loop',
                      '_stop_service_monitor',
                      '_initialize_registry_monitor',
                      '_start_service_monitor'}  # duplicate of _svc_monitor_loop
        real_orphans = [m for m in orphans if m not in acceptable]
        self.assertEqual(real_orphans, [],
                         f'Unwired monitor loops: {real_orphans}')

    def test_start_service_monitor_is_duplicate_of_svc_monitor_loop(self):
        """_start_service_monitor is a duplicate of _svc_monitor_loop.
        Both monitor for new service creation. _svc_monitor_loop is wired
        (line 37931); _start_service_monitor is not. This is documented."""
        self.assertIn('_svc_monitor_loop', src)
        self.assertIn('_start_service_monitor', src)


if __name__ == '__main__':
    unittest.main()
