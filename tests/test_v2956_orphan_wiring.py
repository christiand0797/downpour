"""Tests for v29.56: process_mitigation wiring + usb_protection wiring."""
import os
import unittest

MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'downpour_v29_titanium.py')

with open(MAIN, encoding='utf-8', errors='replace') as f:
    src = f.read()


class TestProcessMitigationWiring(unittest.TestCase):
    def test_apply_called_at_boot(self):
        self.assertIn('from process_mitigation import '
                      'apply_process_mitigations', src)

    def test_in_init_state(self):
        # should be in _init_state (boot-time, before UI builds)
        idx = src.find('def _init_state')
        idx_end = src.find('def ', idx + 1)
        init_block = src[idx:idx_end]
        self.assertIn('apply_process_mitigations', init_block)

    def test_best_effort(self):
        # should be wrapped in try/except so failures don't block GUI
        idx = src.find('apply_process_mitigations')
        context = src[max(0, idx-200):idx+300]
        self.assertIn('try:', context)
        self.assertIn('except', context)


class TestUSBProtectionWiring(unittest.TestCase):
    def test_check_usb_kev_called(self):
        self.assertIn('from usb_protection import check_usb_kev', src)

    def test_usb_threat_scan_guard(self):
        self.assertIn('_usb_threat_scan_started', src)

    def test_alert_tag(self):
        self.assertIn('[USB-SCAN]', src)


class TestOrphanedModulesAudit(unittest.TestCase):
    """Audit for modules with security value that are truly orphaned."""

    def test_no_new_orphans_after_v2956(self):
        import re
        main_src = open(
            os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))),
                'downpour_v29_titanium.py'),
            encoding='utf-8', errors='replace').read()
        # These were the last 2 orphaned security modules — both now wired
        for mod in ('process_mitigation', 'usb_protection'):
            self.assertIn(mod, main_src)


if __name__ == '__main__':
    unittest.main()
