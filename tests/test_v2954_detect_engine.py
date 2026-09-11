"""Tests for the v29.54 detection engine wiring."""
import os
import unittest

MAIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'downpour_v29_titanium.py')

with open(MAIN, encoding='utf-8', errors='replace') as f:
    src = f.read()


class TestDetectionEngineWiring(unittest.TestCase):
    """Source-structure tests — main file read as text, never imported."""

    def test_loop_defined(self):
        self.assertIn('def _detection_engine_loop', src)

    def test_bridge_defined(self):
        self.assertIn('def _detection_alert_bridge', src)

    def test_wired_into_monitors(self):
        self.assertIn('_detection_engine_started', src)
        self.assertIn('_detection_engine_loop', src)

    def test_uses_lolbins(self):
        self.assertIn('from lolbins_detector import', src)
        self.assertIn('detect_lolbins_batch', src)

    def test_uses_dga(self):
        self.assertIn('from dga_detector import', src)
        self.assertIn('DGADetector', src)

    def test_uses_dns_cache(self):
        self.assertIn('dns_cache_watch', src)
        self.assertIn('collect_dns_cache', src)

    def test_alert_tag(self):
        self.assertIn('[DETECT]', src)

    def test_loop_is_daemon_thread(self):
        self.assertIn("name='DetectEngine'", src)

    def test_dedup_present(self):
        self.assertIn('_seen', src)

    def test_120s_cycle(self):
        self.assertIn('time.sleep(120)', src)


if __name__ == '__main__':
    unittest.main()
