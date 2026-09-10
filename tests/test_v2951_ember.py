"""Tests for EMBER feature extraction + transparent scoring (v29.51)."""
import importlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

pe_analyzer = importlib.import_module('pe_analyzer')

NOTEPAD = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'),
                       'System32', 'notepad.exe')


class TestEmberFeatures(unittest.TestCase):
    def setUp(self):
        if not os.path.isfile(NOTEPAD):
            self.skipTest('notepad.exe not available')

    def test_feature_vector_keys(self):
        result = pe_analyzer.analyze_pe(NOTEPAD)
        self.assertTrue(result.is_pe)
        self.assertIsNotNone(result.ember_vector)
        ev = result.ember_vector
        for key in ('file_size', 'machine', 'characteristics', 'subsystem',
                    'entry_point', 'num_sections', 'sections',
                    'max_section_entropy', 'num_imports', 'num_dlls',
                    'technique_counts', 'byte_hist', 'num_exports',
                    'tls_callbacks', 'debug_size'):
            self.assertIn(key, ev)
        self.assertGreater(ev['num_sections'], 0)
        self.assertEqual(len(ev['byte_hist']), 256)
        self.assertAlmostEqual(sum(ev['byte_hist']), 1.0, places=2)

    def test_ember_score_range(self):
        result = pe_analyzer.analyze_pe(NOTEPAD)
        self.assertGreaterEqual(result.ember_score, 0)
        self.assertLessEqual(result.ember_score, 100)

    def test_clean_system_binary_low_score(self):
        result = pe_analyzer.analyze_pe(NOTEPAD)
        self.assertLessEqual(result.ember_score, 20)

    def test_integrated_into_risk_factors(self):
        result = pe_analyzer.analyze_pe(NOTEPAD)
        self.assertIsInstance(result.risk_factors, list)


class TestEmberScoreHeuristics(unittest.TestCase):
    def _f(self, **kw):
        base = {'max_section_entropy': 5.0, 'technique_counts': {},
                'tls_callbacks': 0, 'sections': [], 'num_sections': 3,
                'num_imports': 50, 'debug_size': 100, 'file_size': 50000}
        base.update(kw)
        return base

    def test_clean_features_score_zero(self):
        self.assertEqual(pe_analyzer.ember_score(self._f()), 0)

    def test_high_entropy_boosts(self):
        self.assertGreater(pe_analyzer.ember_score(
            self._f(max_section_entropy=7.6)), 0)

    def test_injection_cluster_boosts(self):
        f = self._f(technique_counts={'process_injection': 3})
        self.assertGreaterEqual(pe_analyzer.ember_score(f), 20)

    def test_tls_callback_boosts(self):
        f = self._f(tls_callbacks=1)
        self.assertGreaterEqual(pe_analyzer.ember_score(f), 10)

    def test_rwx_section_boosts(self):
        f = self._f(sections=[{'write': True, 'exec': True}])
        self.assertGreaterEqual(pe_analyzer.ember_score(f), 15)

    def test_no_imports_boosts(self):
        f = self._f(num_imports=0)
        self.assertGreaterEqual(pe_analyzer.ember_score(f), 10)

    def test_score_capped_at_100(self):
        f = self._f(max_section_entropy=8.0,
                    technique_counts={'process_injection': 10,
                                      'keylogging': 10,
                                      'anti_analysis': 10,
                                      'crypto_ransomware': 10},
                    tls_callbacks=5,
                    sections=[{'write': True, 'exec': True}] * 12,
                    num_sections=15, num_imports=0, debug_size=0,
                    file_size=500000)
        self.assertEqual(pe_analyzer.ember_score(f), 100)


if __name__ == '__main__':
    unittest.main()
