"""Functional tests for all major modules."""

import os
import sys
import tempfile
import sqlite3

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.chdir(os.path.dirname(os.path.abspath(__file__)) + '/..')


def test_config_manager():
    import tempfile
    from config import ConfigManager
    # Use non-existent config file to test initial_config
    with tempfile.NamedTemporaryFile(delete=False) as f:
        tmp_path = f.name
    os.unlink(tmp_path)  # Delete so it doesn't exist
    try:
        cm = ConfigManager(config_path=tmp_path, initial_config={'TEST': {'key': 'value'}})
        assert cm.get('TEST', 'key') == 'value'
        assert cm.get('MISSING', 'key', 'fallback') == 'fallback'
        assert cm.set('NEW', 'key', 'newval') is True
        assert cm.get('NEW', 'key') == 'newval'
        cm.stop_watching()
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
    print('✓ ConfigManager basic ops')


def test_vulnerability_scanner():
    from vulnerability_scanner import VulnerabilityScanner
    vs = VulnerabilityScanner()
    tmpdir = tempfile.mkdtemp()
    vs.db_path = os.path.join(tmpdir, 'test.db')
    vs.init_database()
    
    # Check tables exist
    import sqlite3
    conn = sqlite3.connect(vs.db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {row[0] for row in cursor.fetchall()}
    conn.close()
    
    expected = {'vulnerabilities', 'software_inventory', 'exploit_attempts', 
                'system_vulnerabilities', 'kev_catalog', 'epss_scores', 
                'cwe_mapping', 'threat_actor_vulns', 'vulnerability_trends', 
                'patch_priority_queue'}
    assert expected.issubset(tables), f'Missing: {expected - tables}'
    print('✓ VulnerabilityScanner DB init')


def test_emergency_response():
    from emergency_response import EmergencyResponse
    er = EmergencyResponse()
    assert os.path.exists('emergency_snapshots')
    assert os.path.exists('emergency_quarantine')
    print('✓ EmergencyResponse init')


def test_fp_suppression():
    from fp_suppression import FPSuppressionCache, fp_fingerprint
    cache = FPSuppressionCache()
    fp = fp_fingerprint('[BOTNET] C2 45.88.48.238 :443')
    # Port should be normalized away
    fp2 = fp_fingerprint('[BOTNET] C2 45.88.48.238')
    assert fp == fp2, f'Port not normalized: {fp} != {fp2}'
    cache.set_entry(fp, 3, True)
    # Need to mark cache as loaded for is_suppressed to work
    cache._loaded = True
    # Check with normalized version (no port)
    assert cache.is_suppressed('[BOTNET] C2 45.88.48.238') is True
    print('✓ FP Suppression')


def test_threat_intelligence():
    from threat_intelligence import ThreatIntelligenceManager
    ti = ThreatIntelligenceManager()
    # Check feeds structure
    assert 'threatfox' in ti.feeds
    assert 'urlhaus' in ti.feeds
    assert 'phishtank' in ti.feeds
    assert ti.feeds['threatfox']['enabled'] is True
    print('✓ ThreatIntelligenceManager init')


def test_network_monitor():
    from network_monitor import NetworkMonitor
    nm = NetworkMonitor()
    # Basic init - check connection_history instead of _callbacks
    assert hasattr(nm, 'connection_history')
    assert hasattr(nm, 'malicious_ips')
    print('✓ NetworkMonitor init')


def test_process_monitor():
    from process_monitor import ProcessMonitor
    from downpour_v29_titanium import AdvancedProcessScanner
    pm = ProcessMonitor()
    assert hasattr(pm, 'known_processes')
    # AdvancedProcessScanner requires yara and learning engines - skip instantiation test
    print('✓ ProcessMonitor init')


if __name__ == '__main__':
    test_config_manager()
    test_vulnerability_scanner()
    test_emergency_response()
    test_fp_suppression()
    test_threat_intelligence()
    test_network_monitor()
    test_process_monitor()
    print('\nAll functional tests passed!')