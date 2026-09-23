"""Unit tests for v29.95-v29.96: Threat Intelligence Feed Expansion and Performance Optimizations"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from unittest.mock import patch, MagicMock


class TestThreatFeedExpansion(unittest.TestCase):
    """Test the expanded threat intelligence feeds (v29.95)"""

    def test_ultimate_threat_intel_imports(self):
        """Verify ultimate_threat_intel module loads with all feeds"""
        from ultimate_threat_intel import ThreatFeedRegistry
        self.assertTrue(hasattr(ThreatFeedRegistry, 'FEEDS'))
        self.assertTrue(hasattr(ThreatFeedRegistry, 'get_enabled_feeds'))

    def test_feed_count(self):
        """Verify we have 80 feeds total"""
        from ultimate_threat_intel import ThreatFeedRegistry
        feeds = ThreatFeedRegistry.FEEDS
        self.assertEqual(len(feeds), 80, f"Expected 80 feeds, got {len(feeds)}")

    def test_new_feeds_present(self):
        """Verify all 22 new feeds are present"""
        from ultimate_threat_intel import ThreatFeedRegistry
        feeds = ThreatFeedRegistry.FEEDS
        
        new_feeds = [
            'alienvault_otx', 'ibm_xforce', 'hybrid_analysis', 'cisco_talos',
            'emerging_threats', 'bambenek_consulting', 'zeus_tracker',
            'palevo_tracker', 'ransomware_tracker', 'cybercrime_tracker',
            'malc0de', 'threatminer', 'fraudguard', 'dshield', 'firehol',
            'cleanmx', 'malware_domain_list', 'blocklist_de_apache',
            'blocklist_de_ssh', 'blocklist_de_ftp', 'blocklist_de_bots',
            'blocklist_de_bruteforce'
        ]
        
        for feed_id in new_feeds:
            self.assertIn(feed_id, feeds, f"Missing new feed: {feed_id}")
            feed = feeds[feed_id]
            self.assertIn('url', feed, f"Feed {feed_id} missing URL")
            self.assertIn('type', feed, f"Feed {feed_id} missing type")
            self.assertIn('priority', feed, f"Feed {feed_id} missing priority")

    def test_feed_types_distribution(self):
        """Verify feed type distribution"""
        from ultimate_threat_intel import ThreatFeedRegistry
        feeds = ThreatFeedRegistry.FEEDS
        
        type_counts = {}
        for feed in feeds.values():
            ftype = feed.get('type', 'unknown')
            type_counts[ftype] = type_counts.get(ftype, 0) + 1
        
        # Verify expected types exist
        self.assertIn('ip', type_counts)
        self.assertIn('domain', type_counts)
        self.assertIn('url', type_counts)
        self.assertIn('vulnerability', type_counts)

    def test_get_enabled_feeds(self):
        """Test get_enabled_feeds returns all feeds by default"""
        from ultimate_threat_intel import ThreatFeedRegistry
        enabled = ThreatFeedRegistry.get_enabled_feeds()
        self.assertEqual(len(enabled), 80)
        
        # Verify all enabled feeds have required fields
        for feed_id, config in enabled.items():
            self.assertIn('url', config)
            self.assertIn('type', config)
            self.assertIn('priority', config)


class TestThreatFeedAggregator(unittest.TestCase):
    """Test threat feed aggregator integration"""

    def test_aggregator_import(self):
        from threat_feed_aggregator import ThreatFeedAggregator
        self.assertTrue(ThreatFeedAggregator)

    def test_aggregator_initialization(self):
        from threat_feed_aggregator import ThreatFeedAggregator
        aggregator = ThreatFeedAggregator()
        self.assertIsNotNone(aggregator.db)
        self.assertEqual(aggregator.stats['feeds_updated'], 0)

    def test_aggregator_statistics(self):
        from threat_feed_aggregator import ThreatFeedAggregator
        aggregator = ThreatFeedAggregator()
        stats = aggregator.get_statistics()
        
        self.assertIn('total_indicators', stats)
        self.assertIn('indicators_by_type', stats)
        self.assertIn('aggregator', stats)
        self.assertIn('feeds_available', stats)
        self.assertIn('feeds_enabled', stats)
        self.assertEqual(stats['feeds_available'], 80)
        self.assertEqual(stats['feeds_enabled'], 80)


class TestAIEngine(unittest.TestCase):
    """Test AI Security Engine (v29.94+)"""

    def test_ai_engine_import(self):
        from ai_security_engine import AISecurityEngine, get_ai_threat_score
        self.assertTrue(AISecurityEngine)
        self.assertTrue(get_ai_threat_score)

    def test_ai_engine_initialization(self):
        from ai_security_engine import AISecurityEngine
        engine = AISecurityEngine()
        self.assertTrue(hasattr(engine, 'learning_active'))
        self.assertTrue(hasattr(engine, 'get_security_insights'))
        self.assertTrue(hasattr(engine, 'analyze_process_behavior'))

    def test_get_ai_threat_score(self):
        from ai_security_engine import get_ai_threat_score
        
        # Test with anomaly detected
        score = get_ai_threat_score(
            {'anomaly_detected': True, 'suspicious_parents': True},
            {'suspicious_connections': 5, 'unusual_ports': True},
            {'severity': 'HIGH'}
        )
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 100)

        # Test with no anomalies
        score = get_ai_threat_score(
            {'anomaly_detected': False},
            {'suspicious_connections': 0},
            {'severity': 'UNKNOWN'}
        )
        self.assertEqual(score, 0)

    def test_kev_correlation(self):
        from ai_security_engine import correlate_kev_with_ai_anomalies
        result = correlate_kev_with_ai_anomalies({'process_count': 100}, {})
        self.assertIsInstance(result, dict)
        self.assertIn('matched_kev', result)
        self.assertIn('risk_multiplier', result)
        self.assertIn('recommendations', result)


class TestPEAnalyzer(unittest.TestCase):
    """Test PE Analyzer (v29.51+)"""

    def test_pe_analyzer_import(self):
        from pe_analyzer import analyze_pe, batch_analyze, PEAnalysisResult
        self.assertTrue(analyze_pe)
        self.assertTrue(batch_analyze)
        self.assertTrue(PEAnalysisResult)

    def test_analyze_notepad(self):
        from pe_analyzer import analyze_pe
        import os
        
        notepad = r"C:\Windows\System32\notepad.exe"
        if os.path.exists(notepad):
            result = analyze_pe(notepad)
            self.assertTrue(result.is_pe)
            self.assertGreaterEqual(result.risk_score, 0)
            self.assertIsInstance(result.sections, list)
            self.assertIsInstance(result.suspicious_imports, list)
            self.assertIsInstance(result.packers_detected, list)
        else:
            self.skipTest("notepad.exe not found")

    def test_batch_analyze(self):
        from pe_analyzer import batch_analyze
        import os
        
        test_files = [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\calc.exe",
        ]
        existing = [f for f in test_files if os.path.exists(f)]
        if existing:
            results = batch_analyze(existing)
            self.assertEqual(len(results), len(existing))
            for r in results:
                self.assertTrue(r.is_pe)


class TestMemoryForensics(unittest.TestCase):
    """Test Memory Forensics (v29.93+)"""

    def test_memory_forensics_import(self):
        from memory_forensics import MemoryForensicsAnalyzer, get_memory_analyzer
        self.assertTrue(MemoryForensicsAnalyzer)
        self.assertTrue(get_memory_analyzer)

    def test_analyze_current_process(self):
        from memory_forensics import MemoryForensicsAnalyzer
        import os
        
        analyzer = MemoryForensicsAnalyzer()
        pid = os.getpid()
        result = analyzer.analyze_process_memory(pid)
        
        self.assertIsInstance(result, dict)
        self.assertIn('process_info', result)
        self.assertIn('memory_regions', result)
        self.assertIn('risk_score', result)
        self.assertIn('analysis_time', result)


class TestYARAEngine(unittest.TestCase):
    """Test YARA Engine (v29.93+)"""

    def test_yara_import(self):
        from yara_x_engine import YaraXScanEngine, scan_file, scan_bytes
        self.assertTrue(YaraXScanEngine)
        self.assertTrue(scan_file)
        self.assertTrue(scan_bytes)

    def test_yara_engine_info(self):
        from yara_x_engine import YaraXScanEngine
        engine = YaraXScanEngine()
        info = engine.engine_info()
        self.assertIn('engine', info)
        self.assertIn('rulesets', info)
        self.assertIn('rules_dir', info)


class TestSensorHub(unittest.TestCase):
    """Test Sensor Hub (v29.42y+)"""

    def test_sensor_hub_import(self):
        from sensor_hub import SensorHub
        self.assertTrue(SensorHub)

    def test_sensor_hub_initialization(self):
        from sensor_hub import SensorHub
        hub = SensorHub()
        self.assertTrue(hasattr(hub, 'start'))
        self.assertTrue(hasattr(hub, 'stop'))
        self.assertTrue(hasattr(hub, 'get_last_snapshot'))
        self.assertTrue(hasattr(hub, 'get_stats'))


class TestShardedContext(unittest.TestCase):
    """Test Sharded Context (v29.80)"""

    def test_sharded_context_import(self):
        from sharded_context import ShardedContextManager, ContextScope
        self.assertTrue(ShardedContextManager)
        self.assertTrue(ContextScope)

    def test_basic_operations(self):
        from sharded_context import ShardedContextManager, ContextScope
        import time
        mgr = ShardedContextManager(shard_count=4)
        
        # Set and get
        mgr.set('test_key', 'test_value', scope=ContextScope.SHARED)
        value = mgr.get('test_key')
        self.assertEqual(value, 'test_value')
        
        # Subscribe - use global * to catch all events
        # (fnmatch pattern matching only works in query(), not in event notifications)
        received = []
        def callback(event):
            received.append((event.key, event.new_value))
        mgr.subscribe('*', callback)  # Global subscriber
        mgr.set('test_key2', 'value2', scope=ContextScope.SHARED)
        
        # Wait for background event processing thread
        time.sleep(0.3)
        # Two events: CREATED for test_key, CREATED for test_key2
        self.assertEqual(len(received), 2)
        self.assertIn(('test_key', 'test_value'), received)
        self.assertIn(('test_key2', 'value2'), received)


if __name__ == '__main__':
    unittest.main(verbosity=2)