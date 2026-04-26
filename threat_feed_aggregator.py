"""
Threat Feed Aggregator v1.0
===========================
Fetches and processes threat intelligence from 50+ sources.
Handles rate limiting, error recovery, and incremental updates.
"""

import os
import re
import json
import time
import sqlite3
try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
import threading
import logging
import csv
import gzip
import zipfile
from io import StringIO, BytesIO
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ultimate_threat_intel import (
    ThreatIndicator, ThreatCategory, ThreatSeverity,
    ThreatFeedRegistry, ThreatDatabase, get_database
)

logger = logging.getLogger(__name__)

# ============================================================================
# FEED PARSERS - One for each feed format
# ============================================================================

class FeedParser:
    """Base class for feed parsers"""

    @staticmethod
    def parse(content: str, feed_config: Dict) -> List[ThreatIndicator]:
        raise NotImplementedError


class URLhausParser(FeedParser):
    """Parser for URLhaus CSV feed"""

    @staticmethod
    def parse(content: str, feed_config: Dict) -> List[ThreatIndicator]:
        indicators = []
        lines = content.strip().split('\n')

        for line in lines:
            if line.startswith('#') or not line.strip():
                continue

            try:
                # CSV format: id,dateadded,url,url_status,threat,tags,urlhaus_reference
                parts = line.split('","')
                if len(parts) < 3:
                    continue

                url = parts[2].strip('"') if len(parts) > 2 else ""
                threat = parts[4].strip('"') if len(parts) > 4 else ""
                tags = parts[5].strip('"').split(',') if len(parts) > 5 else []

                if url and url.startswith('http'):
                    severity = ThreatSeverity.HIGH
                    if 'ransomware' in threat.lower():
                        severity = ThreatSeverity.CRITICAL

                    indicators.append(ThreatIndicator(
                        value=url,
                        indicator_type='url',
                        category=ThreatCategory.MALWARE,
                        subcategory=threat.lower() if threat else '',
                        severity=severity,
                        confidence=85,
                        source='urlhaus',
                        description=f"Malicious URL: {threat}",
                        tags=[t.strip() for t in tags if t.strip()]
                    ))

            except Exception as e:
                continue

        return indicators


class ThreatFoxParser(FeedParser):
    """Parser for ThreatFox JSON feed"""

    @staticmethod
    def parse(content: str, feed_config: Dict) -> List[ThreatIndicator]:
        indicators = []

        try:
            data = json.loads(content)
            items = data if isinstance(data, list) else data.get('data', [])

            for item in items:
                try:
                    ioc_value = item.get('ioc_value', '') or item.get('ioc', '')
                    ioc_type = item.get('ioc_type', '') or item.get('type', '')
                    malware = item.get('malware', '') or item.get('threat_type', '')
                    tags = item.get('tags', []) or []
                    confidence = item.get('confidence_level', 75)

                    if not ioc_value:
                        continue

                    # Map IOC types
                    if 'ip' in ioc_type.lower():
                        ind_type = 'ip'
                    elif 'domain' in ioc_type.lower():
                        ind_type = 'domain'
                    elif 'url' in ioc_type.lower():
                        ind_type = 'url'
                    elif 'hash' in ioc_type.lower() or 'md5' in ioc_type.lower() or 'sha' in ioc_type.lower():
                        ind_type = 'hash'
                    else:
                        ind_type = 'other'

                    indicators.append(ThreatIndicator(
                        value=ioc_value,
                        indicator_type=ind_type,
                        category=ThreatCategory.MALWARE,
                        subcategory=malware.lower() if malware else '',
                        severity=ThreatSeverity.HIGH,
                        confidence=confidence,
                        source='threatfox',
                        description=f"ThreatFox IOC: {malware}",
                        tags=tags if isinstance(tags, list) else [tags]
                    ))

                except Exception:
                    continue

        except json.JSONDecodeError:
            logger.error("Failed to parse ThreatFox JSON")

        return indicators


class IPListParser(FeedParser):
    """Parser for simple IP list feeds"""

    @staticmethod
    def parse(content: str, feed_config: Dict) -> List[ThreatIndicator]:
        indicators = []
        category = feed_config.get('category', ThreatCategory.NETWORK)

        for line in content.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith(';'):
                continue

            # Extract IP (may have additional info after it)
            parts = line.split()
            ip = parts[0] if parts else line

            # Validate IP format
            ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if not re.match(ip_pattern, ip):
                continue

            # Check for reputation score if present
            severity = ThreatSeverity.MEDIUM
            if len(parts) > 1:
                try:
                    score = int(parts[1])
                    if score >= 8:
                        severity = ThreatSeverity.CRITICAL
                    elif score >= 5:
                        severity = ThreatSeverity.HIGH
                except Exception:
                    pass

            indicators.append(ThreatIndicator(
                value=ip,
                indicator_type='ip',
                category=category,
                severity=severity,
                confidence=70,
                source=feed_config.get('name', 'ip_list'),
                description="Known malicious IP"
            ))

        return indicators


class DomainListParser(FeedParser):
    """Parser for domain list feeds"""

    @staticmethod
    def parse(content: str, feed_config: Dict) -> List[ThreatIndicator]:
        indicators = []
        category = feed_config.get('category', ThreatCategory.MALWARE)

        for line in content.strip().split('\n'):
            line = line.strip().lower()
            if not line or line.startswith('#') or line.startswith('!'):
                continue

            # Clean domain
            domain = line.split()[0] if ' ' in line else line

            # Remove any protocol prefix
            domain = re.sub(r'^https?://', '', domain)
            domain = domain.split('/')[0]  # Remove path

            # Basic domain validation
            if not domain or '.' not in domain or len(domain) < 4:
                continue

            indicators.append(ThreatIndicator(
                value=domain,
                indicator_type='domain',
                category=category,
                severity=ThreatSeverity.MEDIUM,
                confidence=70,
                source=feed_config.get('name', 'domain_list'),
                description="Known malicious domain"
            ))

        return indicators


class PhishTankParser(FeedParser):
    """Parser for PhishTank CSV feed"""

    @staticmethod
    def parse(content: str, feed_config: Dict) -> List[ThreatIndicator]:
        indicators = []

        try:
            reader = csv.reader(StringIO(content))

            # Skip header
            header = next(reader, None)
            if not header:
                return indicators

            for row in reader:
                try:
                    if len(row) < 2:
                        continue

                    url = row[1] if len(row) > 1 else ''
                    target = row[6] if len(row) > 6 else ''

                    if url and url.startswith('http'):
                        indicators.append(ThreatIndicator(
                            value=url,
                            indicator_type='url',
                            category=ThreatCategory.PHISHING,
                            severity=ThreatSeverity.HIGH,
                            confidence=90,
                            source='phishtank',
                            description=f"Phishing URL targeting: {target}",
                            tags=['phishing', target.lower()] if target else ['phishing']
                        ))

                except Exception:
                    continue

        except Exception as e:
            logger.error(f"PhishTank parse error: {e}")

        return indicators


class MalwareBazaarParser(FeedParser):
    """Parser for MalwareBazaar CSV feed"""

    @staticmethod
    def parse(content: str, feed_config: Dict) -> List[ThreatIndicator]:
        indicators = []

        for line in content.strip().split('\n'):
            if line.startswith('#') or not line.strip():
                continue

            try:
                parts = line.split(',')
                if len(parts) < 6:
                    continue

                sha256 = parts[1].strip('"') if len(parts) > 1 else ''
                md5 = parts[2].strip('"') if len(parts) > 2 else ''
                sha1 = parts[3].strip('"') if len(parts) > 3 else ''
                signature = parts[5].strip('"') if len(parts) > 5 else ''
                tags = parts[8].strip('"').split() if len(parts) > 8 else []

                # Add all hash types
                for hash_val, hash_type in [(sha256, 'sha256'), (md5, 'md5'), (sha1, 'sha1')]:
                    if hash_val and len(hash_val) > 10:
                        indicators.append(ThreatIndicator(
                            value=hash_val.lower(),
                            indicator_type='hash',
                            category=ThreatCategory.MALWARE,
                            subcategory=signature.lower() if signature else '',
                            severity=ThreatSeverity.CRITICAL,
                            confidence=95,
                            source='malwarebazaar',
                            description=f"Malware: {signature}",
                            tags=tags,
                            metadata={'hash_type': hash_type}
                        ))

            except Exception:
                continue

        return indicators


class CISAKEVParser(FeedParser):
    """Parser for CISA Known Exploited Vulnerabilities"""

    @staticmethod
    def parse(content: str, feed_config: Dict) -> List[ThreatIndicator]:
        indicators = []

        try:
            data = json.loads(content)
            vulnerabilities = data.get('vulnerabilities', [])

            for vuln in vulnerabilities:
                cve_id = vuln.get('cveID', '')
                vendor = vuln.get('vendorProject', '')
                product = vuln.get('product', '')
                description = vuln.get('shortDescription', '')
                due_date = vuln.get('dueDate', '')

                if cve_id:
                    indicators.append(ThreatIndicator(
                        value=cve_id,
                        indicator_type='cve',
                        category=ThreatCategory.EXPLOIT,
                        severity=ThreatSeverity.CRITICAL,
                        confidence=100,
                        source='cisa_kev',
                        description=f"{vendor} {product}: {description}",
                        tags=['actively_exploited', vendor.lower(), product.lower()],
                        metadata={
                            'vendor': vendor,
                            'product': product,
                            'due_date': due_date
                        }
                    ))

        except Exception as e:
            logger.error(f"CISA KEV parse error: {e}")

        return indicators


# ============================================================================
# FEED AGGREGATOR - Main orchestrator
# ============================================================================

class ThreatFeedAggregator:
    """
    Aggregates threat intelligence from multiple sources.
    Handles fetching, parsing, and storing threat data.
    """

    # Map feed types to parsers
    PARSERS = {
        'urlhaus': URLhausParser,
        'threatfox': ThreatFoxParser,
        'ip': IPListParser,
        'ip_range': IPListParser,
        'domain': DomainListParser,
        'url': DomainListParser,  # Fallback
        'phishtank': PhishTankParser,
        'malwarebazaar': MalwareBazaarParser,
        'vulnerability': CISAKEVParser,
        'mixed': ThreatFoxParser,  # Default for mixed
        'hash': MalwareBazaarParser,
        'pattern': DomainListParser,  # Simplified
    }

    def __init__(self, db: ThreatDatabase = None):
        self.db = db or get_database()
        if _REQUESTS_AVAILABLE:
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'FamilySecuritySuite/1.0 ThreatIntel'
            })
        else:
            self.session = None
        self.running = False
        self._update_thread = None
        self.stats = {
            'feeds_updated': 0,
            'indicators_added': 0,
            'last_update': None,
            'errors': []
        }

    def fetch_feed(self, feed_id: str, feed_config: Dict) -> Optional[str]:
        """Fetch content from a single feed"""
        try:
            url = feed_config['url']
            timeout = feed_config.get('timeout', 30)

            response = self.session.get(url, timeout=timeout)
            response.raise_for_status()

            # Handle compressed content
            content_type = response.headers.get('Content-Type', '')
            if 'gzip' in content_type or url.endswith('.gz'):
                content = gzip.decompress(response.content).decode('utf-8', errors='ignore')
            else:
                content = response.text

            logger.info(f"Fetched {feed_id}: {len(content)} bytes")
            return content

        except requests.exceptions.Timeout:
            logger.warning(f"Timeout fetching {feed_id}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching {feed_id}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error fetching {feed_id}: {e}")

        return None

    def parse_feed(self, feed_id: str, content: str, feed_config: Dict) -> List[ThreatIndicator]:
        """Parse feed content into indicators"""
        feed_type = feed_config.get('type', 'domain')

        # Get appropriate parser
        if feed_id in self.PARSERS:
            parser_class = self.PARSERS[feed_id]
        elif feed_type in self.PARSERS:
            parser_class = self.PARSERS[feed_type]
        else:
            parser_class = DomainListParser

        try:
            indicators = parser_class.parse(content, feed_config)
            logger.info(f"Parsed {feed_id}: {len(indicators)} indicators")
            return indicators

        except Exception as e:
            logger.error(f"Error parsing {feed_id}: {e}")
            return []

    def update_feed(self, feed_id: str, feed_config: Dict) -> int:
        """Update a single feed"""
        content = self.fetch_feed(feed_id, feed_config)
        if not content:
            return 0

        indicators = self.parse_feed(feed_id, content, feed_config)
        if not indicators:
            return 0

        # Store in database
        added = self.db.add_indicators_bulk(indicators)

        # Update feed status
        self._update_feed_status(feed_id, added, len(indicators))

        return added

    def update_all_feeds(self, force: bool = False, priority: str = None) -> Dict:
        """Update all enabled feeds"""
        results = {
            'updated': 0,
            'indicators': 0,
            'errors': [],
            'feeds': {}
        }

        feeds = ThreatFeedRegistry.get_enabled_feeds()
        if priority:
            feeds = {k: v for k, v in feeds.items() if v.get('priority') == priority}

        logger.info(f"Updating {len(feeds)} feeds...")

        for feed_id, feed_config in feeds.items():
            try:
                # Check update interval
                if not force and not self._should_update(feed_id, feed_config):
                    continue

                added = self.update_feed(feed_id, feed_config)
                results['feeds'][feed_id] = {'status': 'success', 'added': added}
                results['updated'] += 1
                results['indicators'] += added

            except Exception as e:
                error_msg = f"{feed_id}: {str(e)}"
                results['errors'].append(error_msg)
                results['feeds'][feed_id] = {'status': 'error', 'message': str(e)}
                logger.error(f"Failed to update {feed_id}: {e}")

        self.stats['feeds_updated'] = results['updated']
        self.stats['indicators_added'] = results['indicators']
        self.stats['last_update'] = datetime.now()
        self.stats['errors'] = results['errors']

        logger.info(f"Update complete: {results['updated']} feeds, {results['indicators']} indicators")
        return results

    def _should_update(self, feed_id: str, feed_config: Dict) -> bool:
        """Check if feed should be updated based on interval"""
        try:
            with self.db.lock:
                conn = sqlite3.connect(self.db.db_path)
                try:
                    c = conn.cursor()
                    c.execute('SELECT last_update FROM feed_status WHERE feed_id = ?', (feed_id,))
                    row = c.fetchone()
                finally:
                    conn.close()

                if not row:
                    return True

                last_update = datetime.fromisoformat(row[0])
                interval = feed_config.get('update_interval', 3600)
                return (datetime.now() - last_update).total_seconds() > interval

        except Exception:
            return True

    def _update_feed_status(self, feed_id: str, added: int, total: int):
        """Update feed status in database"""
        try:
            with self.db.lock:
                conn = sqlite3.connect(self.db.db_path)
                try:
                    c = conn.cursor()
                    c.execute('''INSERT OR REPLACE INTO feed_status
                                 (feed_id, last_update, last_success, records_added, records_total, status)
                                 VALUES (?, ?, ?, ?, ?, ?)''',
                              (feed_id, datetime.now().isoformat(), datetime.now().isoformat(),
                               added, total, 'success'))
                    conn.commit()
                finally:
                    conn.close()
        except Exception as e:
            logger.error(f"Error updating feed status: {e}")

    def start_background_updates(self, interval: int = 300):
        """Start background update thread"""
        self.running = True

        def update_loop():
            while self.running:
                try:
                    self.update_all_feeds()
                except Exception as e:
                    logger.error(f"Background update error: {e}")

                # Sleep in small increments for responsiveness
                for _ in range(interval):
                    if not self.running:
                        break
                    time.sleep(1)

        self._update_thread = threading.Thread(target=update_loop, daemon=True)
        self._update_thread.start()
        logger.info("Background threat feed updates started")

    def stop_background_updates(self):
        """Stop background updates"""
        self.running = False
        if self._update_thread:
            self._update_thread.join(timeout=5)
        logger.info("Background updates stopped")

    def get_statistics(self) -> Dict:
        """Get aggregator statistics"""
        db_stats = self.db.get_statistics()
        return {
            **db_stats,
            'aggregator': self.stats,
            'feeds_available': len(ThreatFeedRegistry.FEEDS),
            'feeds_enabled': len(ThreatFeedRegistry.get_enabled_feeds())
        }


# sqlite3 imported at top of file


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

_aggregator_instance = None

def get_aggregator() -> ThreatFeedAggregator:
    """Get global aggregator instance"""
    global _aggregator_instance
    if _aggregator_instance is None:
        _aggregator_instance = ThreatFeedAggregator()
    return _aggregator_instance


def quick_update(priority: str = 'critical') -> Dict:
    """Quick update of high-priority feeds only"""
    aggregator = get_aggregator()
    return aggregator.update_all_feeds(priority=priority)


def full_update() -> Dict:
    """Full update of all feeds"""
    aggregator = get_aggregator()
    return aggregator.update_all_feeds(force=True)


# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Threat Feed Aggregator')
    parser.add_argument('--update', action='store_true', help='Update all feeds')
    parser.add_argument('--priority', type=str, help='Only update feeds of this priority')
    parser.add_argument('--stats', action='store_true', help='Show statistics')
    parser.add_argument('--daemon', action='store_true', help='Run as background daemon')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO,
                        format='[%(asctime)s] %(levelname)s: %(message)s')

    aggregator = get_aggregator()

    if args.stats:
        stats = aggregator.get_statistics()
        print("\n" + "=" * 60)
        print("THREAT FEED AGGREGATOR STATISTICS")
        print("=" * 60)
        print(f"\nTotal Indicators: {stats.get('total_indicators', 0):,}")
        print(f"\nBy Type:")
        for t, count in stats.get('by_type', {}).items():
            print(f"  {t}: {count:,}")
        print(f"\nBy Category:")
        for c, count in stats.get('by_category', {}).items():
            print(f"  {c}: {count:,}")
        print(f"\nFeeds Available: {stats.get('feeds_available', 0)}")
        print(f"Feeds Enabled: {stats.get('feeds_enabled', 0)}")

    elif args.daemon:
        print("Starting background updates...")
        aggregator.start_background_updates()
        try:
            while True:
                time.sleep(60)
                stats = aggregator.get_statistics()
                print(f"[{datetime.now()}] Indicators: {stats.get('total_indicators', 0):,}")
        except KeyboardInterrupt:
            aggregator.stop_background_updates()
            print("\nStopped.")

    elif args.update:
        print("Updating threat feeds...")
        results = aggregator.update_all_feeds(priority=args.priority)
        print(f"\nUpdated: {results['updated']} feeds")
        print(f"Added: {results['indicators']} indicators")
        if results['errors']:
            print(f"Errors: {len(results['errors'])}")

    else:
        parser.print_help()
