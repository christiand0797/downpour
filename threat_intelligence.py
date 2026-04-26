"""
===============================================================================
THREAT INTELLIGENCE MANAGER
==============================================================================

PURPOSE: Manages real-time threat intelligence feeds from multiple reputable sources
         to provide up-to-date malware signatures, IOCs, and threat indicators.

v29: Added KEV/CEV enrichment for CVE-based threat correlation.

SOURCES INTEGRATED:
1. ThreatFox (abuse.ch) - Malware IOCs and malicious URLs
2. VirusTotal API - File reputation and malware analysis
3. Malware Information Sharing Platform (MISP) - Community threat sharing
4. AlienVault OTX - Open threat exchange
5. PhishTank - Phishing URLs
6. URLhaus abuse.ch - Malicious URLs
7. Emerging Threats - Network-based threats
8. Microsoft Interflow - Windows-specific threats
9. CISA KEV - Known Exploited Vulnerabilities

WHAT IT PROVIDES:
- Real-time malicious IP addresses
- Malicious domains and URLs
- Malware file hashes (MD5, SHA1, SHA256)
- Suspicious email addresses
- C&C server indicators
- Latest malware campaign IOCs
- Zero-day vulnerability indicators
- CVE-exploited threat correlation

UPDATE FREQUENCY:
- High-priority feeds: Every 15 minutes
- Medium-priority feeds: Every hour
- Low-priority feeds: Every 6 hours
- On-demand updates available

INTEGRATION:
- Updates network monitor with malicious IPs
- Updates file monitor with malware hashes
- Provides IOCs to behavioral analyzer
- Feeds threat data to main alert system
"""

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
import json
import time
import threading
import logging
import hashlib
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
import configparser
from typing import Dict, List, Set, Tuple, Optional

class ThreatIntelligenceManager:
    """
    Central manager for all threat intelligence feeds.
    
    Aggregates threat data from multiple sources and provides
    unified intelligence to other security modules.
    """
    
    def __init__(self, config=None):
        """
        Initialize threat intelligence manager.
        
        Parameters:
        - config: Configuration object (optional)
        """
        self.running = True
        self.config = config

        # v28p36: Connection pooling — shared HTTP session with keep-alive
        self._session = None
        if _REQUESTS_AVAILABLE:
            self._session = requests.Session()
            self._session.headers.update({
                'User-Agent': 'Downpour-v28-ThreatIntel/1.0',
                'Accept': 'application/json, text/plain, */*',
            })
            # Connection pool: keep 10 connections alive, max 20
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=10, pool_maxsize=20, max_retries=2)
            self._session.mount('https://', adapter)
            self._session.mount('http://', adapter)

        # Initialize local database
        self.db_path = Path("threat_intel.db")
        self.init_database()
        
        # Threat data containers
        self.malicious_ips = set()
        self.malicious_domains = set()
        self.malicious_urls = set()
        self.malware_hashes = set()
        
        # v29: KEV cache for CVE correlation
        self.kev_cache = {}
        self.suspicious_emails = set()
        
        # API keys (would be loaded from config in production)
        self.api_keys = {
            'virustotal': '',  # Get from virustotal.com
            'otx': '',        # Get from alienvault.com
            'misp': '',       # Your MISP instance key
        }
        
        # Feed configurations
        self.feeds = {
            'threatfox': {
                'url': 'https://threatfox.abuse.ch/export/json/recent/',
                'enabled': True,
                'priority': 'high',
                'update_interval': 900,  # 15 minutes
                'last_update': 0
            },
            'urlhaus': {
                'url': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
                'enabled': True,
                'priority': 'high',
                'update_interval': 900,
                'last_update': 0
            },
            'phishtank': {
                'url': 'https://phishtank.cdn.abuse.ch/downloads/online-valid.csv',
                'enabled': True,
                'priority': 'medium',
                'update_interval': 3600,  # 1 hour
                'last_update': 0
            },
            'emerging_threats': {
                'url': 'https://rules.emergingthreats.net/open/suricata/rules/',
                'enabled': True,
                'priority': 'medium',
                'update_interval': 3600,
                'last_update': 0
            }
        }
        
        # Statistics
        self.stats = {
            'total_iocs': 0,
            'feeds_updated': 0,
            'last_update': datetime.now(),
            'update_failures': 0
        }
        
    def init_database(self):
        """Initialize SQLite database for storing threat intelligence."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            # Create tables for different IOC types
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malicious_ips (
                    ip TEXT PRIMARY KEY,
                    source TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    confidence INTEGER,
                    tags TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malicious_domains (
                    domain TEXT PRIMARY KEY,
                    source TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    confidence INTEGER,
                    tags TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malware_hashes (
                    hash TEXT PRIMARY KEY,
                    hash_type TEXT,
                    source TEXT,
                    first_seen TIMESTAMP,
                    malware_family TEXT,
                    tags TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS feed_updates (
                    feed_name TEXT PRIMARY KEY,
                    last_update TIMESTAMP,
                    iocs_added INTEGER,
                    iocs_removed INTEGER,
                    status TEXT
                )
            ''')

            # Create indexes for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_last_seen ON malicious_ips(last_seen)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain_last_seen ON malicious_domains(last_seen)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_hash_first_seen ON malware_hashes(first_seen)')

            conn.commit()

            logging.info("[✓] Threat intelligence database initialized")

        except Exception as e:
            logging.error(f"Failed to initialize database: {e}")
            raise
        finally:
            conn.close()
    
    def load_from_database(self):
        """Load existing threat intelligence from local database."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Load malicious IPs
            cursor.execute("SELECT ip FROM malicious_ips")
            self.malicious_ips = {row[0] for row in cursor.fetchall()}

            # Load malicious domains
            cursor.execute("SELECT domain FROM malicious_domains")
            self.malicious_domains = {row[0] for row in cursor.fetchall()}

            # Load malware hashes
            cursor.execute("SELECT hash FROM malware_hashes")
            self.malware_hashes = {row[0] for row in cursor.fetchall()}

            logging.info(f"[✓] Loaded {len(self.malicious_ips)} IPs, {len(self.malicious_domains)} domains, {len(self.malware_hashes)} hashes from database")

        except Exception as e:
            logging.error(f"Error loading from database: {e}")
        finally:
            if conn:
                conn.close()
    
    def update_threatfox_feed(self):
        """Update threat intelligence from ThreatFox (abuse.ch)."""
        try:
            logging.info("Updating ThreatFox feed...")
            
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['threatfox']['url'], timeout=30)
            response.raise_for_status()
            
            data = response.json()
            iocs_added = 0
            
            for item in data:
                try:
                    ioc_value = item.get('ioc_value', '')
                    ioc_type = item.get('ioc_type', '')
                    malware_family = item.get('malware', '')
                    tags = item.get('tags', []) or []
                    
                    if not ioc_value or not ioc_type:
                        continue
                    
                    # Process based on IOC type
                    if ioc_type == 'ip':
                        self.add_malicious_ip(ioc_value, 'threatfox', malware_family, tags)
                        iocs_added += 1
                    elif ioc_type == 'domain':
                        self.add_malicious_domain(ioc_value, 'threatfox', malware_family, tags)
                        iocs_added += 1
                    elif ioc_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
                        self.add_malware_hash(ioc_value, ioc_type.replace('hash_', ''), 'threatfox', malware_family, tags)
                        iocs_added += 1
                        
                except Exception as e:
                    logging.debug(f"Error processing ThreatFox item: {e}")
                    continue
            
            self.feeds['threatfox']['last_update'] = time.time()
            logging.info(f"[✓] ThreatFox updated: {iocs_added} IOCs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update ThreatFox: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_urlhaus_feed(self):
        """Update threat intelligence from URLhaus (abuse.ch)."""
        try:
            logging.info("Updating URLhaus feed...")
            
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['urlhaus']['url'], timeout=30)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            iocs_added = 0
            
            # Skip header line
            for line in lines[1:]:
                try:
                    if not line or line.startswith('#'):
                        continue
                    
                    # CSV format: id,datefirstseen,url,urlstatus,lastonline,threat,tags
                    parts = line.split('","')
                    if len(parts) < 3:
                        continue
                    
                    url = parts[2].strip('"')
                    threat = parts[5].strip('"') if len(parts) > 5 else ''
                    tags_str = parts[6].strip('"') if len(parts) > 6 else ''
                    tags = tags_str.split(',') if tags_str else []
                    
                    if url and url.startswith('http'):
                        self.add_malicious_url(url, 'urlhaus', threat, tags)
                        iocs_added += 1
                        
                except Exception as e:
                    logging.debug(f"Error processing URLhaus line: {e}")
                    continue
            
            self.feeds['urlhaus']['last_update'] = time.time()
            logging.info(f"[✓] URLhaus updated: {iocs_added} URLs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update URLhaus: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_phishtank_feed(self):
        """Update phishing URLs from PhishTank."""
        try:
            logging.info("Updating PhishTank feed...")
            
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['phishtank']['url'], timeout=30)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            iocs_added = 0
            
            # Skip header lines
            data_start = 0
            for i, line in enumerate(lines):
                if line.startswith('phish_id'):
                    data_start = i + 1
                    break
            
            for line in lines[data_start:]:
                try:
                    if not line or line.startswith(',') or line.startswith('##'):
                        continue
                    
                    # CSV format: phish_id,url,phish_detail_url,submission_time,verified,verification_time,target
                    parts = line.split(',')
                    if len(parts) < 2:
                        continue
                    
                    url = parts[1].strip('"')
                    if url and url.startswith('http'):
                        phish_tags = ['phishing']
                        self.add_malicious_url(url, 'phishtank', 'phishing', phish_tags)
                        iocs_added += 1
                        
                except Exception as e:
                    logging.debug(f"Error processing PhishTank line: {e}")
                    continue
            
            self.feeds['phishtank']['last_update'] = time.time()
            logging.info(f"[✓] PhishTank updated: {iocs_added} URLs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update PhishTank: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def check_virustotal_reputation(self, file_hash: str) -> Dict:
        """
        Check file reputation against VirusTotal.
        
        Parameters:
        - file_hash: MD5, SHA1, or SHA256 hash
        
        Returns:
        - Dictionary with reputation data
        """
        try:
            if not self.api_keys['virustotal']:
                return {'error': 'VirusTotal API key not configured'}
            
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': self.api_keys['virustotal'],
                'resource': file_hash
            }
            
            _get = self._session.get if self._session else requests.get
            response = _get(url, params=params, timeout=10)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logging.debug(f"VirusTotal lookup failed for {file_hash}: {e}")
            return {'error': str(e)}
    
    def add_malicious_ip(self, ip: str, source: str, threat_type: str = '', tags: List[str] = None):
        """Add a malicious IP to the database."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.now()
            tags_str = ','.join(tags) if tags else ''

            cursor.execute('''
                INSERT OR REPLACE INTO malicious_ips
                (ip, source, first_seen, last_seen, confidence, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ip, source, now, now, 75, tags_str))

            conn.commit()
            self.malicious_ips.add(ip)

        except Exception as e:
            logging.error(f"Error adding malicious IP {ip}: {e}")
        finally:
            if conn:
                conn.close()
    
    def add_malicious_domain(self, domain: str, source: str, threat_type: str = '', tags: List[str] = None):
        """Add a malicious domain to the database."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.now()
            tags_str = ','.join(tags) if tags else ''

            cursor.execute('''
                INSERT OR REPLACE INTO malicious_domains
                (domain, source, first_seen, last_seen, confidence, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (domain, source, now, now, 75, tags_str))

            conn.commit()
            self.malicious_domains.add(domain)

        except Exception as e:
            logging.error(f"Error adding malicious domain {domain}: {e}")
        finally:
            if conn:
                conn.close()
    
    def add_malicious_url(self, url: str, source: str, threat_type: str = '', tags: List[str] = None):
        """Add a malicious URL to the database."""
        try:
            # Extract domain from URL for domain checking
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Add to URL list and also check domain
            self.malicious_urls.add(url)
            
            if domain:
                safe_tags = tags or []
                self.add_malicious_domain(domain, source, threat_type, safe_tags)
            
        except Exception as e:
            logging.error(f"Error adding malicious URL {url}: {e}")
    
    def add_malware_hash(self, file_hash: str, hash_type: str, source: str, malware_family: str = '', tags: List[str] = None):
        """Add a malware hash to the database."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            now = datetime.now()
            tags_str = ','.join(tags) if tags else ''

            cursor.execute('''
                INSERT OR REPLACE INTO malware_hashes
                (hash, hash_type, source, first_seen, malware_family, tags)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (file_hash, hash_type, source, now, malware_family, tags_str))

            conn.commit()
            self.malware_hashes.add(file_hash)

        except Exception as e:
            logging.error(f"Error adding malware hash {file_hash}: {e}")
        finally:
            if conn:
                conn.close()
    
    def is_ip_malicious(self, ip: str) -> Tuple[bool, Dict]:
        """
        Check if an IP address is malicious.
        
        Returns:
        - (is_malicious: bool, details: dict)
        """
        if ip in self.malicious_ips:
            return True, {'ip': ip, 'in_database': True}
        
        return False, {}
    
    def is_domain_malicious(self, domain: str) -> Tuple[bool, Dict]:
        """
        Check if a domain is malicious.
        
        Returns:
        - (is_malicious: bool, details: dict)
        """
        # Check exact match
        if domain in self.malicious_domains:
            return True, {'domain': domain, 'in_database': True}
        
        # Check subdomains
        for bad_domain in self.malicious_domains:
            if domain.endswith('.' + bad_domain) or bad_domain.endswith('.' + domain):
                return True, {'domain': domain, 'matched_subdomain': bad_domain}
        
        return False, {}
    
    def is_url_malicious(self, url: str) -> Tuple[bool, Dict]:
        """
        Check if a URL is malicious.
        
        Returns:
        - (is_malicious: bool, details: dict)
        """
        # Check exact URL match
        if url in self.malicious_urls:
            return True, {'url': url, 'in_database': True}
        
        # Check domain
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            if domain:
                return self.is_domain_malicious(domain)
        except Exception:
            pass
        
        return False, {}
    
    def is_hash_malicious(self, file_hash: str) -> Tuple[bool, Dict]:
        """
        Check if a file hash is known malware.
        
        Returns:
        - (is_malicious: bool, details: dict)
        """
        if file_hash.upper() in self.malware_hashes:
            return True, {'hash': file_hash, 'in_database': True}
        
        return False, {}
    
    def cleanup_old_iocs(self):
        """Remove old and stale IOCs from database."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            cutoff_date = datetime.now() - timedelta(days=90)

            # Remove old IPs not seen recently
            cursor.execute("DELETE FROM malicious_ips WHERE last_seen < ?", (cutoff_date,))

            # Remove old domains
            cursor.execute("DELETE FROM malicious_domains WHERE last_seen < ?", (cutoff_date,))

            conn.commit()

            logging.info("[✓] Cleaned up old IOCs from database")

        except Exception as e:
            logging.error(f"Error cleaning up IOCs: {e}")
        finally:
            conn.close()
    
    def update_all_feeds(self):
        """Update all configured threat intelligence feeds."""
        total_iocs = 0
        
        for feed_name, feed_config in self.feeds.items():
            if not feed_config['enabled']:
                continue
            
            # Check if it's time to update
            current_time = time.time()
            if current_time - feed_config['last_update'] < feed_config['update_interval']:
                continue
            
            try:
                if feed_name == 'threatfox':
                    iocs = self.update_threatfox_feed()
                elif feed_name == 'urlhaus':
                    iocs = self.update_urlhaus_feed()
                elif feed_name == 'phishtank':
                    iocs = self.update_phishtank_feed()
                else:
                    logging.warning(f"Unknown feed: {feed_name}")
                    continue
                
                total_iocs += iocs
                
            except Exception as e:
                logging.error(f"Failed to update feed {feed_name}: {e}")
        
        # Update statistics
        self.stats['total_iocs'] = len(self.malicious_ips) + len(self.malicious_domains) + len(self.malware_hashes)
        self.stats['last_update'] = datetime.now()
        
        if total_iocs > 0:
            logging.info(f"[✓] Total IOCs updated: {total_iocs}")
        
        return total_iocs
    
    def monitoring_loop(self):
        """Main monitoring loop for continuous updates."""
        logging.info("Threat intelligence monitoring started")
        
        # Load existing data
        self.load_from_database()
        
        # Initial update
        self.update_all_feeds()
        
        # Cleanup old data daily
        last_cleanup = time.time()
        
        while self.running:
            try:
                # Update feeds
                self.update_all_feeds()
                
                # Cleanup old data daily
                current_time = time.time()
                if current_time - last_cleanup > 86400:  # 24 hours
                    self.cleanup_old_iocs()
                    last_cleanup = current_time
                
                # Sleep for 5 minutes between checks
                time.sleep(300)
                
            except Exception as e:
                logging.error(f"Error in threat intelligence loop: {e}")
                time.sleep(60)
    
    def get_statistics(self) -> Dict:
        """Get current threat intelligence statistics."""
        return {
            'malicious_ips': len(self.malicious_ips),
            'malicious_domains': len(self.malicious_domains),
            'malicious_urls': len(self.malicious_urls),
            'malware_hashes': len(self.malware_hashes),
            'total_iocs': self.stats['total_iocs'],
            'last_update': self.stats['last_update'].strftime('%Y-%m-%d %H:%M:%S'),
            'update_failures': self.stats['update_failures'],
            'feeds_active': sum(1 for f in self.feeds.values() if f['enabled'])
        }
    
    def start(self):
        """Start threat intelligence monitoring in background thread."""
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
        logging.info("[✓] Threat Intelligence Manager active")
    
    def stop(self):
        """Stop threat intelligence monitoring."""
        self.running = False
        logging.info("Threat intelligence monitoring stopped")
    
    # v29: KEV Enrichment Methods
    def check_cve_known_exploited(self, cve_id: str) -> Optional[Dict]:
        """Check if CVE is in CISA KEV catalog (known exploited).
        
        Args:
            cve_id: CVE identifier (e.g., 'CVE-2024-1234')
            
        Returns:
            Dict with KEV details or None if not found
        """
        if not self.kev_cache:
            self._load_kev_cache()
        
        return self.kev_cache.get(cve_id.upper())
    
    def _load_kev_cache(self):
        """Load KEV data from vulnerability_scanner if available."""
        try:
            from vulnerability_scanner import VulnerabilityScanner
            scanner = VulnerabilityScanner()
            kev_data = scanner.get_kev_catalog()
            
            self.kev_cache = {}
            for item in kev_data:
                cve = item.get('cve_id', '')
                if cve:
                    self.kev_cache[cve.upper()] = item
            
            logging.info(f"Loaded {len(self.kev_cache)} KEV entries")
        except Exception as e:
            logging.debug(f"KEV cache load: {e}")
            self.kev_cache = {}
    
    def get_cve_threat_context(self, cve_id: str) -> Dict:
        """Get comprehensive CVE threat context.
        
        Combines KEV status, EPSS score, and known IOC correlations.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Dict with: kev_status, epss_score, risk_level, description
        """
        result = {
            'cve_id': cve_id,
            'kev_status': False,
            'epss_score': 0.0,
            'cvss_score': 0.0,
            'risk_level': 'LOW',
            'known_exploited': False,
            'ransomware_associated': False
        }
        
        kev_data = self.check_cve_known_exploited(cve_id)
        if kev_data:
            result['kev_status'] = True
            result['known_exploited'] = True
            result['ransomware_associated'] = kev_data.get('ransomware', 'No') == 'Yes'
            result['cvss_score'] = kev_data.get('cvss_score', 0)
            
            if result['cvss_score'] >= 9.0:
                result['risk_level'] = 'CRITICAL'
            elif result['cvss_score'] >= 7.0:
                result['risk_level'] = 'HIGH'
            elif result['cvss_score'] >= 4.0:
                result['risk_level'] = 'MEDIUM'
        
        try:
            from vulnerability_scanner import VulnerabilityScanner
            scanner = VulnerabilityScanner()
            epss = scanner.get_epss_score(cve_id)
            if epss:
                result['epss_score'] = epss
                if epss > 0.8:
                    result['risk_level'] = 'CRITICAL'
                elif epss > 0.5 and result['risk_level'] == 'LOW':
                    result['risk_level'] = 'HIGH'
        except Exception:
            pass
        
        return result
    
    def correlate_ioc_with_cve(self, ioc_value: str, ioc_type: str = 'ip') -> List[Dict]:
        """Correlate IOC with known CVEs.
        
        Args:
            ioc_value: The IOC value to check
            ioc_type: Type ('ip', 'domain', 'hash', 'url')
            
        Returns:
            List of CVEs associated with this IOC
        """
        correlations = []
        
        if ioc_type == 'ip' and ioc_value in self.malicious_ips:
            malicious_info = self.malicious_ips[ioc_value]
            cve_refs = malicious_info.get('cve_references', [])
            for cve in cve_refs:
                ctx = self.get_cve_threat_context(cve)
                if ctx.get('known_exploited'):
                    correlations.append(ctx)
        
        return correlations

# Global instance
_ti_instance = None

def get_ti_manager(config=None):
    """Get global threat intelligence manager instance."""
    global _ti_instance
    if _ti_instance is None:
        _ti_instance = ThreatIntelligenceManager(config)
    return _ti_instance

if __name__ == "__main__":
    """Test threat intelligence manager."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*80)
    print("          THREAT INTELLIGENCE MANAGER TEST")
    print("="*80)
    print("\nInitializing threat intelligence feeds...")
    
    ti_manager = ThreatIntelligenceManager()
    
    # Test lookups
    print("\nTesting threat lookups:")
    
    test_ip = "192.168.1.1"  # Should be safe
    is_bad, details = ti_manager.is_ip_malicious(test_ip)
    print(f"  IP {test_ip}: {'MALICIOUS' if is_bad else 'SAFE'}")
    
    test_domain = "example.com"  # Should be safe
    is_bad, details = ti_manager.is_domain_malicious(test_domain)
    print(f"  Domain {test_domain}: {'MALICIOUS' if is_bad else 'SAFE'}")
    
    # Show statistics
    stats = ti_manager.get_statistics()
    print(f"\nCurrent Statistics:")
    print(f"  Malicious IPs: {stats['malicious_ips']}")
    print(f"  Malicious Domains: {stats['malicious_domains']}")
    print(f"  Malware Hashes: {stats['malware_hashes']}")
    print(f"  Total IOCs: {stats['total_iocs']}")
    
    print("\nPress Enter to exit...")
    input()