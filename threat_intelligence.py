"""
import logging
_log = logging.getLogger(__name__)
_log.info("Threat Intelligence Manager loaded (v29)")
__version__ = "29.0.0"

================================================================================
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
10. GreyNoise - Internet noise and scanner detection
11. Shodan - Internet-connected device intelligence
12. AbuseIPDB - IP reputation and abuse reporting
13. Censys - Internet-wide scanning data
14. URLScan.io - URL analysis and scanning
15. MalwareBazaar - Malware sample repository

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
                'User-Agent': 'Downpour-v29-ThreatIntel/1.0',
                'Accept': 'application/json, text/plain, */*',
            })
            # v29.39: Optimized connection pool for reduced memory usage
            adapter = requests.adapters.HTTPAdapter(
                pool_connections=5, pool_maxsize=10, max_retries=2,
                pool_block=False)
            self._session.mount('https://', adapter)
            self._session.mount('http://', adapter)
        
        # v29.39: Real-time IOC hit tracking for Performance tab
        self._ioc_hits_last_hour = 0
        self._ioc_hit_history = []  # Timestamps of IOC hits for hourly calculation
        
        # v29.39: Historical trend tracking for OSINT feeds
        self._feed_history = {}  # feed_name -> list of (timestamp, ioc_count) tuples
        self._max_history_points = 100  # Keep last 100 data points per feed
        
        # v29.39: Real-time file threat detection tracking
        self._file_threats_hour = 0
        self._file_threat_history = []  # Timestamps of file threat detections for hourly calculation
        self._total_file_threats = 0
        
        # v29.39: Real-time phishing URL detection tracking
        self._phishing_urls_hour = 0
        self._phishing_url_history = []  # Timestamps of phishing URL detections for hourly calculation
        self._total_phishing_urls = 0
        
        # v29.39: Real-time C2 server detection tracking
        self._c2_servers_hour = 0
        self._c2_server_history = []  # Timestamps of C2 server detections for hourly calculation
        self._total_c2_servers = 0
        
        # v29.39: Real-time suspicious DNS query tracking
        self._suspicious_dns_hour = 0
        self._suspicious_dns_history = []  # Timestamps of suspicious DNS queries for hourly calculation
        self._total_suspicious_dns = 0
        
        # v29.39: Real-time malware hash detection tracking
        self._malware_hashes_hour = 0
        self._malware_hash_history = []  # Timestamps of malware hash detections for hourly calculation
        self._total_malware_hashes = 0
        
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
            'greynoise': '',  # Get from greynoise.io
            'shodan': '',     # Get from shodan.io
            'abuseipdb': '',  # Get from abuseipdb.com
            'censys': '',     # Get from censys.io
            'urlscan': '',    # Get from urlscan.io
            'threatwinds': '',  # Get from threatwinds.com
            'darkapi': '',    # Get from darkapi.io
            'threatbook': '',  # Get from threatbook.io
            'threatradar': '',  # Get from radar.offseq.com
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
            },
            'malwarebazaar': {
                'url': 'https://bazaar.abuse.ch/export/csv/recent/',
                'enabled': True,
                'priority': 'high',
                'update_interval': 1800,  # 30 minutes
                'last_update': 0
            },
            'mitre_attack': {
                'url': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
                'enabled': True,
                'priority': 'low',
                'update_interval': 86400,  # 24 hours
                'last_update': 0
            },
            'alienvault_otx': {
                'url': 'https://otx.alienvault.com/api/v1/indicators/export',
                'enabled': True,
                'priority': 'medium',
                'update_interval': 86400,  # 24 hours
                'last_update': 0
            },
            'spamhaus_dbl': {
                'url': 'https://www.spamhaus.org/dbl/dbl.txt',
                'enabled': True,
                'priority': 'high',
                'update_interval': 3600,  # 1 hour
                'last_update': 0
            },
            'spamhaus_drop': {
                'url': 'https://www.spamhaus.org/drop/drop.txt',
                'enabled': True,
                'priority': 'high',
                'update_interval': 3600,
                'last_update': 0
            },
            'cisco_talos': {
                'url': 'https://talosintelligence.com/documents/ip-blacklist',
                'enabled': True,
                'priority': 'medium',
                'update_interval': 3600,
                'last_update': 0
            },
            'abuse_ch_feodo': {
                'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.csv',
                'enabled': True,
                'priority': 'high',
                'update_interval': 3600,
                'last_update': 0
            },
            'abuse_ch_ssl': {
                'url': 'https://sslbl.abuse.ch/blacklist/sslblacklist.csv',
                'enabled': True,
                'priority': 'high',
                'update_interval': 3600,
                'last_update': 0
            },
            # v29: New OSINT feeds
            'threatwinds': {
                'url': 'https://api.threatwinds.com/v1/threats',
                'enabled': True,
                'priority': 'high',
                'update_interval': 1800,  # 30 minutes
                'last_update': 0,
                'api_required': True
            },
            'darkapi': {
                'url': 'https://api.darkapi.com/v1/indicators',
                'enabled': True,
                'priority': 'high',
                'update_interval': 1800,
                'last_update': 0,
                'api_required': True
            },
            'threatbook': {
                'url': 'https://api.threatbook.com/v3/scene/ioc',
                'enabled': True,
                'priority': 'high',
                'update_interval': 1800,
                'last_update': 0,
                'api_required': True
            },
            'threatradar': {
                'url': 'https://radar.offseq.com/api/v1/threats',
                'enabled': True,
                'priority': 'high',
                'update_interval': 1800,
                'last_update': 0,
                'api_required': True
            },
            'cisa_ics': {'last_update': 0, 'interval': 3600, 'enabled': True, 'error_count': 0},
            'blocklist_de': {'last_update': 0, 'interval': 3600, 'enabled': True, 'error_count': 0},
            'nvd_recent': {'last_update': 0, 'interval': 3600, 'enabled': True, 'error_count': 0},
            'greynoise': {'last_update': 0, 'interval': 3600, 'enabled': True, 'error_count': 0},
            'abuseipdb': {'last_update': 0, 'interval': 3600, 'enabled': True, 'error_count': 0},
            'urlscan': {'last_update': 0, 'interval': 3600, 'enabled': True, 'error_count': 0},
            'darkapi_urlhaus': {'last_update': 0, 'interval': 900, 'enabled': True, 'error_count': 0},
            'darkapi_malwarebazaar': {'last_update': 0, 'interval': 900, 'enabled': True, 'error_count': 0},
            'threatbook_ioc': {'last_update': 0, 'interval': 3600, 'enabled': True, 'error_count': 0}
        }
        
        # Statistics
        self.stats = {
            'total_iocs': 0,
            'feeds_updated': 0,
            'last_update': datetime.now(),
            'update_failures': 0
        }
    
    def _track_ioc_hit(self):
        """Track IOC hit for real-time metrics."""
        now = time.time()
        self._ioc_hit_history.append(now)
        # Clean up old IOC hits (older than 1 hour)
        self._ioc_hit_history = [t for t in self._ioc_hit_history if now - t < 3600]
        self._ioc_hits_last_hour = len(self._ioc_hit_history)
    
    def _track_phishing_url(self):
        """Track phishing URL detection for real-time metrics."""
        now = time.time()
        self._phishing_url_history.append(now)
        # Clean up old detections (older than 1 hour)
        self._phishing_url_history = [t for t in self._phishing_url_history if now - t < 3600]
        self._phishing_urls_hour = len(self._phishing_url_history)
        self._total_phishing_urls += 1
    
    def _track_c2_server(self):
        """Track C2 server detection for real-time metrics."""
        now = time.time()
        self._c2_server_history.append(now)
        # Clean up old detections (older than 1 hour)
        self._c2_server_history = [t for t in self._c2_server_history if now - t < 3600]
        self._c2_servers_hour = len(self._c2_server_history)
        self._total_c2_servers += 1
    
    def _track_suspicious_dns(self):
        """Track suspicious DNS query for real-time metrics."""
        now = time.time()
        self._suspicious_dns_history.append(now)
        # Clean up old queries (older than 1 hour)
        self._suspicious_dns_history = [t for t in self._suspicious_dns_history if now - t < 3600]
        self._suspicious_dns_hour = len(self._suspicious_dns_history)
        self._total_suspicious_dns += 1
    
    def _track_malware_hash(self):
        """Track malware hash detection for real-time metrics."""
        now = time.time()
        self._malware_hash_history.append(now)
        # Clean up old detections (older than 1 hour)
        self._malware_hash_history = [t for t in self._malware_hash_history if now - t < 3600]
        self._malware_hashes_hour = len(self._malware_hash_history)
        self._total_malware_hashes += 1
    
    def _track_file_threat(self):
        """Track file threat detection for real-time metrics."""
        now = time.time()
        self._file_threat_history.append(now)
        # Clean up old file threats (older than 1 hour)
        self._file_threat_history = [t for t in self._file_threat_history if now - t < 3600]
        self._file_threats_hour = len(self._file_threat_history)
        self._total_file_threats += 1
        
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

            logging.info("[OK] Threat intelligence database initialized")

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

            logging.info(f"[OK] Loaded {len(self.malicious_ips)} IPs, {len(self.malicious_domains)} domains, {len(self.malware_hashes)} hashes from database")

        except Exception as e:
            logging.error(f"Error loading from database: {e}")
        finally:
            if conn:
                conn.close()
    
    def _record_feed_history(self, feed_name: str, ioc_count: int):
        """Append a (timestamp, ioc_count) point to feed trend history, capped."""
        try:
            stop = getattr(self, '_max_history_points', 100)
            self._feed_history.setdefault(feed_name, []).append((time.time(), ioc_count))
            if len(self._feed_history[feed_name]) > stop:
                del self._feed_history[feed_name][:-stop]
        except Exception:
            pass

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
            self._record_feed_history('threatfox', iocs_added)
            logging.info(f"[OK] ThreatFox updated: {iocs_added} IOCs added")
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
            self._record_feed_history('urlhaus', iocs_added)
            logging.info(f"[OK] URLhaus updated: {iocs_added} URLs added")
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
                        # v29.39: Track phishing URL detection for real-time metrics
                        self._track_phishing_url()
                        iocs_added += 1
                        
                except Exception as e:
                    logging.debug(f"Error processing PhishTank line: {e}")
                    continue
            
            self.feeds['phishtank']['last_update'] = time.time()
            self._record_feed_history('phishtank', iocs_added)
            logging.info(f"[OK] PhishTank updated: {iocs_added} URLs added")
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
            
            # v29.39: Track IOC hit for real-time metrics
            self._track_ioc_hit()
            
            # v29.39: Track C2 server if tagged as such
            if tags and any('c2' in tag.lower() or 'command' in tag.lower() or 'control' in tag.lower() for tag in tags):
                self._track_c2_server()

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
            
            # v29.39: Track IOC hit for real-time metrics
            self._track_ioc_hit()
            
            # v29.39: Track C2 server if tagged as such
            if tags and any('c2' in tag.lower() or 'command' in tag.lower() or 'control' in tag.lower() for tag in tags):
                self._track_c2_server()
            
            # v29.39: Track suspicious DNS if tagged as such
            if tags and any('dns' in tag.lower() or 'dga' in tag.lower() or 'tunnel' in tag.lower() for tag in tags):
                self._track_suspicious_dns()

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
            
            # v29.39: Track file threat for real-time metrics
            self._track_file_threat()
            
            # v29.39: Track malware hash for real-time metrics
            self._track_malware_hash()

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
            # v29.39: Track IOC hit for real-time metrics
            self._track_ioc_hit()
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
            # v29.39: Track IOC hit for real-time metrics
            self._track_ioc_hit()
            return True, {'domain': domain, 'in_database': True}
        
        # Check subdomains
        for bad_domain in self.malicious_domains:
            if domain.endswith('.' + bad_domain) or bad_domain.endswith('.' + domain):
                # v29.39: Track IOC hit for real-time metrics
                self._track_ioc_hit()
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
            # v29.39: Track IOC hit for real-time metrics
            self._track_ioc_hit()
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
            # v29.39: Track IOC hit for real-time metrics
            self._track_ioc_hit()
            return True, {'hash': file_hash, 'in_database': True}
        
        return False, {}
    
    def update_malwarebazaar_feed(self):
        """Update threat intelligence from MalwareBazaar (abuse.ch)."""
        try:
            logging.info("Updating MalwareBazaar feed...")
            
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['malwarebazaar']['url'], timeout=30)
            response.raise_for_status()
            
            # MalwareBazaar returns CSV
            lines = response.text.strip().split('\n')
            iocs_added = 0
            
            # Skip header line
            for line in lines[1:]:
                try:
                    if not line or line.startswith('#'):
                        continue
                    
                    # CSV format: first_seen_utc,sha256_hash,md5_hash,sha1_hash,......
                    parts = line.split(',')
                    if len(parts) < 3:
                        continue
                    
                    sha256_hash = parts[1].strip('"') if len(parts) > 1 else ''
                    md5_hash = parts[2].strip('"') if len(parts) > 2 else ''
                    malware_family = parts[5].strip('"') if len(parts) > 5 else ''
                    
                    if sha256_hash:
                        self.add_malware_hash(sha256_hash, 'sha256', 'malwarebazaar', malware_family, ['malwarebazaar'])
                        iocs_added += 1
                    if md5_hash and md5_hash != sha256_hash:
                        self.add_malware_hash(md5_hash, 'md5', 'malwarebazaar', malware_family, ['malwarebazaar'])
                    
                except Exception as e:
                    logging.debug(f"Error processing MalwareBazaar line: {e}")
                    continue
            
            self.feeds['malwarebazaar']['last_update'] = time.time()
            self._record_feed_history('malwarebazaar', iocs_added)
            logging.info(f"[+] MalwareBazaar updated: {iocs_added} hashes added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update MalwareBazaar: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_mitre_attack_feed(self):
        """
        Update MITRE ATT&CK techniques mapping.
        Downloads STIX data and extracts technique-to-tactic mappings.
        """
        try:
            logging.info("Updating MITRE ATT&CK feed...")
            
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['mitre_attack']['url'], timeout=60)
            response.raise_for_status()
            
            data = response.json()
            techniques = {}
            
            # Parse STIX 2.0 bundle
            for obj in data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    ext_id = ''
                    for ref in obj.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            ext_id = ref.get('external_id', '')
                            break
                    
                    if ext_id.startswith('T'):
                        techniques[ext_id] = {
                            'name': obj.get('name', ''),
                            'description': obj.get('description', '')[:200],
                            'tactic': self._extract_tactic(obj)
                        }
            
            # Store in database
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                
                # Create table if not exists
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS mitre_attack_techniques (
                        technique_id TEXT PRIMARY KEY,
                        technique_name TEXT,
                        description TEXT,
                        tactic TEXT,
                        last_updated TIMESTAMP
                    )
                ''')
                
                for tid, info in techniques.items():
                    cursor.execute('''
                        INSERT OR REPLACE INTO mitre_attack_techniques
                        (technique_id, technique_name, description, tactic, last_updated)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (tid, info['name'], info['description'], info['tactic'], datetime.now()))
                
                conn.commit()
                logging.info(f"[+] MITRE ATT&CK updated: {len(techniques)} techniques loaded")
                
            finally:
                conn.close()
            
            self.feeds['mitre_attack']['last_update'] = time.time()
            return len(techniques)
            
        except Exception as e:
            logging.error(f"Failed to update MITRE ATT&CK: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_alienvault_otx_feed(self):
        """Update threat intelligence from AlienVault OTX."""
        try:
            logging.info("Updating AlienVault OTX feed...")
            headers = {}
            if self.api_keys.get('otx'):
                headers['X-OTX-API-KEY'] = self.api_keys['otx']
            
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['alienvault_otx']['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            iocs_added = 0
            
            for indicator in data.get('results', []):
                ioc_type = indicator.get('type', '')
                ioc_value = indicator.get('indicator', '')
                if not ioc_value:
                    continue
                
                if ioc_type == 'IPv4':
                    self.add_malicious_ip(ioc_value, 'alienvault_otx')
                    iocs_added += 1
                elif ioc_type == 'domain':
                    self.add_malicious_domain(ioc_value, 'alienvault_otx')
                    iocs_added += 1
                elif ioc_type in ['URL', 'URI']:
                    self.add_malicious_url(ioc_value, 'alienvault_otx')
                    iocs_added += 1
                elif ioc_type in ['FileHash-SHA256', 'FileHash-MD5', 'FileHash-SHA1']:
                    hash_type = ioc_type.split('-')[-1].lower()
                    self.add_malware_hash(ioc_value, hash_type, 'alienvault_otx')
                    iocs_added += 1
            
            self.feeds['alienvault_otx']['last_update'] = time.time()
            logging.info(f"[+] AlienVault OTX updated: {iocs_added} IOCs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update AlienVault OTX: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_spamhaus_dbl_feed(self):
        """Update domain blacklist from Spamhaus DBL."""
        try:
            logging.info("Updating Spamhaus DBL feed...")
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['spamhaus_dbl']['url'], timeout=30)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            iocs_added = 0
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith(';'):
                    continue
                
                # Extract domain (ignore comments)
                domain = line.split(';')[0].strip()
                if domain:
                    self.add_malicious_domain(domain, 'spamhaus_dbl', tags=['spam', 'phishing'])
                    iocs_added += 1
            
            self.feeds['spamhaus_dbl']['last_update'] = time.time()
            logging.info(f"[+] Spamhaus DBL updated: {iocs_added} domains added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update Spamhaus DBL: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def _extract_tactic(self, attack_pattern_obj: Dict) -> str:
        """Extract tactic from ATT&CK pattern object."""
        for ref in attack_pattern_obj.get('kill_chain_phases', []):
            if ref.get('kill_chain_name') == 'mitre-attack':
                return ref.get('phase_name', '')
        return ''
    
    def update_emerging_threats_feed(self):
        """Update threat intelligence from Emerging Threats (Suricata rules).
        
        Note: Emerging Threats provides Suricata rules. This method extracts
        IOCs from rule contents where possible.
        """
        try:
            logging.info("Updating Emerging Threats feed...")
            
            # Emerging Threats URL is a directory - we'll use a specific rules file
            # For simplicity, we'll use the compromised hosts rules which contain IPs
            rules_url = "https://rules.emergingthreats.net/open/suricata/rules/compromised.rules"
            
            _get = self._session.get if self._session else requests.get
            response = _get(rules_url, timeout=30)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            iocs_added = 0
            
            import re
            # Pattern to extract IPs from Suricata rules
            ip_pattern = re.compile(r'(?:src_ip|dest_ip|content|alert)\s*[:\s]\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Extract IPs from rule
                matches = ip_pattern.findall(line)
                for ip in matches:
                    # Validate IP (basic check)
                    parts = ip.split('.')
                    if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                        self.add_malicious_ip(ip, 'emerging_threats', tags=['emerging_threats'])
                        iocs_added += 1
            
            self.feeds['emerging_threats']['last_update'] = time.time()
            logging.info(f"[+] Emerging Threats updated: {iocs_added} IOCs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update Emerging Threats: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_cisa_ics_feed(self):
        """Update CISA ICS-CERT advisories from ICS Advisory Project CSV."""
        try:
            logging.info("Updating CISA ICS-CERT feed...")
            
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['cisa_ics']['url'], timeout=60)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            iocs_added = 0
            
            # Skip header line
            for line in lines[1:]:
                try:
                    if not line or line.startswith('#'):
                        continue
                    
                    # CSV columns: icsadv_ID,Original_Release_Date,...,CVE_Number,...
                    parts = line.split(',')
                    if len(parts) < 9:
                        continue
                    
                    cve_numbers = parts[8].strip('"')  # CVE_Number column
                    if not cve_numbers:
                        continue
                    
                    # Split multiple CVEs (separated by commas)
                    for cve in cve_numbers.split(','):
                        cve = cve.strip()
                        if cve.startswith('CVE-'):
                            # Add to KEV cache
                            if cve not in self.kev_cache:
                                self.kev_cache[cve] = {
                                    'source': 'cisa_ics',
                                    'vendor': parts[5].strip('"') if len(parts) > 5 else '',
                                    'product': parts[6].strip('"') if len(parts) > 6 else '',
                                    'title': parts[4].strip('"') if len(parts) > 4 else '',
                                    'date_added': datetime.now().isoformat()
                                }
                            iocs_added += 1
                            
                except Exception as e:
                    logging.debug(f"Error processing CISA ICS line: {e}")
                    continue
            
            self.feeds['cisa_ics']['last_update'] = time.time()
            logging.info(f"[OK] CISA ICS-CERT updated: {iocs_added} CVEs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update CISA ICS-CERT: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_blocklist_de_feed(self):
        """Update malicious IPs from BlockList.de (public IP blocklist)."""
        try:
            logging.info("Updating BlockList.de feed...")
            
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['blocklist_de']['url'], timeout=30)
            response.raise_for_status()
            
            lines = response.text.strip().split('\n')
            iocs_added = 0
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Validate IP (basic check)
                parts = line.split('.')
                if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                    self.add_malicious_ip(line, 'blocklist_de', 'blocklist_de', [])
                    iocs_added += 1
                    
            self.feeds['blocklist_de']['last_update'] = time.time()
            logging.info(f"[OK] BlockList.de updated: {iocs_added} IPs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update BlockList.de: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_nvd_recent_feed(self):
        """Update recent CVEs from NVD (National Vulnerability Database)."""
        try:
            logging.info("Updating NVD Recent CVEs feed...")
            
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['nvd_recent']['url'], timeout=60)
            response.raise_for_status()
            
            data = response.json()
            iocs_added = 0
            
            if 'vulnerabilities' in data:
                for vuln in data.get('vulnerabilities', []):
                    try:
                        cve_data = vuln.get('cve', {})
                        cve_id = cve_data.get('id', '')
                        if not cve_id.startswith('CVE-'):
                            continue
                        
                        # Add to KEV cache with NVD source
                        if cve_id not in self.kev_cache:
                            self.kev_cache[cve_id] = {
                                'source': 'nvd_recent',
                                'published': cve_data.get('published', ''),
                                'last_modified': cve_data.get('lastModified', ''),
                                'status': cve_data.get('vulnStatus', ''),
                                'date_added': datetime.now().isoformat()
                            }
                        iocs_added += 1
                        
                    except Exception as e:
                        logging.debug(f"Error processing NVD CVE: {e}")
                        continue
            
            self.feeds['nvd_recent']['last_update'] = time.time()
            logging.info(f"[OK] NVD Recent CVEs updated: {iocs_added} CVEs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update NVD Recent CVEs: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    # v29.39: New OSINT feed update methods from OSINT4ALL integration
    
    def update_greynoise_feed(self):
        """Update threat intelligence from GreyNoise Community API."""
        try:
            logging.info("Updating GreyNoise feed...")
            
            if not self.api_keys.get('greynoise'):
                logging.warning("GreyNoise API key not configured, skipping")
                return 0
            
            headers = {'Accept': 'application/json'}
            _get = self._session.get if self._session else requests.get
            
            # Get recent noise IPs from GreyNoise (192.0.2.1 is a documentation-reserved test IP)
            response = _get('https://api.greynoise.io/v3/community/noise/quick/192.0.2.1', 
                          headers=headers, timeout=30)
            response.raise_for_status()
            
            # Note: GreyNoise Community API requires per-IP lookups
            # This is a placeholder for bulk integration
            self.feeds['greynoise']['last_update'] = time.time()
            logging.info("[OK] GreyNoise feed updated (placeholder for bulk integration)")
            return 0
            
        except Exception as e:
            logging.error(f"Failed to update GreyNoise: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_abuseipdb_feed(self):
        """Update threat intelligence from AbuseIPDB blocklist."""
        try:
            logging.info("Updating AbuseIPDB feed...")
            
            headers = {}
            if self.api_keys.get('abuseipdb'):
                headers['Key'] = self.api_keys['abuseipdb']
            
            _get = self._session.get if self._session else requests.get
            response = _get('https://api.abuseipdb.com/api/v2/blacklist',
                          headers=headers, params={'limit': 10000}, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            iocs_added = 0
            
            for entry in data.get('data', []):
                ip = entry.get('ipAddress', '')
                if ip:
                    self.add_malicious_ip(ip, 'abuseipdb', 'abuseipdb', 
                                        [entry.get('abuseConfidence', '')])
                    iocs_added += 1
            
            self.feeds['abuseipdb']['last_update'] = time.time()
            logging.info(f"[OK] AbuseIPDB updated: {iocs_added} IPs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update AbuseIPDB: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_urlscan_feed(self):
        """Update threat intelligence from URLScan.io."""
        try:
            logging.info("Updating URLScan.io feed...")
            
            if not self.api_keys.get('urlscan'):
                logging.warning("URLScan.io API key not configured, skipping")
                return 0
            
            headers = {'API-Key': self.api_keys['urlscan']}
            _get = self._session.get if self._session else requests.get
            
            # Get recent scans (requires API key)
            response = _get('https://urlscan.io/api/v1/search/?q=malware',
                          headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            iocs_added = 0
            
            for result in data.get('results', []):
                url = result.get('page', {}).get('url', '')
                if url:
                    self.add_malicious_url(url, 'urlscan')
                    iocs_added += 1
            
            self.feeds['urlscan']['last_update'] = time.time()
            logging.info(f"[OK] URLScan.io updated: {iocs_added} URLs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update URLScan.io: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def check_shodan_ip(self, ip: str) -> Dict:
        """Check IP against Shodan for device intelligence."""
        try:
            if not self.api_keys.get('shodan'):
                return {'error': 'Shodan API key not configured'}
            
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_keys['shodan']}"
            _get = self._session.get if self._session else requests.get
            response = _get(url, timeout=30)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logging.debug(f"Shodan lookup failed for {ip}: {e}")
            return {'error': str(e)}
    
    def check_censys_ip(self, ip: str) -> Dict:
        """Check IP against Censys for device intelligence."""
        try:
            if not self.api_keys.get('censys'):
                return {'error': 'Censys API key not configured'}
            
            url = f"https://search.censys.io/api/v2/hosts/{ip}"
            headers = {'Authorization': f"Bearer {self.api_keys['censys']}"}
            _get = self._session.get if self._session else requests.get
            response = _get(url, headers=headers, timeout=30)
            response.raise_for_status()
            
            return response.json()
            
        except Exception as e:
            logging.debug(f"Censys lookup failed for {ip}: {e}")
            return {'error': str(e)}
    
    # v29.39: Additional OSINT feed update methods for new sources
    
    def update_threatwinds_feed(self):
        """Update threat intelligence from ThreatWinds Feeds API."""
        try:
            logging.info("Updating ThreatWinds feed...")
            
            if not self.api_keys.get('threatwinds'):
                logging.warning("ThreatWinds API key not configured, skipping")
                return 0
            
            headers = {}
            if self.api_keys.get('threatwinds'):
                headers['Authorization'] = f"Bearer {self.api_keys['threatwinds']}"
            
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['threatwinds']['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            iocs_added = 0
            
            # Process ThreatWinds feed data
            if isinstance(data, dict) and 'feeds' in data:
                for feed in data.get('feeds', []):
                    # Extract IPs from feed
                    if 'indicators' in feed:
                        for indicator in feed.get('indicators', []):
                            if indicator.get('type') == 'ip':
                                self.add_malicious_ip(indicator.get('value'), 'threatwinds')
                                iocs_added += 1
            
            self.feeds['threatwinds']['last_update'] = time.time()
            logging.info(f"[OK] ThreatWinds updated: {iocs_added} IOCs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update ThreatWinds: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_darkapi_urlhaus_feed(self):
        """Update threat intelligence from DarkAPI URLhaus feed."""
        try:
            logging.info("Updating DarkAPI URLhaus feed...")
            
            if not self.api_keys.get('darkapi'):
                logging.warning("DarkAPI API key not configured, skipping")
                return 0
            
            headers = {'Authorization': f"Bearer {self.api_keys['darkapi']}"}
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['darkapi_urlhaus']['url'], headers=headers, 
                          params={'limit': 1000}, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            iocs_added = 0
            
            # Process URLhaus feed data
            if isinstance(data, list):
                for entry in data:
                    url = entry.get('url', '')
                    if url:
                        self.add_malicious_url(url, 'darkapi_urlhaus')
                        iocs_added += 1
                    
                    ip = entry.get('ip_address', '')
                    if ip:
                        self.add_malicious_ip(ip, 'darkapi_urlhaus')
                        iocs_added += 1
            
            self.feeds['darkapi_urlhaus']['last_update'] = time.time()
            logging.info(f"[OK] DarkAPI URLhaus updated: {iocs_added} IOCs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update DarkAPI URLhaus: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_darkapi_malwarebazaar_feed(self):
        """Update threat intelligence from DarkAPI MalwareBazaar feed."""
        try:
            logging.info("Updating DarkAPI MalwareBazaar feed...")
            
            if not self.api_keys.get('darkapi'):
                logging.warning("DarkAPI API key not configured, skipping")
                return 0
            
            headers = {'Authorization': f"Bearer {self.api_keys['darkapi']}"}
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['darkapi_malwarebazaar']['url'], headers=headers,
                          params={'limit': 1000}, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            iocs_added = 0
            
            # Process MalwareBazaar feed data
            if isinstance(data, list):
                for entry in data:
                    sha256 = entry.get('sha256_hash', '')
                    if sha256:
                        self.add_malware_hash(sha256, 'darkapi_malwarebazaar')
                        iocs_added += 1
            
            self.feeds['darkapi_malwarebazaar']['last_update'] = time.time()
            logging.info(f"[OK] DarkAPI MalwareBazaar updated: {iocs_added} hashes added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update DarkAPI MalwareBazaar: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_threatbook_ioc_feed(self):
        """Update threat intelligence from ThreatBook IOC feed."""
        try:
            logging.info("Updating ThreatBook IOC feed...")
            
            if not self.api_keys.get('threatbook'):
                logging.warning("ThreatBook API key not configured, skipping")
                return 0
            
            headers = {'Authorization': f"Bearer {self.api_keys['threatbook']}"}
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['threatbook_ioc']['url'], headers=headers, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            iocs_added = 0
            
            # Process ThreatBook IOC feed data
            if isinstance(data, dict) and 'data' in data:
                for ioc in data.get('data', []):
                    ioc_type = ioc.get('ioc_type', '')
                    ioc_value = ioc.get('ioc_value', '')
                    
                    if ioc_type == 'ip' and ioc_value:
                        self.add_malicious_ip(ioc_value, 'threatbook')
                        iocs_added += 1
                    elif ioc_type == 'domain' and ioc_value:
                        self.add_malicious_domain(ioc_value, 'threatbook')
                        iocs_added += 1
                    elif ioc_type == 'url' and ioc_value:
                        self.add_malicious_url(ioc_value, 'threatbook')
                        iocs_added += 1
                    elif ioc_type == 'hash' and ioc_value:
                        self.add_malware_hash(ioc_value, 'threatbook')
                        iocs_added += 1
            
            self.feeds['threatbook_ioc']['last_update'] = time.time()
            logging.info(f"[OK] ThreatBook IOC updated: {iocs_added} IOCs added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update ThreatBook IOC: {e}")
            self.stats['update_failures'] += 1
            return 0
    
    def update_threatradar_feed(self):
        """Update threat intelligence from Threat Radar API."""
        try:
            logging.info("Updating Threat Radar feed...")
            
            if not self.api_keys.get('threatradar'):
                logging.warning("ThreatRadar API key not configured, skipping")
                return 0
            
            headers = {'X-API-Key': self.api_keys['threatradar']}
            _get = self._session.get if self._session else requests.get
            response = _get(self.feeds['threatradar']['url'], headers=headers,
                          params={'days': 7, 'limit': 100}, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            iocs_added = 0
            
            # Process Threat Radar data
            if isinstance(data, dict) and 'data' in data:
                for threat in data.get('data', []):
                    # Extract CVEs and add to KEV cache
                    cve = threat.get('cve', '')
                    if cve and cve.startswith('CVE-'):
                        if cve not in self.kev_cache:
                            self.kev_cache[cve] = {
                                'source': 'threatradar',
                                'severity': threat.get('severity', ''),
                                'cvss': threat.get('cvss', 0),
                                'published': threat.get('publishedDate', ''),
                                'date_added': datetime.now().isoformat()
                            }
                        iocs_added += 1
            
            self.feeds['threatradar']['last_update'] = time.time()
            logging.info(f"[OK] Threat Radar updated: {iocs_added} threats added")
            return iocs_added
            
        except Exception as e:
            logging.error(f"Failed to update Threat Radar: {e}")
            self.stats['update_failures'] += 1
            return 0
    
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

            logging.info("[OK] Cleaned up old IOCs from database")

        except Exception as e:
            logging.error(f"Error cleaning up IOCs: {e}")
        finally:
            conn.close()
    
    # v29.39: Feed health monitoring and alerting
    
    def check_feed_health(self) -> dict:
        """
        Check health status of all configured feeds.
        
        Returns:
        - dict with feed health status: {feed_name: {'status': 'ok'|'stale'|'error', 'last_update': timestamp, 'message': str}}
        """
        health_report = {}
        current_time = time.time()
        
        for feed_name, feed_config in self.feeds.items():
            if not feed_config['enabled']:
                health_report[feed_name] = {'status': 'disabled', 'last_update': 0, 'message': 'Feed disabled'}
                continue
            
            last_update = feed_config.get('last_update', 0)
            update_interval = feed_config.get('update_interval', 3600)
            
            # Check if feed is stale (not updated within 3x interval)
            if last_update == 0:
                status = 'never_updated'
                message = 'Feed has never been updated'
            elif current_time - last_update > (update_interval * 3):
                status = 'stale'
                message = f'Feed not updated for {int((current_time - last_update) / 60)} minutes'
            else:
                status = 'ok'
                message = f'Last updated {int((current_time - last_update) / 60)} minutes ago'
            
            health_report[feed_name] = {
                'status': status,
                'last_update': last_update,
                'message': message
            }
        
        return health_report
    
    def get_feed_alerts(self) -> list:
        """
        Get alerts for feeds that need attention.
        
        Returns:
        - list of alert dicts: [{'feed': name, 'severity': 'warning'|'critical', 'message': str}]
        """
        alerts = []
        health = self.check_feed_health()
        
        for feed_name, feed_health in health.items():
            if feed_health['status'] == 'stale':
                alerts.append({
                    'feed': feed_name,
                    'severity': 'warning',
                    'message': f"{feed_name}: {feed_health['message']}"
                })
            elif feed_health['status'] == 'never_updated':
                alerts.append({
                    'feed': feed_name,
                    'severity': 'critical',
                    'message': f"{feed_name}: {feed_health['message']}"
                })
        
        # Check for high error rate
        if self.stats.get('update_failures', 0) > 5:
            alerts.append({
                'feed': 'global',
                'severity': 'warning',
                'message': f"High feed error rate: {self.stats['update_failures']} failures"
            })
        
        return alerts
    
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
                elif feed_name == 'malwarebazaar':
                    iocs = self.update_malwarebazaar_feed()
                elif feed_name == 'mitre_attack':
                    iocs = self.update_mitre_attack_feed()
                elif feed_name == 'alienvault_otx':
                    iocs = self.update_alienvault_otx_feed()
                elif feed_name == 'spamhaus_dbl':
                    iocs = self.update_spamhaus_dbl_feed()
                elif feed_name == 'emerging_threats':
                    iocs = self.update_emerging_threats_feed()
                elif feed_name == 'cisa_ics':
                    iocs = self.update_cisa_ics_feed()
                elif feed_name == 'blocklist_de':
                    iocs = self.update_blocklist_de_feed()
                elif feed_name == 'nvd_recent':
                    iocs = self.update_nvd_recent_feed()
                # v29.39: New OSINT feeds
                elif feed_name == 'greynoise':
                    iocs = self.update_greynoise_feed()
                elif feed_name == 'abuseipdb':
                    iocs = self.update_abuseipdb_feed()
                elif feed_name == 'urlscan':
                    iocs = self.update_urlscan_feed()
                elif feed_name == 'threatwinds':
                    iocs = self.update_threatwinds_feed()
                elif feed_name == 'darkapi_urlhaus':
                    iocs = self.update_darkapi_urlhaus_feed()
                elif feed_name == 'darkapi_malwarebazaar':
                    iocs = self.update_darkapi_malwarebazaar_feed()
                elif feed_name == 'threatbook_ioc':
                    iocs = self.update_threatbook_ioc_feed()
                elif feed_name == 'threatradar':
                    iocs = self.update_threatradar_feed()
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
            logging.info(f"[+] Total IOCs updated: {total_iocs}")
        
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
        logging.info("[OK] Threat Intelligence Manager active")
    
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

    def start_monitoring(self):
        """Start background feed monitoring."""
        if not self.running:
            self.running = True
            self.monitor_thread = threading.Thread(
                target=self.monitoring_loop, 
                daemon=True, 
                name='ThreatIntelMonitor'
            )
            self.monitor_thread.start()
            logging.info("Threat intelligence monitoring started")

    def get_mitre_technique_count(self):
        """Return number of loaded MITRE ATT&CK techniques."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM mitre_attack_techniques")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return 0

# Global instance
_ti_instance = None

def get_ti_manager(config=None) -> 'ThreatIntelligenceManager':
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
