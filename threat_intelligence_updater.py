"""
===============================================================================
THREAT INTELLIGENCE UPDATER - Real-Time Protection Database
===============================================================================

This module downloads and maintains threat intelligence from multiple sources:
- VirusTotal API
- AbuseIPDB
- URLhaus (Malware URLs)
- Malware Bazaar (Malware hashes)
- PhishTank (Phishing URLs)
- CISA KEV (Known Exploited Vulnerabilities)
- EPSS (Exploit Prediction Scoring System)

v29: Added KEV/CEV/EPSS integration for real-time exploit tracking.

Continuously updates local database to improve detection capabilities.
"""

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
import json
import sqlite3
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import threading

# v29: KEV/CISA constants
CISA_KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog.csv"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_API_KEY = ""  # Set your API key if available

class ThreatIntelligenceUpdater:
    """Manages threat intelligence database with online updates.

    v28p36: Added exponential backoff, retry logic, and rate limiting.
    """

    # v28p36: Retry config
    MAX_RETRIES = 3
    BACKOFF_BASE = 2.0     # seconds — doubles each retry (2, 4, 8)
    RATE_LIMIT_S = 1.0     # min seconds between requests to same source

    def __init__(self, db_path="threat_intelligence.db"):
        self.db_path = db_path
        self.last_update = None
        self.update_interval = 3600  # 1 hour
        self.running = False
        self._last_request_time = {}  # per-source rate limit tracking
        self._backoff_state = {}      # per-source backoff counters
        
        # Free public threat intelligence sources
        self.sources = {
            'urlhaus': 'https://urlhaus.abuse.ch/downloads/csv_recent/',
            'malware_bazaar': 'https://bazaar.abuse.ch/export/csv/recent/',
            'abuse_ipdb': 'https://api.abuseipdb.com/api/v2/blacklist',
            'phishtank': 'http://data.phishtank.com/data/online-valid.json'
        }
        
        self.init_database()
        
    def init_database(self):
        """Initialize threat intelligence database."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                # Malicious file hashes
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS malicious_hashes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        hash_type TEXT NOT NULL,
                        hash_value TEXT NOT NULL UNIQUE,
                        threat_name TEXT,
                        severity TEXT,
                        source TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Malicious URLs
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS malicious_urls (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT NOT NULL UNIQUE,
                        threat_type TEXT,
                        severity TEXT,
                        source TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Malicious IP addresses
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS malicious_ips (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT NOT NULL UNIQUE,
                        threat_type TEXT,
                        severity TEXT,
                        country TEXT,
                        source TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Known malware signatures
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS malware_signatures (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        signature TEXT NOT NULL,
                        malware_family TEXT,
                        description TEXT,
                        severity TEXT,
                        source TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Update history
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS update_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source TEXT NOT NULL,
                        records_added INTEGER DEFAULT 0,
                        records_updated INTEGER DEFAULT 0,
                        update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT,
                        error_message TEXT
                    )
                ''')

                # v29: KEV vulnerabilities (CISA Known Exploited Vulnerabilities)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS kev_vulnerabilities (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cve_id TEXT NOT NULL UNIQUE,
                        vendor_project TEXT,
                        product TEXT,
                        vulnerability_name TEXT,
                        date_added DATE,
                        due_date DATE,
                        patch_available TEXT,
                        severity TEXT,
                        known_ransomware_campaign_use TEXT,
                        epss_score REAL,
                        cvss_score REAL,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # v29: CVE to IOC mapping
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS cve_ioc_mapping (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        cve_id TEXT NOT NULL,
                        ioc_type TEXT NOT NULL,
                        ioc_value TEXT NOT NULL,
                        source TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (cve_id) REFERENCES kev_vulnerabilities(cve_id)
                    )
                ''')

                conn.commit()
            finally:
                conn.close()
            logging.info("Threat intelligence database initialized with KEV support")
            
        except Exception as e:
            logging.error(f"Failed to initialize threat database: {e}")
    
    def start_auto_update(self):
        """Start automatic background updates."""
        self.running = True
        threading.Thread(target=self._update_loop, daemon=True).start()
        logging.info("Threat intelligence auto-update started")
    
    def stop_auto_update(self):
        """Stop automatic updates."""
        self.running = False
        logging.info("Threat intelligence auto-update stopped")
    
    def _update_loop(self):
        """Background loop for periodic updates."""
        while self.running:
            try:
                # Check if update is needed
                if self.needs_update():
                    logging.info("Starting threat intelligence update...")
                    self.update_all_sources()
                    self.last_update = datetime.now()
                
                # Wait before next check (check every 5 minutes)
                time.sleep(300)
                
            except Exception as e:
                logging.error(f"Update loop error: {e}")
                time.sleep(600)  # Wait 10 minutes on error
    
    def needs_update(self):
        """Check if update is needed."""
        if not self.last_update:
            return True
        
        elapsed = (datetime.now() - self.last_update).total_seconds()
        return elapsed >= self.update_interval
    
    def _fetch_with_backoff(self, source_name, url, **kwargs):
        """Fetch URL with exponential backoff, retry, and rate limiting.

        Returns requests.Response on success, None on failure after all retries.
        """
        if not _REQUESTS_AVAILABLE:
            return None
        # Rate limit — wait if needed
        now = time.monotonic()
        last = self._last_request_time.get(source_name, 0)
        wait = self.RATE_LIMIT_S - (now - last)
        if wait > 0:
            time.sleep(wait)

        kwargs.setdefault('timeout', 30)
        kwargs.setdefault('headers', {'User-Agent': 'Downpour-v29-ThreatIntel/1.0'})

        for attempt in range(self.MAX_RETRIES):
            try:
                self._last_request_time[source_name] = time.monotonic()
                resp = requests.get(url, **kwargs)
                if resp.status_code == 429:
                    # Rate limited — backoff longer
                    backoff = self.BACKOFF_BASE * (2 ** (attempt + 1))
                    logging.warning(f"[{source_name}] Rate limited (429), backing off {backoff:.1f}s")
                    time.sleep(backoff)
                    continue
                if resp.status_code >= 500:
                    # Server error — retry with backoff
                    backoff = self.BACKOFF_BASE * (2 ** attempt)
                    logging.warning(f"[{source_name}] Server error {resp.status_code}, retry in {backoff:.1f}s")
                    time.sleep(backoff)
                    continue
                # Success or client error (4xx other than 429)
                self._backoff_state[source_name] = 0
                return resp
            except requests.exceptions.Timeout:
                backoff = self.BACKOFF_BASE * (2 ** attempt)
                logging.warning(f"[{source_name}] Timeout, retry {attempt+1}/{self.MAX_RETRIES} in {backoff:.1f}s")
                time.sleep(backoff)
            except requests.exceptions.ConnectionError:
                backoff = self.BACKOFF_BASE * (2 ** attempt)
                logging.warning(f"[{source_name}] Connection error, retry {attempt+1}/{self.MAX_RETRIES} in {backoff:.1f}s")
                time.sleep(backoff)
            except Exception as e:
                logging.error(f"[{source_name}] Unexpected error: {e}")
                break

        self._backoff_state[source_name] = self._backoff_state.get(source_name, 0) + 1
        logging.error(f"[{source_name}] All {self.MAX_RETRIES} retries exhausted")
        return None

    def update_all_sources(self):
        """Update from all threat intelligence sources."""
        results = {}
        
        # Update URLhaus (malicious URLs)
        results['urlhaus'] = self.update_urlhaus()
        
        # Update Malware Bazaar (malware hashes)
        results['malware_bazaar'] = self.update_malware_bazaar()
        
        # Add some known malware hashes for testing
        results['static_hashes'] = self.add_static_threats()
        
        return results
    
    def update_urlhaus(self):
        """Update from URLhaus threat feed with exponential backoff."""
        try:
            logging.info("Updating URLhaus threat database...")

            response = self._fetch_with_backoff('urlhaus', self.sources['urlhaus'])
            if response is None:
                return {'success': False, 'error': 'All retries exhausted'}
            
            if response.status_code == 200:
                # Parse CSV data
                lines = response.text.split('\n')
                added = 0
                
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()

                    for line in lines[9:]:  # Skip header lines
                        if not line.strip() or line.startswith('#'):
                            continue

                        try:
                            parts = line.split(',')
                            if len(parts) >= 3:
                                url = parts[2].strip('"')
                                threat_type = parts[4].strip('"') if len(parts) > 4 else 'malware'

                                cursor.execute('''
                                    INSERT OR IGNORE INTO malicious_urls
                                    (url, threat_type, severity, source)
                                    VALUES (?, ?, ?, ?)
                                ''', (url, threat_type, 'HIGH', 'URLhaus'))

                                if cursor.rowcount > 0:
                                    added += 1
                        except Exception:
                            continue

                    conn.commit()
                finally:
                    conn.close()
                
                # Log update
                self.log_update('URLhaus', added, 0, 'SUCCESS')
                logging.info(f"URLhaus update complete: {added} new threats added")
                return {'success': True, 'added': added}
                
        except Exception as e:
            logging.error(f"URLhaus update failed: {e}")
            self.log_update('URLhaus', 0, 0, 'FAILED', str(e))
            return {'success': False, 'error': str(e)}
    
    def update_malware_bazaar(self):
        """Update from Malware Bazaar hash database with exponential backoff."""
        try:
            logging.info("Updating Malware Bazaar hash database...")

            response = self._fetch_with_backoff('malware_bazaar', self.sources['malware_bazaar'])
            if response is None:
                return {'success': False, 'error': 'All retries exhausted'}
            
            if response.status_code == 200:
                lines = response.text.split('\n')
                added = 0
                
                conn = sqlite3.connect(self.db_path)
                try:
                    cursor = conn.cursor()

                    for line in lines[9:]:  # Skip headers
                        if not line.strip() or line.startswith('#'):
                            continue

                        try:
                            parts = line.split(',')
                            if len(parts) >= 3:
                                sha256_hash = parts[1].strip('"')
                                md5_hash = parts[2].strip('"')
                                threat_name = parts[5].strip('"') if len(parts) > 5 else 'malware'

                                # Add SHA256
                                if sha256_hash:
                                    cursor.execute('''
                                        INSERT OR IGNORE INTO malicious_hashes
                                        (hash_type, hash_value, threat_name, severity, source)
                                        VALUES (?, ?, ?, ?, ?)
                                    ''', ('SHA256', sha256_hash, threat_name, 'CRITICAL', 'MalwareBazaar'))
                                    if cursor.rowcount > 0:
                                        added += 1

                                # Add MD5
                                if md5_hash:
                                    cursor.execute('''
                                        INSERT OR IGNORE INTO malicious_hashes
                                        (hash_type, hash_value, threat_name, severity, source)
                                        VALUES (?, ?, ?, ?, ?)
                                    ''', ('MD5', md5_hash, threat_name, 'CRITICAL', 'MalwareBazaar'))
                                    if cursor.rowcount > 0:
                                        added += 1
                        except Exception:
                            continue

                    conn.commit()
                finally:
                    conn.close()
                
                self.log_update('MalwareBazaar', added, 0, 'SUCCESS')
                logging.info(f"Malware Bazaar update complete: {added} new hashes added")
                return {'success': True, 'added': added}
                
        except Exception as e:
            logging.error(f"Malware Bazaar update failed: {e}")
            self.log_update('MalwareBazaar', 0, 0, 'FAILED', str(e))
            return {'success': False, 'error': str(e)}
    
    def add_static_threats(self):
        """Add known malicious patterns for testing and baseline protection."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            added = 0

            # Known malware file extensions
            malicious_signatures = [
                ('.exe.txt', 'File Extension Spoofing', 'HIGH'),
                ('.scr', 'Screensaver Malware', 'HIGH'),
                ('.vbs', 'VBScript Malware', 'MEDIUM'),
                ('.js', 'JavaScript Malware', 'MEDIUM'),
                ('.wsf', 'Windows Script File', 'MEDIUM'),
                ('invoice.zip', 'Common Phishing Pattern', 'HIGH'),
                ('payment.pdf.exe', 'PDF Spoofing', 'CRITICAL'),
            ]

            for sig, family, severity in malicious_signatures:
                cursor.execute('''
                    INSERT OR IGNORE INTO malware_signatures
                    (signature, malware_family, description, severity, source)
                    VALUES (?, ?, ?, ?, ?)
                ''', (sig, family, f'Detects {family}', severity, 'Static'))
                if cursor.rowcount > 0:
                    added += 1

            conn.commit()

            logging.info(f"Added {added} static threat signatures")
            return {'success': True, 'added': added}

        except Exception as e:
            logging.error(f"Failed to add static threats: {e}")
            return {'success': False, 'error': str(e)}
        finally:
            if conn:
                conn.close()
    
    def check_file_hash(self, file_path):
        """Check if file hash matches known malware."""
        conn = None
        try:
            md5_hash = self.calculate_hash(file_path, 'md5')
            sha256_hash = self.calculate_hash(file_path, 'sha256')

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check MD5
            cursor.execute('''
                SELECT threat_name, severity, source
                FROM malicious_hashes
                WHERE hash_type = 'MD5' AND hash_value = ?
            ''', (md5_hash,))
            result = cursor.fetchone()

            if result:
                return {
                    'is_malicious': True,
                    'hash_type': 'MD5',
                    'threat_name': result[0],
                    'severity': result[1],
                    'source': result[2]
                }

            # Check SHA256
            cursor.execute('''
                SELECT threat_name, severity, source
                FROM malicious_hashes
                WHERE hash_type = 'SHA256' AND hash_value = ?
            ''', (sha256_hash,))
            result = cursor.fetchone()

            if result:
                return {
                    'is_malicious': True,
                    'hash_type': 'SHA256',
                    'threat_name': result[0],
                    'severity': result[1],
                    'source': result[2]
                }

            return {'is_malicious': False}

        except Exception as e:
            logging.error(f"Hash check error: {e}")
            return {'is_malicious': False, 'error': str(e)}
        finally:
            if conn:
                conn.close()
    
    def check_url(self, url):
        """Check if URL is malicious."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT threat_type, severity, source
                FROM malicious_urls
                WHERE url LIKE ?
            ''', (f'%{url}%',))
            result = cursor.fetchone()

            if result:
                return {
                    'is_malicious': True,
                    'threat_type': result[0],
                    'severity': result[1],
                    'source': result[2]
                }

            return {'is_malicious': False}

        except Exception as e:
            logging.error(f"URL check error: {e}")
            return {'is_malicious': False, 'error': str(e)}
        finally:
            if conn:
                conn.close()
    
    @staticmethod
    def calculate_hash(file_path, algorithm='md5'):
        """Calculate file hash."""
        try:
            hash_obj = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            logging.error(f"Hash calculation error: {e}")
            return None
    
    def log_update(self, source, added, updated, status, error_msg=None):
        """Log update to history."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO update_history (source, records_added, records_updated, status, error_message)
                VALUES (?, ?, ?, ?, ?)
            ''', (source, added, updated, status, error_msg))

            conn.commit()
        except Exception as e:
            logging.error(f"Failed to log update: {e}")
        finally:
            if conn:
                conn.close()
    
    def get_statistics(self):
        """Get database statistics."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('SELECT COUNT(*) FROM malicious_hashes')
            hash_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM malicious_urls')
            url_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM malicious_ips')
            ip_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM malware_signatures')
            sig_count = cursor.fetchone()[0]

            cursor.execute('SELECT COUNT(*) FROM kev_vulnerabilities')
            kev_count = cursor.fetchone()[0]

            cursor.execute('''
                SELECT source, MAX(update_time), status
                FROM update_history
                GROUP BY source
            ''')
            last_updates = cursor.fetchall()

            return {
                'total_hashes': hash_count,
                'total_urls': url_count,
                'total_ips': ip_count,
                'total_signatures': sig_count,
                'total_kev': kev_count,
                'last_updates': last_updates
            }

        except Exception as e:
            logging.error(f"Statistics error: {e}")
            return {}
        finally:
            if conn:
                conn.close()
    
    # v29: KEV Update Methods
    def update_kev_catalog(self):
        """Update CISA KEV catalog."""
        added = 0
        try:
            logging.info("Updating CISA KEV catalog...")
            
            if not _REQUESTS_AVAILABLE:
                logging.warning("requests not available, skipping KEV update")
                return 0
            
            resp = self._fetch_with_backoff('cisa_kev', CISA_KEV_URL)
            if not resp or resp.status_code != 200:
                logging.warning(f"KEV update failed: {resp.status_code if resp else 'no response'}")
                return 0
            
            lines = resp.text.strip().split('\n')
            if len(lines) < 2:
                return 0
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            header = lines[0].lower().split(',')
            for line in lines[1:]:
                try:
                    fields = line.split(',')
                    if len(fields) < 6:
                        continue
                    
                    record = dict(zip(header, fields))
                    cve_id = record.get('cve id', record.get('cve_id', ''))
                    if not cve_id:
                        continue
                    
                    cursor.execute('''
                        INSERT OR REPLACE INTO kev_vulnerabilities 
                        (cve_id, vendor_project, product, vulnerability_name, date_added, 
                         due_date, patch_available, severity, known_ransomware_campaign_use)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        cve_id,
                        record.get('vendor project', record.get('vendor', '')),
                        record.get('product', ''),
                        record.get('vulnerability name', ''),
                        record.get('date added', ''),
                        record.get('due date', ''),
                        record.get('patch available', ''),
                        record.get('severity', ''),
                        record.get('known ransomware campaign use', '')
                    ))
                    added += 1
                except Exception as e:
                    logging.debug(f"KEV record error: {e}")
            
            conn.commit()
            conn.close()
            logging.info(f"KEV catalog updated: {added} entries")
            
        except Exception as e:
            logging.error(f"KEV update error: {e}")
        
        return added
    
    def update_epss_scores(self, cve_ids=None):
        """Update EPSS scores for given CVEs."""
        if not cve_ids:
            return 0
        
        try:
            logging.info(f"Updating EPSS scores for {len(cve_ids)} CVEs...")
            
            if not _REQUESTS_AVAILABLE:
                return 0
            
            cve_list = ','.join(cve_ids[:100])  # Limit batch size
            url = f"{EPSS_API_URL}?cve={cve_list}"
            if EPSS_API_KEY:
                url += f"&token={EPSS_API_KEY}"
            
            resp = self._fetch_with_backoff('epss', url)
            if not resp or resp.status_code != 200:
                return 0
            
            data = resp.json()
            updated = 0
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for item in data.get('data', []):
                try:
                    cve = item.get('cve', '')
                    epss = float(item.get('epss', 0))
                    cvss = float(item.get('cvss', 0))
                    
                    cursor.execute('''
                        UPDATE kev_vulnerabilities 
                        SET epss_score = ?, cvss_score = ?, last_updated = CURRENT_TIMESTAMP
                        WHERE cve_id = ?
                    ''', (epss, cvss, cve))
                    updated += 1
                except Exception:
                    pass
            
            conn.commit()
            conn.close()
            logging.info(f"EPSS scores updated: {updated}")
            
        except Exception as e:
            logging.error(f"EPSS update error: {e}")
        
        return updated
    
    def get_kev_statistics(self):
        """Get KEV vulnerability statistics."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM kev_vulnerabilities')
            total = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM kev_vulnerabilities WHERE severity = 'Critical'")
            critical = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM kev_vulnerabilities WHERE known_ransomware_campaign_use = 'Yes'")
            ransomware = cursor.fetchone()[0]
            
            cursor.execute('SELECT AVG(epss_score) FROM kev_vulnerabilities WHERE epss_score > 0')
            avg_epss = cursor.fetchone()[0] or 0
            
            return {
                'total_kev': total,
                'critical': critical,
                'ransomware': ransomware,
                'avg_epss': round(avg_epss, 3)
            }
            
        except Exception as e:
            logging.error(f"KEV stats error: {e}")
            return {}
        finally:
            if conn:
                conn.close()
    
    def check_cve_in_kev(self, cve_id):
        """Check if CVE is in KEV catalog."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT cve_id, vendor_project, product, severity, known_ransomware_campaign_use, epss_score
                FROM kev_vulnerabilities WHERE cve_id = ?
            ''', (cve_id,))
            
            result = cursor.fetchone()
            if result:
                return {
                    'cve_id': result[0],
                    'vendor': result[1],
                    'product': result[2],
                    'severity': result[3],
                    'ransomware': result[4],
                    'epss': result[5]
                }
            return None
            
        except Exception as e:
            logging.error(f"KEV check error: {e}")
            return None
        finally:
            if conn:
                conn.close()
    
    def get_total_threats(self):
        """Get total number of threats in database."""
        try:
            stats = self.get_statistics()
            return (stats.get('total_hashes', 0) + 
                   stats.get('total_urls', 0) + 
                   stats.get('total_ips', 0) + 
                   stats.get('total_signatures', 0))
        except Exception:
            return 0
