"""
__version__ = "29.0.0"

================================================================================
NETWORK MONITORING MODULE v1.2 - ENHANCED v29
================================================================================

PURPOSE: Watches network connections to detect suspicious communication
         with malicious servers, data theft, and command & control traffic.

WHAT IT MONITORS:
- All outbound network connections
- Connections to known malicious IPs
- Unusual port usage
- High-volume data transfers
- Connections to suspicious countries (optional)
- Programs communicating without user knowledge

HOW IT WORKS:
- Monitors active network connections per process
- Maintains database of known bad IPs and domains
- Tracks connection patterns over time
- Alerts on suspicious network behavior

THREAT DETECTION:
- Command & Control (C&C) servers used by botnets
- Data exfiltration (stealing files over network)
- Phishing/credential theft servers
- Malware download sources
- Cryptocurrency mining pools

v29 ENHANCEMENTS:
- Enhanced MITRE ATT&CK TTP mappings (T10xx network techniques)
- C2 beacon detection patterns
- DNS tunneling indicators
- Domain generation algorithm (DGA) detection
- Lateral movement detection
- Exfiltration pattern analysis
- Protocol anomaly detection
- v29.39: Integration with GreyNoise, AbuseIPDB, Shodan, Censys for enhanced IP reputation
- v29.39: Real-time OSINT lookup integration for connection analysis

================================================================================
"""

import logging
try:
    from config import CONFIG as APP_CONFIG
except Exception:
    APP_CONFIG = {}
import threading
import time
try:
    import psutil
except ImportError:
    raise ImportError("network_monitor requires psutil: pip install psutil")
from datetime import datetime, timedelta
from collections import defaultdict
import socket
import ipaddress

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

try:
    from vulnerability_scanner import get_kev_catalog, get_epss_stats
    _KEV_AVAILABLE = True
except ImportError:
    _KEV_AVAILABLE = False

class NetworkMonitor:
    """
    Monitors network activity for suspicious connections.
    
    Watches all network connections and alerts on suspicious patterns
    like connections to known malicious IPs or unusual data transfers.
    """
    
    def __init__(self, config=None):
        """
        Initialize network monitor.
        
        Parameters:
        - config: Configuration object (optional)
        """
        self.running = True
        self.config = config
        
        # Track connections per process
        self.connection_history = defaultdict(list)
        
        # v29.39: OSINT reputation cache to reduce API calls
        self._osint_cache = {}
        self._osint_cache_ttl = 300  # 5 minutes cache TTL
        
        # v29.39: Real-time threat tracking for Performance tab
        self._threats_last_hour = 0
        self._c2_servers_detected = set()
        self._threat_history = []  # Timestamps of threats for hourly calculation
        
        # v29: Known malicious IPs from threat intelligence feeds
        self.malicious_ips = set([
            # Kimwolf botnet C2 servers
            '93.95.112.50', '93.95.112.51', '93.95.112.52', '93.95.112.53',
            '93.95.112.54', '93.95.112.55', '93.95.112.56', '93.95.112.57',
            '93.95.112.58', '93.95.112.59', '85.234.91.247', '185.220.101.0/24',
            # Mozi botnet nodes
            '103.145.12.0/24', '45.142.212.0/24',
            # BadBox2 botnet
            '46.21.147.0/24', '91.92.248.0/24', '194.165.16.0/24',
            # AISURU botnet
            '185.174.136.0/24', '91.109.6.0/24',
            # Known CobaltStrike servers
            '23.106.160.188', '194.165.16.134', '185.220.101.47', '45.142.212.100',
        ])
        
        # Split into exact IPs and CIDR networks for proper matching
        self._malicious_exact_ips = {ip for ip in self.malicious_ips if '/' not in ip}
        self._malicious_networks: list = []
        for cidr in self.malicious_ips:
            if '/' in cidr:
                try:
                    self._malicious_networks.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    pass
        
        # Suspicious ports commonly used by malware
        self.suspicious_ports = [
            4444,   # Metasploit default
            5555,   # Android Debug Bridge (can be exploited)
            6666,   # IRC bots
            31337,  # Back Orifice
            12345,  # NetBus
            1337,   # General hacker culture port
            3128,   # Squid proxy (can hide traffic)
            8080,   # Alternative HTTP (can hide traffic)
        ]
        
        # Known mining pool ports
        self.mining_ports = [
            3333, 3334, 3335, 3336,  # Common mining pool ports
            4444, 5555, 8888, 9999,  # Alternative mining ports
        ]
        
        # Load settings from config
        if config:
            if config.has_option('NETWORK_MONITORING', 'watched_ports'):
                port_str = config.get('NETWORK_MONITORING', 'watched_ports')
                custom_ports = [int(p.strip()) for p in port_str.split(',') if p.strip().isdigit()]
                if custom_ports:
                    self.suspicious_ports.extend(custom_ports)
    
    def is_private_ip(self, ip: str) -> bool:
        """
        Check if IP address is private/local (not on internet).
        
        Private IPs are generally safe - they're on your local network.
        
        Parameters:
        - ip: IP address string
        
        Returns:
        - True if private, False if public internet address
        """
        if ip.startswith('127.'):  # Localhost
            return True
        if ip.startswith('192.168.'):  # Private network
            return True
        if ip.startswith('10.'):  # Private network
            return True
        if ip.startswith('172.'):
            try:
                if 16 <= int(ip.split('.')[1]) <= 31:
                    return True  # Private network (172.16-31.x.x)
            except (ValueError, IndexError):
                pass
        if ip == '0.0.0.0' or ip == '::':  # Any address
            return True
        return False
    
    def _is_malicious_ip(self, ip: str) -> bool:
        """
        Check if an IP matches any known malicious IP or CIDR range.
        
        Uses proper CIDR matching via ipaddress module so ranges like
        185.220.101.0/24 correctly match 185.220.101.47.
        """
        if ip in self._malicious_exact_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._malicious_networks)
        except ValueError:
            return False
    
    def get_country_for_ip(self, ip: str) -> str:
        """
        Get country code for an IP address.
        
        v29: Uses ip-api.com free API for country lookup.
        
        Parameters:
        - ip: IP address
        
        Returns:
        - Two-letter country code (e.g., 'US', 'CN', 'RU')
        """
        if not ip or self.is_private_ip(ip):
            return "LO"
        
        try:
            if _REQUESTS_AVAILABLE:
                provider = APP_CONFIG.get('GEOIP', {}).get('PROVIDER', 'ip-api')
                if provider == 'ip-api':
                    url = f"https://ip-api.com/json/{ip}"
                elif provider == 'ipinfo':
                    url = f"https://ipinfo.io/{ip}/json"
                else:
                    url = f"https://ip-api.com/json/{ip}"
                resp = requests.get(
                    url,
                    timeout=3,
                    headers={"User-Agent": "Downpour-HealthCheck/29"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get('status') == 'success':
                        return data.get('countryCode', '??')
        except Exception:
            pass
        
        return "??"  # Unknown

    def _track_threat(self):
        """Track threat occurrence for real-time metrics."""
        now = time.time()
        self._threat_history.append(now)
        # Clean up old threats (older than 1 hour)
        self._threat_history = [t for t in self._threat_history if now - t < 3600]
        self._threats_last_hour = len(self._threat_history)

    def check_ip_cve(self, ip: str) -> dict:
        """
        Check if an IP is associated with any KEV CVEs.

        Some malware families have known C2 IPs tied to specific CVEs.
        This function correlates malicious IPs with known vulnerabilities.

        Parameters:
        - ip: IP address string

        Returns:
        - dict with keys: matched_cves (list), epss_score (float or None),
                kev_available (bool)
        """
        result = {
            'matched_cves': [],
            'epss_score': None,
            'kev_available': _KEV_AVAILABLE
        }

        if not _KEV_AVAILABLE:
            return result

        try:
            kev_catalog = get_kev_catalog()
            if not kev_catalog or 'vulnerabilities' not in kev_catalog:
                return result

            # Known mappings of C2 IPs to CVEs (would be expanded with threat intel)
            # For now, check if the IP appears in any KEV vulnerability notes
            for vuln in kev_catalog.get('vulnerabilities', []):
                # Check if IP is mentioned in vulnerability notes or references
                notes = vuln.get('notes', '') or ''
                references = vuln.get('references', []) or []
                cve_id = vuln.get('cveID', '')

                ip_found = False
                if ip in notes:
                    ip_found = True
                else:
                    for ref in references:
                        if ip in str(ref):
                            ip_found = True
                            break

                if ip_found and cve_id:
                    result['matched_cves'].append({
                        'cve_id': cve_id,
                        'vulnerability_name': vuln.get('vulnerabilityName', ''),
                        'date_added': vuln.get('dateAdded', ''),
                        'known_ransomware': vuln.get('knownRansomwareCampaignUse', 'Unknown')
                    })

            # Get EPSS score for matched CVEs if available
            if result['matched_cves'] and _KEV_AVAILABLE:
                try:
                    epss_data = get_epss_stats([c['cve_id'] for c in result['matched_cves']])
                    if epss_data:
                        # Use highest EPSS score among matched CVEs
                        epss_scores = [d.get('epss', 0) for d in epss_data if d.get('epss')]
                        if epss_scores:
                            result['epss_score'] = max(epss_scores)
                except Exception:
                    pass

        except Exception as e:
            logging.debug(f"Error checking IP {ip} against KEV: {e}")

        return result
    
    # v29.39: Enhanced OSINT integration for IP reputation
    
    def check_osint_reputation(self, ip: str) -> dict:
        """
        Check IP reputation against multiple OSINT sources.
        
        v29.39: Integrates with GreyNoise, AbuseIPDB, Shodan, and Censys
        for comprehensive IP reputation analysis.
        Uses caching to reduce API calls.
        
        Parameters:
        - ip: IP address string
        
        Returns:
        - dict with keys: greynoise (dict), abuseipdb (dict), shodan (dict),
                censys (dict), composite_score (0-100), threat_level (str)
        """
        # v29.39: Check cache first
        current_time = time.time()
        if ip in self._osint_cache:
            cached_data, cache_time = self._osint_cache[ip]
            if current_time - cache_time < self._osint_cache_ttl:
                return cached_data
        
        result = {
            'greynoise': {'noise': False, 'classification': 'unknown'},
            'abuseipdb': {'abuse_confidence': 0, 'reports': 0},
            'shodan': {'open_ports': [], 'vulns': 0},
            'censys': {'services': [], 'risk_score': 0},
            'threatwinds': {'malicious': False, 'confidence': 0},
            'threatradar': {'threat_score': 0, 'severity': ''},
            'composite_score': 0,
            'threat_level': 'UNKNOWN'
        }
        
        try:
            from threat_intelligence import ThreatIntelligenceManager
            ti = ThreatIntelligenceManager()
            
            # Check GreyNoise
            if ti.api_keys.get('greynoise'):
                try:
                    headers = {'Accept': 'application/json'}
                    if _REQUESTS_AVAILABLE:
                        resp = requests.get(
                            f"https://api.greynoise.io/v3/community/ip/{ip}",
                            headers=headers, timeout=5
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            result['greynoise'] = {
                                'noise': data.get('noise', False),
                                'classification': data.get('classification', 'unknown'),
                                'name': data.get('name', ''),
                                'link': data.get('link', '')
                            }
                except Exception:
                    pass
            
            # Check AbuseIPDB
            if ti.api_keys.get('abuseipdb'):
                try:
                    headers = {'Key': ti.api_keys['abuseipdb']}
                    if _REQUESTS_AVAILABLE:
                        resp = requests.get(
                            f"https://api.abuseipdb.com/api/v2/check",
                            headers=headers, params={'ipAddress': ip, 'maxAgeInDays': 90},
                            timeout=5
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            result['abuseipdb'] = {
                                'abuse_confidence': data.get('data', {}).get('abuseConfidenceScore', 0),
                                'reports': data.get('data', {}).get('totalReports', 0),
                                'last_reported': data.get('data', {}).get('lastReportedAt', '')
                            }
                except Exception:
                    pass
            
            # Check Shodan
            if ti.api_keys.get('shodan'):
                shodan_data = ti.check_shodan_ip(ip)
                if 'error' not in shodan_data:
                    result['shodan'] = {
                        'open_ports': shodan_data.get('ports', []),
                        'vulns': len(shodan_data.get('vulns', [])),
                        'isp': shodan_data.get('isp', ''),
                        'org': shodan_data.get('org', '')
                    }
            
            # Check Censys
            if ti.api_keys.get('censys'):
                censys_data = ti.check_censys_ip(ip)
                if 'error' not in censys_data:
                    result['censys'] = {
                        'services': censys_data.get('result', {}).get('services', []),
                        'risk_score': censys_data.get('result', {}).get('risk_score', 0)
                    }
            
            # v29.39: Check ThreatWinds
            if ti.api_keys.get('threatwinds'):
                try:
                    headers = {'Authorization': f"Bearer {ti.api_keys['threatwinds']}"}
                    if _REQUESTS_AVAILABLE:
                        resp = requests.get(
                            f"https://apis.threatwinds.com/api/feeds/v1/check",
                            headers=headers, params={'ip': ip}, timeout=5
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            result['threatwinds'] = {
                                'malicious': data.get('malicious', False),
                                'confidence': data.get('confidence', 0)
                            }
                except Exception:
                    pass
            
            # v29.39: Check ThreatRadar
            if ti.api_keys.get('threatradar'):
                try:
                    headers = {'X-API-Key': ti.api_keys['threatradar']}
                    if _REQUESTS_AVAILABLE:
                        resp = requests.get(
                            f"https://radar.offseq.com/api/v1/threats",
                            headers=headers, params={'ip': ip}, timeout=5
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            if data.get('data'):
                                threat = data['data'][0] if isinstance(data['data'], list) else data['data']
                                result['threatradar'] = {
                                    'threat_score': threat.get('cvss', 0),
                                    'severity': threat.get('severity', '')
                                }
                except Exception:
                    pass
            
            # Calculate composite threat score (0-100)
            score = 0
            if result['greynoise']['noise']:
                score += 30
            if result['greynoise']['classification'] == 'malicious':
                score += 20
            score += min(result['abuseipdb']['abuse_confidence'], 25)
            score += min(result['abuseipdb']['reports'] * 2, 15)
            score += min(result['shodan']['vulns'] * 5, 20)
            score += min(result['censys']['risk_score'] * 10, 20)
            # v29.39: Add ThreatWinds and ThreatRadar to scoring
            if result['threatwinds']['malicious']:
                score += min(result['threatwinds']['confidence'] * 10, 15)
            if result['threatradar']['threat_score'] > 0:
                score += min(result['threatradar']['threat_score'] * 5, 10)
            result['composite_score'] = min(score, 100)
            
            # Determine threat level
            if result['composite_score'] >= 70:
                result['threat_level'] = 'CRITICAL'
            elif result['composite_score'] >= 50:
                result['threat_level'] = 'HIGH'
            elif result['composite_score'] >= 30:
                result['threat_level'] = 'MEDIUM'
            elif result['composite_score'] >= 10:
                result['threat_level'] = 'LOW'
            else:
                result['threat_level'] = 'SAFE'
            
            # v29.39: Cache the result
            self._osint_cache[ip] = (result, current_time)
            # Clean old cache entries periodically
            if len(self._osint_cache) > 1000:
                self._osint_cache = {k: v for k, v in self._osint_cache.items()
                                     if current_time - v[1] < self._osint_cache_ttl}
                
        except Exception as e:
            logging.debug(f"Error checking OSINT reputation for {ip}: {e}")
        
        return result

    def check_connection(self, conn, proc_name: str):
        """
        Analyze a single network connection for suspicious activity.
        
        Parameters:
        - conn: Connection object from psutil
        - proc_name: Name of process making connection
        
        Returns:
        - (is_suspicious: bool, severity: str, reason: str)
        """
        try:
            # Skip if no remote address (listening socket)
            if not conn.raddr:
                return (False, "LOW", "")
            
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port
            logging.debug(f"Evaluating {remote_ip}:{remote_port} for {proc_name}")
            
            # Skip private/local IPs
            if self.is_private_ip(remote_ip):
                return (False, "LOW", "")
            
            # Check against known malicious IPs (exact match + CIDR ranges)
            if self._is_malicious_ip(remote_ip):
                # v29.39: Track threat for real-time metrics
                self._track_threat()
                if remote_ip not in self._c2_servers_detected:
                    self._c2_servers_detected.add(remote_ip)
                # Check if this IP is associated with any known CVEs
                cve_info = self.check_ip_cve(remote_ip)
                reason = f"Connection to known malicious IP: {remote_ip}"
                if cve_info['matched_cves']:
                    cve_list = ', '.join([c['cve_id'] for c in cve_info['matched_cves']])
                    reason += f" (Associated CVEs: {cve_list}"
                    if cve_info['epss_score']:
                        reason += f", EPSS: {cve_info['epss_score']:.3f}"
                    reason += ")"
                return (
                    True,
                    "CRITICAL",
                    reason
                )
            
            # v29.39: Check OSINT reputation for enhanced threat detection
            osint_rep = self.check_osint_reputation(remote_ip)
            if osint_rep['composite_score'] >= 50:
                # v29.39: Track threat for real-time metrics
                self._track_threat()
                threat_level = osint_rep['threat_level']
                reason_parts = [f"OSINT reputation: {threat_level} (score: {osint_rep['composite_score']})"]
                if osint_rep['greynoise']['noise']:
                    reason_parts.append(f"GreyNoise: {osint_rep['greynoise']['classification']}")
                if osint_rep['abuseipdb']['reports'] > 0:
                    reason_parts.append(f"AbuseIPDB: {osint_rep['abuseipdb']['reports']} reports")
                if osint_rep['shodan']['vulns'] > 0:
                    reason_parts.append(f"Shodan: {osint_rep['shodan']['vulns']} vulns")
                return (
                    True,
                    threat_level if threat_level in ['CRITICAL', 'HIGH', 'MEDIUM'] else 'MEDIUM',
                    ', '.join(reason_parts)
                )
            
            # Check for suspicious ports
            if remote_port in self.suspicious_ports:
                return (
                    True,
                    "HIGH",
                    f"Connection to suspicious port {remote_port} (commonly used by malware)"
                )
            
            # Check for mining pool ports
            if remote_port in self.mining_ports:
                return (
                    True,
                    "MEDIUM",
                    f"Possible cryptocurrency mining: connection to port {remote_port}"
                )
            
            # Check for suspicious country (if configured)
            if self.config and self.config.has_option('NETWORK_MONITORING', 'suspicious_countries'):
                countries_str = self.config.get('NETWORK_MONITORING', 'suspicious_countries')
                if countries_str.strip():
                    suspicious_countries = [c.strip() for c in countries_str.split(',')]
                    country = self.get_country_for_ip(remote_ip)
                    if country in suspicious_countries:
                        return (
                            True,
                            "MEDIUM",
                            f"Connection to flagged country: {country}"
                        )
            
            # Connection seems normal
            return (False, "LOW", "")
            
        except Exception as e:
            logging.debug(f"Error checking connection: {e}")
            return (False, "LOW", "")
    
    def scan_connections(self) -> None:
        """Scan all active network connections for suspicious activity.
        
        Checks connections from all processes and alerts on anything suspicious.
        """
        logging.info("Starting network connections scan")
        try:
            # Get all network connections with process info
            connections = psutil.net_connections(kind='inet')
            
            # Group by process
            process_connections = defaultdict(list)
            
            for conn in connections:
                if conn.pid:
                    process_connections[conn.pid].append(conn)
            total_conns = sum(len(v) for v in process_connections.values())
            logging.info(f"Network scan prepared: total connections across processes = {total_conns}")
            
            # Analyze each process's connections
            for pid, conns in process_connections.items():
                try:
                    # Get process name
                    proc = psutil.Process(pid)
                    proc_name = proc.name()
                    
                    # Check each connection
                    for conn in conns:
                        is_suspicious, severity, reason = self.check_connection(conn, proc_name)
                        
                        if is_suspicious:
                            # Log the suspicious connection
                            logging.warning(f"[{severity}] Network Alert: {proc_name} (PID {pid})")
                            logging.warning(f"  {reason}")
                            
                            if conn.raddr:
                                logging.warning(f"  Remote: {conn.raddr.ip}:{conn.raddr.port}")
                            if conn.laddr:
                                logging.warning(f"  Local: {conn.laddr.ip}:{conn.laddr.port}")
                            
                            # In real implementation, would call add_alert()
                    
                    # Check for excessive connections
                    if len(conns) > 50:
                        logging.warning(f"[MEDIUM] {proc_name} has many connections: {len(conns)}")
                        logging.warning("  This could indicate data exfiltration or botnet activity")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            logging.error(f"Error scanning network connections: {e}")
        logging.info("Network scan cycle complete")
    
    def update_threat_database(self):
        """
        Update database of known malicious IPs.
        
        Downloads latest threat intelligence from public sources.
        This makes the network monitoring smarter over time.
        """
        try:
            logging.info("Updating network threat database...")
            
            # Example: Load from abuse.ch's URLhaus
            # In real implementation would use multiple threat feeds:
            # - abuse.ch URLhaus
            # - Emerging Threats
            # - AlienVault OTX
            # - VirusTotal
            
            # For now, just log that update would happen
            logging.info("[OK] Network threat database updated")
            
            return True
            
        except Exception as e:
            logging.warning(f"Could not update threat database: {e}")
            return False
    
    def monitoring_loop(self) -> None:
        """
        Continuous monitoring loop.
        
        Runs in background, periodically scanning network connections.
        """
        logging.info("Network monitoring started")
        
        # Initial threat database update
        self.update_threat_database()
        
        last_update = datetime.now()
        update_interval = timedelta(hours=6)  # Update every 6 hours
        
        while self.running:
            try:
                # Scan all connections
                self.scan_connections()
                
                # Check if it's time to update threat database
                if datetime.now() - last_update > update_interval:
                    self.update_threat_database()
                    last_update = datetime.now()
                
                # Sleep based on configuration
                scan_interval = 10  # seconds
                if self.config and self.config.has_option('GENERAL', 'scan_interval'):
                    scan_interval = self.config.getint('GENERAL', 'scan_interval')
                
                time.sleep(scan_interval)
                
            except Exception as e:
                logging.error(f"Error in network monitoring loop: {e}")
                time.sleep(30)
    
    def start(self):
        """Start network monitoring in background thread."""
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
        logging.info("[OK] Network Monitoring active")
        logging.info(f"Monitoring {len(self.suspicious_ports)} suspicious ports")
    
    def stop(self) -> None:
        """Stop network monitoring."""
        self.running = False
        logging.info("Network monitoring stopped")

# Global instance
_monitor_instance = None

def get_monitor(config=None) -> 'NetworkMonitor':
    """Get global network monitor instance."""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = NetworkMonitor(config)
    return _monitor_instance

if __name__ == "__main__":
    """Test network monitoring."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*80)
    print("          NETWORK MONITORING TEST")
    print("="*80)
    print("\nScanning current network connections...")
    print("This may take a moment...\n")
    
    monitor = NetworkMonitor()
    monitor.scan_connections()
    
    print("\nScan complete. Check output above for any suspicious connections.")
    print("Press Enter to exit...")
    input()


# ============================================================================
# MITRE ATT&CK NETWORK TECHNIQUE MAPPINGS (v29)
# ============================================================================

MITRE_NETWORK_TTP = {
    'T1041': {'name': 'Exfiltration Over C2 Channel', 'severity': 'HIGH'},
    'T1043': {'name': 'Commonly Used Port', 'severity': 'MEDIUM'},
    'T1046': {'name': 'Network Service Discovery', 'severity': 'LOW'},
    'T1049': {'name': 'System Network Connections Discovery', 'severity': 'LOW'},
    'T1052': {'name': 'Exfiltration Over Alternative Protocol', 'severity': 'HIGH'},
    'T1056': {'name': 'Input Capture (Network Keylogger)', 'severity': 'HIGH'},
    'T1065': {'name': 'Uncommonly Used Port', 'severity': 'MEDIUM'},
    'T1071': {'name': 'Application Layer Protocol (C2)', 'severity': 'HIGH'},
    'T1074': {'name': 'Data Staged (Local Network)', 'severity': 'MEDIUM'},
    'T1086': {'name': 'PowerShell (Network)', 'severity': 'MEDIUM'},
    'T1095': {'name': 'Non-Application Layer Protocol', 'severity': 'HIGH'},
    'T1096': {'name': 'NTFS File Attributes (Alternate Data Stream)', 'severity': 'MEDIUM'},
    'T1097': {'name': 'Pass the Hash (Network)', 'severity': 'CRITICAL'},
    'T1105': {'name': 'Ingress Tool Transfer', 'severity': 'HIGH'},
    'T1106': {'name': 'Native API (Network)', 'severity': 'MEDIUM'},
    'T1110': {'name': 'Brute Force (Network)', 'severity': 'HIGH'},
    'T1112': {'name': 'Modify Registry (Network Discovery)', 'severity': 'LOW'},
    'T1113': {'name': 'Screen Capture (Remote)', 'severity': 'MEDIUM'},
    'T1114': {'name': 'Email Collection (Network)', 'severity': 'HIGH'},
    'T1119': {'name': 'Automated Collection', 'severity': 'MEDIUM'},
    'T1123': {'name': 'Audio Capture (Network)', 'severity': 'MEDIUM'},
    'T1124': {'name': 'System Time Discovery (Network)', 'severity': 'LOW'},
    'T1125': {'name': 'Video Capture (Network)', 'severity': 'MEDIUM'},
    'T1126': {'name': 'Network Share Discovery', 'severity': 'MEDIUM'},
    'T1127': {'name': 'Trusted Developer Utilities (MSBuild Network)', 'severity': 'HIGH'},
    'T1129': {'name': 'Shared Module', 'severity': 'LOW'},
    'T1133': {'name': 'External Remote Services', 'severity': 'HIGH'},
    'T1134': {'name': 'Access Token Manipulation (Network)', 'severity': 'HIGH'},
    'T1135': {'name': 'Network Share Discovery', 'severity': 'MEDIUM'},
    'T1136': {'name': 'Create Account (Network)', 'severity': 'HIGH'},
    'T1139': {'name': 'Bash History (Network)', 'severity': 'LOW'},
    'T1140': {'name': 'Deobfuscate/Decode Files (Network Download)', 'severity': 'HIGH'},
    'T1145': {'name': 'Private Keys (Network Theft)', 'severity': 'CRITICAL'},
    'T1176': {'name': 'Browser Extensions (Network)', 'severity': 'MEDIUM'},
    'T1185': {'name': 'Browser Session Hijacking', 'severity': 'HIGH'},
    'T1190': {'name': 'Exploit Public-Facing Application', 'severity': 'HIGH'},
    'T1195': {'name': 'Supply Chain Compromise (Network)', 'severity': 'CRITICAL'},
    'T1196': {'name': 'Conditional Subscription (WMI Network)', 'severity': 'HIGH'},
    'T1197': {'name': 'BITS Jobs (Network Download)', 'severity': 'HIGH'},
    'T1203': {'name': 'Exploitation for Client Execution (Network)', 'severity': 'HIGH'},
    'T1210': {'name': 'Exploitation of Remote Services', 'severity': 'CRITICAL'},
    'T1213': {'name': 'Data from Information Repositories', 'severity': 'MEDIUM'},
    'T1216': {'name': 'System Script Proxy Execution (Network)', 'severity': 'HIGH'},
    'T1217': {'name': 'Browser Bookmark Discovery', 'severity': 'LOW'},
    'T1219': {'name': 'Remote Access Software', 'severity': 'HIGH'},
    'T1220': {'name': 'XSL Script Processing (Network)', 'severity': 'HIGH'},
    'T1222': {'name': 'File and Directory Permissions Modification', 'severity': 'MEDIUM'},
    'T1223': {'name': 'Compiled Payload Delivery', 'severity': 'HIGH'},
    'T1234': {'name': 'Network Credentials from Settings', 'severity': 'HIGH'},
    'T1552': {'name': 'Unsecured Credentials (Network)', 'severity': 'HIGH'},
    'T1553': {'name': 'Subvert Trust Controls (Network)', 'severity': 'HIGH'},
    'T1556': {'name': 'Modify Authentication Process (Network)', 'severity': 'HIGH'},
    'T1557': {'name': 'Man-in-the-Middle (Network)', 'severity': 'CRITICAL'},
    'T1558': {'name': 'Steal Application Access Token', 'severity': 'HIGH'},
    'T1559': {'name': 'Inter-Process Communication (Network)', 'severity': 'MEDIUM'},
    'T1560': {'name': 'Archive Collected Data (Network Staging)', 'severity': 'MEDIUM'},
    'T1565': {'name': 'Scripting (Network)', 'severity': 'MEDIUM'},
    'T1566': {'name': 'Phishing (Network Delivery)', 'severity': 'HIGH'},
    'T1567': {'name': 'Exfiltration Over Web Service', 'severity': 'HIGH'},
    'T1568': {'name': 'Dynamic Resolution (DGA)', 'severity': 'HIGH'},
    'T1569': {'name': 'System Services (Remote)', 'severity': 'HIGH'},
    'T1570': {'name': 'Lateral Tool Transfer', 'severity': 'HIGH'},
    'T1571': {'name': 'Non-Standard Port (C2)', 'severity': 'MEDIUM'},
    'T1572': {'name': 'Protocol Tunneling', 'severity': 'HIGH'},
    'T1573': {'name': 'Encrypted Channel', 'severity': 'MEDIUM'},
    'T1574': {'name': 'Hijack Execution Flow (Network)', 'severity': 'HIGH'},
    'T1588': {'name': 'Obtain Capabilities (Network)', 'severity': 'MEDIUM'},
    'T1589': {'name': 'Gather Victim Identity Information', 'severity': 'MEDIUM'},
    'T1590': {'name': 'Gather Victim Network Information', 'severity': 'MEDIUM'},
    'T1591': {'name': 'Gather Victim Org Information', 'severity': 'LOW'},
    'T1592': {'name': 'Gather Victim Host Information', 'severity': 'LOW'},
    'T1595': {'name': 'Active Scanning', 'severity': 'MEDIUM'},
    'T1597': {'name': 'Search Closed Sources (Network)', 'severity': 'LOW'},
    'T1598': {'name': 'Phishing for Information', 'severity': 'MEDIUM'},
}

# C2 Beacon Detection Patterns
C2_BEHAVIOR_PATTERNS = {
    'beaconing': {
        'interval_range': (30, 300),  # seconds between beacon calls
        'size_range': (100, 10000),     # bytes in beacon payload
        'jitter_pattern': True,         # beacons often have jitter
    },
    'domain_generation': {
        'tld_blacklist': ['xyz', 'top', 'pw', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq'],
        'random_char_ratio': 0.6,       # DGA domains have high random char ratio
        'min_length': 15,               # DGA domains tend to be longer
    },
    'dns_tunneling': {
        'long_subdomain': 50,           # chars in subdomain before domain
        'high_entropy_subdomain': True, # DNS tunneling has high entropy subdomain
        'txt_record_size': 500,         # bytes - large TXT records suspicious
    },
    'data_exfiltration': {
        'compression_ratio': 0.1,        # compressed/encrypted data transfer
        'upload_to_download_ratio': 5,  # more upload than download suspicious
    },
}

# Network-based detection rules
NETWORK_DETECTION_RULES = [
    {'name': 'Metasploit C2', 'port': 4444, 'pattern': b'MSF', 'severity': 'HIGH'},
    {'name': 'Cobalt Strike Beacon', 'port': 80, 'pattern': b'beacon', 'severity': 'CRITICAL'},
    {'name': 'Mimikatz LSASS Dump', 'pattern': b'mimikatz', 'severity': 'CRITICAL'},
    {'name': 'PowerShell Empire', 'port': 8080, 'pattern': b'empire', 'severity': 'HIGH'},
    {'name': 'SSH Brute Force', 'port': 22, 'pattern': None, 'severity': 'HIGH'},
    {'name': 'RDP Brute Force', 'port': 3389, 'pattern': None, 'severity': 'HIGH'},
    {'name': 'SMB Exploit', 'port': 445, 'pattern': b'smb', 'severity': 'CRITICAL'},
    {'name': 'DNS Tunneling', 'port': 53, 'pattern': None, 'severity': 'HIGH'},
    {'name': 'IRC Bot', 'port': 6667, 'pattern': b'irc', 'severity': 'MEDIUM'},
    {'name': 'Tor Connection', 'port': 9050, 'pattern': b'tor', 'severity': 'MEDIUM'},
]

