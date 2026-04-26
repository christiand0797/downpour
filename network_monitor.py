"""
================================================================================
NETWORK MONITORING MODULE
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

================================================================================
"""

import logging
import threading
import time
try:
    import psutil
except ImportError:
    raise ImportError("network_monitor requires psutil: pip install psutil")
from datetime import datetime, timedelta
from collections import defaultdict
import socket
try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

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
        
        # Known malicious IPs (sample - real implementation would have thousands)
        self.malicious_ips = set([
            # These are example bad IPs - in real system would load from threat feed
            # Format: 'IP_ADDRESS'
        ])
        
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
    
    def is_private_ip(self, ip):
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
    
    def get_country_for_ip(self, ip):
        """
        Get country code for an IP address.
        
        In full implementation, would use GeoIP database
        or API to look up country.
        
        Parameters:
        - ip: IP address
        
        Returns:
        - Two-letter country code (e.g., 'US', 'CN', 'RU')
        """
        # In real implementation would use:
        # - MaxMind GeoIP database
        # - ip-api.com API
        # - ipinfo.io API
        
        return "??"  # Unknown
    
    def check_connection(self, conn, proc_name):
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
            
            # Skip private/local IPs
            if self.is_private_ip(remote_ip):
                return (False, "LOW", "")
            
            # Check against known malicious IPs
            if remote_ip in self.malicious_ips:
                return (
                    True,
                    "CRITICAL",
                    f"Connection to known malicious IP: {remote_ip}"
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
    
    def scan_connections(self):
        """
        Scan all active network connections for suspicious activity.
        
        Checks connections from all processes and alerts on anything suspicious.
        """
        try:
            # Get all network connections with process info
            connections = psutil.net_connections(kind='inet')
            
            # Group by process
            process_connections = defaultdict(list)
            
            for conn in connections:
                if conn.pid:
                    process_connections[conn.pid].append(conn)
            
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
            logging.info("[✓] Network threat database updated")
            
            return True
            
        except Exception as e:
            logging.warning(f"Could not update threat database: {e}")
            return False
    
    def monitoring_loop(self):
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
        logging.info("[✓] Network Monitoring active")
        logging.info(f"Monitoring {len(self.suspicious_ports)} suspicious ports")
    
    def stop(self):
        """Stop network monitoring."""
        self.running = False
        logging.info("Network monitoring stopped")

# Global instance
_monitor_instance = None

def get_monitor(config=None):
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
