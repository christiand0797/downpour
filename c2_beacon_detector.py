#!/usr/bin/env python3
"""
C2 Beaconing Detector
Statistical detection of command-and-control beaconing using Coefficient of Variation
of inter-arrival times. Based on enterprise NDR platform approaches and academic research.
Detects periodic connections with jitter, DGA-based C2, and reverse shells.
"""
from __future__ import annotations
import os
import time
import math
import functools
import threading
import logging
import statistics
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime
import ipaddress
import socket

_log = logging.getLogger(__name__)

# Configuration
MIN_CONNECTIONS_FOR_DETECTION = 5  # Minimum connections to analyze
MAX_HISTORY_PER_DEST = 200  # Max connections tracked per destination
CV_THRESHOLD_LOW = 0.05  # Very regular (likely beacon)
CV_THRESHOLD_MEDIUM = 0.25  # Regular with jitter
CV_THRESHOLD_HIGH = 0.5  # Irregular (likely not beacon)
MIN_INTERVAL_SECONDS = 1.0  # Minimum beacon interval
MAX_INTERVAL_SECONDS = 86400  # Maximum beacon interval (1 day)
JITTER_TOLERANCE = 0.5  # Acceptable jitter ratio
DETECTION_WINDOW = 3600  # 1 hour analysis window
DGA_ENTROPY_THRESHOLD = 3.5  # Shannon entropy threshold for DGA domains
DGA_LENGTH_THRESHOLD = 15  # Minimum domain length for DGA suspicion

@dataclass
class ConnectionEvent:
    """Single network connection event."""
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # tcp/udp
    pid: int = 0
    process_name: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0
    domain: str = ""  # Resolved domain if applicable
    
    def __hash__(self):
        return hash((self.timestamp, self.src_ip, self.dst_ip, self.dst_port))

@dataclass
class DestinationProfile:
    """Profile of connections to a specific destination."""
    dst_ip: str
    dst_port: int
    protocol: str
    connections: deque = field(default_factory=lambda: deque(maxlen=MAX_HISTORY_PER_DEST))
    intervals: deque = field(default_factory=lambda: deque(maxlen=MAX_HISTORY_PER_DEST))
    domains: Set[str] = field(default_factory=set)
    
    # Statistical measures
    cv: float = 1.0  # Coefficient of variation
    mean_interval: float = 0.0
    std_interval: float = 0.0
    median_interval: float = 0.0
    periodicity_score: float = 0.0
    
    # Classification
    is_beacon: bool = False
    beacon_confidence: float = 0.0
    beacon_type: str = ""  # "regular", "jittered", "dga", "reverse_shell"
    estimated_interval: float = 0.0
    jitter_ratio: float = 0.0
    
    # Metadata
    first_seen: float = 0.0
    last_seen: float = 0.0
    total_connections: int = 0
    total_bytes: int = 0
    
    # Process info
    pids: Set[int] = field(default_factory=set)
    process_names: Set[str] = field(default_factory=set)

@dataclass
class DGAProfile:
    """Profile for DGA (Domain Generation Algorithm) detection."""
    domain: str
    entropy: float
    length: int
    subdomain_count: int
    tld: str
    timestamp: float
    src_ip: str
    pid: int = 0
    process_name: str = ""
    is_suspicious: bool = False
    confidence: float = 0.0

@dataclass
class BeaconAlert:
    """Alert for detected beaconing."""
    timestamp: float
    alert_type: str  # "beacon", "dga", "reverse_shell", "periodic"
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    dst_ip: str
    dst_port: int
    protocol: str
    message: str
    mitre_technique: str
    details: Dict = field(default_factory=dict)

class CoefficientOfVariationCalculator:
    """Statistical calculator for Coefficient of Variation and periodicity detection."""
    
    @staticmethod
    def calculate_cv(intervals: List[float]) -> Tuple[float, float, float]:
        """
        Calculate Coefficient of Variation (CV) = std/mean.
        Returns (cv, mean, std).
        """
        if len(intervals) < 2:
            return 1.0, 0.0, 0.0
        
        mean = statistics.mean(intervals)
        if mean == 0:
            return 1.0, 0.0, 0.0
        
        try:
            std = statistics.stdev(intervals)
            cv = std / mean
        except statistics.StatisticsError:
            cv = 1.0
            std = 0.0
        
        return cv, mean, std
    
    @staticmethod
    def detect_periodicity(intervals: List[float]) -> Tuple[float, float]:
        """
        Detect periodicity using autocorrelation.
        Returns (periodicity_score, estimated_period).
        """
        if len(intervals) < 5:
            return 0.0, 0.0
        
        # Use autocorrelation at lag 1 as basic periodicity measure
        try:
            mean = statistics.mean(intervals)
            if mean == 0:
                return 0.0, 0.0
            
            # Normalize
            normalized = [(x - mean) / mean for x in intervals]
            
            # Autocorrelation at lag 1
            if len(normalized) >= 2:
                corr = sum(normalized[i] * normalized[i-1] for i in range(1, len(normalized)))
                corr /= sum(x * x for x in normalized) if sum(x * x for x in normalized) > 0 else 1
                periodicity = max(0, corr)  # Only positive correlation
            else:
                periodicity = 0.0
            
            estimated_period = mean
            return periodicity, estimated_period
        except Exception:
            return 0.0, 0.0
    
    @staticmethod
    def analyze_jitter(intervals: List[float], expected_interval: float) -> float:
        """Analyze jitter ratio around expected interval."""
        if not intervals or expected_interval <= 0:
            return 1.0
        
        deviations = [abs(i - expected_interval) / expected_interval for i in intervals]
        return statistics.mean(deviations) if deviations else 1.0

class ShannonEntropyCalculator:
    """Shannon entropy calculator for DGA detection."""
    
    @staticmethod
    @functools.lru_cache(maxsize=8192)
    def calculate(domain: str) -> float:
        """Calculate Shannon entropy of domain string (excluding TLD)."""
        if not domain:
            return 0.0
        
        # Remove TLD for entropy calculation
        parts = domain.split('.')
        if len(parts) > 1:
            # Analyze the subdomain part (most indicative of DGA)
            label = '.'.join(parts[:-1])
        else:
            label = domain
        
        if not label:
            return 0.0
        
        freq = defaultdict(int)
        for c in label.lower():
            freq[c] += 1
        
        entropy = 0.0
        n = len(label)
        for count in freq.values():
            p = count / n
            entropy -= p * math.log2(p)
        
        return entropy
    
    @staticmethod
    def analyze_domain(domain: str) -> Dict[str, Any]:
        """Comprehensive domain analysis for DGA detection."""
        parts = domain.split('.')
        tld = parts[-1] if len(parts) > 1 else ""
        subdomain = '.'.join(parts[:-1]) if len(parts) > 1 else domain
        
        entropy = ShannonEntropyCalculator.calculate(domain)
        
        # Check for dictionary words (low entropy indicators)
        common_words = ['www', 'mail', 'ftp', 'api', 'cdn', 'static', 'assets', 
                       'blog', 'shop', 'app', 'dev', 'test', 'stage', 'prod',
                       'admin', 'login', 'auth', 'secure', 'payment', 'billing']
        
        has_dict_word = any(word in subdomain.lower() for word in common_words)
        
        # Check for suspicious patterns
        digit_ratio = sum(c.isdigit() for c in subdomain) / max(1, len(subdomain))
        hyphen_count = subdomain.count('-')
        length = len(subdomain)
        
        # Subdomain count
        subdomain_count = len(parts) - 1 if len(parts) > 1 else 1
        
        return {
            'domain': domain,
            'entropy': entropy,
            'length': length,
            'subdomain': subdomain,
            'tld': tld,
            'subdomain_count': subdomain_count,
            'digit_ratio': digit_ratio,
            'hyphen_count': hyphen_count,
            'has_dict_word': has_dict_word,
            'is_suspicious': entropy > DGA_ENTROPY_THRESHOLD and length > DGA_LENGTH_THRESHOLD and not has_dict_word,
        }

class C2BeaconDetector:
    """
    Main C2 Beaconing Detector using statistical analysis of inter-arrival times.
    Detects:
    - Regular beacons (low CV)
    - Jittered beacons (medium CV with periodicity)
    - DGA-based C2 (high entropy domains)
    - Reverse shells (persistent low-bandwidth connections)
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Destination profiles
        self.dest_profiles: Dict[str, DestinationProfile] = {}  # key: "ip:port:proto"
        
        # DGA profiles
        self.dga_profiles: deque = deque(maxlen=10000)
        
        # Alerts
        self.alerts: deque = deque(maxlen=1000)
        self.alert_callbacks: List[callable] = []
        
        # Statistics
        self.stats = {
            'connections_analyzed': 0,
            'destinations_tracked': 0,
            'beacons_detected': 0,
            'dga_detected': 0,
            'reverse_shells_detected': 0,
            'alerts_generated': 0,
        }
        
        # Calculators
        self.cv_calc = CoefficientOfVariationCalculator()
        self.entropy_calc = ShannonEntropyCalculator()
        
        # Network baseline
        self.baseline_intervals: Dict[str, List[float]] = defaultdict(list)
        self.known_good_destinations: Set[str] = set()  # Whitelisted destinations
        
        # Local IP ranges (for filtering internal traffic)
        self.local_networks = [
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12'),
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('127.0.0.0/8'),
            ipaddress.IPv4Network('169.254.0.0/16'),
        ]
    
    def start(self):
        """Start the detector."""
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._analysis_loop, daemon=True, name="C2-Beacon-Detector")
        self._thread.start()
        _log.info("C2 Beaconing Detector started")
    
    def stop(self):
        """Stop the detector."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        _log.info("C2 Beaconing Detector stopped")
    
    def register_alert_callback(self, callback: callable):
        """Register callback for alerts."""
        self.alert_callbacks.append(callback)
    
    def add_connection(self, event: ConnectionEvent):
        """Add a connection event for analysis."""
        # Skip local/internal traffic
        if self._is_local_ip(event.dst_ip):
            return
        
        # Skip whitelisted destinations
        dest_key = f"{event.dst_ip}:{event.dst_port}:{event.protocol}"
        if dest_key in self.known_good_destinations:
            return
        
        with self._lock:
            self.stats['connections_analyzed'] += 1
            
            # Get or create destination profile
            profile = self.dest_profiles.get(dest_key)
            if not profile:
                profile = DestinationProfile(
                    dst_ip=event.dst_ip,
                    dst_port=event.dst_port,
                    protocol=event.protocol,
                )
                profile.first_seen = event.timestamp
                self.dest_profiles[dest_key] = profile
                self.stats['destinations_tracked'] += 1
            
            # Add connection
            profile.connections.append(event)
            profile.last_seen = event.timestamp
            profile.total_connections += 1
            profile.total_bytes += event.bytes_sent + event.bytes_recv
            profile.pids.add(event.pid)
            profile.process_names.add(event.process_name)
            
            if event.domain:
                profile.domains.add(event.domain)
            
            # Calculate interval
            if len(profile.connections) >= 2:
                prev = profile.connections[-2]
                interval = event.timestamp - prev.timestamp
                if MIN_INTERVAL_SECONDS <= interval <= MAX_INTERVAL_SECONDS:
                    profile.intervals.append(interval)
    
    def add_dns_query(self, domain: str, src_ip: str, pid: int = 0, process_name: str = ""):
        """Add DNS query for DGA analysis."""
        analysis = self.entropy_calc.analyze_domain(domain)
        
        if analysis['is_suspicious']:
            with self._lock:
                profile = DGAProfile(
                    domain=domain,
                    entropy=analysis['entropy'],
                    length=analysis['length'],
                    subdomain_count=analysis['subdomain_count'],
                    tld=analysis['tld'],
                    timestamp=time.time(),
                    src_ip=src_ip,
                    pid=pid,
                    process_name=process_name,
                    is_suspicious=True,
                    confidence=min(1.0, (analysis['entropy'] - DGA_ENTROPY_THRESHOLD) / 2.0),
                )
                self.dga_profiles.append(profile)
                self.stats['dga_detected'] += 1
                
                # Generate alert for high-confidence DGA
                if profile.confidence > 0.7:
                    self._generate_alert(BeaconAlert(
                        timestamp=time.time(),
                        alert_type="dga",
                        severity="HIGH",
                        dst_ip=src_ip,
                        dst_port=53,
                        protocol="udp",
                        message=f"DGA domain detected: {domain} (entropy={analysis['entropy']:.2f})",
                        mitre_technique="T1568.002",
                        details={
                            'domain': domain,
                            'entropy': analysis['entropy'],
                            'length': analysis['length'],
                            'subdomain_count': analysis['subdomain_count'],
                            'pid': pid,
                            'process': process_name,
                        }
                    ))
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is in local network ranges."""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return any(ip_obj in net for net in self.local_networks)
        except Exception:
            return False
    
    def _analysis_loop(self):
        """Main analysis loop."""
        while self._running and not self._stop_event.is_set():
            start = time.time()
            try:
                self._analyze_destinations()
            except Exception as e:
                _log.error(f"C2 analysis error: {e}")
            
            elapsed = time.time() - start
            sleep_time = max(0, 30 - elapsed)  # Analyze every 30 seconds
            if sleep_time > 0:
                self._stop_event.wait(sleep_time)
    
    def _analyze_destinations(self):
        """Analyze all destination profiles for beaconing."""
        now = time.time()
        cutoff = now - DETECTION_WINDOW
        
        with self._lock:
            for dest_key, profile in list(self.dest_profiles.items()):
                # Remove old connections
                while profile.connections and profile.connections[0].timestamp < cutoff:
                    profile.connections.popleft()
                
                # Skip if not enough data
                if len(profile.intervals) < MIN_CONNECTIONS_FOR_DETECTION:
                    continue
                
                # Calculate statistics
                intervals = list(profile.intervals)
                cv, mean_interval, std_interval = self.cv_calc.calculate_cv(intervals)
                periodicity, estimated_period = self.cv_calc.detect_periodicity(intervals)
                
                profile.cv = cv
                profile.mean_interval = mean_interval
                profile.std_interval = std_interval
                profile.median_interval = statistics.median(intervals) if intervals else 0
                profile.periodicity_score = periodicity
                
                # Classify beacon type
                was_beacon = profile.is_beacon
                profile.is_beacon = False
                profile.beacon_confidence = 0.0
                profile.beacon_type = ""
                profile.estimated_interval = mean_interval
                
                if cv < CV_THRESHOLD_LOW and mean_interval >= MIN_INTERVAL_SECONDS:
                    # Very regular beacon
                    profile.is_beacon = True
                    profile.beacon_type = "regular"
                    profile.beacon_confidence = 1.0 - cv
                    profile.jitter_ratio = 0.0
                elif cv < CV_THRESHOLD_MEDIUM and periodicity > 0.5:
                    # Jittered beacon with strong periodicity
                    profile.is_beacon = True
                    profile.beacon_type = "jittered"
                    profile.beacon_confidence = periodicity * (1.0 - cv)
                    profile.jitter_ratio = self.cv_calc.analyze_jitter(intervals, mean_interval)
                elif cv < CV_THRESHOLD_HIGH and periodicity > 0.3:
                    # Possible beacon with high jitter
                    profile.is_beacon = True
                    profile.beacon_type = "jittered"
                    profile.beacon_confidence = periodicity * (1.0 - cv) * 0.7
                    profile.jitter_ratio = self.cv_calc.analyze_jitter(intervals, mean_interval)
                
                profile.estimated_interval = mean_interval
                
                # Detect reverse shell (persistent connection with small data transfers)
                if self._detect_reverse_shell(profile):
                    if profile.beacon_type != "reverse_shell":
                        profile.beacon_type = "reverse_shell"
                        profile.beacon_confidence = max(profile.beacon_confidence, 0.8)
                
                # Generate alerts for new beacons
                if profile.is_beacon and not was_beacon and profile.beacon_confidence > 0.6:
                    self._generate_beacon_alert(profile)
                    self.stats['beacons_detected'] += 1
                
                # Check for DGA in domains
                for domain in profile.domains:
                    if domain:
                        analysis = self.entropy_calc.analyze_domain(domain)
                        if analysis['is_suspicious']:
                            # Update profile with DGA info
                            pass
    
    def _detect_reverse_shell(self, profile: DestinationProfile) -> bool:
        """Detect reverse shell patterns."""
        # Reverse shells typically have:
        # - Long-lived connections
        # - Small, regular data transfers
        # - Interactive-like timing (human keystroke intervals)
        
        if len(profile.connections) < 10:
            return False
        
        # Check for small packet sizes (interactive)
        recent_conns = list(profile.connections)[-10:]
        avg_packet_size = statistics.mean(c.bytes_sent + c.bytes_recv for c in recent_conns)
        
        # Check for regular small intervals (human typing ~100-500ms)
        if len(profile.intervals) >= 5:
            recent_intervals = list(profile.intervals)[-10:]
            small_intervals = sum(1 for i in recent_intervals if 0.05 <= i <= 2.0)
            if small_intervals / len(recent_intervals) > 0.6 and avg_packet_size < 1000:
                return True
        
        # Check for very long connection with low data rate
        if profile.last_seen - profile.first_seen > 300:  # 5+ minutes
            data_rate = profile.total_bytes / (profile.last_seen - profile.first_seen)
            if data_rate < 1000:  # < 1 KB/s
                return True
        
        return False
    
    def _generate_beacon_alert(self, profile: DestinationProfile):
        """Generate alert for detected beacon."""
        severity = "CRITICAL" if profile.beacon_confidence > 0.8 else "HIGH"
        
        # Check if known bad port
        suspicious_ports = {443, 80, 8080, 8443, 53, 4444, 5555, 6666, 7777, 8888, 9999}
        port_risk = " (suspicious port)" if profile.dst_port in suspicious_ports else ""
        
        alert = BeaconAlert(
            timestamp=time.time(),
            alert_type="beacon",
            severity=severity,
            dst_ip=profile.dst_ip,
            dst_port=profile.dst_port,
            protocol=profile.protocol,
            message=f"C2 Beacon detected: {profile.dst_ip}:{profile.dst_port} ({profile.beacon_type}, CV={profile.cv:.3f}, interval~{profile.estimated_interval:.1f}s){port_risk}",
            mitre_technique="T1071.001" if profile.protocol == "tcp" else "T1071.004",
            details={
                'cv': profile.cv,
                'mean_interval': profile.mean_interval,
                'periodicity': profile.periodicity_score,
                'jitter_ratio': profile.jitter_ratio,
                'beacon_type': profile.beacon_type,
                'confidence': profile.beacon_confidence,
                'total_connections': profile.total_connections,
                'total_bytes': profile.total_bytes,
                'pids': list(profile.pids),
                'processes': list(profile.process_names),
                'domains': list(profile.domains),
            }
        )
        self.alerts.append(alert)
        self.stats['alerts_generated'] += 1
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                _log.error(f"Alert callback error: {e}")
    
    def get_status(self) -> Dict:
        """Get detector status."""
        with self._lock:
            beacons = [p for p in self.dest_profiles.values() if p.is_beacon]
            return {
                'running': self._running,
                'destinations_tracked': len(self.dest_profiles),
                'active_beacons': len(beacons),
                'recent_alerts': list(self.alerts)[-10:],
                'stats': self.stats.copy(),
                'beacon_details': [
                    {
                        'dst': f"{p.dst_ip}:{p.dst_port}",
                        'type': p.beacon_type,
                        'cv': p.cv,
                        'interval': p.estimated_interval,
                        'confidence': p.beacon_confidence,
                        'connections': p.total_connections,
                    }
                    for p in beacons
                ],
            }
    
    def get_destination_profile(self, dst_ip: str, dst_port: int, protocol: str) -> Optional[Dict]:
        """Get profile for specific destination."""
        key = f"{dst_ip}:{dst_port}:{protocol}"
        with self._lock:
            profile = self.dest_profiles.get(key)
            if not profile:
                return None
            return {
                'dst_ip': profile.dst_ip,
                'dst_port': profile.dst_port,
                'protocol': profile.protocol,
                'is_beacon': profile.is_beacon,
                'beacon_type': profile.beacon_type,
                'cv': profile.cv,
                'mean_interval': profile.mean_interval,
                'periodicity': profile.periodicity_score,
                'confidence': profile.beacon_confidence,
                'total_connections': profile.total_connections,
                'first_seen': profile.first_seen,
                'last_seen': profile.last_seen,
                'pids': list(profile.pids),
                'processes': list(profile.process_names),
                'domains': list(profile.domains),
            }
    
    def whitelist_destination(self, dst_ip: str, dst_port: int, protocol: str):
        """Add destination to whitelist."""
        key = f"{dst_ip}:{dst_port}:{protocol}"
        self.known_good_destinations.add(key)

# Singleton instance
_c2_detector: Optional[C2BeaconDetector] = None
_c2_lock = threading.Lock()

def get_c2_detector() -> C2BeaconDetector:
    global _c2_detector
    with _c2_lock:
        if _c2_detector is None:
            _c2_detector = C2BeaconDetector()
        return _c2_detector

def start_c2_detector() -> C2BeaconDetector:
    detector = get_c2_detector()
    detector.start()
    return detector

def stop_c2_detector():
    global _c2_detector
    if _c2_detector:
        _c2_detector.stop()
        _c2_detector = None

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    detector = start_c2_detector()
    try:
        while True:
            time.sleep(10)
            status = detector.get_status()
            print(f"Destinations: {status['destinations_tracked']}, Beacons: {status['active_beacons']}")
    except KeyboardInterrupt:
        stop_c2_detector()