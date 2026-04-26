"""
Threat Detection Engine v1.0
==============================
Real-time threat detection using comprehensive signature database.
Provides detection, analysis, and protection recommendations.

v29: Added KEV/CEV/EPSS integration for CVE-based threat enhancement.
"""

import os
import re
import json
import time
import hashlib
import threading
import logging
from datetime import datetime
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict

# v29: KEV constants
CISA_KEV_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog.csv"

# Import our modules — ultimate_threat_intel is optional (may not be present)
try:
    from ultimate_threat_intel import (
        ThreatIndicator, ThreatCategory, ThreatSeverity,
        ThreatDatabase, get_database
    )
except ImportError:
    # Provide lightweight stubs so the module can be imported without the file
    class ThreatCategory:
        MALWARE = 'malware'; NETWORK = 'network'; NETWORK_C2 = 'network_c2'
        PHISHING = 'phishing'; MALWARE_RANSOMWARE = 'malware_ransomware'
        MALWARE_MINER = 'malware_miner'; MALWARE_STEALER = 'malware_stealer'

    class ThreatSeverity:
        LOW = 10; MEDIUM = 40; HIGH = 70; CRITICAL = 90

    class ThreatIndicator:
        pass

    class ThreatDatabase:
        def check_indicator(self, value, itype):
            return None

    def get_database():
        return ThreatDatabase()

from mega_threat_signatures import (
    MALWARE_FAMILIES, SUSPICIOUS_PORTS, MINER_PORTS,
    SUSPICIOUS_PROCESS_PATTERNS, SUSPICIOUS_CMDLINE_PATTERNS,
    RISKY_EXTENSIONS, RANSOMWARE_EXTENSIONS, RANSOMWARE_NOTE_NAMES,
    get_all_signatures
)

logger = logging.getLogger(__name__)

# ============================================================================
# DETECTION RESULT CLASSES
# ============================================================================

@dataclass
class DetectionResult:
    """Result of a threat detection check"""
    detected: bool = False
    threat_type: str = ""
    category: str = ""
    severity: int = 0
    confidence: int = 0
    description: str = ""
    indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            "detected": self.detected,
            "threat_type": self.threat_type,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "indicators": self.indicators,
            "recommendations": self.recommendations,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class ProcessAnalysis:
    """Analysis result for a process"""
    pid: int
    name: str
    path: str = ""
    cmdline: str = ""
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    malware_matches: List[str] = field(default_factory=list)
    network_risks: List[Dict] = field(default_factory=list)
    is_suspicious: bool = False
    recommended_action: str = "none"


@dataclass
class FileAnalysis:
    """Analysis result for a file"""
    path: str
    name: str
    extension: str = ""
    size: int = 0
    hash_md5: str = ""
    hash_sha256: str = ""
    risk_score: int = 0
    risk_factors: List[str] = field(default_factory=list)
    is_suspicious: bool = False
    is_ransomware: bool = False
    recommended_action: str = "none"


# ============================================================================
# THREAT DETECTION ENGINE
# ============================================================================

class ThreatDetectionEngine:
    """
    Main threat detection engine.
    Analyzes processes, files, network connections, and behaviors.
    """

    def __init__(self, db: ThreatDatabase = None):
        self.db = db or get_database()
        self.signatures = get_all_signatures()
        self.detection_cache = {}
        self.cache_ttl = 300  # 5 minutes
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile regex patterns for performance"""
        self.compiled_process_patterns = []
        for pattern, score, desc in SUSPICIOUS_PROCESS_PATTERNS:
            try:
                self.compiled_process_patterns.append(
                    (re.compile(pattern, re.IGNORECASE), score, desc)
                )
            except re.error:
                continue

        self.compiled_cmdline_patterns = []
        for pattern, score, desc in SUSPICIOUS_CMDLINE_PATTERNS:
            try:
                self.compiled_cmdline_patterns.append(
                    (re.compile(pattern, re.IGNORECASE), score, desc)
                )
            except re.error:
                continue

    # ========================================================================
    # IP ADDRESS ANALYSIS
    # ========================================================================

    def check_ip(self, ip: str) -> DetectionResult:
        """Check if an IP address is malicious"""
        result = DetectionResult()

        # Check cache
        cache_key = f"ip:{ip}"
        if cache_key in self.detection_cache:
            cached = self.detection_cache[cache_key]
            if time.time() - cached['time'] < self.cache_ttl:
                return cached['result']

        # Check database
        db_result = self.db.check_indicator(ip, 'ip')
        if db_result:
            result.detected = True
            result.threat_type = "malicious_ip"
            result.category = db_result.get('category', ThreatCategory.NETWORK)
            result.severity = db_result.get('severity', ThreatSeverity.HIGH)
            result.confidence = db_result.get('confidence', 75)
            result.description = db_result.get('description', 'Known malicious IP')
            result.indicators.append(f"IP: {ip}")
            result.recommendations = [
                "Block this IP address in your firewall",
                "Check which process initiated this connection",
                "Scan system for malware"
            ]
            result.metadata = db_result

        # Cache result
        self.detection_cache[cache_key] = {'result': result, 'time': time.time()}
        return result

    # ========================================================================
    # DOMAIN ANALYSIS
    # ========================================================================

    def check_domain(self, domain: str) -> DetectionResult:
        """Check if a domain is malicious"""
        result = DetectionResult()
        domain = domain.lower().strip()

        # Check cache
        cache_key = f"domain:{domain}"
        if cache_key in self.detection_cache:
            cached = self.detection_cache[cache_key]
            if time.time() - cached['time'] < self.cache_ttl:
                return cached['result']

        # Check database
        db_result = self.db.check_indicator(domain, 'domain')
        if db_result:
            result.detected = True
            result.threat_type = "malicious_domain"
            result.category = db_result.get('category', ThreatCategory.MALWARE)
            result.severity = db_result.get('severity', ThreatSeverity.HIGH)
            result.confidence = db_result.get('confidence', 75)
            result.description = db_result.get('description', 'Known malicious domain')
            result.indicators.append(f"Domain: {domain}")
            result.recommendations = [
                "Block this domain in your DNS/hosts file",
                "Do not visit or interact with this site",
                "Check browser history for visits"
            ]

        # Check for suspicious TLDs — only the free/abuse-heavy ones, not mainstream TLDs
        # v28p37: Removed .xyz (used by Google, Alphabet) and .work/.click (legitimate)
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                result.severity = max(result.severity, 20)  # v28p37: lowered from 30
                result.indicators.append(f"Free/abuse-heavy TLD: {tld}")

        self.detection_cache[cache_key] = {'result': result, 'time': time.time()}
        return result

    # ========================================================================
    # URL ANALYSIS
    # ========================================================================

    def check_url(self, url: str) -> DetectionResult:
        """Check if a URL is malicious"""
        result = DetectionResult()

        # Check database
        db_result = self.db.check_indicator(url, 'url')
        if db_result:
            result.detected = True
            result.threat_type = db_result.get('subcategory', 'malicious_url')
            result.category = db_result.get('category', ThreatCategory.MALWARE)
            result.severity = db_result.get('severity', ThreatSeverity.HIGH)
            result.confidence = db_result.get('confidence', 80)
            result.description = db_result.get('description', 'Known malicious URL')
            result.indicators.append(f"URL: {url}")

            if 'phish' in result.category.lower():
                result.recommendations = [
                    "DO NOT enter any credentials on this site",
                    "Do not download anything from this URL",
                    "Report this phishing attempt"
                ]
            else:
                result.recommendations = [
                    "Do not visit this URL",
                    "Block in browser/firewall",
                    "Scan system if already visited"
                ]

        # Check for suspicious URL patterns
        suspicious_patterns = [
            (r'login.*\.php\?', 50, "Suspicious login page"),
            (r'verify.*account', 45, "Account verification lure"),
            (r'update.*payment', 50, "Payment update scam"),
            (r'secure.*bank', 55, "Banking phish indicator"),
            (r'\.exe$', 60, "Direct executable download"),
            (r'\.scr$', 65, "Screensaver download"),
            (r'bit\.ly|tinyurl|goo\.gl', 30, "URL shortener (verify destination)"),
        ]

        for pattern, score, desc in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                result.indicators.append(desc)
                if not result.detected:
                    result.severity = max(result.severity, score)

        return result

    # ========================================================================
    # FILE HASH ANALYSIS
    # ========================================================================

    def check_hash(self, file_hash: str) -> DetectionResult:
        """Check if a file hash is known malware"""
        result = DetectionResult()
        file_hash = file_hash.lower().strip()

        db_result = self.db.check_indicator(file_hash, 'hash')
        if db_result:
            result.detected = True
            result.threat_type = db_result.get('subcategory', 'malware')
            result.category = ThreatCategory.MALWARE
            result.severity = ThreatSeverity.CRITICAL
            result.confidence = db_result.get('confidence', 95)
            result.description = db_result.get('description', 'Known malware hash')
            result.indicators.append(f"Hash: {file_hash}")
            result.recommendations = [
                "DELETE this file immediately",
                "Quarantine and do not execute",
                "Run full system malware scan",
                "Check for persistence mechanisms"
            ]
            result.metadata = db_result

        return result

    # ========================================================================
    # PORT ANALYSIS
    # ========================================================================

    def check_port(self, port: int, direction: str = "outbound") -> DetectionResult:
        """Check if a port is suspicious"""
        result = DetectionResult()

        if port in SUSPICIOUS_PORTS:
            port_info = SUSPICIOUS_PORTS[port]
            result.detected = True
            result.threat_type = "suspicious_port"
            result.category = ThreatCategory.NETWORK
            result.severity = port_info['risk']
            result.confidence = 70
            result.description = f"{port_info['name']}: {port_info['reason']}"
            result.indicators.append(f"Port {port}: {port_info['name']}")

            if port_info['risk'] >= 80:
                result.recommendations = [
                    f"Block port {port} in firewall",
                    "Identify the process using this port",
                    "Check for RAT or backdoor infection"
                ]

        if port in MINER_PORTS:
            result.detected = True
            result.threat_type = "miner_port"
            result.category = ThreatCategory.MALWARE_MINER
            result.severity = max(result.severity, 70)
            result.indicators.append(f"Port {port}: Known mining pool port")
            result.recommendations.append("Check for cryptominer infection")

        return result

    # ========================================================================
    # PROCESS ANALYSIS
    # ========================================================================

    def analyze_process(self, name: str, path: str = "", cmdline: str = "",
                       connections: List[Dict] = None, pid: int = 0) -> ProcessAnalysis:
        """Analyze a process for threats"""
        analysis = ProcessAnalysis(
            pid=pid,
            name=name,
            path=path,
            cmdline=cmdline
        )

        name_lower = name.lower()
        path_lower = path.lower() if path else ""
        cmdline_lower = cmdline.lower() if cmdline else ""

        # Check against malware families
        # v28p37: Use WORD BOUNDARY matching instead of substring matching.
        # The old code matched "ghost" inside "GhostScript.exe", "lime" inside
        # "SublimeText.exe", "agent" inside "WindowsUpdateAgent.exe" etc.
        # This was a massive source of false positives.
        for category, families in MALWARE_FAMILIES.items():
            for family_name, family_info in families.items():
                # Require the malware name to appear as a whole word or be the
                # entire filename (minus extension), not just a substring.
                # E.g., "njrat" should match "njrat.exe" or "njrat_loader.exe"
                # but NOT "projectmanager.exe" (which contains "ject" etc.)
                _fname_pattern = r'(?:^|[^a-z])' + re.escape(family_name) + r'(?:[^a-z]|$)'
                if re.search(_fname_pattern, name_lower):
                    analysis.malware_matches.append(family_name)
                    analysis.risk_score += family_info.get('severity', 80)
                    analysis.risk_factors.append(f"Matches malware family: {family_name}")

                # Check aliases with same word-boundary logic
                for alias in family_info.get('aliases', []):
                    if len(alias) < 4:
                        # Very short aliases (e.g., "cs", "bit", "loki") are too
                        # prone to false matches — require exact filename match
                        _base_name = name_lower.rsplit('.', 1)[0] if '.' in name_lower else name_lower
                        if _base_name == alias:
                            analysis.malware_matches.append(f"{family_name} ({alias})")
                            analysis.risk_score += family_info.get('severity', 80)
                            analysis.risk_factors.append(f"Matches malware alias: {alias}")
                    else:
                        _alias_pattern = r'(?:^|[^a-z])' + re.escape(alias) + r'(?:[^a-z]|$)'
                        if re.search(_alias_pattern, name_lower) or re.search(_alias_pattern, path_lower):
                            analysis.malware_matches.append(f"{family_name} ({alias})")
                            analysis.risk_score += family_info.get('severity', 80)
                            analysis.risk_factors.append(f"Matches malware alias: {alias}")

        # Check process name patterns
        for pattern, score, desc in self.compiled_process_patterns:
            if pattern.search(name_lower):
                analysis.risk_score += score
                analysis.risk_factors.append(desc)

        # Check command line patterns
        if cmdline:
            for pattern, score, desc in self.compiled_cmdline_patterns:
                if pattern.search(cmdline_lower):
                    analysis.risk_score += score
                    analysis.risk_factors.append(f"Command: {desc}")

        # Check path anomalies — only flag temp dirs, NOT downloads (users run things from there)
        # v28p37: Reduced score and removed downloads folder (that's where people get software)
        temp_paths = ['\\temp\\', '\\tmp\\', '\\appdata\\local\\temp']
        for temp in temp_paths:
            if temp in path_lower:
                analysis.risk_score += 10  # v28p37: reduced from 25 — needs other indicators
                analysis.risk_factors.append("Running from temp directory")
                break

        # Check for system process impersonation
        system_procs = {
            'svchost.exe': 'c:\\windows\\system32\\',
            'csrss.exe': 'c:\\windows\\system32\\',
            'lsass.exe': 'c:\\windows\\system32\\',
            'services.exe': 'c:\\windows\\system32\\',
            'explorer.exe': 'c:\\windows\\',
        }

        if name_lower in system_procs:
            expected = system_procs[name_lower]
            if path and not path_lower.startswith(expected):
                analysis.risk_score += 80
                analysis.risk_factors.append("System process impersonation")

        # Check network connections
        if connections:
            for conn in connections:
                port = conn.get('remote_port', 0)
                port_result = self.check_port(port)
                if port_result.detected:
                    analysis.network_risks.append({
                        'port': port,
                        'severity': port_result.severity,
                        'description': port_result.description
                    })
                    analysis.risk_score += port_result.severity // 2

                # Check IP
                ip = conn.get('remote_ip', '')
                if ip:
                    ip_result = self.check_ip(ip)
                    if ip_result.detected:
                        analysis.network_risks.append({
                            'ip': ip,
                            'severity': ip_result.severity,
                            'description': ip_result.description
                        })
                        analysis.risk_score += ip_result.severity

        # Cap risk score
        analysis.risk_score = min(100, analysis.risk_score)

        # v28p37: Require MULTIPLE risk factors before flagging as suspicious.
        # A single weak indicator (e.g., "running from temp") should never
        # trigger a threat by itself. Require either a high score OR a high
        # score with corroborating evidence.
        _has_strong_evidence = len(analysis.malware_matches) > 0 or len(analysis.network_risks) > 0
        _has_multiple_factors = len(analysis.risk_factors) >= 2
        if analysis.risk_score >= 70 and (_has_strong_evidence or _has_multiple_factors):
            analysis.is_suspicious = True
        elif analysis.risk_score >= 85:
            # Very high score is suspicious even with single factor
            analysis.is_suspicious = True
        else:
            analysis.is_suspicious = False

        # Determine recommended action — raised thresholds
        if analysis.risk_score >= 95 and _has_strong_evidence:
            analysis.recommended_action = "terminate_and_quarantine"
        elif analysis.risk_score >= 80 and _has_strong_evidence:
            analysis.recommended_action = "terminate"
        elif analysis.risk_score >= 70 and _has_multiple_factors:
            analysis.recommended_action = "investigate"
        elif analysis.risk_score >= 50 and _has_multiple_factors:
            analysis.recommended_action = "monitor"
        else:
            analysis.recommended_action = "none"

        return analysis

    # ========================================================================
    # FILE ANALYSIS
    # ========================================================================

    def analyze_file(self, path: str, compute_hash: bool = True) -> FileAnalysis:
        """Analyze a file for threats"""
        path = Path(path)
        analysis = FileAnalysis(
            path=str(path),
            name=path.name,
            extension=path.suffix.lower()
        )

        try:
            if path.exists():
                analysis.size = path.stat().st_size

                # Compute hashes if requested
                if compute_hash and analysis.size < 100_000_000:  # < 100MB
                    try:
                        with open(path, 'rb') as f:
                            data = f.read()
                            analysis.hash_md5 = hashlib.md5(data).hexdigest()
                            analysis.hash_sha256 = hashlib.sha256(data).hexdigest()

                        # Check hash in database
                        for hash_val in [analysis.hash_md5, analysis.hash_sha256]:
                            hash_result = self.check_hash(hash_val)
                            if hash_result.detected:
                                analysis.risk_score = 100
                                analysis.risk_factors.append("Known malware hash!")
                                analysis.is_suspicious = True
                                analysis.recommended_action = "quarantine"
                                break
                    except Exception:
                        pass

        except Exception as e:
            logger.debug(f"Error analyzing file {path}: {e}")

        # Check extension risk
        if analysis.extension in RISKY_EXTENSIONS:
            ext_info = RISKY_EXTENSIONS[analysis.extension]
            analysis.risk_score += ext_info['risk']
            analysis.risk_factors.append(f"Risky extension: {ext_info['type']}")

        # Check for ransomware indicators
        if analysis.extension in RANSOMWARE_EXTENSIONS:
            analysis.is_ransomware = True
            analysis.risk_score = 100
            analysis.risk_factors.append("Ransomware encrypted file extension!")
            analysis.recommended_action = "investigate_ransomware"

        if analysis.name.lower() in [n.lower() for n in RANSOMWARE_NOTE_NAMES]:
            analysis.is_ransomware = True
            analysis.risk_score = 100
            analysis.risk_factors.append("Ransomware note detected!")
            analysis.recommended_action = "ransomware_response"

        # Check path
        path_lower = str(path).lower()
        if '\\temp\\' in path_lower or '\\tmp\\' in path_lower:
            analysis.risk_score += 15
            analysis.risk_factors.append("File in temp directory")

        if '\\downloads\\' in path_lower:
            analysis.risk_score += 10
            analysis.risk_factors.append("File in downloads folder")

        # Cap and evaluate
        analysis.risk_score = min(100, analysis.risk_score)
        analysis.is_suspicious = analysis.risk_score >= 50

        if not analysis.recommended_action or analysis.recommended_action == "none":
            if analysis.risk_score >= 80:
                analysis.recommended_action = "quarantine"
            elif analysis.risk_score >= 60:
                analysis.recommended_action = "scan"
            elif analysis.risk_score >= 40:
                analysis.recommended_action = "review"

        return analysis

    # ========================================================================
    # PROTECTION RECOMMENDATIONS
    # ========================================================================

    def get_protection_recommendations(self, threat_type: str) -> List[str]:
        """Get protection recommendations for a threat type"""
        recommendations = {
            ThreatCategory.MALWARE: [
                "Run a full system antivirus scan",
                "Update Windows and all software",
                "Enable real-time protection in Windows Defender",
                "Check startup programs for suspicious entries",
                "Review scheduled tasks for malicious entries"
            ],
            ThreatCategory.MALWARE_RANSOMWARE: [
                "IMMEDIATELY disconnect from network",
                "Do NOT pay the ransom",
                "Check for shadow copy backups (vssadmin list shadows)",
                "Boot into Safe Mode and run antivirus",
                "Restore from clean backup if available",
                "Report to law enforcement"
            ],
            ThreatCategory.PHISHING: [
                "Do NOT enter any credentials",
                "Do NOT download any attachments",
                "Report the phishing attempt",
                "If credentials entered, change passwords immediately",
                "Enable 2-factor authentication"
            ],
            ThreatCategory.NETWORK_C2: [
                "Block the IP/domain in firewall",
                "Identify and terminate the malicious process",
                "Run malware scan",
                "Check for persistence mechanisms",
                "Review firewall rules"
            ],
            ThreatCategory.MALWARE_MINER: [
                "Terminate mining processes",
                "Check CPU/GPU usage for abnormalities",
                "Block mining pool ports (3333, 4444, etc.)",
                "Scan for cryptominer malware",
                "Review browser extensions"
            ],
            ThreatCategory.MALWARE_STEALER: [
                "Change all passwords immediately",
                "Enable 2-factor authentication everywhere",
                "Check browser saved passwords",
                "Monitor financial accounts",
                "Run credential scanner"
            ],
        }

        return recommendations.get(threat_type, [
            "Run antivirus scan",
            "Update all software",
            "Review system for suspicious activity"
        ])


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

_engine_instance = None

def get_engine() -> ThreatDetectionEngine:
    """Get global engine instance"""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = ThreatDetectionEngine()
    return _engine_instance


def quick_check_ip(ip: str) -> Dict:
    """Quick check for IP"""
    return get_engine().check_ip(ip).to_dict()


def quick_check_domain(domain: str) -> Dict:
    """Quick check for domain"""
    return get_engine().check_domain(domain).to_dict()


def quick_check_url(url: str) -> Dict:
    """Quick check for URL"""
    return get_engine().check_url(url).to_dict()


def quick_check_hash(file_hash: str) -> Dict:
    """Quick check for file hash"""
    return get_engine().check_hash(file_hash).to_dict()


# ============================================================================
# CLI INTERFACE
# ============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Threat Detection Engine')
    parser.add_argument('--ip', type=str, help='Check IP address')
    parser.add_argument('--domain', type=str, help='Check domain')
    parser.add_argument('--url', type=str, help='Check URL')
    parser.add_argument('--hash', type=str, help='Check file hash')
    parser.add_argument('--file', type=str, help='Analyze file')
    parser.add_argument('--process', type=str, help='Analyze process name')

    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    engine = get_engine()

    print("\n" + "=" * 60)
    print("THREAT DETECTION ENGINE")
    print("=" * 60)

    if args.ip:
        result = engine.check_ip(args.ip)
        print(f"\nIP Check: {args.ip}")
        print(f"  Detected: {result.detected}")
        print(f"  Severity: {result.severity}")
        print(f"  Description: {result.description}")

    elif args.domain:
        result = engine.check_domain(args.domain)
        print(f"\nDomain Check: {args.domain}")
        print(f"  Detected: {result.detected}")
        print(f"  Severity: {result.severity}")
        print(f"  Description: {result.description}")

    elif args.url:
        result = engine.check_url(args.url)
        print(f"\nURL Check: {args.url}")
        print(f"  Detected: {result.detected}")
        print(f"  Severity: {result.severity}")
        print(f"  Indicators: {result.indicators}")

    elif args.hash:
        result = engine.check_hash(args.hash)
        print(f"\nHash Check: {args.hash}")
        print(f"  Detected: {result.detected}")
        print(f"  Description: {result.description}")

    elif args.file:
        result = engine.analyze_file(args.file)
        print(f"\nFile Analysis: {args.file}")
        print(f"  Risk Score: {result.risk_score}")
        print(f"  Suspicious: {result.is_suspicious}")
        print(f"  Risk Factors: {result.risk_factors}")
        print(f"  Recommended: {result.recommended_action}")

    elif args.process:
        result = engine.analyze_process(args.process)
        print(f"\nProcess Analysis: {args.process}")
        print(f"  Risk Score: {result.risk_score}")
        print(f"  Suspicious: {result.is_suspicious}")
        print(f"  Risk Factors: {result.risk_factors}")
        print(f"  Recommended: {result.recommended_action}")

    else:
        print("\nNo check specified. Use --help for options.")
        print("\nEngine Statistics:")
        sigs = get_all_signatures()
        total_families = sum(len(cat) for cat in MALWARE_FAMILIES.values())
        print(f"  Malware Families: {total_families}")
        print(f"  Suspicious Ports: {len(SUSPICIOUS_PORTS)}")
        print(f"  Process Patterns: {len(SUSPICIOUS_PROCESS_PATTERNS)}")
        print(f"  Command Patterns: {len(SUSPICIOUS_CMDLINE_PATTERNS)}")

# ========================================================================
# v29: KEV INTEGRATION
# ========================================================================

def correlate_cve_with_detection(cve_id: str) -> Dict:
    """Correlate detected threat with KEV CVE data."""
    result = {
        'cve_id': cve_id,
        'in_kev': False,
        'epss_score': 0.0,
        'cvss_score': 0.0,
        'severity': 'LOW',
        'ransomware_use': False,
        'risk_boost': 0
    }
    
    try:
        from vulnerability_scanner import VulnerabilityScanner
        scanner = VulnerabilityScanner()
        
        kev_data = scanner.search_kev(cve_id)
        if kev_data:
            result['in_kev'] = True
            result['cvss_score'] = kev_data[0].get('cvss_score', 0)
            result['ransomware_use'] = kev_data[0].get('ransomware', 'No') == 'Yes'
            
            epss = scanner.get_epss_score(cve_id)
            if epss:
                result['epss_score'] = epss
                result['risk_boost'] = int(epss * 50)
            
            cvss = result['cvss_score']
            if cvss >= 9.0:
                result['severity'] = 'CRITICAL'
            elif cvss >= 7.0:
                result['severity'] = 'HIGH'
            elif cvss >= 4.0:
                result['severity'] = 'MEDIUM'
                
    except Exception as e:
        logger.debug(f"CVE correlation skipped: {e}")
    
    return result


def enhance_detection_with_kev(analysis: Any, cve_refs: List[str] = None) -> Dict:
    """Enhance detection result with KEV CVE data."""
    if not cve_refs:
        return analysis
    
    kev_correlations = []
    risk_boost = 0
    
    for cve in cve_refs[:5]:
        kev_data = correlate_cve_with_detection(cve)
        if kev_data['in_kev']:
            kev_correlations.append(kev_data)
            risk_boost += kev_data['risk_boost']
    
    if kev_correlations and hasattr(analysis, 'risk_score'):
        analysis.risk_score = min(100, analysis.risk_score + risk_boost)
        analysis.risk_factors.append(f"KEV CVEs: +{risk_boost} risk boost")
    
    return analysis
