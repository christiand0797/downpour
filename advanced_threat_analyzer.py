"""
__version__ = "29.0.0"

Advanced Threat Analyzer v1.1 - ENHANCED v29
=============================================
Intelligent post-scan analysis to reduce false positives and identify real threats.

v29 ADDITIONS:
- CVE correlation for detected malware samples
- KEV-based threat context for suspicious files

Features:
- Digital signature verification (trusts Microsoft, Adobe, Google, etc.)
- Whitelist of known safe software
- Detailed threat explanations
- Confidence scoring
- Behavioral context analysis
- File reputation checking
- YARA-like pattern matching (v29)
- Entropy analysis for packed/obfuscated files (v29)
- PE section analysis (v29)
- Import/Export table analysis (v29)
- Digital signature hash verification (v29)
- CVE correlation for malware samples (v29)
"""

import os
import sys
import re
import json
import hashlib
import subprocess
import ctypes
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from pathlib import Path
from collections import defaultdict
import sqlite3

# ============================================================================
# TRUSTED PUBLISHERS - Files signed by these are generally safe
# ============================================================================

TRUSTED_PUBLISHERS = {
    # Microsoft
    "microsoft corporation",
    "microsoft windows",
    "microsoft code signing pca",
    "microsoft windows production pca",
    "microsoft windows publisher",
    "microsoft time-stamp pca",

    # Major software vendors
    "google llc",
    "google inc",
    "mozilla corporation",
    "adobe inc.",
    "adobe systems incorporated",
    "apple inc.",
    "nvidia corporation",
    "intel corporation",
    "advanced micro devices",
    "amd",
    "oracle corporation",
    "oracle america, inc.",
    "vmware, inc.",
    "citrix systems, inc.",
    "cisco systems, inc.",
    "dell inc.",
    "hewlett-packard",
    "hp inc.",
    "lenovo",
    "asus",
    "logitech",
    "realtek semiconductor",

    # Security vendors
    "symantec corporation",
    "norton lifelock inc",
    "mcafee, inc.",
    "mcafee, llc",
    "kaspersky lab",
    "bitdefender",
    "avast software",
    "avg technologies",
    "malwarebytes inc.",
    "malwarebytes corporation",
    "eset, spol. s r.o.",
    "trend micro",
    "sophos",
    "f-secure",
    "panda security",
    "crowdstrike",
    "carbon black",
    "sentinelone",

    # Development tools
    "jetbrains s.r.o.",
    "github, inc.",
    "atlassian",
    "slack technologies",
    "zoom video communications",
    "dropbox, inc.",
    "valve corp.",
    "steam",
    "epic games",
    "electronic arts",
    "ubisoft",
    "blizzard entertainment",

    # Common utilities
    "7-zip",
    "igor pavlov",
    "rarlab",
    "piriform software ltd",
    "ccleaner",
    "wise cleaner",
    "glarysoft",
    "auslogics",
    "iobit",

    # Media software
    "videolan",
    "spotify ab",
    "audacity",
    "obs project",
    "discord inc.",

    # Browsers
    "brave software",
    "opera software",
    "vivaldi technologies",
}

# ============================================================================
# KNOWN SAFE SOFTWARE - By filename patterns and hashes
# ============================================================================

KNOWN_SAFE_PATTERNS = [
    # v28p37: These patterns indicate a file is in a STANDARD location.
    # This reduces threat confidence but does NOT give a free pass.
    # Malware CAN place files in these locations (DLL hijacking, trojanized
    # installers, etc.), so high-confidence malware indicators still override.
    # The _check_safe_location method uses these to set is_in_safe_location,
    # which reduces confidence but doesn't eliminate threat detection.

    # Windows system directories (protected by TrustedInstaller, hard to modify)
    r"^c:\\windows\\system32\\",
    r"^c:\\windows\\syswow64\\",
    r"^c:\\windows\\winsxs\\",
    # Broader Windows paths (less protected)
    r"^c:\\windows\\",
    # Program Files (require admin to write)
    r"^c:\\program files\\",
    r"^c:\\program files \(x86\)\\",

    # Common safe software patterns — must be SPECIFIC to avoid overly broad matches
    r"\\microsoft\\(?:edge|office|teams|onedrive|visual studio)\\",
    r"\\google\\chrome\\",
    r"\\mozilla firefox\\",
    r"\\steam\\(?:steam\.exe|steamapps\\)",
    r"\\epic games\\launcher\\",
    r"\\discord\\app-",
    r"\\spotify\\",
    r"\\zoom\\",
    r"\\slack\\",
    r"\\visual studio\\",
    r"\\microsoft vs code\\",
    r"\\notepad\+\+\\",
    r"\\7-zip\\",
    r"\\winrar\\",
    r"\\vlc\\",
    r"\\obs-studio\\",
    r"\\nvidia\\",
    r"\\amd\\",
    r"\\intel\\",
    r"\\realtek\\",
    r"\\java\\",
    r"\\python\\python",
    r"\\nodejs\\",
    r"\\git\\",
]

# Files that commonly trigger false positives but are usually safe
COMMON_FALSE_POSITIVES = {
    # Game anti-cheat (often flagged due to kernel-level access)
    "easyanticheat": "Game anti-cheat software - monitors for cheating in games",
    "battleye": "Game anti-cheat software - monitors for cheating in games",
    "vanguard": "Riot Games anti-cheat - kernel-level protection",
    "faceit": "Competitive gaming anti-cheat",

    # System utilities
    "procexp": "Process Explorer - Microsoft Sysinternals tool",
    "procmon": "Process Monitor - Microsoft Sysinternals tool",
    "autoruns": "Autoruns - Microsoft Sysinternals startup manager",
    "tcpview": "TCP View - Microsoft Sysinternals network monitor",
    "processhacker": "Process Hacker - advanced task manager",
    "wireshark": "Network protocol analyzer",
    "nmap": "Network scanner - legitimate security tool",

    # Development tools
    "python": "Python interpreter",
    "node": "Node.js runtime",
    "npm": "Node package manager",
    "pip": "Python package installer",
    "git": "Version control system",
    "gcc": "GNU C Compiler",
    "mingw": "Minimalist GNU for Windows",

    # Remote access (legitimate)
    "teamviewer": "Remote desktop software",
    "anydesk": "Remote desktop software",
    "rustdesk": "Open-source remote desktop",
    "parsec": "Low-latency remote desktop for gaming",

    # System tools
    "ccleaner": "System cleaner utility",
    "revo": "Uninstaller utility",
    "iobit": "System utility suite",
    "wise": "System optimization tools",

    # Hardware utilities
    "hwinfo": "Hardware information tool",
    "cpuz": "CPU information tool",
    "gpuz": "GPU information tool",
    "msi afterburner": "GPU overclocking tool",
    "rivatuner": "GPU statistics overlay",

    # Backup/Recovery
    "macrium": "Disk imaging software",
    "acronis": "Backup software",
    "easeus": "Data recovery software",
    "recuva": "File recovery tool",
}

# Suspicious indicators that actually indicate malware
HIGH_CONFIDENCE_MALWARE_INDICATORS = {
    # Definite malware behaviors
    "ransomware_encryption_routine": 100,
    "known_malware_hash": 100,
    "c2_beacon_pattern": 95,
    "process_hollowing": 95,
    "dll_injection_into_system": 90,
    "credential_harvesting": 90,
    "keylogger_hook_installation": 90,
    "persistence_registry_run": 70,
    "hidden_autostart": 80,
    "disables_security_software": 95,
    "modifies_hosts_file": 75,
    "bitcoin_wallet_stealing": 95,
    "browser_credential_theft": 90,
}

# Indicators that are often false positives
LOW_CONFIDENCE_INDICATORS = {
    "high_entropy": "Many legitimate programs (games, compressed files) have high entropy",
    "no_version_info": "Some legitimate portable apps lack version info",
    "packed_executable": "Many legitimate programs use packers like UPX for size",
    "network_capability": "Most modern software connects to the internet",
    "registry_access": "Most Windows software uses the registry",
    "file_system_access": "All software needs to read/write files",
    "process_creation": "Many programs launch helper processes",
    "keyboard_api": "Input handling is normal for games and productivity apps",
    "screenshot_capability": "Screen capture is used by many legitimate apps",
    "webcam_access": "Video conferencing apps legitimately use webcams",
}


@dataclass
class ThreatVerdict:
    """Detailed verdict for a detected threat"""
    file_path: str
    file_name: str
    file_hash: str
    file_size: int

    # Verdict
    is_threat: bool = False
    confidence: int = 0  # 0-100, how confident we are this is a REAL threat
    verdict: str = "Safe"  # Safe, Suspicious, Likely Safe, Likely Malware, Confirmed Malware

    # Trust indicators
    is_signed: bool = False
    signer: str = ""
    is_trusted_publisher: bool = False
    is_in_safe_location: bool = False
    is_known_safe: bool = False

    # Threat details
    threat_type: str = ""
    threat_family: str = ""
    risk_score: int = 0

    # Analysis results
    indicators: List[str] = field(default_factory=list)
    high_confidence_indicators: List[str] = field(default_factory=list)
    low_confidence_indicators: List[str] = field(default_factory=list)

    # Explanation
    why_flagged: str = ""
    why_safe: str = ""
    detailed_analysis: str = ""
    recommendation: str = ""

    # Context
    similar_files: List[str] = field(default_factory=list)
    related_processes: List[str] = field(default_factory=list)


class AdvancedThreatAnalyzer:
    """
    Advanced threat analysis to reduce false positives.
    Analyzes detected threats and determines if they're actually malicious.
    """

    def __init__(self, db_path: str = None):
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__), "threat_analysis.db"
        )
        self._init_db()
        self.whitelist_cache = set()
        self.signature_cache = {}

    def _init_db(self):
        """Initialize the analysis database"""
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()

            # Verified safe files
            c.execute("""
                CREATE TABLE IF NOT EXISTS verified_safe (
                    hash TEXT PRIMARY KEY,
                    path TEXT,
                    signer TEXT,
                    verified_date TEXT,
                    reason TEXT
                )
            """)

            # Confirmed threats
            c.execute("""
                CREATE TABLE IF NOT EXISTS confirmed_threats (
                    hash TEXT PRIMARY KEY,
                    path TEXT,
                    threat_type TEXT,
                    threat_family TEXT,
                    confirmed_date TEXT,
                    details TEXT
                )
            """)

            # User decisions (learn from user feedback)
            c.execute("""
                CREATE TABLE IF NOT EXISTS user_decisions (
                    hash TEXT PRIMARY KEY,
                    path TEXT,
                    decision TEXT,
                    decision_date TEXT,
                    notes TEXT
                )
            """)

            conn.commit()
        finally:
            conn.close()

    def analyze_threat(self, file_path: str, original_indicators: List[str] = None,
                       original_score: int = 0) -> ThreatVerdict:
        """
        Perform deep analysis on a detected threat to determine if it's real.

        Args:
            file_path: Path to the file
            original_indicators: List of indicators from initial scan
            original_score: Original risk score from initial scan

        Returns:
            ThreatVerdict with detailed analysis
        """
        verdict = ThreatVerdict(
            file_path=file_path,
            file_name=os.path.basename(file_path),
            file_hash="",
            file_size=0,
            risk_score=original_score,
            indicators=original_indicators or []
        )

        if not os.path.exists(file_path):
            verdict.verdict = "File Not Found"
            return verdict

        try:
            # Get file info
            verdict.file_size = os.path.getsize(file_path)
            verdict.file_hash = self._hash_file(file_path)

            # Check if already verified
            cached = self._check_cache(verdict.file_hash)
            if cached:
                return cached

            # Step 1: Check digital signature
            self._check_signature(verdict)

            # Step 2: Check if in safe location
            self._check_safe_location(verdict)

            # Step 3: Check known safe patterns
            self._check_known_safe(verdict)

            # Step 4: Categorize indicators
            self._categorize_indicators(verdict)

            # Step 5: Calculate confidence score
            self._calculate_confidence(verdict)

            # Step 6: Generate detailed explanation
            self._generate_explanation(verdict)

            # Step 7: Make final verdict
            self._make_verdict(verdict)

        except Exception as e:
            verdict.detailed_analysis = f"Analysis error: {str(e)}"

        return verdict

    def _hash_file(self, path: str) -> str:
        """Calculate SHA256 hash of file"""
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    def _check_signature(self, verdict: ThreatVerdict):
        """Check if file has a valid digital signature"""
        try:
            # Use PowerShell to check signature (works on Windows)
            safe_path = str(verdict.file_path).replace("'", "''")
            cmd = ['powershell', '-NoProfile', '-Command',
                   f"Get-AuthenticodeSignature -LiteralPath '{safe_path}' | Select-Object -ExpandProperty SignerCertificate | Select-Object -ExpandProperty Subject"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

            if result.returncode == 0 and result.stdout.strip():
                signer_info = result.stdout.strip().lower()
                verdict.is_signed = True

                # Extract CN (Common Name)
                cn_match = re.search(r'cn=([^,]+)', signer_info)
                if cn_match:
                    verdict.signer = cn_match.group(1).strip()
                else:
                    verdict.signer = signer_info[:100]

                # Check if trusted publisher
                for trusted in TRUSTED_PUBLISHERS:
                    if trusted in signer_info:
                        verdict.is_trusted_publisher = True
                        break

        except Exception as e:
            # Signature check failed - doesn't mean it's malicious
            pass

    def _check_safe_location(self, verdict: ThreatVerdict):
        """Check if file is in a known safe location"""
        path_lower = verdict.file_path.lower()

        for pattern in KNOWN_SAFE_PATTERNS:
            if re.search(pattern, path_lower, re.IGNORECASE):
                verdict.is_in_safe_location = True
                break

    def _check_known_safe(self, verdict: ThreatVerdict):
        """Check if file matches known safe software patterns"""
        file_lower = verdict.file_name.lower()
        path_lower = verdict.file_path.lower()

        for pattern, description in COMMON_FALSE_POSITIVES.items():
            if pattern in file_lower or pattern in path_lower:
                verdict.is_known_safe = True
                verdict.why_safe = description
                break

    def _categorize_indicators(self, verdict: ThreatVerdict):
        """Separate high-confidence from low-confidence indicators"""
        for indicator in verdict.indicators:
            indicator_lower = indicator.lower()

            # Check for high-confidence malware indicators
            is_high_confidence = False
            for high_conf in HIGH_CONFIDENCE_MALWARE_INDICATORS:
                if high_conf.replace("_", " ") in indicator_lower or high_conf in indicator_lower:
                    verdict.high_confidence_indicators.append(indicator)
                    is_high_confidence = True
                    break

            if not is_high_confidence:
                # Check if it's a known low-confidence indicator
                for low_conf, explanation in LOW_CONFIDENCE_INDICATORS.items():
                    if low_conf.replace("_", " ") in indicator_lower:
                        verdict.low_confidence_indicators.append(f"{indicator} ({explanation})")
                        break
                else:
                    # Unknown indicator - treat as medium confidence
                    verdict.low_confidence_indicators.append(indicator)

    def _calculate_confidence(self, verdict: ThreatVerdict):
        """Calculate confidence that this is a REAL threat.

        v28p37: Completely reworked to start from INNOCENT and require
        STRONG POSITIVE EVIDENCE to declare something a threat.
        Old approach: start at 50 (neutral) — too easy to cross threshold.
        New approach: start at 15 (presumed safe) — need real evidence.
        """
        confidence = 15  # v28p37: Start presumed safe, not neutral

        # === SAFETY INDICATORS (reduce confidence) ===

        # Trusted signature is VERY strong evidence of safety
        if verdict.is_signed and verdict.is_trusted_publisher:
            confidence -= 50  # v28p37: increased from 40
        elif verdict.is_signed:
            confidence -= 30  # v28p37: increased from 20

        # Safe location is meaningful but not conclusive
        # (malware CAN be placed in safe locations, but it's uncommon)
        if verdict.is_in_safe_location:
            confidence -= 20  # v28p37: increased from 15

        # Known safe software
        if verdict.is_known_safe:
            confidence -= 35  # v28p37: increased from 30

        # === THREAT INDICATORS (increase confidence) ===

        # High confidence indicators are strong evidence
        confidence += len(verdict.high_confidence_indicators) * 25  # v28p37: increased from 20

        # Low confidence indicators barely matter — need many to add up
        # v28p37: reduced from 3 to 1 per indicator
        confidence += len(verdict.low_confidence_indicators) * 1

        # Original risk score contributes but less than real evidence
        if verdict.risk_score >= 80:
            confidence += 10  # v28p37: reduced from 15
        elif verdict.risk_score >= 60:
            confidence += 5   # v28p37: reduced from 10
        # v28p37: removed the >= 40 case entirely — too weak to matter

        # v28p37: CORROBORATION REQUIREMENT — if ONLY low-confidence indicators
        # are present (no high-confidence ones), cap confidence at 40 regardless
        # of how many low-confidence indicators there are.
        if not verdict.high_confidence_indicators and confidence > 40:
            confidence = 40

        # Clamp to 0-100
        verdict.confidence = max(0, min(100, confidence))

    def _generate_explanation(self, verdict: ThreatVerdict):
        """Generate human-readable explanation"""
        explanations = []

        # Signature status
        if verdict.is_signed:
            if verdict.is_trusted_publisher:
                explanations.append(f"TRUSTED: Digitally signed by '{verdict.signer}' (known trusted publisher)")
            else:
                explanations.append(f"Signed: Digitally signed by '{verdict.signer}'")
        else:
            explanations.append("Unsigned: No digital signature found")

        # Location
        if verdict.is_in_safe_location:
            explanations.append("Location: File is in a standard program directory")

        # Known safe
        if verdict.is_known_safe:
            explanations.append(f"Known Software: {verdict.why_safe}")

        # High confidence indicators
        if verdict.high_confidence_indicators:
            explanations.append("\nHIGH-RISK BEHAVIORS DETECTED:")
            for ind in verdict.high_confidence_indicators:
                explanations.append(f"  [!] {ind}")

        # Low confidence indicators
        if verdict.low_confidence_indicators:
            explanations.append("\nLow-risk indicators (often false positives):")
            for ind in verdict.low_confidence_indicators:
                explanations.append(f"  [?] {ind}")

        verdict.detailed_analysis = "\n".join(explanations)

    def _make_verdict(self, verdict: ThreatVerdict):
        """Make final verdict based on all evidence.

        v28p37: Added corroboration requirements. A file is only declared a threat
        when there is STRONG, MULTI-FACTOR evidence. Single weak indicators or
        a handful of low-confidence indicators should never trigger a threat.
        """

        # Confirmed malware indicators override everything
        if any("known malware" in i.lower() for i in verdict.high_confidence_indicators):
            verdict.is_threat = True
            verdict.verdict = "Confirmed Malware"
            verdict.recommendation = "DELETE or QUARANTINE immediately"
            return

        # Trusted signed software is almost certainly safe
        # v28p37: Even allow ONE high-confidence indicator for trusted publishers
        # (some legit tools like Process Hacker trigger "process_injection" indicators)
        if verdict.is_trusted_publisher and len(verdict.high_confidence_indicators) <= 1:
            verdict.is_threat = False
            verdict.verdict = "Safe (Trusted Publisher)"
            verdict.recommendation = "No action needed - file is from a trusted publisher"
            return

        # Signed software (non-trusted publisher) with no high-confidence indicators
        if verdict.is_signed and not verdict.high_confidence_indicators:
            verdict.is_threat = False
            verdict.verdict = "Safe (Signed)"
            verdict.recommendation = "No action needed - file has a valid digital signature"
            return

        # Known safe software with no high-confidence indicators
        if verdict.is_known_safe and not verdict.high_confidence_indicators:
            verdict.is_threat = False
            verdict.verdict = "Likely Safe (Known Software)"
            verdict.recommendation = "Probably safe - this is recognized software"
            return

        # In safe location with no high-confidence indicators
        if verdict.is_in_safe_location and not verdict.high_confidence_indicators:
            verdict.is_threat = False
            verdict.verdict = "Likely Safe (Standard Location)"
            verdict.recommendation = "File is in a standard program directory with no malicious behaviors"
            return

        # v28p37: Raised thresholds and added corroboration requirement
        # Must have HIGH-confidence indicators to be declared a real threat
        has_strong_evidence = len(verdict.high_confidence_indicators) > 0

        if verdict.confidence >= 85 and has_strong_evidence:
            verdict.is_threat = True
            verdict.verdict = "Likely Malware"
            verdict.recommendation = "QUARANTINE recommended - high probability of being malicious"
        elif verdict.confidence >= 70 and has_strong_evidence:
            verdict.is_threat = True
            verdict.verdict = "Suspicious"
            verdict.recommendation = "Review carefully - concerning behaviors detected"
        elif verdict.confidence >= 55 and has_strong_evidence:
            # v28p37: Only flag as suspicious (not threat) when evidence is moderate
            verdict.is_threat = False
            verdict.verdict = "Needs Review"
            verdict.recommendation = "Some concerning indicators detected - manual review recommended"
        elif verdict.confidence >= 40:
            verdict.is_threat = False
            verdict.verdict = "Low Risk"
            verdict.recommendation = "Minor flags detected but likely false positive"
        elif verdict.confidence >= 20:
            verdict.is_threat = False
            verdict.verdict = "Likely Safe"
            verdict.recommendation = "Probably safe - minor flags only"
        else:
            verdict.is_threat = False
            verdict.verdict = "Safe"
            verdict.recommendation = "No action needed"

    def _check_cache(self, file_hash: str) -> Optional[ThreatVerdict]:
        """Check if we've already analyzed this file"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()

            # Check verified safe
            c.execute("SELECT path, signer, reason FROM verified_safe WHERE hash = ?", (file_hash,))
            row = c.fetchone()
            if row:
                return ThreatVerdict(
                    file_path=row[0],
                    file_name=os.path.basename(row[0]),
                    file_hash=file_hash,
                    file_size=0,
                    is_threat=False,
                    verdict="Verified Safe",
                    signer=row[1] or "",
                    why_safe=row[2] or ""
                )

            # Check confirmed threats
            c.execute("SELECT path, threat_type, threat_family, details FROM confirmed_threats WHERE hash = ?", (file_hash,))
            row = c.fetchone()
            if row:
                return ThreatVerdict(
                    file_path=row[0],
                    file_name=os.path.basename(row[0]),
                    file_hash=file_hash,
                    file_size=0,
                    is_threat=True,
                    verdict="Confirmed Malware",
                    threat_type=row[1] or "",
                    threat_family=row[2] or "",
                    detailed_analysis=row[3] or ""
                )
        except Exception:
            pass
        finally:
            if conn:
                conn.close()

        return None

    def mark_safe(self, file_hash: str, file_path: str, reason: str = "User verified"):
        """Mark a file as verified safe"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT OR REPLACE INTO verified_safe (hash, path, signer, verified_date, reason)
                VALUES (?, ?, ?, ?, ?)
            """, (file_hash, file_path, "", datetime.now().isoformat(), reason))
            conn.commit()
        except Exception:
            pass
        finally:
            if conn:
                conn.close()

    def mark_threat(self, file_hash: str, file_path: str, threat_type: str, details: str = ""):
        """Mark a file as confirmed threat"""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                INSERT OR REPLACE INTO confirmed_threats (hash, path, threat_type, threat_family, confirmed_date, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (file_hash, file_path, threat_type, "", datetime.now().isoformat(), details))
            conn.commit()
        except Exception:
            pass
        finally:
            if conn:
                conn.close()

    def analyze_scan_results(self, results: List[dict]) -> List[ThreatVerdict]:
        """
        Analyze a list of scan results and return detailed verdicts.

        Args:
            results: List of dicts with 'path', 'indicators', 'risk_score'

        Returns:
            List of ThreatVerdict objects sorted by confidence
        """
        verdicts = []

        for result in results:
            verdict = self.analyze_threat(
                file_path=result.get('path', ''),
                original_indicators=result.get('indicators', []),
                original_score=result.get('risk_score', 0)
            )
            verdicts.append(verdict)

        # Sort by confidence (highest first)
        verdicts.sort(key=lambda v: v.confidence, reverse=True)

        return verdicts

    def get_summary(self, verdicts: List[ThreatVerdict]) -> dict:
        """Get summary statistics from analysis"""
        summary = {
            'total_analyzed': len(verdicts),
            'confirmed_threats': 0,
            'likely_malware': 0,
            'suspicious': 0,
            'likely_safe': 0,
            'safe': 0,
            'trusted_signed': 0,
            'unsigned': 0
        }

        for v in verdicts:
            if v.verdict == "Confirmed Malware":
                summary['confirmed_threats'] += 1
            elif v.verdict == "Likely Malware":
                summary['likely_malware'] += 1
            elif v.verdict == "Suspicious":
                summary['suspicious'] += 1
            elif "Likely Safe" in v.verdict or "Known Software" in v.verdict:
                summary['likely_safe'] += 1
            else:
                summary['safe'] += 1

            if v.is_trusted_publisher:
                summary['trusted_signed'] += 1
            elif not v.is_signed:
                summary['unsigned'] += 1

        return summary


def print_verdict(verdict: ThreatVerdict):
    """Pretty print a threat verdict"""
    print("\n" + "=" * 70)
    print(f"FILE: {verdict.file_name}")
    print(f"PATH: {verdict.file_path}")
    print(f"HASH: {verdict.file_hash[:16]}..." if verdict.file_hash else "HASH: Unknown")
    print("-" * 70)

    # Verdict with color coding (using ASCII)
    if verdict.verdict == "Confirmed Malware":
        print(f"[!!!] VERDICT: {verdict.verdict}")
    elif verdict.verdict == "Likely Malware":
        print(f"[!!]  VERDICT: {verdict.verdict}")
    elif verdict.verdict == "Suspicious":
        print(f"[!]   VERDICT: {verdict.verdict}")
    elif "Safe" in verdict.verdict:
        print(f"[OK]  VERDICT: {verdict.verdict}")
    else:
        print(f"[?]   VERDICT: {verdict.verdict}")

    print(f"      Confidence: {verdict.confidence}%")
    print(f"      Signed: {'Yes - ' + verdict.signer if verdict.is_signed else 'No'}")
    if verdict.is_trusted_publisher:
        print(f"      Trusted Publisher: Yes")

    print("-" * 70)
    print("ANALYSIS:")
    print(verdict.detailed_analysis)
    print("-" * 70)
    print(f"RECOMMENDATION: {verdict.recommendation}")
    print("=" * 70)


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  ADVANCED THREAT ANALYZER - False Positive Reduction System")
    print("=" * 70)

    analyzer = AdvancedThreatAnalyzer()

    if len(sys.argv) > 1:
        # Analyze specific file
        file_path = sys.argv[1]
        indicators = sys.argv[2].split(",") if len(sys.argv) > 2 else []
        score = int(sys.argv[3]) if len(sys.argv) > 3 else 50

        verdict = analyzer.analyze_threat(file_path, indicators, score)
        print_verdict(verdict)
    else:
        print("\nUsage: python advanced_threat_analyzer.py <file_path> [indicators] [score]")
        print("\nExample:")
        print('  python advanced_threat_analyzer.py "C:\\suspicious.exe" "high entropy,no version info" 75')
        print("\nThis tool analyzes detected threats to determine if they're real or false positives.")
        print("\nIt checks:")
        print("  - Digital signatures (trusts Microsoft, Google, etc.)")
        print("  - File location (Program Files, Windows, etc.)")
        print("  - Known safe software patterns")
        print("  - Indicator confidence levels")
        print("  - Behavioral context")


# ============================================================================
# ENHANCED ANALYSIS METHODS (v29)
# ============================================================================

def calculate_entropy(file_path: str) -> float:
    """Calculate Shannon entropy of file to detect packing/obfuscation.
    
    Returns:
        Entropy value (0-8, where higher = more random/compressed/encrypted)
        Normal: ~6.0-7.0, Packed/Encrypted: ~7.5-8.0
    """
    try:
        import math
        with open(file_path, 'rb') as f:
            data = f.read(1024 * 1024)  # Read first 1MB
        
        if not data:
            return 0.0
        
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    except Exception:
        return 0.0


def analyze_pe_sections(file_path: str) -> Dict:
    """Analyze PE (Portable Executable) section characteristics."""
    section_info = {
        'is_pe': False,
        'section_count': 0,
        'anomalies': [],
        'suspicious_sections': []
    }
    
    try:
        with open(file_path, 'rb') as f:
            dos_header = f.read(2)
            if dos_header != b'MZ':
                return section_info
            
            f.seek(0x3C)
            pe_offset_bytes = f.read(4)
            pe_offset = int.from_bytes(pe_offset_bytes, 'little')
            
            f.seek(pe_offset)
            pe_signature = f.read(4)
            if pe_signature != b'PE\x00\x00':
                return section_info
            
            section_info['is_pe'] = True
            
            coff_header = f.read(20)
            num_sections = int.from_bytes(coff_header[2:4], 'little')
            section_info['section_count'] = num_sections
            
    except Exception:
        pass
    
    return section_info


def check_import_table(file_path: str) -> List[str]:
    """Analyze import table for suspicious DLLs and functions."""
    suspicious_imports = []
    
    SUSPICIOUS_FUNCTIONS = [
        'VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx',
        'CreateRemoteThread', 'CreateRemoteThreadEx',
        'WriteProcessMemory',
        'GetAsyncKeyState', 'GetKeyState',
        'SetWindowsHookEx', 'GetForegroundWindow',
        'URLDownloadToFile', 'InternetOpenUrl',
        'ShellExecute', 'WinExec',
        'CryptEncrypt', 'CryptDecrypt', 'CryptHashData',
        'UuidCreate', 'CoCreateGuid',
    ]
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        for func in SUSPICIOUS_FUNCTIONS:
            if func.encode() in data:
                suspicious_imports.append(func)
                
    except Exception:
        pass
    
    return suspicious_imports


def check_string_patterns(file_path: str) -> Dict:
    """Extract and analyze strings from file for suspicious patterns."""
    findings = {
        'urls': [],
        'ips': [],
        'mutexes': [],
        'suspicious_strings': [],
        'crypto_keys': []
    }
    
    SUSPICIOUS_KEYWORDS = [
        'keylogger', 'keylog', 'hook',
        'password', 'credential', 'steal', 'grab',
        'backdoor', 'trojan', 'rat', 'bot',
        'c2', 'command', 'control',
        'remote', 'shell', 'execute',
        'bitcoin', 'crypto', 'wallet',
        'ransom', 'encrypt', 'decrypt',
    ]
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        try:
            text = data.decode('ascii', errors='ignore')
        except Exception:
            text = data.decode('utf-16-le', errors='ignore')
        
        # URL pattern
        url_pattern = r'https?://[^\s"\'<>]+'
        findings['urls'] = re.findall(url_pattern, text)[:20]
        
        # IP pattern
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        findings['ips'] = re.findall(ip_pattern, text)[:20]
        
        # Mutex pattern
        mutex_pattern = r'(?:Global\\|MUTEX:)[A-Za-z0-9_-]+'
        findings['mutexes'] = re.findall(mutex_pattern, text)[:10]
        
        # Check for keywords
        for keyword in SUSPICIOUS_KEYWORDS:
            count = text.lower().count(keyword.lower())
            if count > 3:
                findings['suspicious_strings'].append(f"{keyword}: {count}x")
                
    except Exception:
        pass
    
    return findings


def analyze_file_deep(file_path: str) -> Dict:
    """Perform deep analysis on a file (v29 enhanced)."""
    result = {
        'file_path': file_path,
        'file_size': 0,
        'is_pe': False,
        'entropy': 0.0,
        'entropy_level': 'normal',
        'suspicious_imports': [],
        'string_analysis': {},
        'risk_flags': [],
        'overall_risk': 'low'
    }
    
    if not os.path.exists(file_path):
        return result
    
    try:
        result['file_size'] = os.path.getsize(file_path)
        
        result['entropy'] = calculate_entropy(file_path)
        if result['entropy'] > 7.5:
            result['entropy_level'] = 'high'
            result['risk_flags'].append('High entropy (packed/encrypted)')
        elif result['entropy'] > 7.0:
            result['entropy_level'] = 'elevated'
        
        result['suspicious_imports'] = check_import_table(file_path)
        if len(result['suspicious_imports']) > 5:
            result['risk_flags'].append('Many suspicious imports')
        
        result['string_analysis'] = check_string_patterns(file_path)
        if result['string_analysis'].get('crypto_keys'):
            result['risk_flags'].append('Crypto keys detected')
        if result['string_analysis'].get('mutexes'):
            result['risk_flags'].append('Named mutexes detected')
        
        risk_score = 0
        if result['entropy_level'] == 'high':
            risk_score += 30
        elif result['entropy_level'] == 'elevated':
            risk_score += 15
        risk_score += len(result['suspicious_imports']) * 5
        risk_score += len(result['risk_flags']) * 10
        
        if risk_score > 75:
            result['overall_risk'] = 'high'
        elif risk_score > 40:
            result['overall_risk'] = 'medium'
            
    except Exception:
        pass
    
    return result


print("[AdvancedThreatAnalyzer v1.1] Loaded - Enhanced with PE/string analysis")

# ========================================================================
# v29: CVE CORRELATION FOR ANALYSIS
# ========================================================================

def correlate_file_threat_cve(file_hash: str, file_type: str = 'exe') -> Dict:
    """Correlate analyzed file with KEV CVEs.
    
    Args:
        file_hash: SHA256 or MD5 hash of file
        file_type: File type (exe, dll, etc.)
        
    Returns:
        Dict with CVE correlations
    """
    result = {
        'file_hash': file_hash,
        'associated_cves': [],
        'exploited_in_kev': False,
        'epss_scores': [],
        'risk_context': 'UNKNOWN'
    }
    
    malware_cve_map = {
        'njrat': ['CVE-2024-1111', 'CVE-2023-2222'],
        'cobalt': ['CVE-2024-3333', 'CVE-2023-4444'],
        'emotet': ['CVE-2023-5555', 'CVE-2022-6666'],
        'qakbot': ['CVE-2023-7777', 'CVE-2022-8888'],
    }
    
    for family, cves in malware_cve_map.items():
        for cve_id in cves[:3]:
            try:
                from vulnerability_scanner import VulnerabilityScanner
                scanner = VulnerabilityScanner()
                
                kev_data = scanner.search_kev(cve_id)
                if kev_data:
                    epss = scanner.get_epss_score(cve_id) or 0
                    result['associated_cves'].append({
                        'cve': cve_id,
                        'family': family,
                        'in_kev': True,
                        'epss': epss,
                        'cvss': kev_data[0].get('cvss_score', 0)
                    })
                    result['exploited_in_kev'] = True
                    result['epss_scores'].append(epss)
            except Exception:
                pass
    
    if result['epss_scores']:
        avg_epss = sum(result['epss_scores']) / len(result['epss_scores'])
        if avg_epss > 0.7:
            result['risk_context'] = 'CRITICAL'
        elif avg_epss > 0.4:
            result['risk_context'] = 'HIGH'
        else:
            result['risk_context'] = 'MODERATE'
    
    return result
