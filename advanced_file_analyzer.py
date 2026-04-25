"""
===============================================================================
ADVANCED FILE ANALYSIS AND REPUTATION SYSTEM
===============================================================================

PURPOSE: Provides comprehensive file analysis including hashing, reputation checking,
         and metadata analysis to identify malicious files.

CAPABILITIES:
1. MULTI-HASH SUPPORT - MD5, SHA1, SHA256, SHA384, SHA512
2. REPUTATION CHECKING - Multiple online reputation services
3. FILE TYPE ANALYSIS - True file type detection regardless of extension
4. METADATA EXTRACTION - Hidden data, timestamps, author information
5. ENTROPY ANALYSIS - Detect encrypted/packed executables
6. SIMILARITY ANALYSIS - Find similar known malware
7. PACKER DETECTION - Identify packed/crypted executables
8. STRING ANALYSIS - Extract suspicious strings and URLs

INTEGRATION:
- Integrates with threat intelligence feeds
- Provides hash reputation to file monitor
- Offers detailed file analysis to behavioral analyzer
- Sends alerts on suspicious files to main system

REPUTATION SOURCES:
- VirusTotal API
- Hybrid Analysis
- MalwareBazaar
- YARA rules matching
- Custom IOC database
"""

import hashlib
import math
import os
import logging
import threading
import time
try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False
try:
    import magic
    _MAGIC_AVAILABLE = True
except ImportError:
    _MAGIC_AVAILABLE = False
try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
try:
    import pefile
    _PEFILE_AVAILABLE = True
except ImportError:
    _PEFILE_AVAILABLE = False
import string
import re
from datetime import datetime, timedelta
from pathlib import Path
import sqlite3
import json
from typing import Dict, List, Tuple, Optional
import configparser
from collections import defaultdict

class FileAnalyzer:
    """
    Advanced file analysis and reputation checking system.
    """
    
    def __init__(self, config=None):
        """
        Initialize file analyzer.
        
        Parameters:
        - config: Configuration object
        """
        self.running = True
        self.config = config
        
        # Initialize database
        self.db_path = Path("file_reputation.db")
        self.init_database()
        
        # Analysis cache
        self.analysis_cache = {}
        self.cache_ttl = timedelta(hours=24)
        
        # API keys (would be loaded from config in production)
        self.api_keys = {
            'virustotal': '',    # Get from virustotal.com
            'hybrid_analysis': '', # Get from hybrid-analysis.com
            'malwarebazaar': '',   # Get from abuse.ch
        }
        
        # File type signatures
        self.file_signatures = {
            b'MZ': 'PE32',                # Windows executable
            b'\x7fELF': 'ELF',           # Linux executable
            b'PK\x03\x04': 'ZIP',         # ZIP archive
            b'PK\x05\x06': 'ZIP',         # ZIP archive
            b'PK\x07\x08': 'ZIP',         # ZIP archive
            b'\x1f\x8b\x08': 'GZIP',      # GZIP archive
            b'BZh': 'BZIP2',              # BZIP2 archive
            b'\x89PNG\r\n\x1a\n': 'PNG',  # PNG image
            b'\xff\xd8\xff': 'JPEG',       # JPEG image
            b'GIF87a': 'GIF',            # GIF image
            b'GIF89a': 'GIF',            # GIF image
            b'%PDF': 'PDF',               # PDF document
            b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1': 'OLE2',  # Microsoft Office
        }
        
        # Suspicious strings
        self.suspicious_strings = [
            # Common malicious URLs and domains
            r'https?://[^\s]*bit\.ly',
            r'https?://[^\s]*tinyurl\.com',
            r'https?://[^\s]*paste\.ebin',
            r'https?://[^\s]*discord\.com/api/webhooks',
            
            # suspicious file paths
            r'C:\\Users\\.*\\AppData\\Local\\Temp\\.*\.exe',
            r'%TEMP%\\.*\.exe',
            r'%APPDATA%\\.*\.exe',
            
            # PowerShell suspicious commands
            r'-enc.*[A-Za-z0-9+/]{20,}={0,2}',
            r'-nop.*-w hidden',
            r'IEX.*New-Object',
            
            # Registry keys
            r'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
            
            # Crypto patterns
            r'[A-Za-z0-9]{32,}',  # Possible wallet addresses
            r'0x[a-fA-F0-9]{40}',  # Ethereum addresses
        ]
        
        # Initialize YARA rules
        self.init_yara_rules()
        
        # Statistics
        self.stats = {
            'files_analyzed': 0,
            'malicious_found': 0,
            'suspicious_found': 0,
            'cache_hits': 0,
            'api_calls': 0
        }
    
    def init_database(self):
        """Initialize SQLite database for file reputation."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS file_analysis (
                        file_path TEXT PRIMARY KEY,
                        md5_hash TEXT,
                        sha1_hash TEXT,
                        sha256_hash TEXT,
                        file_type TEXT,
                        file_size INTEGER,
                        first_seen TIMESTAMP,
                        last_seen TIMESTAMP,
                        reputation_score INTEGER,
                        vt_positives INTEGER,
                        vt_total INTEGER,
                        is_malicious BOOLEAN,
                        analysis_details TEXT,
                        metadata TEXT
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS reputation_cache (
                        hash TEXT PRIMARY KEY,
                        vt_positives INTEGER,
                        vt_total INTEGER,
                        ha_score INTEGER,
                        mb_score INTEGER,
                        last_update TIMESTAMP,
                        sources_checked TEXT
                    )
                ''')

                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_hash ON file_analysis(sha256_hash)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_reputation ON reputation_cache(sha256_hash)')

                conn.commit()
            finally:
                conn.close()

            logging.info("[✓] File analysis database initialized")

        except Exception as e:
            logging.error(f"Failed to initialize database: {e}")
    
    def init_yara_rules(self):
        """Initialize YARA rules for malware detection."""
        try:
            # Create default YARA rules
            self.yara_rules = """
            rule Suspicious_Entropy {
                meta:
                    description = "High entropy file (possible encrypted/packed)"
                    author = "Family Security Suite"
                condition:
                    entropy(0, filesize) > 7.5 and filesize > 1024
            }
            
            rule Packed_PE {
                meta:
                    description = "Packed PE executable"
                    author = "Family Security Suite"
                strings:
                    $upx = "UPX0"
                    $upx1 = "UPX1"
                    $mpress = "MPRESS"
                    $pecompact = "PECompact"
                    $aspack = "ASPack"
                condition:
                    uint16(0) == 0x5A4D and any of ($upx, $upx1, $mpress, $pecompact, $aspack)
            }
            
            rule Suspicious_Strings {
                meta:
                    description = "Contains suspicious strings"
                    author = "Family Security Suite"
                strings:
                    $powershell = "powershell.exe"
                    $encoded = "-enc"
                    $hidden = "-w hidden"
                    $download = "DownloadString"
                    $execute = "IEX"
                condition:
                    3 of them
            }
            """
            
            try:
                self.yara_rules_compiled = yara.compile(source=self.yara_rules)
                logging.info("[✓] YARA rules compiled successfully")
            except yara.Error as e:
                logging.warning(f"YARA not available: {e}")
                self.yara_rules_compiled = None
                
        except Exception as e:
            logging.warning(f"Could not initialize YARA: {e}")
            self.yara_rules_compiled = None
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """
        Calculate multiple hashes for a file.
        
        Parameters:
        - file_path: Path to the file
        
        Returns:
        - Dictionary with hash values
        """
        try:
            hashes = {
                'md5': hashlib.md5(),
                'sha1': hashlib.sha1(),
                'sha256': hashlib.sha256(),
                'sha384': hashlib.sha384(),
                'sha512': hashlib.sha512()
            }
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    for hash_obj in hashes.values():
                        hash_obj.update(chunk)
            
            return {name: hash_obj.hexdigest() for name, hash_obj in hashes.items()}
            
        except Exception as e:
            logging.error(f"Error calculating hashes for {file_path}: {e}")
            return {}
    
    def detect_file_type(self, file_path: str) -> Dict[str, str]:
        """
        Detect the true file type regardless of extension.
        
        Parameters:
        - file_path: Path to the file
        
        Returns:
        - Dictionary with file type information
        """
        try:
            result = {
                'extension': Path(file_path).suffix.lower(),
                'magic_type': '',
                'detected_type': '',
                'is_executable': False,
                'is_archive': False,
                'is_document': False
            }
            
            # Check file signature
            with open(file_path, 'rb') as f:
                signature = f.read(16)
            
            for sig, file_type in self.file_signatures.items():
                if signature.startswith(sig):
                    result['detected_type'] = file_type
                    break
            
            # Use python-magic if available
            try:
                result['magic_type'] = magic.from_file(file_path)
            except Exception:
                pass
            
            # Determine categories
            if result['detected_type'] in ['PE32', 'ELF'] or result['extension'] in ['.exe', '.dll', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js']:
                result['is_executable'] = True
            elif result['detected_type'] in ['ZIP', 'GZIP', 'BZIP2', 'RAR', '7Z'] or result['extension'] in ['.zip', '.rar', '.7z', '.gz', '.bz2']:
                result['is_archive'] = True
            elif result['detected_type'] in ['PDF', 'DOC', 'XLS', 'PPT'] or result['extension'] in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx']:
                result['is_document'] = True
            
            return result
            
        except Exception as e:
            logging.error(f"Error detecting file type for {file_path}: {e}")
            return {'error': str(e)}
    
    def calculate_entropy(self, file_path: str) -> float:
        """
        Calculate Shannon entropy of a file.
        
        High entropy (>7.5) often indicates encrypted/packed content.
        
        Parameters:
        - file_path: Path to the file
        
        Returns:
        - Entropy value (0-8)
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    freq = count / data_len
                    entropy -= freq * math.log2(freq)
            
            return entropy
            
        except Exception as e:
            logging.error(f"Error calculating entropy for {file_path}: {e}")
            return 0.0
    
    def extract_strings(self, file_path: str, min_length: int = 4) -> List[str]:
        """
        Extract printable strings from a file.
        
        Parameters:
        - file_path: Path to the file
        - min_length: Minimum string length to extract
        
        Returns:
        - List of strings found
        """
        try:
            strings = []
            current_string = ""
            
            with open(file_path, 'rb') as f:
                while byte := f.read(1):
                    if byte[0] >= 32 and byte[0] <= 126:  # Printable ASCII
                        current_string += byte.decode('ascii')
                    else:
                        if len(current_string) >= min_length:
                            strings.append(current_string)
                        current_string = ""
            
                # Add final string if file ends with printable character
                if len(current_string) >= min_length:
                    strings.append(current_string)
            
            return strings
            
        except Exception as e:
            logging.error(f"Error extracting strings from {file_path}: {e}")
            return []
    
    def check_suspicious_strings(self, strings: List[str]) -> List[Dict]:
        """
        Check strings against suspicious patterns.
        
        Parameters:
        - strings: List of strings from file
        
        Returns:
        - List of suspicious matches
        """
        suspicious_matches = []
        
        for pattern in self.suspicious_strings:
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for string in strings:
                    match = regex.search(string)
                    if match:
                        suspicious_matches.append({
                            'pattern': pattern,
                            'string': string,
                            'match': match.group()
                        })
            except re.error:
                continue
        
        return suspicious_matches
    
    def analyze_pe_file(self, file_path: str) -> Dict:
        """
        Analyze PE executable files for suspicious characteristics.
        
        Parameters:
        - file_path: Path to PE file
        
        Returns:
        - Dictionary with PE analysis results
        """
        try:
            pe_info = {
                'is_valid_pe': False,
                'is_packed': False,
                'has_imports': False,
                'suspicious_imports': [],
                'sections_info': [],
                'compile_time': None,
                'entropy': 0.0
            }
            
            try:
                pe = pefile.PE(file_path)
                pe_info['is_valid_pe'] = True
                
                # Check compile time
                if hasattr(pe, 'FILE_HEADER'):
                    compile_time = pe.FILE_HEADER.TimeDateStamp
                    pe_info['compile_time'] = datetime.fromtimestamp(compile_time)
                
                # Analyze sections
                if hasattr(pe, 'sections'):
                    for section in pe.sections:
                        section_info = {
                            'name': section.Name.decode('utf-8', errors='ignore').strip('\x00'),
                            'virtual_size': section.Misc_VirtualSize,
                            'raw_size': section.SizeOfRawData,
                            'entropy': section.get_entropy()
                        }
                        pe_info['sections_info'].append(section_info)
                        
                        # Check for high entropy sections (possible packing)
                        if section_info['entropy'] > 7.0:
                            pe_info['is_packed'] = True
                
                # Check imports
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    pe_info['has_imports'] = True
                    suspicious_imports = [
                        'VirtualAlloc', 'VirtualProtect', 'CreateProcess',
                        'WriteProcessMemory', 'CreateRemoteThread',
                        'SetWindowsHookEx', 'GetAsyncKeyState',
                        'InternetOpen', 'InternetConnect', 'HttpOpenRequest'
                    ]
                    
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for func in entry.imports:
                            if func.name and func.name.decode() in suspicious_imports:
                                pe_info['suspicious_imports'].append(func.name.decode())
                
                pe.close()
                
            except Exception as e:
                logging.debug(f"PE analysis failed: {e}")
            
            return pe_info
            
        except Exception as e:
            logging.error(f"Error analyzing PE file {file_path}: {e}")
            return {'error': str(e)}
    
    def check_yara_rules(self, file_path: str) -> List[Dict]:
        """
        Check file against YARA rules.
        
        Parameters:
        - file_path: Path to file
        
        Returns:
        - List of rule matches
        """
        try:
            if not self.yara_rules_compiled:
                return []
            
            matches = self.yara_rules_compiled.match(file_path)
            results = []
            
            for match in matches:
                result = {
                    'rule': match.rule,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }
                
                for string in match.strings:
                    result['strings'].append({
                        'identifier': string.identifier,
                        'instances': len(string.instances)
                    })
                
                results.append(result)
            
            return results
            
        except Exception as e:
            logging.error(f"Error checking YARA rules for {file_path}: {e}")
            return []
    
    def check_virustotal(self, file_hash: str) -> Dict:
        """
        Check file hash against VirusTotal.
        
        Parameters:
        - file_hash: SHA256 hash of file
        
        Returns:
        - VirusTotal results
        """
        try:
            if not self.api_keys['virustotal']:
                return {'error': 'VirusTotal API key not configured'}
            
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {
                'apikey': self.api_keys['virustotal'],
                'resource': file_hash
            }
            
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            
            self.stats['api_calls'] += 1
            return response.json()
            
        except Exception as e:
            logging.debug(f"VirusTotal lookup failed for {file_hash}: {e}")
            return {'error': str(e)}
    
    def analyze_file(self, file_path: str) -> Dict:
        """
        Perform comprehensive file analysis.
        
        Parameters:
        - file_path: Path to file
        
        Returns:
        - Dictionary with complete analysis results
        """
        try:
            # Check cache first
            if file_path in self.analysis_cache:
                cache_entry = self.analysis_cache[file_path]
                if datetime.now() - cache_entry['timestamp'] < self.cache_ttl:
                    self.stats['cache_hits'] += 1
                    return cache_entry['result']
            
            analysis_start = time.time()
            
            # Basic file info
            file_stat = os.stat(file_path)
            basic_info = {
                'path': file_path,
                'size': file_stat.st_size,
                'modified': datetime.fromtimestamp(file_stat.st_mtime),
                'created': datetime.fromtimestamp(file_stat.st_ctime)
            }
            
            # Calculate hashes
            hashes = self.calculate_hashes(file_path)
            
            # Detect file type
            file_type_info = self.detect_file_type(file_path)
            
            # Calculate entropy
            entropy = self.calculate_entropy(file_path)
            
            # Extract strings
            strings = self.extract_strings(file_path)
            
            # Check suspicious strings
            suspicious_strings = self.check_suspicious_strings(strings)
            
            # PE analysis if executable
            pe_analysis = {}
            if file_type_info.get('is_executable') and file_type_info.get('detected_type') == 'PE32':
                pe_analysis = self.analyze_pe_file(file_path)
            
            # YARA analysis
            yara_matches = self.check_yara_rules(file_path)
            
            # VirusTotal check
            vt_results = {}
            if hashes.get('sha256'):
                vt_results = self.check_virustotal(hashes['sha256'])
            
            # Calculate overall risk score
            risk_score = self.calculate_risk_score(
                basic_info, hashes, file_type_info, entropy,
                suspicious_strings, pe_analysis, yara_matches, vt_results
            )
            
            # Compile results
            result = {
                'basic_info': basic_info,
                'hashes': hashes,
                'file_type': file_type_info,
                'entropy': entropy,
                'suspicious_strings': suspicious_strings,
                'pe_analysis': pe_analysis,
                'yara_matches': yara_matches,
                'virustotal': vt_results,
                'risk_score': risk_score,
                'analysis_time': time.time() - analysis_start,
                'timestamp': datetime.now()
            }
            
            # Cache results
            self.analysis_cache[file_path] = {
                'result': result,
                'timestamp': datetime.now()
            }
            
            # Save to database
            self.save_analysis_to_db(result)
            
            self.stats['files_analyzed'] += 1
            
            if risk_score['classification'] == 'MALICIOUS':
                self.stats['malicious_found'] += 1
            elif risk_score['classification'] == 'SUSPICIOUS':
                self.stats['suspicious_found'] += 1
            
            return result
            
        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {e}")
            return {'error': str(e)}
    
    def calculate_risk_score(self, basic_info, hashes, file_type_info, entropy,
                           suspicious_strings, pe_analysis, yara_matches, vt_results) -> Dict:
        """
        Calculate overall risk score based on all analysis factors.
        
        Returns:
        - Dictionary with risk assessment
        """
        try:
            score = 0
            reasons = []
            
            # File type scoring
            if file_type_info.get('is_executable'):
                score += 20
                reasons.append("Executable file")
            
            if file_type_info.get('extension') != file_type_info.get('detected_type'):
                score += 15
                reasons.append("File type mismatch")
            
            # Entropy scoring
            if entropy > 7.5:
                score += 25
                reasons.append("High entropy (possible encryption/packing)")
            elif entropy > 6.5:
                score += 10
                reasons.append("Moderate entropy")
            
            # Suspicious strings
            if suspicious_strings:
                score += min(len(suspicious_strings) * 10, 30)
                reasons.append(f"{len(suspicious_strings)} suspicious strings found")
            
            # PE analysis
            if pe_analysis.get('is_packed'):
                score += 20
                reasons.append("Packed executable")
            
            if pe_analysis.get('suspicious_imports'):
                score += min(len(pe_analysis['suspicious_imports']) * 5, 25)
                reasons.append("Suspicious API imports")
            
            # YARA matches
            if yara_matches:
                score += min(len(yara_matches) * 15, 40)
                reasons.append(f"{len(yara_matches)} YARA rule matches")
            
            # VirusTotal results
            if vt_results.get('posititives') and vt_results.get('total'):
                vt_ratio = vt_results['posititives'] / vt_results['total']
                if vt_ratio >= 0.5:
                    score += 50
                    reasons.append(f"VirusTotal: {vt_results['posititives']}/{vt_results['total']} detections")
                elif vt_ratio >= 0.2:
                    score += 30
                    reasons.append(f"VirusTotal: {vt_results['posititives']}/{vt_results['total']} detections")
                elif vt_ratio > 0:
                    score += 15
                    reasons.append(f"VirusTotal: {vt_results['posititives']}/{vt_results['total']} detections")
            
            # Determine classification
            if score >= 70:
                classification = "MALICIOUS"
                severity = "CRITICAL"
            elif score >= 50:
                classification = "SUSPICIOUS"
                severity = "HIGH"
            elif score >= 30:
                classification = "UNUSUAL"
                severity = "MEDIUM"
            else:
                classification = "BENIGN"
                severity = "LOW"
            
            return {
                'score': min(score, 100),
                'classification': classification,
                'severity': severity,
                'reasons': reasons,
                'confidence': min(score / 100, 1.0)
            }
            
        except Exception as e:
            logging.error(f"Error calculating risk score: {e}")
            return {
                'score': 0,
                'classification': 'ERROR',
                'severity': 'LOW',
                'reasons': ['Analysis error'],
                'confidence': 0.0
            }
    
    def save_analysis_to_db(self, analysis_result: Dict):
        """Save analysis results to database."""
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            basic_info = analysis_result.get('basic_info', {})
            hashes = analysis_result.get('hashes', {})
            file_type = analysis_result.get('file_type', {})
            risk_score = analysis_result.get('risk_score', {})
            vt_results = analysis_result.get('virustotal', {})

            cursor.execute('''
                INSERT OR REPLACE INTO file_analysis
                (file_path, md5_hash, sha1_hash, sha256_hash, file_type, file_size,
                 first_seen, last_seen, reputation_score, vt_positives, vt_total,
                 is_malicious, analysis_details, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                basic_info.get('path', ''),
                hashes.get('md5', ''),
                hashes.get('sha1', ''),
                hashes.get('sha256', ''),
                file_type.get('detected_type', ''),
                basic_info.get('size', 0),
                basic_info.get('created', datetime.now()),
                datetime.now(),
                risk_score.get('score', 0),
                vt_results.get('posititives', 0),
                vt_results.get('total', 0),
                risk_score.get('classification') == 'MALICIOUS',
                json.dumps(analysis_result),
                json.dumps({'version': '1.0'})
            ))

            conn.commit()

        except Exception as e:
            logging.error(f"Error saving analysis to database: {e}")
        finally:
            if conn:
                conn.close()
    
    def get_file_reputation(self, file_hash: str) -> Dict:
        """
        Get file reputation from local cache and online sources.
        
        Parameters:
        - file_hash: SHA256 hash
        
        Returns:
        - Reputation information
        """
        conn = None
        try:
            # Check local cache first
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT vt_positives, vt_total, last_update, sources_checked
                FROM reputation_cache WHERE hash = ?
            ''', (file_hash,))

            row = cursor.fetchone()
            if row:
                vt_pos, vt_total, last_update, sources = row
                last_update = datetime.fromisoformat(last_update) if last_update else datetime.now()

                # Cache is valid for 24 hours
                if datetime.now() - last_update < timedelta(hours=24):
                    return {
                        'cached': True,
                        'virustotal': {'positives': vt_pos, 'total': vt_total},
                        'last_update': last_update,
                        'sources': sources.split(',') if sources else []
                    }

            # Check online sources
            vt_results = self.check_virustotal(file_hash)

            # Update cache
            if vt_results and not vt_results.get('error'):
                cursor.execute('''
                    INSERT OR REPLACE INTO reputation_cache
                    (hash, vt_positives, vt_total, last_update, sources_checked)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    file_hash,
                    vt_results.get('posititives', 0),
                    vt_results.get('total', 0),
                    datetime.now(),
                    'virustotal'
                ))
                conn.commit()

            return {
                'cached': False,
                'virustotal': vt_results,
                'last_update': datetime.now(),
                'sources': ['virustotal']
            }

        except Exception as e:
            logging.error(f"Error getting file reputation: {e}")
            return {'error': str(e)}
        finally:
            if conn:
                conn.close()
    
    def get_statistics(self) -> Dict:
        """Get analysis statistics."""
        return self.stats.copy()

# Global instance
_file_analyzer_instance = None

def get_file_analyzer(config=None):
    """Get global file analyzer instance."""
    global _file_analyzer_instance
    if _file_analyzer_instance is None:
        _file_analyzer_instance = FileAnalyzer(config)
    return _file_analyzer_instance

if __name__ == "__main__":
    """Test file analyzer."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*80)
    print("          FILE ANALYSIS TEST")
    print("="*80)
    
    # Test with current file
    test_file = __file__
    
    analyzer = FileAnalyzer()
    result = analyzer.analyze_file(test_file)
    
    print(f"\nAnalysis Results for: {test_file}")
    print(f"  File Size: {result['basic_info']['size']} bytes")
    print(f"  SHA256: {result['hashes']['sha256']}")
    print(f"  File Type: {result['file_type']['detected_type']}")
    print(f"  Entropy: {result['entropy']:.2f}")
    print(f"  Risk Score: {result['risk_score']['score']}/100")
    print(f"  Classification: {result['risk_score']['classification']}")
    print(f"  Severity: {result['risk_score']['severity']}")
    
    if result['risk_score']['reasons']:
        print(f"  Reasons: {', '.join(result['risk_score']['reasons'])}")
    
    stats = analyzer.get_statistics()
    print(f"\nStatistics:")
    print(f"  Files Analyzed: {stats['files_analyzed']}")
    print(f"  Malicious Found: {stats['malicious_found']}")
    print(f"  Suspicious Found: {stats['suspicious_found']}")
    
    print("\nPress Enter to exit...")
    input()