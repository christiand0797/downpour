"""
__version__ = "29.0.0"
File Scanner - v29
__version__ = "29.0.0"

================================================================================
FILE & FOLDER SCANNER - On-Demand Security Analysis
===============================================================================

Comprehensive scanner for files and folders with:
- Hash-based malware detection
- Pattern matching for suspicious content
- File metadata analysis
- Archive scanning (ZIP, RAR, etc.)
- Detailed threat reports
- Quarantine capabilities
"""

import os
import hashlib
import mimetypes
import logging
import json
from pathlib import Path
from datetime import datetime
import zipfile
import tarfile
import re
from collections import defaultdict

# Try to import advanced features
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False


class FileScanner:
    """Comprehensive file and folder scanner with threat detection."""
    
    def __init__(self, threat_db=None):
        self.threat_db = threat_db  # ThreatIntelligenceUpdater instance
        self.scan_results = []
        self.statistics = defaultdict(int)
        
        # Suspicious file patterns
        # v28p37: Dramatically tightened to reduce false positives.
        # Philosophy: flag DECEPTION (files pretending to be something they're not),
        # not CAPABILITY (files that are executables — that's just normal software).
        self.suspicious_patterns = {
            'double_extension': re.compile(r'\.(exe|scr|bat|cmd|vbs|js|jar|com|pif)\.(txt|pdf|doc|xls|jpg|png|mp3|mp4|avi)$', re.IGNORECASE),
            # REMOVED 'suspicious_names' — words like "invoice" and "password" appear
            # in millions of legitimate files. Flagging them generated massive FPs.
            'suspicious_names': [],
            # REMOVED blanket extension flagging — every .exe on the system was
            # being flagged as "dangerous". Extensions indicate file TYPE, not INTENT.
            # Only flag truly rare/abused extensions that normal users never encounter.
            'dangerous_extensions': [
                '.scr', '.pif', '.hta', '.wsh', '.wsf', '.sct',
                '.application', '.gadget',
            ],
            'macro_extensions': [
                '.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm',
                '.ppsm', '.sldm'
            ]
        }
        
        # Suspicious content patterns (hex signatures)
        self.file_signatures = {
            'PE_EXECUTABLE': b'MZ',  # Windows executable
            'ELF_EXECUTABLE': b'\x7fELF',  # Linux executable
            'JAVA_CLASS': b'\xCA\xFE\xBA\xBE',  # Java class file
            'FLASH': b'FWS',  # Flash file
            'PDF': b'%PDF',  # PDF file
            'ZIP': b'PK\x03\x04',  # ZIP archive
            'RAR': b'Rar!\x1a\x07',  # RAR archive
            'SCRIPT_TAG': b'<script',  # HTML with script
            'POWERSHELL': b'powershell',  # PowerShell content
        }
    
    def scan_file(self, file_path):
        """Perform comprehensive scan of a single file."""
        result = {
            'file_path': str(file_path),
            'file_name': Path(file_path).name,
            'scan_time': datetime.now().isoformat(),
            'is_malicious': False,
            'threats': [],
            'warnings': [],
            'file_info': {},
            'hashes': {}
        }
        
        try:
            # Check if file exists and is accessible
            if not os.path.exists(file_path):
                result['error'] = 'File not found'
                return result
            
            if not os.path.isfile(file_path):
                result['error'] = 'Not a file'
                return result
            
            # Get file info
            result['file_info'] = self.get_file_info(file_path)
            
            # Calculate hashes
            result['hashes'] = self.calculate_all_hashes(file_path)
            
            # Check against threat database
            if self.threat_db:
                hash_check = self.threat_db.check_file_hash(file_path)
                if hash_check.get('is_malicious'):
                    result['is_malicious'] = True
                    result['threats'].append({
                        'type': 'KNOWN_MALWARE',
                        'severity': hash_check.get('severity', 'CRITICAL'),
                        'description': f"File matches known malware: {hash_check.get('threat_name')}",
                        'source': hash_check.get('source', 'Unknown')
                    })
            
            # v28p36: Check magic byte / extension mismatch
            if result['file_info'].get('extension_mismatch'):
                detail = result['file_info'].get('magic_detail', 'Extension mismatch')
                result['threats'].append({
                    'type': 'EXTENSION_MISMATCH',
                    'severity': 'HIGH',
                    'description': f"File type disguise detected: {detail}",
                    'source': 'Magic Byte Analysis'
                })
                # PE executable disguised as non-exe is CRITICAL
                if result['file_info'].get('magic_type') == 'exe':
                    result['is_malicious'] = True
                    result['threats'][-1]['severity'] = 'CRITICAL'
                    result['threats'][-1]['description'] = (
                        f"EXECUTABLE disguised as '{result['file_info'].get('extension')}' "
                        f"— potential malware dropper"
                    )

            # Check file name patterns
            name_threats = self.check_suspicious_name(file_path)
            if name_threats:
                result['warnings'].extend(name_threats)
            
            # Check file content
            content_threats = self.check_file_content(file_path, result['file_info'])
            if content_threats:
                result['threats'].extend(content_threats)
                if any(t['severity'] in ['CRITICAL', 'HIGH'] for t in content_threats):
                    result['is_malicious'] = True
            
            # Check for suspicious patterns
            pattern_warnings = self.check_suspicious_patterns(file_path, result['file_info'])
            if pattern_warnings:
                result['warnings'].extend(pattern_warnings)
            
            # Check archives
            if self.is_archive(file_path):
                archive_results = self.scan_archive(file_path)
                if archive_results.get('threats'):
                    result['threats'].extend(archive_results['threats'])
                    result['is_malicious'] = True
                if archive_results.get('warnings'):
                    result['warnings'].extend(archive_results['warnings'])
            
            # Update statistics
            self.statistics['files_scanned'] += 1
            if result['is_malicious']:
                self.statistics['threats_found'] += 1
            if result['warnings']:
                self.statistics['warnings_generated'] += len(result['warnings'])
            
        except Exception as e:
            result['error'] = str(e)
            logging.error(f"SCAN_ERROR | Path: {file_path} | Error: {type(e).__name__}: {e}")
        
        self.scan_results.append(result)
        return result
    
    def scan_folder(self, folder_path, recursive=True):
        """Scan all files in a folder. Uses logging for visibility."""
        import logging as _logging
        _logging.info(f"Starting file scan in folder: {folder_path}")
        results = {
            'folder_path': str(folder_path),
            'scan_time': datetime.now().isoformat(),
            'files': [],
            'summary': {
                'total_files': 0,
                'malicious_files': 0,
                'suspicious_files': 0,
                'clean_files': 0
            }
        }
        
        try:
            folder = Path(folder_path)
            
            if not folder.exists():
                results['error'] = 'Folder not found'
                return results
            
            if not folder.is_dir():
                results['error'] = 'Not a folder'
                return results
            
            # Get all files
            if recursive:
                files = list(folder.rglob('*'))
            else:
                files = list(folder.glob('*'))
            
            # Filter only files (not directories)
            files = [f for f in files if f.is_file()]
            
            results['summary']['total_files'] = len(files)
            
            # Scan each file
            for file_path in files:
                file_result = self.scan_file(file_path)
                results['files'].append(file_result)
                
                if file_result.get('is_malicious'):
                    results['summary']['malicious_files'] += 1
                elif file_result.get('warnings'):
                    results['summary']['suspicious_files'] += 1
                else:
                    results['summary']['clean_files'] += 1
            
        except Exception as e:
            results['error'] = str(e)
            logging.error(f"Folder scan error for {folder_path}: {e}")
        
        return results
    
    # v28p36: Magic byte signatures for file type detection
    _MAGIC_BYTES = {
        b'MZ':                          'exe',    # PE executable
        b'\x7fELF':                     'elf',    # ELF binary
        b'PK\x03\x04':                 'zip',    # ZIP archive (also docx/xlsx/jar)
        b'PK\x05\x06':                 'zip',    # ZIP empty archive
        b'\x50\x4b\x07\x08':           'zip',    # ZIP spanned
        b'\x1f\x8b':                    'gz',     # Gzip
        b'Rar!\x1a\x07':               'rar',    # RAR archive
        b'\xfd7zXZ\x00':               'xz',     # XZ archive
        b'7z\xbc\xaf\x27\x1c':        '7z',     # 7-Zip
        b'\x25PDF':                     'pdf',    # PDF document
        b'\xd0\xcf\x11\xe0':           'ole',    # OLE2 (doc/xls/ppt)
        b'\x89PNG':                     'png',    # PNG image
        b'\xff\xd8\xff':               'jpg',    # JPEG image
        b'GIF87a':                      'gif',    # GIF 87a
        b'GIF89a':                      'gif',    # GIF 89a
        b'RIFF':                        'riff',   # WAV/AVI/WebP
        b'\x00\x00\x01\x00':           'ico',    # ICO
        b'#!':                          'script', # Shell script / shebang
        b'\xca\xfe\xba\xbe':           'java',   # Java class / Mach-O fat
        b'\xef\xbb\xbf':               'bom',    # UTF-8 BOM text
    }

    # Extension groups that match magic byte types
    _MAGIC_EXT_MAP = {
        'exe': {'.exe', '.dll', '.sys', '.scr', '.ocx', '.cpl', '.drv'},
        'elf': {'.so', '.bin', '.elf', '.out'},
        'zip': {'.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk', '.odt', '.ods'},
        'gz':  {'.gz', '.tgz'},
        'rar': {'.rar'},
        'xz':  {'.xz', '.txz'},
        '7z':  {'.7z'},
        'pdf': {'.pdf'},
        'ole': {'.doc', '.xls', '.ppt', '.msg'},
        'png': {'.png'},
        'jpg': {'.jpg', '.jpeg', '.jfif'},
        'gif': {'.gif'},
        'riff': {'.wav', '.avi', '.webp'},
        'script': {'.sh', '.bash', '.py', '.pl', '.rb', '.ps1', '.bat', '.cmd'},
    }

    def detect_magic_type(self, file_path):
        """Detect real file type from magic bytes. Returns (type_name, is_mismatch, detail)."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
            if len(header) < 2:
                return (None, False, '')
            for sig, ftype in self._MAGIC_BYTES.items():
                if header[:len(sig)] == sig:
                    ext = Path(file_path).suffix.lower()
                    expected_exts = self._MAGIC_EXT_MAP.get(ftype, set())
                    if expected_exts and ext and ext not in expected_exts:
                        return (ftype, True, f"Extension '{ext}' but magic bytes indicate '{ftype}'")
                    return (ftype, False, '')
            return (None, False, '')
        except Exception:
            return (None, False, '')

    def get_file_info(self, file_path):
        """Get comprehensive file information including magic byte analysis."""
        try:
            stat = os.stat(file_path)
            path = Path(file_path)

            info = {
                'size': stat.st_size,
                'size_human': self.format_size(stat.st_size),
                'extension': path.suffix.lower(),
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            }

            # Get MIME type
            mime_type, _ = mimetypes.guess_type(file_path)
            info['mime_type'] = mime_type or 'unknown'

            # Check if executable
            info['is_executable'] = path.suffix.lower() in self.suspicious_patterns['dangerous_extensions']

            # v28p36: Magic byte detection — real file type
            magic_type, is_mismatch, detail = self.detect_magic_type(file_path)
            info['magic_type'] = magic_type
            info['extension_mismatch'] = is_mismatch
            info['magic_detail'] = detail

            return info

        except Exception as e:
            logging.error(f"File info error: {e}")
            return {}
    
    def calculate_all_hashes(self, file_path):
        """Calculate MD5, SHA1, and SHA256 hashes."""
        hashes = {}
        
        try:
            # Read file in chunks to handle large files
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            
            hashes['md5'] = md5.hexdigest()
            hashes['sha1'] = sha1.hexdigest()
            hashes['sha256'] = sha256.hexdigest()
            
        except Exception as e:
            logging.error(f"Hash calculation error: {e}")
        
        return hashes
    
    def check_suspicious_name(self, file_path):
        """Check for suspicious file name patterns.

        v28p37: Dramatically reduced false positives. Only flags DECEPTIVE naming
        (double extensions, truly rare dangerous extensions), NOT normal software.
        """
        warnings = []
        path = Path(file_path)
        name = path.name.lower()

        # Check for double extension — this IS genuinely suspicious (file disguise)
        if self.suspicious_patterns['double_extension'].search(name):
            warnings.append({
                'type': 'SUSPICIOUS_NAME',
                'severity': 'HIGH',
                'description': 'File has double extension (possible disguise attempt)',
                'detail': f'Suspicious pattern in filename: {path.name}'
            })

        # v28p37: REMOVED keyword-based flagging entirely.
        # Words like "invoice", "password", "receipt" appear in millions of
        # legitimate business files. Flagging them was the #1 source of FPs.

        # Only flag truly rare/abused extensions that normal users never encounter
        # (.scr, .pif, .hta, .wsh etc.) — NOT .exe, .bat, .ps1 which are normal.
        if path.suffix.lower() in self.suspicious_patterns['dangerous_extensions']:
            # Even then, only flag if the file is in a user-facing location
            # (not system directories where these may legitimately exist)
            path_lower = str(file_path).lower()
            is_system_path = any(p in path_lower for p in [
                '\\windows\\', '\\program files', '\\programdata\\',
                '\\winsxs\\', '\\system32\\', '\\syswow64\\'
            ])
            if not is_system_path:
                warnings.append({
                    'type': 'RARE_EXTENSION',
                    'severity': 'MEDIUM',
                    'description': f'File has rarely-used executable extension: {path.suffix}',
                    'detail': 'This file type is uncommon and sometimes used by malware'
                })

        # Macro documents: only warn, don't treat as threat — many orgs use macros
        if path.suffix.lower() in self.suspicious_patterns['macro_extensions']:
            warnings.append({
                'type': 'MACRO_DOCUMENT',
                'severity': 'LOW',
                'description': 'Macro-enabled document detected',
                'detail': 'Review macros before enabling if from untrusted source'
            })

        return warnings
    
    def check_file_content(self, file_path, file_info):
        """Check file content for suspicious patterns.

        v28p37: Dramatically tightened to only flag genuine deception, not capability.
        - PE magic bytes (MZ) appearing at offset 0 of a non-executable extension = real threat
        - PE bytes appearing somewhere inside another file = normal (embedded resources)
        - "powershell" or "<script" appearing in binary data = not a threat (common in docs, configs)
        """
        threats = []

        try:
            with open(file_path, 'rb') as f:
                header = f.read(1024)

            ext = Path(file_path).suffix.lower()

            # Only check PE_EXECUTABLE: flag when a file STARTS with MZ but has
            # a non-executable extension (actual file type disguise).
            # The magic-byte mismatch detection in get_file_info already handles
            # this more accurately, so only flag clear-cut cases here.
            if header[:2] == b'MZ':
                pe_extensions = {'.exe', '.dll', '.sys', '.scr', '.ocx', '.cpl',
                                 '.drv', '.msi', '.msp', '.mui', '.efi', '.ax',
                                 '.acm', '.tsp', '.ime'}
                if ext and ext not in pe_extensions:
                    # Skip known container formats that can legitimately contain MZ
                    container_exts = {'.zip', '.rar', '.7z', '.cab', '.iso',
                                      '.img', '.wim', '.vhd', '.vmdk', '.msu',
                                      '.msix', '.appx', '.nupkg', '.vsix'}
                    if ext not in container_exts:
                        threats.append({
                            'type': 'HIDDEN_EXECUTABLE',
                            'severity': 'CRITICAL',
                            'description': f'PE executable disguised as {ext} file',
                            'detail': 'File starts with MZ header but has non-executable extension'
                        })

            # v28p37: REMOVED "SCRIPT_TAG" and "POWERSHELL" content checks.
            # The string "powershell" appears in thousands of legitimate files
            # (documentation, config files, log files, help text).
            # "<script" appears in every HTML file and many documents.
            # These were generating enormous numbers of false positives.

            # v28p37: REMOVED "suspicious size" check for large .txt/.jpg/.png/.pdf.
            # Large PDFs (textbooks, manuals) and large images (photography, medical)
            # are completely normal. Size alone is never an indicator of malice.

        except Exception as e:
            logging.error(f"Content check error: {e}")

        return threats
    
    def check_suspicious_patterns(self, file_path, file_info):
        """Check for additional suspicious patterns.

        v28p37: Dramatically tightened. Only flag patterns that indicate
        actual deception or evasion, not normal system behavior.
        - Hidden files: Only flag if ALSO executable and in user-facing location
        - Recently created: REMOVED entirely — files get created constantly
        """
        warnings = []

        try:
            # Check for hidden EXECUTABLE files in user directories
            # (hidden non-executables are completely normal — desktop.ini, thumbs.db, etc.)
            if os.name == 'nt':
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                FILE_ATTRIBUTE_SYSTEM = 0x04
                attrs = ctypes.windll.kernel32.GetFileAttributesW(str(file_path))
                if attrs != -1 and (attrs & FILE_ATTRIBUTE_HIDDEN):
                    ext = Path(file_path).suffix.lower()
                    executable_exts = {'.exe', '.scr', '.bat', '.cmd', '.vbs',
                                       '.ps1', '.hta', '.pif', '.com', '.wsf'}
                    path_lower = str(file_path).lower()
                    # Only flag hidden executables outside of system directories
                    is_system_dir = any(p in path_lower for p in [
                        '\\windows\\', '\\program files', '\\programdata\\',
                        '\\winsxs\\', '\\system32\\', '\\syswow64\\',
                        '\\assembly\\', '\\installer\\'
                    ])
                    if ext in executable_exts and not is_system_dir:
                        warnings.append({
                            'type': 'HIDDEN_EXECUTABLE',
                            'severity': 'HIGH',
                            'description': f'Hidden executable file: {Path(file_path).name}',
                            'detail': 'Executable with hidden attribute in user directory'
                        })

            # v28p37: REMOVED "recently created" check.
            # Files are created constantly during normal operation — installs,
            # downloads, temp files, builds, updates. Age alone means nothing.

        except Exception as e:
            logging.error(f"Pattern check error: {e}")

        return warnings
    
    def is_archive(self, file_path):
        """Check if file is an archive."""
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz']
        return Path(file_path).suffix.lower() in archive_extensions
    
    def scan_archive(self, archive_path):
        """Scan contents of archive file.

        v28p37: Only flag archives with DECEPTIVE content (double extensions,
        disguised executables), not archives that simply contain .exe files.
        Software installers, game mods, and tools are commonly distributed as
        archives containing executables — that's completely normal.
        """
        archive_path = str(archive_path)
        results = {
            'archive_type': Path(archive_path).suffix,
            'files': [],
            'threats': [],
            'warnings': []
        }

        try:
            members = []
            if archive_path.endswith('.zip'):
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    members = zf.namelist()
            elif archive_path.endswith(('.tar', '.tar.gz', '.tgz')):
                with tarfile.open(archive_path, 'r:*') as tf:
                    members = [m.name for m in tf.getmembers() if m.isfile()]

            for member in members:
                member_lower = member.lower()
                # Flag double extensions inside archives (actual deception)
                if self.suspicious_patterns['double_extension'].search(member_lower):
                    results['threats'].append({
                        'type': 'ARCHIVE_DISGUISED_FILE',
                        'severity': 'HIGH',
                        'description': f'Archive contains disguised file: {member}',
                        'detail': 'Double extension detected — file is pretending to be a different type'
                    })
                # Flag .hta, .scr, .pif etc. in archives (genuinely rare/suspicious)
                elif any(member_lower.endswith(ext) for ext in self.suspicious_patterns['dangerous_extensions']):
                    results['warnings'].append({
                        'type': 'ARCHIVE_RARE_EXTENSION',
                        'severity': 'MEDIUM',
                        'description': f'Archive contains rarely-used executable type: {member}',
                        'detail': 'This file type is uncommon and sometimes used by malware'
                    })

        except Exception as e:
            logging.error(f"Archive scan error: {e}")
            results['error'] = str(e)

        return results
    
    @staticmethod
    def format_size(size_bytes):
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} TB"
    
    def get_scan_report(self):
        """Generate comprehensive scan report."""
        report = {
            'scan_time': datetime.now().isoformat(),
            'statistics': dict(self.statistics),
            'results': self.scan_results,
            'summary': {
                'total_scanned': self.statistics['files_scanned'],
                'threats_found': self.statistics['threats_found'],
                'warnings_generated': self.statistics['warnings_generated'],
                'clean_files': self.statistics['files_scanned'] - self.statistics['threats_found']
            }
        }
        
        return report
    
    def export_report(self, output_path):
        """Export scan report to JSON file."""
        try:
            report = self.get_scan_report()
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            logging.info(f"Scan report exported to {output_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to export report: {e}")
            return False
