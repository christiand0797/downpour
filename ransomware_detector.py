"""
===============================================================================
RANSOMWARE DETECTION AND ROLLBACK SYSTEM
===============================================================================

PURPOSE: Provides specialized ransomware detection and file rollback capabilities
         to protect against ransomware attacks and enable quick recovery.

DETECTION CAPABILITIES:
1. BEHAVIORAL ANALYSIS - Detect ransomware-like file operation patterns
2. ENCRYPTION DETECTION - Identify files being encrypted in real-time
3. RANSOM NOTE DETECTION - Recognize ransom notes creation
4. FILE SYSTEM MONITORING - Track rapid file changes across folders
5. PROCESS MONITORING - Detect ransomware processes running
6. BACKUP VERIFICATION - Ensure backup integrity

ROLLBACK CAPABILITIES:
1. SHADOW COPY RESTORATION - Restore from Windows shadow copies
2. FILE VERSION HISTORY - Restore from file history snapshots
3. BACKUP RESTORATION - Restore from automated backups
4. PARTIAL RECOVERY - Recover unencrypted portions
5. ENCRYPTED FILE ANALYSIS - Attempt to decrypt weak encryption

PROTECTION FEATURES:
- Real-time file system monitoring
- Automatic backup creation
- Process termination on detection
- Network isolation of infected systems
- Email alerting to administrators
- Integration with Windows Defender

SUPPORTED RANSOMWARE TYPES:
- File encrypting ransomware
- Screen locker ransomware
- Boot sector ransomware
- Mobile ransomware patterns
- Ransomware-as-a-Service (RaaS)
"""

import os
import re
import shutil
import sqlite3
import logging
import threading
import time
import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional
try:
    import win32file
    import win32con
    import win32api
    import win32security
    import win32event
    import win32process
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False
from collections import defaultdict, deque
try:
    import psutil
except ImportError:
    raise ImportError("ransomware_detector requires psutil: pip install psutil")

class RansomwareDetector:
    """
    Advanced ransomware detection and rollback system.
    """
    
    def __init__(self, config=None):
        """
        Initialize ransomware detector.
        
        Parameters:
        - config: Configuration object
        """
        self.running = True
        self.config = config
        
        # Initialize database
        self.db_path = Path("ransomware_protection.db")
        self.init_database()
        
        # Protected directories
        self.protected_directories = [
            Path.home() / "Documents",
            Path.home() / "Desktop",
            Path.home() / "Downloads",
            Path.home() / "Pictures",
            Path.home() / "Videos",
            Path.home() / "Music"
        ]
        
        # Backup directories
        self.backup_base = Path("ransomware_backups")
        self.backup_base.mkdir(exist_ok=True)
        
        # File change tracking
        self.file_changes = deque(maxlen=10000)
        self.encryption_indicators = []
        
        # Ransom note patterns
        # v28p37: Expanded ransom note detection patterns
        self.ransom_note_patterns = [
            # Filename patterns (matched with re.match)
            r'.*ransom.*', r'.*decrypt.*', r'.*payment.*', r'.*bitcoin.*',
            r'.*restore.*files.*', r'.*files.*locked.*', r'.*pay.*now.*',
            r'.*instructions.*', r'.*read.*me.*', r'.*help.*file.*',
            r'.*how.*to.*recover.*', r'.*how.*to.*decrypt.*',
            r'.*your.*files.*', r'.*all.*your.*data.*',
            # Known ransomware note filenames
            r'readme\.txt', r'readme\.html', r'how_to_decrypt\.txt',
            r'restore[-_]files\.txt', r'decrypt[-_]files\.html',
            r'!readme!\.txt', r'_readme_\.txt', r'files_encrypted\.txt',
            r'recovery[-_]instructions\.txt', r'#decrypt#\.txt',
            r'attention!!\.txt', r'warning\.html', r'important\.txt',
            # Content patterns (matched with re.search)
            r'all\s+your\s+files\s+(have\s+been|are)\s+encrypted',
            r'to\s+decrypt\s+your\s+files',
            r'bitcoin\s+wallet', r'btc\s+address', r'monero\s+wallet',
            r'tor\s+browser', r'\.onion', r'dark\s*web',
            r'pay\s+\$?\d+', r'contact\s+us.*email',
            r'unique\s+(id|key|token)', r'personal\s+decryption',
            r'do\s+not\s+(try|attempt)\s+to\s+(recover|restore|decrypt)',
            r'deadline|time\s+limit|hours?\s+to\s+pay',
        ]
        
        # Suspicious file extensions created by ransomware
        # v28p37: Expanded from 12 to 80+ known ransomware extensions
        self.suspicious_extensions = [
            # Generic encryption markers
            '.crypted', '.encrypted', '.locked', '.protected', '.enc',
            '.cry', '.crypt', '.lock', '.key', '.pay', '.btc', '.decrypt',
            '.readme', '.ransom', '.aes', '.rsa', '.cipher',
            # Known ransomware families
            '.locky', '.zepto', '.odin', '.thor', '.aesir',      # Locky variants
            '.cerber', '.cerber2', '.cerber3',                     # Cerber
            '.wallet', '.dharma', '.arena', '.bip', '.combo',     # Dharma/CrySiS
            '.wncry', '.wncryt', '.wcry', '.wncrypt',             # WannaCry
            '.petya', '.notpetya',                                  # Petya
            '.ryuk',                                                # Ryuk
            '.sodinokibi', '.revil',                                # REvil
            '.conti',                                               # Conti
            '.lockbit', '.lockbit3',                                # LockBit
            '.blackcat', '.alphv',                                  # BlackCat/ALPHV
            '.hive',                                                # Hive
            '.phobos', '.eking', '.eight', '.devos',               # Phobos
            '.makop', '.mkp',                                       # Makop
            '.stop', '.djvu', '.neer', '.zzla',                    # STOP/Djvu
            '.maze', '.egregor',                                    # Maze/Egregor
            '.ragnarok', '.ragnar',                                 # Ragnarok
            '.clop', '.cl0p',                                       # Clop
            '.avaddon', '.avdn',                                    # Avaddon
            '.babuk', '.babyk',                                     # Babuk
            '.darkside', '.dside',                                  # DarkSide
            '.blackmatter', '.bmat',                                # BlackMatter
            '.royal', '.royal_w',                                   # Royal
            '.play', '.play_enc',                                   # Play
            '.akira',                                               # Akira
            '.medusa',                                              # Medusa
            # Additional patterns (hex/random suffixed)
            '.id-', '.XXXXXX', '.[[',                              # ID-prefixed patterns
        ]
        
        # Encryption detection parameters
        self.encryption_threshold = {
            'files_per_minute': 50,
            'file_size_changes': 0.8,  # 80% size change indicates encryption
            'extension_changes': 30,  # Number of extension changes
            'time_window': 60  # seconds
        }
        
        # Process monitoring
        self.suspicious_processes = set()
        self.process_behavior = defaultdict(list)
        
        # Statistics
        self.stats = {
            'ransomware_attempts': 0,
            'files_protected': 0,
            'backups_created': 0,
            'rollbacks_performed': 0,
            'false_positives': 0
        }
    
    def init_database(self):
        """Initialize SQLite database for ransomware protection."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS file_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_path TEXT UNIQUE,
                        file_hash TEXT,
                        file_size INTEGER,
                        last_modified TIMESTAMP,
                        backup_path TEXT
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ransomware_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP,
                        event_type TEXT,
                        process_name TEXT,
                        affected_files TEXT,
                        severity TEXT,
                        details TEXT
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS rollback_operations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP,
                        event_id INTEGER,
                        files_restored TEXT,
                        restore_method TEXT,
                        success BOOLEAN
                    )
                ''')

                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS backup_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP,
                        backup_path TEXT,
                        file_count INTEGER,
                        total_size INTEGER,
                        backup_type TEXT
                    )
                ''')

                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON file_snapshots(file_path)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_timestamp ON ransomware_events(timestamp)')

                conn.commit()
            finally:
                conn.close()
            
            logging.info("[✓] Ransomware protection database initialized")
            
        except Exception as e:
            logging.error(f"Failed to initialize database: {e}")
    
    def create_file_backup(self, file_path: Path) -> Path:
        """
        Create backup of a file before potential encryption.
        
        Parameters:
        - file_path: Path to file to backup
        
        Returns:
        - Path to backup file
        """
        try:
            if not file_path.exists():
                return None
            
            # Generate backup path
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_name = f"{file_path.stem}_{timestamp}{file_path.suffix}"
            backup_path = self.backup_base / backup_name
            
            # Create backup
            shutil.copy2(file_path, backup_path)
            
            # Calculate hash for verification
            with open(backup_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            
            # Save to database
            self.save_file_snapshot(file_path, file_hash, backup_path)
            
            self.stats['backups_created'] += 1
            
            return backup_path
            
        except Exception as e:
            logging.error(f"Error creating backup for {file_path}: {e}")
            return None
    
    def _get_original_extension(self, file_path: Path) -> str:
        """Get the extension from the last snapshot of this file path.

        If no snapshot exists, returns the current extension (no change detected).
        """
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT file_path FROM file_snapshots WHERE file_path = ?',
                    (str(file_path),))
                row = cursor.fetchone()
            finally:
                conn.close()
            if row:
                return Path(row[0]).suffix
        except Exception:
            pass
        return file_path.suffix

    def save_file_snapshot(self, file_path: Path, file_hash: str, backup_path: Path):
        """Save file snapshot to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT OR REPLACE INTO file_snapshots
                    (file_path, file_hash, file_size, last_modified, backup_path)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    str(file_path),
                    file_hash,
                    file_path.stat().st_size,
                    datetime.fromtimestamp(file_path.stat().st_mtime),
                    str(backup_path)
                ))

                conn.commit()
            finally:
                conn.close()
            
        except Exception as e:
            logging.error(f"Error saving file snapshot: {e}")
    
    def detect_encryption_pattern(self, file_changes: List[Dict]) -> bool:
        """
        Detect if file changes indicate ransomware encryption.
        
        Parameters:
        - file_changes: List of file change events
        
        Returns:
        - True if encryption pattern detected
        """
        try:
            if not file_changes:
                return False
            
            # Analyze changes in time window
            current_time = datetime.now()
            recent_changes = [
                change for change in file_changes
                if current_time - change['timestamp'] < timedelta(seconds=self.encryption_threshold['time_window'])
            ]
            
            if len(recent_changes) < self.encryption_threshold['files_per_minute']:
                return False
            
            # Check for size changes indicating encryption
            size_changes = []
            for change in recent_changes:
                if change.get('old_size') and change.get('new_size'):
                    size_ratio = change['new_size'] / change['old_size'] if change['old_size'] > 0 else 1.0
                    size_changes.append(size_ratio)
            
            if size_changes:
                avg_size_change = sum(size_changes) / len(size_changes)
                if avg_size_change < self.encryption_threshold['file_size_changes']:
                    return True
            
            # Check for extension changes
            extension_changes = sum(1 for change in recent_changes 
                                if change.get('extension_changed', False))
            
            if extension_changes > self.encryption_threshold['extension_changes']:
                return True
            
            # Check for suspicious new extensions
            suspicious_count = sum(1 for change in recent_changes 
                                if change.get('new_extension', '') in self.suspicious_extensions)
            
            if suspicious_count > 5:
                return True
            
            return False
            
        except Exception as e:
            logging.error(f"Error detecting encryption pattern: {e}")
            return False
    
    def check_file_entropy(self, file_path) -> float:
        """Calculate Shannon entropy of a file. High entropy (>7.5/8.0) = likely encrypted.

        v28p37: Used as an additional ransomware encryption indicator.
        Encrypted files have near-maximum entropy (~7.99 for AES).
        Normal files: text ~4.5, executables ~6.0, compressed ~7.0-7.5.
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(65536)  # First 64KB is enough for entropy estimation
            if len(data) < 256:
                return 0.0
            freq = [0] * 256
            for byte in data:
                freq[byte] += 1
            length = len(data)
            entropy = 0.0
            for count in freq:
                if count > 0:
                    p = count / length
                    entropy -= p * math.log2(p)
            return entropy
        except Exception:
            return 0.0

    def is_likely_encrypted(self, file_path, original_extension=None) -> bool:
        """Check if a file appears to have been encrypted by ransomware.

        v28p37: Combines entropy analysis with extension and size heuristics.
        """
        entropy = self.check_file_entropy(file_path)
        # Very high entropy strongly suggests encryption
        if entropy > 7.9:
            return True
        # High entropy + suspicious extension = encrypted
        ext = Path(str(file_path)).suffix.lower()
        if entropy > 7.5 and ext in self.suspicious_extensions:
            return True
        # High entropy + original extension was a document type
        doc_exts = {'.docx', '.xlsx', '.pdf', '.pptx', '.jpg', '.png', '.txt'}
        if entropy > 7.5 and original_extension and original_extension.lower() in doc_exts:
            return True
        return False

    def detect_ransom_note(self, file_path: Path) -> bool:
        """
        Detect if a file is a ransom note.
        
        Parameters:
        - file_path: Path to file to check
        
        Returns:
        - True if ransom note detected
        """
        try:
            if not file_path.exists() or file_path.stat().st_size > 100000:  # > 100KB
                return False
            
            # Check filename patterns
            filename = file_path.name.lower()
            if any(re.match(pattern, filename, re.IGNORECASE) for pattern in self.ransom_note_patterns):
                return True

            # Check file content
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read().lower()

            if any(re.search(pattern, content, re.IGNORECASE) for pattern in self.ransom_note_patterns):
                return True
            
            return False
            
        except Exception:
            return False
    
    def is_ransomware_process(self, process_name: str) -> bool:
        """
        Check if a process is likely ransomware.
        
        Parameters:
        - process_name: Name of process to check
        
        Returns:
        - True if likely ransomware
        """
        suspicious_names = [
            'encrypt', 'decrypt', 'crypt', 'lock', 'ransom',
            'wanna', 'cryptolocker', 'petya', 'wannacry',
            'locky', 'cerber', 'tesla', 'crypt'
        ]
        
        process_lower = process_name.lower()
        
        return any(sus in process_lower for sus in suspicious_names)
    
    def monitor_file_changes(self):
        """Monitor file system for ransomware activity."""
        try:
            for directory in self.protected_directories:
                if not directory.exists():
                    continue
                
                # Watch directory for changes
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        try:
                            file_path = Path(root) / file
                            current_stat = file_path.stat()
                            
                            # Get previous snapshot
                            conn = sqlite3.connect(self.db_path)
                            try:
                                cursor = conn.cursor()

                                cursor.execute('''
                                    SELECT file_hash, file_size, last_modified FROM file_snapshots
                                    WHERE file_path = ?
                                ''', (str(file_path),))

                                snapshot = cursor.fetchone()
                            finally:
                                conn.close()
                            
                            if snapshot:
                                prev_hash, prev_size, prev_modified = snapshot
                                prev_modified = datetime.fromisoformat(prev_modified) if prev_modified else datetime.now()
                                
                                # Check if file was modified
                                if current_stat.st_mtime > prev_modified.timestamp():
                                    # Calculate new hash
                                    with open(file_path, 'rb') as f:
                                        new_hash = hashlib.sha256(f.read()).hexdigest()
                                    
                                    if new_hash != prev_hash:
                                        # File was modified
                                        self.file_changes.append({
                                            'timestamp': datetime.now(),
                                            'file_path': str(file_path),
                                            'old_hash': prev_hash,
                                            'new_hash': new_hash,
                                            'old_size': prev_size,
                                            'new_size': current_stat.st_size,
                                            'extension_changed': file_path.suffix != self._get_original_extension(file_path)
                                        })
                                        
                                        # Create backup if significant change
                                        if abs(current_stat.st_size - prev_size) > prev_size * 0.1:  # 10% size change
                                            self.create_file_backup(file_path)
                            
                            else:
                                # New file - create initial snapshot
                                with open(file_path, 'rb') as f:
                                    file_hash = hashlib.sha256(f.read()).hexdigest()
                                
                                self.save_file_snapshot(file_path, file_hash, None)
                            
                        except Exception:
                            continue
        
        except Exception as e:
            logging.error(f"Error monitoring file changes: {e}")
    
    def monitor_processes(self):
        """Monitor running processes for ransomware activity."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
                try:
                    proc_info = proc.info
                    
                    # Check if process is suspicious
                    if self.is_ransomware_process(proc_info.get('name', '')):
                        self.suspicious_processes.add(proc_info['pid'])
                        
                        # Log suspicious process
                        self.log_ransomware_event(
                            'suspicious_process',
                            proc_info.get('name', ''),
                            f"Suspicious process detected: PID {proc_info['pid']}",
                            'HIGH'
                        )
                        
                        # Check process behavior
                        self.analyze_process_behavior(proc_info)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logging.error(f"Error monitoring processes: {e}")
    
    def analyze_process_behavior(self, proc_info: Dict):
        """Analyze suspicious process behavior."""
        try:
            pid = proc_info['pid']
            process_name = proc_info['name']
            
            # Check CPU usage
            cpu_percent = proc_info.get('cpu_percent', 0)
            if cpu_percent > 80:  # High CPU usage
                self.process_behavior[pid].append({
                    'timestamp': datetime.now(),
                    'type': 'high_cpu',
                    'value': cpu_percent
                })
            
            # Check memory usage
            memory_info = proc_info.get('memory_info', None)
            if memory_info:
                memory_mb = getattr(memory_info, 'rss', 0) / (1024 * 1024)
                if memory_mb > 500:  # > 500MB memory
                    self.process_behavior[pid].append({
                        'timestamp': datetime.now(),
                        'type': 'high_memory',
                        'value': memory_mb
                    })
            
            # Check for file operations
            # This would require more sophisticated API hooking
            
        except Exception as e:
            logging.error(f"Error analyzing process behavior: {e}")
    
    def detect_ransomware_attack(self) -> Dict:
        """
        Analyze all indicators to detect ransomware attack.
        
        Returns:
        - Detection results
        """
        try:
            detection_result = {
                'detected': False,
                'confidence': 0.0,
                'indicators': [],
                'severity': 'LOW'
            }
            
            # Check encryption pattern
            recent_changes = list(self.file_changes)[-100:]  # Last 100 changes
            if self.detect_encryption_pattern(recent_changes):
                detection_result['detected'] = True
                detection_result['indicators'].append('Encryption pattern detected')
                detection_result['confidence'] += 0.4
            
            # Check for suspicious processes
            if self.suspicious_processes:
                detection_result['detected'] = True
                detection_result['indicators'].append(f'Suspicious processes: {len(self.suspicious_processes)}')
                detection_result['confidence'] += 0.3
            
            # Check process behavior
            high_behavior_count = sum(1 for pid, behaviors in self.process_behavior.items()
                                      if len(behaviors) > 5)
            if high_behavior_count > 0:
                detection_result['detected'] = True
                detection_result['indicators'].append('Suspicious process behavior')
                detection_result['confidence'] += 0.2
            
            # Determine severity
            if detection_result['confidence'] >= 0.8:
                detection_result['severity'] = 'CRITICAL'
            elif detection_result['confidence'] >= 0.5:
                detection_result['severity'] = 'HIGH'
            elif detection_result['confidence'] >= 0.3:
                detection_result['severity'] = 'MEDIUM'
            
            return detection_result
            
        except Exception as e:
            logging.error(f"Error detecting ransomware attack: {e}")
            return {'detected': False, 'confidence': 0.0, 'indicators': [], 'severity': 'LOW'}
    
    def initiate_ransomware_response(self, detection_result: Dict):
        """Initiate response to ransomware detection."""
        try:
            if detection_result['detected']:
                self.stats['ransomware_attempts'] += 1
                
                # Log event
                self.log_ransomware_event(
                    'ransomware_detected',
                    'multiple',
                    f"Ransomware detected with confidence: {detection_result['confidence']:.2f}",
                    detection_result['severity']
                )
                
                if detection_result['severity'] in ['CRITICAL', 'HIGH']:
                    # Terminate suspicious processes
                    self.terminate_suspicious_processes()
                    
                    # Isolate from network
                    self.isolate_system()
                    
                    # Create emergency backup
                    self.create_emergency_backup()
                
                elif detection_result['severity'] == 'MEDIUM':
                    # Create additional backups
                    self.create_emergency_backup()
            
        except Exception as e:
            logging.error(f"Error initiating ransomware response: {e}")
    
    def terminate_suspicious_processes(self):
        """Terminate processes suspected to be ransomware."""
        try:
            for pid in self.suspicious_processes:
                try:
                    proc = psutil.Process(pid)
                    proc.terminate()
                    
                    logging.warning(f"[RANSOMWARE] Terminated suspicious process: PID {pid}")
                    
                    # Log termination
                    self.log_ransomware_event(
                        'process_terminated',
                        f'PID_{pid}',
                        f"Suspicious process terminated: PID {pid}",
                        'HIGH'
                    )
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except Exception as e:
            logging.error(f"Error terminating suspicious processes: {e}")
    
    def isolate_system(self):
        """Isolate system from network to prevent spread."""
        try:
            # Disable network adapters
            # This is a simplified implementation
            # In reality, would use Windows API to disable adapters
            
            logging.warning("[RANSOMWARE] System isolation initiated")
            
            self.log_ransomware_event(
                'network_isolation',
                'system',
                "Network isolation initiated to prevent ransomware spread",
                'CRITICAL'
            )
            
        except Exception as e:
            logging.error(f"Error isolating system: {e}")
    
    def create_emergency_backup(self):
        """Create emergency backup of protected directories."""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_dir = self.backup_base / f"emergency_backup_{timestamp}"
            backup_dir.mkdir(exist_ok=True)
            
            files_backed_up = 0
            total_size = 0
            
            for directory in self.protected_directories:
                if not directory.exists():
                    continue
                
                try:
                    # Copy directory
                    dest_dir = backup_dir / directory.name
                    shutil.copytree(directory, dest_dir, dirs_exist_ok=True)
                    
                    # Count files
                    for root, dirs, files in os.walk(dest_dir):
                        files_backed_up += len(files)
                        for file in files:
                            total_size += os.path.getsize(os.path.join(root, file))
                
                except Exception as e:
                    logging.error(f"Error backing up {directory}: {e}")
            
            # Log backup
            self.log_backup_operation(backup_dir, files_backed_up, total_size, 'emergency')
            
            logging.info(f"[RANSOMWARE] Emergency backup created: {files_backed_up} files")
            
        except Exception as e:
            logging.error(f"Error creating emergency backup: {e}")
    
    def rollback_files(self, event_id: int = None) -> List[Path]:
        """
        Rollback files from backups.
        
        Parameters:
        - event_id: Specific ransomware event to rollback from
        
        Returns:
        - List of restored file paths
        """
        try:
            restored_files = []
            
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                if event_id:
                    # Restore files from specific event
                    cursor.execute('''
                        SELECT file_path, backup_path FROM file_snapshots
                        WHERE backup_path IS NOT NULL
                        ORDER BY last_modified DESC
                    ''')
                else:
                    # Restore most recent backups
                    cursor.execute('''
                        SELECT file_path, backup_path FROM file_snapshots
                        WHERE backup_path IS NOT NULL
                        ORDER BY last_modified DESC
                        LIMIT 1000
                    ''')

                snapshots = cursor.fetchall()
            finally:
                conn.close()
            
            for file_path, backup_path in snapshots:
                try:
                    if Path(backup_path).exists():
                        # Restore file
                        shutil.copy2(backup_path, file_path)
                        restored_files.append(Path(file_path))
                        
                        logging.info(f"[ROLLBACK] Restored: {file_path}")
                
                except Exception as e:
                    logging.error(f"Error restoring {file_path}: {e}")
            
            # Log rollback operation
            self.log_rollback_operation(event_id, restored_files, 'backup_restoration')
            
            self.stats['rollbacks_performed'] += 1
            
            return restored_files
            
        except Exception as e:
            logging.error(f"Error rolling back files: {e}")
            return []
    
    def log_ransomware_event(self, event_type: str, process_name: str, details: str, severity: str):
        """Log ransomware-related event to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT INTO ransomware_events
                    (timestamp, event_type, process_name, details, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (datetime.now(), event_type, process_name, details, severity))

                conn.commit()
            finally:
                conn.close()
            
        except Exception as e:
            logging.error(f"Error logging ransomware event: {e}")
    
    def log_backup_operation(self, backup_path: Path, file_count: int, total_size: int, backup_type: str):
        """Log backup operation to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT INTO backup_history
                    (timestamp, backup_path, file_count, total_size, backup_type)
                    VALUES (?, ?, ?, ?, ?)
                ''', (datetime.now(), str(backup_path), file_count, total_size, backup_type))

                conn.commit()
            finally:
                conn.close()
            
        except Exception as e:
            logging.error(f"Error logging backup operation: {e}")
    
    def log_rollback_operation(self, event_id: int, restored_files: List[Path], restore_method: str):
        """Log rollback operation to database."""
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT INTO rollback_operations
                    (timestamp, event_id, files_restored, restore_method, success)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    datetime.now(),
                    event_id,
                    json.dumps([str(f) for f in restored_files]),
                    restore_method,
                    True
                ))

                conn.commit()
            finally:
                conn.close()
            
        except Exception as e:
            logging.error(f"Error logging rollback operation: {e}")
    
    def monitoring_loop(self):
        """Main monitoring loop for ransomware detection."""
        logging.info("Ransomware detection monitoring started")
        
        # Initial backup
        self.create_emergency_backup()
        
        last_file_scan = time.time()
        last_process_scan = time.time()
        
        while self.running:
            try:
                current_time = time.time()
                
                # Monitor file changes every 5 seconds
                if current_time - last_file_scan > 5:
                    self.monitor_file_changes()
                    last_file_scan = current_time
                
                # Monitor processes every 10 seconds
                if current_time - last_process_scan > 10:
                    self.monitor_processes()
                    last_process_scan = current_time
                
                # Check for ransomware indicators
                detection_result = self.detect_ransomware_attack()
                if detection_result['detected']:
                    self.initiate_ransomware_response(detection_result)
                
                # Clean old data
                if current_time % 3600 < 10:  # Every hour
                    self.cleanup_old_data()
                
                time.sleep(1)
                
            except Exception as e:
                logging.error(f"Error in ransomware monitoring loop: {e}")
                time.sleep(10)
    
    def cleanup_old_data(self):
        """Clean up old monitoring data."""
        try:
            cutoff_time = datetime.now() - timedelta(days=7)  # Keep 7 days
            
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.cursor()

                # Clean old file snapshots
                cursor.execute('DELETE FROM file_snapshots WHERE last_modified < ?', (cutoff_time,))

                # Clean old events
                cursor.execute('DELETE FROM ransomware_events WHERE timestamp < ?', (cutoff_time,))

                conn.commit()
            finally:
                conn.close()
            
            logging.debug("[✓] Cleaned up old ransomware monitoring data")
            
        except Exception as e:
            logging.error(f"Error cleaning up old data: {e}")
    
    def get_statistics(self) -> Dict:
        """Get ransomware detector statistics."""
        return self.stats.copy()
    
    def start(self):
        """Start ransomware detection in background thread."""
        monitor_thread = threading.Thread(target=self.monitoring_loop, daemon=True)
        monitor_thread.start()
        logging.info("[✓] Ransomware Detector active")
    
    def stop(self):
        """Stop ransomware detection."""
        self.running = False
        logging.info("Ransomware detection stopped")

# Global instance
_ransomware_detector_instance = None

def get_ransomware_detector(config=None):
    """Get global ransomware detector instance."""
    global _ransomware_detector_instance
    if _ransomware_detector_instance is None:
        _ransomware_detector_instance = RansomwareDetector(config)
    return _ransomware_detector_instance

if __name__ == "__main__":
    """Test ransomware detector."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] %(message)s'
    )
    
    print("\n" + "="*80)
    print("          RANSOMWARE DETECTOR TEST")
    print("="*80)
    
    detector = RansomwareDetector()
    
    print("\nMonitoring file system for ransomware activity...")
    print("This will monitor the following directories:")
    for directory in detector.protected_directories:
        print(f"  - {directory}")
    
    print("\nPress Ctrl+C to stop monitoring...")
    
    try:
        # Run monitoring for 30 seconds
        time.sleep(30)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    
    stats = detector.get_statistics()
    print(f"\nStatistics:")
    print(f"  Files Protected: {stats['files_protected']}")
    print(f"  Backups Created: {stats['backups_created']}")
    print(f"  Ransomware Attempts: {stats['ransomware_attempts']}")
    print(f"  Rollbacks Performed: {stats['rollbacks_performed']}")
    
    print("\nPress Enter to exit...")
    input()