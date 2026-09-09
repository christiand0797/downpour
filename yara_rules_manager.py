#!/usr/bin/env python3
"""
YARA Rules Manager - Enhanced with 100DaysOfYARA 2025 Community Rules
Manages YARA rule sets from multiple sources:
- 100DaysOfYARA 2025 (community contributions)
- YARA-Rules (Trellix ATR)
- MalwareBazaar daily rules
- Custom rules
Supports automatic updates, compilation, and testing.
"""
from __future__ import annotations
import os
import time
import threading
import logging
import hashlib
import subprocess
import tempfile
import shutil
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple
from pathlib import Path
import json
import urllib.request
import zipfile

_log = logging.getLogger(__name__)

# Rule sources
RULE_SOURCES = {
    '100days_yara_2025': {
        'name': '100DaysOfYARA 2025',
        'url': 'https://github.com/100DaysofYARA/2025',
        'type': 'github',
        'paths': [''],
        'description': 'Community YARA rules from 100 Days of YARA 2025 challenge',
        'enabled': True,
    },
    'yara_rules_malware': {
        'name': 'YARA-Rules Malware',
        'url': 'https://github.com/Yara-Rules/rules/tree/master/malware',
        'type': 'github',
        'paths': ['malware/'],
        'description': 'Trellix ATR team malware YARA rules',
        'enabled': True,
    },
    'yara_rules_ransomware': {
        'name': 'YARA-Rules Ransomware',
        'url': 'https://github.com/Yara-Rules/rules/tree/master/ransomware',
        'type': 'github',
        'paths': ['ransomware/'],
        'description': 'Ransomware-specific YARA rules',
        'enabled': True,
    },
    'yara_rules_apt': {
        'name': 'YARA-Rules APT',
        'url': 'https://github.com/Yara-Rules/rules/tree/master/APT',
        'type': 'github',
        'paths': ['APT/'],
        'description': 'APT threat actor YARA rules',
        'enabled': True,
    },
    'malwarebazaar_daily': {
        'name': 'MalwareBazaar Daily',
        'url': 'https://bazaar.abuse.ch/export/csv/recent/',
        'type': 'csv_to_yara',
        'paths': [],
        'description': 'YARA rules generated from MalwareBazaar daily samples',
        'enabled': True,
    },
}

@dataclass
class YaraRule:
    """Single YARA rule metadata."""
    name: str
    namespace: str
    file_path: str
    description: str = ""
    author: str = ""
    date: str = ""
    severity: str = "medium"
    mitre_techniques: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    compiled: bool = False
    hash: str = ""

@dataclass
class YaraRuleSet:
    """Collection of YARA rules from a source."""
    source_id: str
    name: str
    path: str
    rules: List[YaraRule] = field(default_factory=list)
    compiled_path: Optional[str] = None
    last_updated: float = 0
    error: Optional[str] = None
    rule_count: int = 0

class YaraRulesManager:
    """
    Manages YARA rule sets from multiple sources.
    Handles downloading, compilation, testing, and hot-reloading.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._lock = threading.RLock()
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # Rule sets
        self.rule_sets: Dict[str, YaraRuleSet] = {}
        self.compiled_rules: Optional[Any] = None  # yara.Rules object
        
        # Alerts
        self.alerts: deque = deque(maxlen=500)
        self.alert_callbacks: List[Callable] = []
        
        # Statistics
        self.stats = {
            'total_rules': 0,
            'rule_sets': 0,
            'compilations': 0,
            'compilation_errors': 0,
            'scans_performed': 0,
            'matches_found': 0,
            'last_update': 0,
        }
        
        # Configuration
        self.rules_dir = Path(self.config.get('rules_dir', 'yara_rules'))
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        self.auto_update = self.config.get('auto_update', True)
        self.update_interval = self.config.get('update_interval', 86400)  # 24 hours
        self.test_on_compile = self.config.get('test_on_compile', True)
        
        # YARA availability
        self.yara_available = self._check_yara_available()
        
        # Initialize rule sets
        self._initialize_rule_sets()
    
    def _check_yara_available(self) -> bool:
        """Check if yara-python is available."""
        try:
            import yara
            return True
        except ImportError:
            _log.warning("yara-python not available - YARA scanning disabled")
            return False
    
    def _initialize_rule_sets(self):
        """Initialize rule sets from configured sources."""
        for source_id, source_info in RULE_SOURCES.items():
            if source_info.get('enabled', True):
                rule_set = YaraRuleSet(
                    source_id=source_id,
                    name=source_info['name'],
                    path=str(self.rules_dir / source_id),
                )
                self.rule_sets[source_id] = rule_set
        
        self.stats['rule_sets'] = len(self.rule_sets)
    
    def start(self):
        """Start the manager."""
        if self._running:
            return
        
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._management_loop, daemon=True, name="YARA-Rules-Manager")
        self._thread.start()
        
        # Initial load and compile
        self._load_and_compile_all()
        
        _log.info(f"YARA Rules Manager started with {len(self.rule_sets)} rule sets")
    
    def stop(self):
        """Stop the manager."""
        self._running = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        _log.info("YARA Rules Manager stopped")
    
    def register_alert_callback(self, callback: Callable):
        """Register callback for alerts."""
        self.alert_callbacks.append(callback)
    
    def _management_loop(self):
        """Main management loop for auto-updates."""
        while self._running and not self._stop_event.is_set():
            if self.auto_update:
                try:
                    self._update_all_sources()
                    self._load_and_compile_all()
                except Exception as e:
                    _log.error(f"Auto-update error: {e}")
            
            # Sleep for update interval
            for _ in range(self.update_interval):
                if not self._running or self._stop_event.is_set():
                    break
                time.sleep(1)
    
    def _update_all_sources(self):
        """Update all rule sources."""
        for source_id, rule_set in self.rule_sets.items():
            try:
                self._update_source(source_id)
            except Exception as e:
                _log.error(f"Failed to update {source_id}: {e}")
                rule_set.error = str(e)
    
    def _update_source(self, source_id: str):
        """Update a specific rule source."""
        if source_id not in self.rule_sets:
            return
        
        rule_set = self.rule_sets[source_id]
        source_info = RULE_SOURCES.get(source_id)
        if not source_info:
            return
        
        _log.info(f"Updating YARA source: {source_info['name']}")
        
        source_path = Path(rule_set.path)
        source_path.mkdir(parents=True, exist_ok=True)
        
        if source_info['type'] == 'github':
            self._update_github_source(source_id, source_info, source_path)
        elif source_info['type'] == 'csv_to_yara':
            self._update_malwarebazaar_source(source_path)
        
        rule_set.last_updated = time.time()
        rule_set.error = None
    
    def _update_github_source(self, source_id: str, source_info: Dict, target_path: Path):
        """Update rules from a GitHub repository."""
        repo_url = source_info['url'].replace('tree/master', '').replace('tree/main', '').rstrip('/')
        
        # Use git to clone or pull
        git_dir = target_path / '.git'
        
        if git_dir.exists():
            # Pull latest
            try:
                subprocess.run(
                    ['git', '-C', str(target_path), 'pull', 'origin', 'main'],
                    capture_output=True, text=True, timeout=60
                )
            except subprocess.CalledProcessError:
                try:
                    subprocess.run(
                        ['git', '-C', str(target_path), 'pull', 'origin', 'master'],
                        capture_output=True, text=True, timeout=60
                    )
                except subprocess.CalledProcessError as e:
                    _log.warning(f"Git pull failed for {source_id}: {e}")
        else:
            # Clone
            try:
                subprocess.run(
                    ['git', 'clone', '--depth', '1', repo_url + '.git', str(target_path)],
                    capture_output=True, text=True, timeout=120
                )
            except subprocess.CalledProcessError as e:
                _log.error(f"Git clone failed for {source_id}: {e}")
                raise
        
        # Scan for .yar/.yara files
        self._scan_rule_files(rule_set, target_path, source_info.get('paths', ['']))
    
    def _update_malwarebazaar_source(self, target_path: Path):
        """Update rules from MalwareBazaar daily feed."""
        try:
            # Download recent CSV
            url = 'https://bazaar.abuse.ch/export/csv/recent/'
            csv_path = target_path / 'malwarebazaar_recent.csv'
            
            urllib.request.urlretrieve(url, csv_path)
            
            # Convert CSV to YARA rules
            self._csv_to_yara(csv_path, target_path / 'malwarebazaar_daily.yar')
            
        except Exception as e:
            _log.error(f"MalwareBazaar update failed: {e}")
            raise
    
    def _csv_to_yara(self, csv_path: Path, output_path: Path):
        """Convert MalwareBazaar CSV to YARA rules."""
        import csv
        
        rules = []
        with open(csv_path, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                if i >= 1000:  # Limit to 1000 rules per update
                    break
                
                sha256 = row.get('sha256_hash', '').strip()
                sha1 = row.get('sha1_hash', '').strip()
                md5 = row.get('md5_hash', '').strip()
                file_type = row.get('file_type', '').strip()
                signature = row.get('signature', '').strip()
                
                if not sha256:
                    continue
                
                rule_name = f"MalwareBazaar_{signature.replace(' ', '_')}_{sha256[:8]}"
                rule_name = rule_name.replace('/', '_').replace('\\', '_')
                
                conditions = []
                if sha256:
                    conditions.append(f'hash.sha256(0, filesize) == "{sha256.lower()}"')
                if sha1:
                    conditions.append(f'hash.sha1(0, filesize) == "{sha1.lower()}"')
                if md5:
                    conditions.append(f'hash.md5(0, filesize) == "{md5.lower()}"')
                
                if not conditions:
                    continue
                
                rule = f'''rule {rule_name}
{{
    meta:
        description = "MalwareBazaar: {signature}"
        author = "MalwareBazaar/abuse.ch"
        date = "{time.strftime('%Y-%m-%d')}"
        sha256 = "{sha256}"
        sha1 = "{sha1}"
        md5 = "{md5}"
        file_type = "{file_type}"
        severity = "high"
    condition:
        {" or ".join(conditions)}
}}
'''
                rules.append(rule)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(rules))
        
        _log.info(f"Generated {len(rules)} YARA rules from MalwareBazaar CSV")
    
    def _scan_rule_files(self, rule_set: YaraRuleSet, base_path: Path, sub_paths: List[str]):
        """Scan directory for YARA rule files."""
        rule_set.rules = []
        
        for sub_path in sub_paths:
            scan_path = base_path / sub_path
            if not scan_path.exists():
                continue
            
            for yar_file in scan_path.rglob('*.yar'):
                self._parse_rule_file(rule_set, yar_file)
            for yar_file in scan_path.rglob('*.yara'):
                self._parse_rule_file(rule_set, yar_file)
        
        rule_set.rule_count = len(rule_set.rules)
        _log.info(f"Found {rule_set.rule_count} rules in {rule_set.source_id}")
    
    def _parse_rule_file(self, rule_set: YaraRuleSet, file_path: Path):
        """Parse YARA rule file for metadata."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Calculate hash
            file_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
            
            # Simple metadata extraction (regex-based)
            import re
            
            # Extract rule names and metadata
            rule_pattern = re.compile(r'rule\s+(\w+)\s*{', re.MULTILINE)
            meta_pattern = re.compile(r'meta:\s*(.*?)\s*(?:strings:|condition:)', re.DOTALL | re.IGNORECASE)
            
            for match in rule_pattern.finditer(content):
                rule_name = match.group(1)
                
                # Find metadata for this rule
                rule_start = match.end()
                # Find next rule or end of file
                next_match = rule_pattern.search(content, rule_start)
                rule_end = next_match.start() if next_match else len(content)
                rule_content = content[rule_start:rule_end]
                
                # Extract metadata
                meta_match = meta_pattern.search(rule_content)
                description = ""
                author = ""
                date = ""
                severity = "medium"
                mitre = []
                
                if meta_match:
                    meta_content = meta_match.group(1)
                    for line in meta_content.split('\n'):
                        line = line.strip().rstrip(';')
                        if '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip().lower()
                            value = value.strip().strip('"')
                            if key == 'description':
                                description = value
                            elif key == 'author':
                                author = value
                            elif key == 'date':
                                date = value
                            elif key == 'severity':
                                severity = value
                            elif key in ['mitre', 'mitre_attack', 'attack']:
                                mitre = [t.strip() for t in value.split(',')]
                
                rule = YaraRule(
                    name=rule_name,
                    namespace=rule_set.source_id,
                    file_path=str(file_path),
                    description=description,
                    author=author,
                    date=date,
                    severity=severity,
                    mitre_techniques=mitre,
                    hash=file_hash,
                )
                rule_set.rules.append(rule)
                
        except Exception as e:
            _log.debug(f"Failed to parse {file_path}: {e}")
    
    def _load_and_compile_all(self):
        """Load and compile all rule sets."""
        if not self.yara_available:
            _log.warning("YARA not available, skipping compilation")
            return
        
        try:
            import yara
            
            # Create filepaths dict for compilation
            filepaths = {}
            for rule_set in self.rule_sets.values():
                for rule in rule_set.rules:
                    if rule.file_path not in filepaths:
                        filepaths[rule.namespace] = rule.file_path
            
            if not filepaths:
                _log.warning("No rule files to compile")
                return
            
            # Compile
            start = time.time()
            self.compiled_rules = yara.compile(filepaths=filepaths)
            compile_time = time.time() - start
            
            # Update stats
            total_rules = sum(rs.rule_count for rs in self.rule_sets.values())
            self.stats['total_rules'] = total_rules
            self.stats['compilations'] += 1
            self.stats['last_update'] = time.time()
            
            _log.info(f"Compiled {total_rules} YARA rules from {len(filepaths)} namespaces in {compile_time:.2f}s")
            
            # Test compilation if enabled
            if self.test_on_compile:
                self._test_compilation()
                
        except Exception as e:
            _log.error(f"YARA compilation failed: {e}")
            self.stats['compilation_errors'] += 1
            self.compiled_rules = None
    
    def _test_compilation(self):
        """Test compiled rules with sample data."""
        if not self.compiled_rules:
            return
        
        try:
            # Test with benign file
            test_data = b"This is a test file for YARA compilation verification."
            matches = self.compiled_rules.match(data=test_data)
            _log.debug(f"YARA test scan: {len(matches)} matches on test data")
        except Exception as e:
            _log.warning(f"YARA test compilation failed: {e}")
    
    def scan_file(self, file_path: str) -> List[Dict]:
        """Scan a file with compiled YARA rules."""
        if not self.compiled_rules:
            return []
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            return self.scan_data(data)
        except Exception as e:
            _log.error(f"File scan error for {file_path}: {e}")
            return []
    
    def scan_data(self, data: bytes) -> List[Dict]:
        """Scan binary data with compiled YARA rules."""
        if not self.compiled_rules:
            return []
        
        try:
            matches = self.compiled_rules.match(data=data)
            
            results = []
            for match in matches:
                results.append({
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': [(s.identifier, s.instances) for s in match.strings],
                })
            
            with self._lock:
                self.stats['scans_performed'] += 1
                self.stats['matches_found'] += len(results)
            
            # Generate alerts for matches
            for match in matches:
                self._generate_match_alert(match)
            
            return results
            
        except Exception as e:
            _log.error(f"YARA scan error: {e}")
            return []
    
    def scan_process_memory(self, pid: int) -> List[Dict]:
        """Scan process memory (requires admin/debug privileges)."""
        if not self.compiled_rules:
            return []
        
        results = []
        try:
            import psutil
            proc = psutil.Process(pid)
            
            # Read process memory in chunks
            for mem_map in proc.memory_maps():
                if mem_map.perms and 'r' in mem_map.perms:
                    try:
                        # This is simplified - real implementation would use
                        # ReadProcessMemory or similar
                        pass
                    except Exception:
                        continue
        except Exception as e:
            _log.error(f"Process memory scan error: {e}")
        
        return results
    
    def _generate_match_alert(self, match):
        """Generate alert for YARA match."""
        severity_map = {
            'critical': 'CRITICAL',
            'high': 'HIGH',
            'medium': 'MEDIUM',
            'low': 'LOW',
        }
        severity = severity_map.get(match.meta.get('severity', 'medium'), 'MEDIUM')
        
        alert = {
            'timestamp': time.time(),
            'type': 'YARA_MATCH',
            'message': f"YARA match: {match.rule} ({match.namespace})",
            'severity': severity,
            'mitre': match.meta.get('mitre', []),
            'details': {
                'rule': match.rule,
                'namespace': match.namespace,
                'description': match.meta.get('description', ''),
                'author': match.meta.get('author', ''),
                'tags': match.tags,
            }
        }
        
        with self._lock:
            self.alerts.append(alert)
        
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                _log.error(f"Alert callback error: {e}")
    
    def get_status(self) -> Dict:
        """Get manager status."""
        with self._lock:
            return {
                'running': self._running,
                'yara_available': self.yara_available,
                'rule_sets': {
                    sid: {
                        'name': rs.name,
                        'rules': rs.rule_count,
                        'last_updated': rs.last_updated,
                        'error': rs.error,
                    }
                    for sid, rs in self.rule_sets.items()
                },
                'compiled': self.compiled_rules is not None,
                'stats': self.stats.copy(),
            }
    
    def get_rule_info(self, source_id: str) -> Optional[Dict]:
        """Get detailed info about a rule set."""
        if source_id not in self.rule_sets:
            return None
        
        rs = self.rule_sets[source_id]
        return {
            'source_id': rs.source_id,
            'name': rs.name,
            'path': rs.path,
            'rule_count': rs.rule_count,
            'last_updated': rs.last_updated,
            'error': rs.error,
            'rules': [
                {
                    'name': r.name,
                    'namespace': r.namespace,
                    'description': r.description,
                    'author': r.author,
                    'severity': r.severity,
                    'mitre': r.mitre_techniques,
                    'file': r.file_path,
                }
                for r in rs.rules[:100]  # Limit to first 100
            ],
        }
    
    def force_update(self):
        """Force immediate update of all sources."""
        self._update_all_sources()
        self._load_and_compile_all()

# Singleton instance
_yara_manager: Optional[YaraRulesManager] = None
_yara_lock = threading.Lock()

def get_yara_manager() -> YaraRulesManager:
    global _yara_manager
    with _yara_lock:
        if _yara_manager is None:
            _yara_manager = YaraRulesManager()
        return _yara_manager

def start_yara_manager() -> YaraRulesManager:
    manager = get_yara_manager()
    manager.start()
    return manager

def stop_yara_manager():
    global _yara_manager
    if _yara_manager:
        _yara_manager.stop()
        _yara_manager = None

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    manager = start_yara_manager()
    try:
        while True:
            time.sleep(30)
            status = manager.get_status()
            print(f"Rules: {status['stats']['total_rules']}, Sets: {status['stats']['rule_sets']}")
    except KeyboardInterrupt:
        stop_yara_manager()