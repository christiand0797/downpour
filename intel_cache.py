"""
Persistent Intelligence Cache Module for Downpour v29
=====================================================

Provides persistent SQLite + JSON cache for threat intelligence across launches.
Supports multiple feed types with automatic expiration and deduplication.

Features:
- SQLite backend with JSON fallback
- Automatic expiration based on feed TTL
- Deduplication with hash-based detection
- Feed health tracking and statistics
- Thread-safe operations
- Background sync capability

Cache Schema:
- intel_cache: Main cache table with feed_name, ioc_type, ioc_value, source, first_seen, last_seen, expires_at, hash
- feed_health: Feed health tracking with last_update, records_added, errors, status
- feed_stats: Feed statistics with total_records, active_records, expired_records
"""

import sqlite3
import json
import hashlib
import threading
import time
import os
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)

class PersistentIntelCache:
    """Persistent intelligence cache with SQLite backend and JSON fallback."""
    
    def __init__(self, db_path: str = "intel_cache.db", json_fallback: str = "intel_cache.json"):
        self.db_path = Path(db_path)
        self.json_fallback = Path(json_fallback)
        self._lock = threading.RLock()
        self._cache: Dict[str, Dict] = {}
        self._loaded = False
        self._last_sync = 0
        self._sync_interval = 300  # 5 minutes
        
        self._init_db()
        self._load_from_json()
    
    def _init_db(self):
        """Initialize SQLite database with required tables."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS intel_cache (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        feed_name TEXT NOT NULL,
                        ioc_type TEXT NOT NULL,
                        ioc_value TEXT NOT NULL,
                        source TEXT,
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP,
                        hash TEXT UNIQUE,
                        metadata TEXT
                    )
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_intel_hash ON intel_cache(hash)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_intel_ioc ON intel_cache(ioc_type, ioc_value)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_intel_feed ON intel_cache(feed_name)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_intel_expires ON intel_cache(expires_at)
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS feed_health (
                        feed_name TEXT PRIMARY KEY,
                        last_update TIMESTAMP,
                        records_added INTEGER DEFAULT 0,
                        errors INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'unknown',
                        last_error TEXT,
                        records_total INTEGER DEFAULT 0,
                        active_records INTEGER DEFAULT 0,
                        expired_records INTEGER DEFAULT 0
                    )
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS feed_stats (
                        feed_name TEXT PRIMARY KEY,
                        total_records INTEGER DEFAULT 0,
                        active_records INTEGER DEFAULT 0,
                        expired_records INTEGER DEFAULT 0,
                        last_update TIMESTAMP,
                        last_error TEXT,
                        avg_records_per_update REAL DEFAULT 0.0
                    )
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS darkweb_monitor (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        source TEXT NOT NULL,
                        ioc_type TEXT NOT NULL,
                        ioc_value TEXT NOT NULL,
                        threat_level TEXT DEFAULT 'medium',
                        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        source_url TEXT,
                        confidence REAL DEFAULT 0.5,
                        metadata TEXT
                    )
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_darkweb_ioc ON darkweb_monitor(ioc_type, ioc_value)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_darkweb_source ON darkweb_monitor(source)
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS honeypot_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        event_type TEXT NOT NULL,
                        source_ip TEXT,
                        target_port INTEGER,
                        payload TEXT,
                        source_country TEXT,
                        severity TEXT DEFAULT 'medium',
                        metadata TEXT
                    )
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_honeypot_time ON honeypot_events(timestamp)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_honeypot_ip ON honeypot_events(source_ip)
                """)
                
        except Exception as e:
            logging.error(f"Failed to initialize intel cache DB: {e}")
    
    def _load_from_json(self):
        """Load cache from JSON fallback if SQLite not available."""
        try:
            if self.json_fallback.exists():
                with open(self.json_fallback, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._cache = data.get('cache', {})
                    logging.info(f"Loaded {len(self._cache)} entries from JSON cache")
        except Exception as e:
            logging.warning(f"Failed to load JSON cache: {e}")
    
    def _save_to_json(self):
        """Save cache to JSON fallback."""
        try:
            data = {'cache': self._cache, 'timestamp': time.time()}
            with open(self.json_fallback, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logging.warning(f"Failed to save JSON cache: {e}")
    
    def _compute_hash(self, feed_name: str, ioc_type: str, ioc_value: str) -> str:
        """Compute unique hash for IOC deduplication."""
        content = f"{ioc_type}:{ioc_value}"
        return hashlib.sha256(content.encode()).hexdigest()[:32]
    
    def add_ioc(self, feed_name: str, ioc_type: str, ioc_value: str, 
                source: str = "", ttl_hours: int = 24, metadata: Dict = None) -> bool:
        """Add IOC to cache with deduplication."""
        with self._lock:
            hash_val = self._compute_hash(feed_name, ioc_type, ioc_value)
            now = datetime.now()
            expires_at = datetime.now() + timedelta(hours=ttl_hours)
            
            metadata_json = json.dumps(metadata) if metadata else None
            
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT OR REPLACE INTO intel_cache 
                        (feed_name, ioc_type, ioc_value, source, first_seen, last_seen, expires_at, hash, metadata)
                        VALUES (?, ?, ?, ?, 
                            COALESCE((SELECT first_seen FROM intel_cache WHERE hash=?), ?),
                            ?, ?, ?, ?)
                    """, (
                        feed_name, ioc_type, ioc_value, source,
                        hash_val, datetime.now(), datetime.now(),
                        datetime.now() + timedelta(hours=ttl_hours),
                        hash_val, metadata_json
                    ))
                    conn.commit()
                    return True
            except Exception as e:
                logging.error(f"Failed to add IOC to cache: {e}")
                return False
    
    def get_ioc(self, ioc_type: str, ioc_value: str) -> Optional[Dict]:
        """Retrieve IOC from cache."""
        with self._lock:
            hash_val = self._compute_hash("", ioc_type, ioc_value)
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT feed_name, ioc_type, ioc_value, source, first_seen, last_seen, expires_at, metadata
                        FROM intel_cache WHERE ioc_type=? AND ioc_value=?
                    """, (ioc_type, ioc_value))
                    row = cursor.fetchone()
                    if row:
                        return {
                            'feed_name': row[0], 'ioc_type': row[1], 'ioc_value': row[2],
                            'source': row[3], 'first_seen': row[4], 'last_seen': row[5],
                            'expires_at': row[6], 'metadata': json.loads(row[8]) if row[8] else None
                        }
            except Exception as e:
                logging.error(f"Failed to get IOC: {e}")
            return None
    
    def get_all_iocs(self, ioc_type: Optional[str] = None, feed_name: Optional[str] = None) -> List[Dict]:
        """Retrieve all IOCs with optional filtering."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    query = "SELECT feed_name, ioc_type, ioc_value, source, first_seen, last_seen, expires_at, metadata FROM intel_cache WHERE 1=1"
                    params = []
                    if ioc_type:
                        query += " AND ioc_type=?"
                        params.append(ioc_type)
                    if feed_name:
                        query += " AND feed_name=?"
                        params.append(feed_name)
                    query += " ORDER BY last_seen DESC"
                    
                    cursor.execute(query, params)
                    results = []
                    for row in cursor.fetchall():
                        results.append({
                            'feed_name': row[0], 'ioc_type': row[1], 'ioc_value': row[2],
                            'source': row[3], 'first_seen': row[4], 'last_seen': row[5],
                            'expires_at': row[6], 'metadata': json.loads(row[8]) if row[8] else None
                        })
                    return results
            except Exception as e:
                logging.error(f"Failed to get IOCs: {e}")
            return []
    
    def remove_expired(self) -> int:
        """Remove expired IOCs from cache."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM intel_cache WHERE expires_at < ?", (datetime.now(),))
                    deleted = cursor.rowcount
                    conn.commit()
                    return deleted
            except Exception as e:
                logging.error(f"Failed to remove expired: {e}")
            return 0
    
    def get_stats(self) -> Dict:
        """Get cache statistics."""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT COUNT(*) FROM intel_cache")
                    total = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM intel_cache WHERE expires_at > ?", (datetime.now(),))
                    active = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(*) FROM intel_cache WHERE expires_at <= ?", (datetime.now(),))
                    expired = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT COUNT(DISTINCT feed_name) FROM intel_cache")
                    feeds = cursor.fetchone()[0]
                    
                    return {
                        'total': total, 'active': active, 'expired': expired,
                        'feeds': feeds, 'cache_size_mb': self.db_path.stat().st_size / 1024 / 1024 if self.db_path.exists() else 0
                    }
            except Exception as e:
                logging.error(f"Failed to get stats: {e}")
            return {'total': 0, 'active': 0, 'expired': 0, 'feeds': 0, 'cache_size_mb': 0}
    
    def add_darkweb_ioc(self, source: str, ioc_type: str, ioc_value: str,
                        threat_level: str = 'medium', source_url: str = "",
                        confidence: float = 0.5, metadata: Dict = None) -> bool:
        """Add darkweb/OSINT IOC to separate monitoring table."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                metadata_json = json.dumps(metadata) if metadata else None
                cursor.execute("""
                    INSERT OR REPLACE INTO darkweb_monitor
                    (source, ioc_type, ioc_value, threat_level, first_seen, last_seen, source_url, confidence, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (source, ioc_type, ioc_value, threat_level, 
                      datetime.now(), datetime.now(), source, confidence, metadata_json))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Failed to add darkweb IOC: {e}")
            return False
    
    def get_darkweb_iocs(self, ioc_type: Optional[str] = None, 
                         threat_level: Optional[str] = None) -> List[Dict]:
        """Retrieve darkweb/OSINT IOCs."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                query = "SELECT source, ioc_type, ioc_value, threat_level, first_seen, last_seen, source_url, confidence, metadata FROM darkweb_monitor WHERE 1=1"
                params = []
                if ioc_type:
                    query += " AND ioc_type=?"
                    params.append(ioc_type)
                if threat_level:
                    query += " AND threat_level=?"
                    params.append(threat_level)
                query += " ORDER BY last_seen DESC"
                
                cursor.execute(query, params)
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'source': row[0], 'ioc_type': row[1], 'ioc_value': row[2],
                        'threat_level': row[3], 'first_seen': row[4], 'last_seen': row[5],
                        'source_url': row[6], 'confidence': row[7],
                        'metadata': json.loads(row[8]) if row[8] else None
                    })
                return results
        except Exception as e:
            logging.error(f"Failed to get darkweb IOCs: {e}")
            return []
    
    def add_honeypot_event(self, event_type: str, source_ip: str = "",
                           target_port: int = 0, payload: str = "",
                           source_country: str = "", severity: str = "medium",
                           metadata: Dict = None) -> bool:
        """Record honeypot event."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                metadata_json = json.dumps(metadata) if metadata else None
                cursor.execute("""
                    INSERT INTO honeypot_events
                    (event_type, source_ip, target_port, payload, source_country, severity, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (event_type, source_ip, target_port, payload, source_country, severity, metadata_json))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Failed to add honeypot event: {e}")
            return False
    
    def get_honeypot_events(self, hours: int = 24, limit: int = 1000) -> List[Dict]:
        """Retrieve recent honeypot events."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT timestamp, event_type, source_ip, target_port, payload, 
                           source_country, severity, metadata
                    FROM honeypot_events
                    WHERE timestamp >= ?
                    ORDER BY timestamp DESC LIMIT ?
                """, (datetime.now() - timedelta(hours=hours), limit))
                
                results = []
                for row in cursor.fetchall():
                    results.append({
                        'timestamp': row[0], 'event_type': row[1], 'source_ip': row[2],
                        'target_port': row[3], 'payload': row[4], 'source_country': row[5],
                        'severity': row[6], 'metadata': json.loads(row[7]) if row[7] else None
                    })
                return results
        except Exception as e:
            logging.error(f"Failed to get honeypot events: {e}")
            return []
    
    def get_feed_health(self, feed_name: str) -> Optional[Dict]:
        """Get feed health status."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT feed_name, last_update, records_added, errors, status, last_error
                    FROM feed_health WHERE feed_name=?
                """, (feed_name,))
                row = cursor.fetchone()
                if row:
                    return {
                        'feed_name': row[0], 'last_update': row[1],
                        'records_added': row[2], 'errors': row[3],
                        'status': row[4], 'last_error': row[5]
                    }
        except Exception as e:
            logging.error(f"Failed to get feed health: {e}")
        return None
    
    def update_feed_health(self, feed_name: str, records_added: int = 0, 
                           error: str = "", status: str = "ok") -> bool:
        """Update feed health status."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO feed_health
                    (feed_name, last_update, records_added, errors, status, last_error, records_total)
                    VALUES (?, ?, ?, ?, ?, ?, 
                        COALESCE((SELECT records_total FROM feed_health WHERE feed_name=?), 0) + ?)
                """, (feed_name, datetime.now(), 1 if error == "" else 0, 
                      error, status, error if error else None, 1 if error == "" else 0))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Failed to update feed health: {e}")
            return False
    
    def export_to_json(self, filepath: str) -> bool:
        """Export cache to JSON file."""
        try:
            data = self.get_all_iocs()
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump({
                    'exported_at': datetime.now().isoformat(),
                    'total_records': len(data),
                    'records': data
                }, f, indent=2)
            return True
        except Exception as e:
            logging.error(f"Failed to export to JSON: {e}")
            return False
    
    def import_from_json(self, filepath: str) -> int:
        """Import IOCs from JSON file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            count = 0
            for record in data.get('records', []):
                if self.add_ioc(record.get('feed_name', 'import'), 
                                record.get('ioc_type', 'ip'),
                                record.get('ioc_value', ''),
                                record.get('source', 'import'),
                                metadata=record.get('metadata')):
                    count += 1
            return count
        except Exception as e:
            logging.error(f"Failed to import from JSON: {e}")
            return 0
    
    def sync_to_disk(self):
        """Force sync cache to disk."""
        self._save_to_json()
        # SQLite auto-commits on each transaction
    
    def close(self):
        """Close cache and sync to disk."""
        self.sync_to_disk()

# Global cache instance
_intel_cache: Optional[PersistentIntelCache] = None

def get_intel_cache(db_path: str = "intel_cache.db") -> PersistentIntelCache:
    """Get global intel cache instance."""
    global _intel_cache
    if _intel_cache is None:
        _intel_cache = PersistentIntelCache(db_path)
    return _intel_cache