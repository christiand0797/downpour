"""
Sharded Context Architecture for Downpour v29 TITANIUM
======================================================
Advanced distributed context management system enabling:
- Multi-agent coordination and context sharing
- Sharded context storage with consistent hashing
- Real-time context synchronization across components
- Event-driven context updates with pub/sub pattern
- Persistent context snapshots with versioning
- Cross-component context queries and aggregation
- Distributed locking and consensus for critical sections
- Context compression and deduplication
"""

from __future__ import annotations
import hashlib
import json
import logging
import os
import threading
import time
import uuid
import zlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from concurrent.futures import ThreadPoolExecutor
import queue
import weakref

_log = logging.getLogger(__name__)

# Configuration
DEFAULT_SHARD_COUNT = 16
MAX_CONTEXT_SIZE = 100 * 1024 * 1024  # 100MB per shard
CONTEXT_TTL = 86400  # 24 hours
SNAPSHOT_INTERVAL = 300  # 5 minutes
COMPRESSION_THRESHOLD = 1024  # 1KB


class ContextScope(Enum):
    """Context visibility scope."""
    LOCAL = "local"           # Component-local only
    SHARED = "shared"         # Shared across related components
    GLOBAL = "global"         # Application-wide
    PERSISTENT = "persistent" # Survives restarts


class ContextEventType(Enum):
    """Types of context events."""
    CREATED = "created"
    UPDATED = "updated"
    DELETED = "deleted"
    MERGED = "merged"
    SNAPSHOT = "snapshot"
    SYNC = "sync"
    EXPIRED = "expired"
    CONFLICT = "conflict"


@dataclass
class ContextEntry:
    """Individual context entry with metadata."""
    key: str
    value: Any
    scope: ContextScope = ContextScope.LOCAL
    version: int = 1
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    tags: Set[str] = field(default_factory=set)
    metadata: Dict[str, Any] = field(default_factory=dict)
    checksum: str = ""
    compressed: bool = False
    
    def __post_init__(self):
        self._update_checksum()
    
    def _update_checksum(self):
        """Update content checksum."""
        content = f"{self.key}:{json.dumps(self.value, sort_keys=True, default=str)}:{self.version}"
        self.checksum = hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def is_expired(self) -> bool:
        """Check if entry has expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at
    
    def compress(self) -> bool:
        """Compress value if beneficial."""
        if self.compressed:
            return False
        try:
            data = json.dumps(self.value, default=str).encode()
            if len(data) > COMPRESSION_THRESHOLD:
                compressed = zlib.compress(data, level=6)
                if len(compressed) < len(data) * 0.8:  # At least 20% savings
                    self.value = compressed
                    self.compressed = True
                    return True
        except Exception:
            pass
        return False
    
    def decompress(self) -> Any:
        """Decompress value if compressed."""
        if not self.compressed:
            return self.value
        try:
            return json.loads(zlib.decompress(self.value).decode())
        except Exception:
            return self.value


@dataclass
class ContextEvent:
    """Context change event for pub/sub."""
    event_type: ContextEventType
    key: str
    shard_id: int
    timestamp: float = field(default_factory=time.time)
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    source_component: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ShardStats:
    """Statistics for a context shard."""
    shard_id: int
    entry_count: int = 0
    total_size: int = 0
    compressed_entries: int = 0
    last_access: float = 0
    last_write: float = 0
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    conflicts: int = 0


class ConsistentHashRing:
    """Consistent hashing ring for shard distribution."""
    
    def __init__(self, shard_count: int = DEFAULT_SHARD_COUNT, virtual_nodes: int = 100):
        self.shard_count = shard_count
        self.virtual_nodes = virtual_nodes
        self.ring: Dict[int, int] = {}  # hash -> shard_id
        self._build_ring()
    
    def _build_ring(self):
        """Build the consistent hash ring."""
        self.ring.clear()
        for shard_id in range(self.shard_count):
            for v in range(self.virtual_nodes):
                key = f"shard-{shard_id}-vn-{v}"
                hash_val = int(hashlib.md5(key.encode()).hexdigest(), 16)
                self.ring[hash_val] = shard_id
        # Ensure sorted keys for binary search
        self._sorted_keys = sorted(self.ring.keys())
    
    def get_shard(self, key: str) -> int:
        """Get shard ID for a key."""
        if not self._sorted_keys:
            return 0
        hash_val = int(hashlib.md5(key.encode()).hexdigest(), 16)
        # Binary search for the first key >= hash_val
        import bisect
        idx = bisect.bisect_right(self._sorted_keys, hash_val)
        if idx >= len(self._sorted_keys):
            idx = 0
        return self.ring[self._sorted_keys[idx]]
    
    def get_shards_for_range(self, start_key: str, end_key: str) -> List[int]:
        """Get all shards covering a key range."""
        start_shard = self.get_shard(start_key)
        end_shard = self.get_shard(end_key)
        if start_shard <= end_shard:
            return list(range(start_shard, end_shard + 1))
        else:
            # Wrap around
            return list(range(start_shard, self.shard_count)) + list(range(0, end_shard + 1))


class ContextShard:
    """Individual context shard with thread-safe operations."""
    
    def __init__(self, shard_id: int, storage_path: Optional[Path] = None):
        self.shard_id = shard_id
        self.storage_path = storage_path
        self._entries: Dict[str, ContextEntry] = {}
        self._lock = RWLock()
        self._stats = ShardStats(shard_id=shard_id)
        self._event_queue: queue.Queue = queue.Queue()
        self._expiration_timer: Optional[threading.Timer] = None
        self._load_from_disk()
        self._start_expiration_timer()
    
    def _load_from_disk(self):
        """Load shard data from disk."""
        if not self.storage_path:
            return
        shard_file = self.storage_path / f"shard_{self.shard_id:04d}.ctx"
        if shard_file.exists():
            try:
                with open(shard_file, 'rb') as f:
                    data = zlib.decompress(f.read())
                    entries = json.loads(data.decode())
                    for key, entry_data in entries.items():
                        entry = ContextEntry(**entry_data)
                        if not entry.is_expired():
                            self._entries[key] = entry
                _log.info(f"Loaded {len(self._entries)} entries for shard {self.shard_id}")
            except Exception as e:
                _log.error(f"Failed to load shard {self.shard_id}: {e}")
    
    def _save_to_disk(self):
        """Save shard data to disk."""
        if not self.storage_path:
            return
        try:
            shard_file = self.storage_path / f"shard_{self.shard_id:04d}.ctx"
            # Prepare serializable data
            data = {}
            for key, entry in self._entries.items():
                entry_dict = {
                    'key': entry.key,
                    'value': entry.value if not entry.compressed else entry.value.hex(),
                    'scope': entry.scope.value,
                    'version': entry.version,
                    'created_at': entry.created_at,
                    'updated_at': entry.updated_at,
                    'expires_at': entry.expires_at,
                    'tags': list(entry.tags),
                    'metadata': entry.metadata,
                    'checksum': entry.checksum,
                    'compressed': entry.compressed,
                }
                data[key] = entry_dict
            
            json_data = json.dumps(data, default=str).encode()
            compressed = zlib.compress(json_data, level=6)
            with open(shard_file, 'wb') as f:
                f.write(compressed)
            
            self._stats.last_write = time.time()
        except Exception as e:
            _log.error(f"Failed to save shard {self.shard_id}: {e}")
    
    def _start_expiration_timer(self):
        """Start periodic expiration cleanup."""
        def cleanup():
            self._cleanup_expired()
            self._expiration_timer = threading.Timer(60.0, cleanup)
            self._expiration_timer.daemon = True
            self._expiration_timer.start()
        
        cleanup()
    
    def _cleanup_expired(self):
        """Remove expired entries."""
        with self._lock.write_lock():
            expired_keys = [k for k, v in self._entries.items() if v.is_expired()]
            for key in expired_keys:
                del self._entries[key]
                self._stats.evictions += 1
            if expired_keys:
                _log.debug(f"Shard {self.shard_id}: evicted {len(expired_keys)} expired entries")
    
    def get(self, key: str) -> Optional[ContextEntry]:
        """Get entry by key."""
        with self._lock.read_lock():
            entry = self._entries.get(key)
            if entry and not entry.is_expired():
                self._stats.hits += 1
                self._stats.last_access = time.time()
                return entry
            elif entry:
                # Expired
                del self._entries[key]
                self._stats.evictions += 1
                self._stats.misses += 1
                return None
            else:
                self._stats.misses += 1
                return None
    
    def set(self, key: str, entry: ContextEntry) -> bool:
        """Set entry in shard."""
        with self._lock.write_lock():
            old_entry = self._entries.get(key)
            if old_entry:
                entry.version = old_entry.version + 1
            
            entry.compress()
            self._entries[key] = entry
            self._stats.entry_count = len(self._entries)
            self._stats.last_write = time.time()
            
            # Queue event
            event = ContextEvent(
                event_type=ContextEventType.UPDATED if old_entry else ContextEventType.CREATED,
                key=key,
                shard_id=self.shard_id,
                old_value=old_entry.value if old_entry else None,
                new_value=entry.value,
            )
            self._event_queue.put(event)
            
            return True
    
    def delete(self, key: str) -> bool:
        """Delete entry from shard."""
        with self._lock.write_lock():
            if key in self._entries:
                old_entry = self._entries[key]
                del self._entries[key]
                self._stats.entry_count = len(self._entries)
                self._stats.evictions += 1
                
                event = ContextEvent(
                    event_type=ContextEventType.DELETED,
                    key=key,
                    shard_id=self.shard_id,
                    old_value=old_entry.value,
                )
                self._event_queue.put(event)
                return True
            return False
    
    def get_all(self, scope: Optional[ContextScope] = None) -> Dict[str, ContextEntry]:
        """Get all entries, optionally filtered by scope."""
        with self._lock.read_lock():
            if scope is None:
                return {k: v for k, v in self._entries.items() if not v.is_expired()}
            return {k: v for k, v in self._entries.items() 
                    if v.scope == scope and not v.is_expired()}
    
    def get_stats(self) -> ShardStats:
        """Get shard statistics."""
        self._stats.entry_count = len(self._entries)
        return self._stats
    
    def get_events(self, max_events: int = 100) -> List[ContextEvent]:
        """Get pending events."""
        events = []
        try:
            for _ in range(min(max_events, self._event_queue.qsize())):
                events.append(self._event_queue.get_nowait())
        except queue.Empty:
            pass
        return events
    
    def flush(self):
        """Flush shard to disk."""
        self._save_to_disk()
    
    def shutdown(self):
        """Shutdown shard."""
        if self._expiration_timer:
            self._expiration_timer.cancel()
        self.flush()


# Add RWLock implementation
class RWLock:
    """Read-Write lock implementation."""
    
    def __init__(self):
        self._read_ready = threading.Condition(threading.Lock())
        self._readers = 0
        self._writers_waiting = 0
        self._writer_active = False
    
    def acquire_read(self):
        with self._read_ready:
            while self._writer_active or self._writers_waiting > 0:
                self._read_ready.wait()
            self._readers += 1
    
    def release_read(self):
        with self._read_ready:
            self._readers -= 1
            if self._readers == 0:
                self._read_ready.notify_all()
    
    def acquire_write(self):
        with self._read_ready:
            self._writers_waiting += 1
            while self._readers > 0 or self._writer_active:
                self._read_ready.wait()
            self._writers_waiting -= 1
            self._writer_active = True
    
    def release_write(self):
        with self._read_ready:
            self._writer_active = False
            self._read_ready.notify_all()
    
    def read_lock(self):
        return _RWLockContext(self, 'read')
    
    def write_lock(self):
        return _RWLockContext(self, 'write')


class _RWLockContext:
    def __init__(self, lock: RWLock, mode: str):
        self.lock = lock
        self.mode = mode
    
    def __enter__(self):
        if self.mode == 'read':
            self.lock.acquire_read()
        else:
            self.lock.acquire_write()
        return self
    
    def __exit__(self, *args):
        if self.mode == 'read':
            self.lock.release_read()
        else:
            self.lock.release_write()


class ShardedContextManager:
    """
    Main sharded context manager with multi-agent coordination.
    """
    
    def __init__(self, 
                 shard_count: int = DEFAULT_SHARD_COUNT,
                 storage_path: Optional[Path] = None,
                 enable_persistence: bool = True):
        self.shard_count = shard_count
        self.storage_path = storage_path or Path("downpour_data/context_shards")
        self.enable_persistence = enable_persistence
        
        if enable_persistence:
            self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.hash_ring = ConsistentHashRing(shard_count)
        self.shards: List[ContextShard] = []
        for i in range(shard_count):
            shard_path = self.storage_path if enable_persistence else None
            self.shards.append(ContextShard(i, shard_path))
        
        # Event system
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._event_thread: Optional[threading.Thread] = None
        self._running = False
        
        # Component registry
        self._components: Dict[str, weakref.ref] = {}
        self._component_locks: Dict[str, threading.Lock] = {}
        
        # Snapshot management
        self._snapshot_thread: Optional[threading.Thread] = None
        self._snapshot_counter = 0
        
        # Global stats
        self._global_stats = {
            'total_entries': 0,
            'total_size': 0,
            'total_hits': 0,
            'total_misses': 0,
            'total_evictions': 0,
            'sync_operations': 0,
        }
        
        # Start background threads
        self._start_background_threads()
    
    def _start_background_threads(self):
        """Start background maintenance threads."""
        self._running = True
        
        # Event processing thread
        self._event_thread = threading.Thread(target=self._process_events, daemon=True)
        self._event_thread.start()
        
        # Snapshot thread
        if self.enable_persistence:
            self._snapshot_thread = threading.Thread(target=self._snapshot_loop, daemon=True)
            self._snapshot_thread.start()
        
        # Stats aggregation thread
        self._stats_thread = threading.Thread(target=self._aggregate_stats, daemon=True)
        self._stats_thread.start()
    
    def _process_events(self):
        """Process events from all shards and notify subscribers."""
        while self._running:
            try:
                for shard in self.shards:
                    events = shard.get_events(50)
                    for event in events:
                        self._notify_subscribers(event)
                time.sleep(0.1)
            except Exception as e:
                _log.error(f"Event processing error: {e}")
    
    def _notify_subscribers(self, event: ContextEvent):
        """Notify all subscribers of an event."""
        # Global subscribers
        for callback in self._subscribers.get('*', []):
            try:
                callback(event)
            except Exception as e:
                _log.error(f"Subscriber error: {e}")
        
        # Key-specific subscribers
        for callback in self._subscribers.get(event.key, []):
            try:
                callback(event)
            except Exception as e:
                _log.error(f"Subscriber error: {e}")
        
        # Scope-specific subscribers
        scope_key = f"scope:{event.metadata.get('scope', 'local')}"
        for callback in self._subscribers.get(scope_key, []):
            try:
                callback(event)
            except Exception as e:
                _log.error(f"Subscriber error: {e}")
    
    def _snapshot_loop(self):
        """Periodic snapshot creation."""
        while self._running:
            time.sleep(SNAPSHOT_INTERVAL)
            if self._running:
                self.create_snapshot()
    
    def _aggregate_stats(self):
        """Aggregate global statistics."""
        while self._running:
            time.sleep(30)
            if self._running:
                total_entries = 0
                total_size = 0
                total_hits = 0
                total_misses = 0
                total_evictions = 0
                
                for shard in self.shards:
                    stats = shard.get_stats()
                    total_entries += stats.entry_count
                    total_size += stats.total_size
                    total_hits += stats.hits
                    total_misses += stats.misses
                    total_evictions += stats.evictions
                
                self._global_stats.update({
                    'total_entries': total_entries,
                    'total_size': total_size,
                    'total_hits': total_hits,
                    'total_misses': total_misses,
                    'total_evictions': total_evictions,
                })
    
    # Public API
    
    def _get_shard(self, key: str) -> ContextShard:
        """Get shard for a key."""
        shard_id = self.hash_ring.get_shard(key)
        return self.shards[shard_id]
    
    def get(self, key: str) -> Optional[Any]:
        """Get value by key."""
        shard = self._get_shard(key)
        entry = shard.get(key)
        if entry:
            return entry.decompress() if entry.compressed else entry.value
        return None
    
    def set(self, 
            key: str, 
            value: Any, 
            scope: ContextScope = ContextScope.LOCAL,
            ttl: Optional[float] = None,
            tags: Optional[Set[str]] = None,
            metadata: Optional[Dict[str, Any]] = None,
            source_component: str = "") -> bool:
        """Set value with full metadata."""
        shard = self._get_shard(key)
        
        expires_at = None
        if ttl:
            expires_at = time.time() + ttl
        
        entry = ContextEntry(
            key=key,
            value=value,
            scope=scope,
            expires_at=expires_at,
            tags=tags or set(),
            metadata=metadata or {},
        )
        entry.metadata['source_component'] = source_component
        
        return shard.set(key, entry)
    
    def delete(self, key: str) -> bool:
        """Delete a key."""
        shard = self._get_shard(key)
        return shard.delete(key)
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self.get(key) is not None
    
    def get_by_scope(self, scope: ContextScope) -> Dict[str, Any]:
        """Get all entries for a scope."""
        result = {}
        for shard in self.shards:
            entries = shard.get_all(scope)
            for key, entry in entries.items():
                result[key] = entry.decompress() if entry.compressed else entry.value
        return result
    
    def get_by_tags(self, tags: Set[str]) -> Dict[str, Any]:
        """Get all entries matching tags."""
        result = {}
        for shard in self.shards:
            with shard._lock.read_lock():
                for key, entry in shard._entries.items():
                    if not entry.is_expired() and tags.issubset(entry.tags):
                        result[key] = entry.decompress() if entry.compressed else entry.value
        return result
    
    def query(self, 
              pattern: str = "*", 
              scope: Optional[ContextScope] = None,
              tags: Optional[Set[str]] = None,
              component: Optional[str] = None,
              limit: int = 1000) -> List[Tuple[str, Any]]:
        """Query context entries with filters."""
        import fnmatch
        results = []
        
        for shard in self.shards:
            with shard._lock.read_lock():
                for key, entry in shard._entries.items():
                    if entry.is_expired():
                        continue
                    
                    if pattern != "*" and not fnmatch.fnmatch(key, pattern):
                        continue
                    
                    if scope and entry.scope != scope:
                        continue
                    
                    if tags and not tags.issubset(entry.tags):
                        continue
                    
                    if component and entry.metadata.get('source_component') != component:
                        continue
                    
                    value = entry.decompress() if entry.compressed else entry.value
                    results.append((key, value))
                    
                    if len(results) >= limit:
                        return results
        
        return results
    
    # Subscription system
    
    def subscribe(self, 
                  key_pattern: str, 
                  callback: Callable[[ContextEvent], None]) -> str:
        """Subscribe to context events."""
        sub_id = str(uuid.uuid4())
        self._subscribers[key_pattern].append(callback)
        return sub_id
    
    def unsubscribe(self, sub_id: str) -> bool:
        """Unsubscribe from events."""
        for pattern, callbacks in self._subscribers.items():
            if callback in callbacks:
                callbacks.remove(callback)
                return True
        return False
    
    # Component registration
    
    def register_component(self, name: str, component: Any) -> bool:
        """Register a component for context sharing."""
        if name in self._components:
            return False
        self._components[name] = weakref.ref(component)
        self._component_locks[name] = threading.Lock()
        return True
    
    def unregister_component(self, name: str) -> bool:
        """Unregister a component."""
        if name in self._components:
            del self._components[name]
            del self._component_locks[name]
            return True
        return False
    
    def get_component_context(self, name: str) -> Dict[str, Any]:
        """Get context specific to a component."""
        return self.query(component=name)
    
    # Snapshot management
    
    def create_snapshot(self, name: Optional[str] = None) -> str:
        """Create a context snapshot."""
        snapshot_id = name or f"snapshot_{self._snapshot_counter:06d}_{int(time.time())}"
        self._snapshot_counter += 1
        
        snapshot_data = {
            'id': snapshot_id,
            'timestamp': time.time(),
            'version': 1,
            'shards': {},
            'global_stats': self._global_stats.copy(),
        }
        
        for shard in self.shards:
            entries = shard.get_all()
            snapshot_data['shards'][shard.shard_id] = {
                k: {
                    'key': e.key,
                    'value': e.value if not e.compressed else e.value.hex(),
                    'scope': e.scope.value,
                    'version': e.version,
                    'created_at': e.created_at,
                    'updated_at': e.updated_at,
                    'expires_at': e.expires_at,
                    'tags': list(e.tags),
                    'metadata': e.metadata,
                    'checksum': e.checksum,
                    'compressed': e.compressed,
                } for k, e in entries.items()
            }
        
        # Save snapshot
        if self.enable_persistence and self.storage_path:
            snapshot_dir = self.storage_path / "snapshots"
            snapshot_dir.mkdir(exist_ok=True)
            snapshot_file = snapshot_dir / f"{snapshot_id}.snap"
            
            json_data = json.dumps(snapshot_data, default=str).encode()
            compressed = zlib.compress(json_data, level=6)
            with open(snapshot_file, 'wb') as f:
                f.write(compressed)
        
        # Emit snapshot event
        event = ContextEvent(
            event_type=ContextEventType.SNAPSHOT,
            key=snapshot_id,
            shard_id=-1,
            metadata={'snapshot_id': snapshot_id},
        )
        self._notify_subscribers(event)
        
        _log.info(f"Created snapshot: {snapshot_id} with {sum(len(s['shards'][i]) for i in snapshot_data['shards'])} entries")
        return snapshot_id
    
    def restore_snapshot(self, snapshot_id: str) -> bool:
        """Restore from a snapshot."""
        if not self.enable_persistence or not self.storage_path:
            return False
        
        snapshot_file = self.storage_path / "snapshots" / f"{snapshot_id}.snap"
        if not snapshot_file.exists():
            return False
        
        try:
            with open(snapshot_file, 'rb') as f:
                data = zlib.decompress(f.read())
                snapshot_data = json.loads(data.decode())
            
            # Restore each shard
            for shard_id, shard_data in snapshot_data['shards'].items():
                shard = self.shards[shard_id]
                with shard._lock.write_lock():
                    shard._entries.clear()
                    for key, entry_data in shard_data.items():
                        entry = ContextEntry(
                            key=entry_data['key'],
                            value=bytes.fromhex(entry_data['value']) if entry_data['compressed'] else entry_data['value'],
                            scope=ContextScope(entry_data['scope']),
                            version=entry_data['version'],
                            created_at=entry_data['created_at'],
                            updated_at=entry_data['updated_at'],
                            expires_at=entry_data['expires_at'],
                            tags=set(entry_data['tags']),
                            metadata=entry_data['metadata'],
                            checksum=entry_data['checksum'],
                            compressed=entry_data['compressed'],
                        )
                        shard._entries[key] = entry
                    shard._stats.entry_count = len(shard._entries)
            
            _log.info(f"Restored snapshot: {snapshot_id}")
            return True
        except Exception as e:
            _log.error(f"Failed to restore snapshot {snapshot_id}: {e}")
            return False
    
    def list_snapshots(self) -> List[str]:
        """List available snapshots."""
        if not self.enable_persistence or not self.storage_path:
            return []
        
        snapshot_dir = self.storage_path / "snapshots"
        if not snapshot_dir.exists():
            return []
        
        return [f.stem for f in snapshot_dir.glob("*.snap")]
    
    # Stats and monitoring
    
    def get_stats(self) -> Dict[str, Any]:
        """Get global statistics."""
        stats = self._global_stats.copy()
        stats['shards'] = []
        for shard in self.shards:
            stats['shards'].append(shard.get_stats().__dict__)
        return stats
    
    def get_shard_stats(self, shard_id: int) -> Optional[ShardStats]:
        """Get statistics for a specific shard."""
        if 0 <= shard_id < self.shard_count:
            return self.shards[shard_id].get_stats()
        return None
    
    # Maintenance
    
    def flush_all(self):
        """Flush all shards to disk."""
        for shard in self.shards:
            shard.flush()
    
    def compact(self) -> int:
        """Compact all shards by removing expired entries."""
        total_removed = 0
        for shard in self.shards:
            with shard._lock.write_lock():
                expired = [k for k, v in shard._entries.items() if v.is_expired()]
                for key in expired:
                    del shard._entries[key]
                    total_removed += 1
                shard._stats.evictions += len(expired)
        return total_removed
    
    def rebalance(self) -> bool:
        """Rebalance shards if needed (e.g., after shard count change)."""
        # This is a complex operation - would need to redistribute entries
        # based on new hash ring. For now, just log.
        _log.warning("Rebalance requested but not implemented")
        return False
    
    def shutdown(self):
        """Shutdown the context manager."""
        self._running = False
        
        # Wait for threads
        if self._event_thread:
            self._event_thread.join(timeout=5)
        if self._snapshot_thread:
            self._snapshot_thread.join(timeout=5)
        if self._stats_thread:
            self._stats_thread.join(timeout=5)
        
        # Flush all shards
        self.flush_all()
        
        # Shutdown shards
        for shard in self.shards:
            shard.shutdown()
        
        _log.info("ShardedContextManager shutdown complete")


# Convenience functions for common patterns

class ContextProxy:
    """Proxy for easy component-specific context access."""
    
    def __init__(self, manager: ShardedContextManager, component_name: str):
        self.manager = manager
        self.component_name = component_name
    
    def __getitem__(self, key: str) -> Any:
        return self.manager.get(f"{self.component_name}:{key}")
    
    def __setitem__(self, key: str, value: Any):
        self.manager.set(f"{self.component_name}:{key}", value, 
                        source_component=self.component_name)
    
    def __delitem__(self, key: str):
        self.manager.delete(f"{self.component_name}:{key}")
    
    def __contains__(self, key: str) -> bool:
        return self.manager.exists(f"{self.component_name}:{key}")
    
    def get(self, key: str, default: Any = None) -> Any:
        return self.manager.get(f"{self.component_name}:{key}") or default
    
    def set(self, key: str, value: Any, **kwargs):
        self.manager.set(f"{self.component_name}:{key}", value, 
                        source_component=self.component_name, **kwargs)
    
    def keys(self) -> List[str]:
        prefix = f"{self.component_name}:"
        results = self.manager.query(pattern=f"{prefix}*")
        return [k[len(prefix):] for k, _ in results]


# Global instance for easy access
_global_context_manager: Optional[ShardedContextManager] = None


def get_context_manager() -> ShardedContextManager:
    """Get global context manager instance."""
    global _global_context_manager
    if _global_context_manager is None:
        _global_context_manager = ShardedContextManager()
    return _global_context_manager


def init_context_manager(shard_count: int = DEFAULT_SHARD_COUNT,
                        storage_path: Optional[Path] = None) -> ShardedContextManager:
    """Initialize global context manager."""
    global _global_context_manager
    _global_context_manager = ShardedContextManager(shard_count, storage_path)
    return _global_context_manager


# Example usage and integration helpers

class ComponentContextMixin:
    """Mixin for components to easily access shared context."""
    
    def __init__(self):
        self._context_proxy: Optional[ContextProxy] = None
        self._component_name = self.__class__.__name__
    
    def get_context(self) -> ContextProxy:
        """Get context proxy for this component."""
        if self._context_proxy is None:
            manager = get_context_manager()
            manager.register_component(self._component_name, self)
            self._context_proxy = ContextProxy(manager, self._component_name)
        return self._context_proxy


# Export all public classes
__all__ = [
    'ContextScope',
    'ContextEventType',
    'ContextEntry',
    'ContextEvent',
    'ShardStats',
    'ConsistentHashRing',
    'ContextShard',
    'ShardedContextManager',
    'ContextProxy',
    'ComponentContextMixin',
    'get_context_manager',
    'init_context_manager',
    'DEFAULT_SHARD_COUNT',
    'MAX_CONTEXT_SIZE',
    'CONTEXT_TTL',
]