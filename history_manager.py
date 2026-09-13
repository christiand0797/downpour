"""
Persistent History/Version Control System for Downpour v29
==========================================================

Provides persistent, granular history tracking with the ability to revert
specific changes from any past session. Unlike simple undo/redo, this system
tracks every file change with metadata, allows browsing history, and supports
selective revert of individual changes from any session.

Features:
- Persistent SQLite database across sessions
- Granular change tracking (file, line range, operation type)
- Semantic change descriptions (not just diffs)
- Selective revert of individual changes from any session
- Branching support for experimental changes
- Change annotations and tagging
- Rollback preview before commit
- Integration with existing audit logging

Database Schema:
- history_changes: Main change log with metadata
- change_branches: Support for branching
- change_tags: User-defined tags for organization
- revert_log: Audit trail of reverts
"""

import sqlite3
import json
import hashlib
import threading
import time
import os
import difflib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)


class ChangeType(Enum):
    """Types of changes tracked."""
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    RENAME = "rename"
    REVERT = "revert"
    MERGE = "merge"
    REFACTOR = "refactor"
    FIX = "fix"
    FEATURE = "feature"
    REFACTOR = "refactor"
    DOCS = "docs"
    TEST = "test"
    CONFIG = "config"
    BUILD = "build"
    DEPS = "deps"
    STYLE = "style"
    PERF = "perf"
    SECURITY = "security"
    REFACTOR = "refactor"
    REVERT = "revert"


class ChangeStatus(Enum):
    """Status of a change."""
    PENDING = "pending"
    COMMITTED = "committed"
    REVERTED = "reverted"
    MERGED = "merged"
    CONFLICT = "conflict"
    SUPERSEDED = "superseded"


@dataclass
class FileChange:
    """Represents a single file change."""
    file_path: str
    change_type: ChangeType
    old_content: Optional[str] = None
    new_content: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    description: str = ""
    tags: List[str] = None
    metadata: Dict = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if self.metadata is None:
            self.metadata = {}


@dataclass
class HistoryChange:
    """Represents a committed change with full metadata."""
    id: Optional[int] = None
    session_id: str = ""
    timestamp: datetime = None
    author: str = "system"
    branch: str = "main"
    changes: List[FileChange] = None
    description: str = ""
    message: str = ""
    tags: List[str] = None
    status: ChangeStatus = ChangeStatus.COMMITTED
    parent_ids: List[int] = None
    tags_list: List[str] = None
    metadata: Dict = None
    hash: str = ""
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
        if self.changes is None:
            self.changes = []
        if self.tags is None:
            self.tags = []
        if self.parent_ids is None:
            self.parent_ids = []
        if self.tags_list is None:
            self.tags_list = []
        if self.metadata is None:
            self.metadata = {}
        if not self.hash:
            self.hash = self._compute_hash()
    
    def _compute_hash(self) -> str:
        # FIX: `changes` may hold dicts (from commit_session's asdict
        # serialization) OR FileChange dataclasses — handle both, and never
        # let hash computation raise out of __post_init__.
        try:
            serialized = [asdict(c) if not isinstance(c, dict) else c
                          for c in (self.changes or [])]
            content = f"{self.session_id}{self.timestamp}" \
                      f"{json.dumps(serialized, sort_keys=True, default=str)}"
            return hashlib.sha256(content.encode()).hexdigest()[:16]
        except Exception:
            return hashlib.sha256(
                f"{self.session_id}{self.timestamp}".encode()).hexdigest()[:16]


class HistoryManager:
    """Persistent history manager with granular revert capabilities."""
    
    def __init__(self, db_path: str = "history.db", repo_root: str = "."):
        self.db_path = Path(db_path)
        self.repo_root = Path(repo_root).resolve()
        self._lock = threading.RLock()
        self._current_session = self._generate_session_id()
        self._pending_changes: List[FileChange] = []
        self._init_db()
    
    def _init_db(self):
        """Initialize SQLite database with required tables."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS history_changes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        session_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        author TEXT DEFAULT 'system',
                        branch TEXT DEFAULT 'main',
                        changes_json TEXT NOT NULL,
                        description TEXT DEFAULT '',
                        message TEXT DEFAULT '',
                        tags TEXT DEFAULT '[]',
                        status TEXT DEFAULT 'committed',
                        parent_ids TEXT DEFAULT '[]',
                        tags_list TEXT DEFAULT '[]',
                        metadata TEXT DEFAULT '{}',
                        hash TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_history_session ON history_changes(session_id)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_history_timestamp ON history_changes(timestamp)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_history_hash ON history_changes(hash)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_history_branch ON history_changes(branch)
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS change_branches (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE NOT NULL,
                        base_change_id INTEGER,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        parent_branch TEXT DEFAULT 'main',
                        description TEXT DEFAULT '',
                        is_active BOOLEAN DEFAULT 1
                    )
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS change_tags (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        change_id INTEGER NOT NULL,
                        tag TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (change_id) REFERENCES history_changes(id) ON DELETE CASCADE
                    )
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_change_tags_change ON change_tags(change_id)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_change_tags_tag ON change_tags(tag)
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS revert_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        reverted_change_id INTEGER NOT NULL,
                        revert_change_id INTEGER NOT NULL,
                        reason TEXT DEFAULT '',
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (reverted_change_id) REFERENCES history_changes(id),
                        FOREIGN KEY (revert_change_id) REFERENCES history_changes(id)
                    )
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS change_annotations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        change_id INTEGER NOT NULL,
                        annotation TEXT NOT NULL,
                        author TEXT DEFAULT 'system',
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (change_id) REFERENCES history_changes(id) ON DELETE CASCADE
                    )
                """)
                
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS file_snapshots (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_path TEXT NOT NULL,
                        content_hash TEXT NOT NULL,
                        content TEXT NOT NULL,
                        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        change_id INTEGER,
                        FOREIGN KEY (change_id) REFERENCES history_changes(id)
                    )
                """)
                
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_file_snapshots_path ON file_snapshots(file_path)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_file_snapshots_change ON file_snapshots(change_id)
                """)
                
        except Exception as e:
            logging.error(f"Failed to initialize history DB: {e}")
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID."""
        return f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}"
    
    def start_session(self, author: str = "system", branch: str = "main") -> str:
        """Start a new change tracking session."""
        with self._lock:
            self._current_session = self._generate_session_id()
            self._pending_changes = []
            return self._current_session
    
    def track_change(self, file_path: str, change_type: ChangeType, 
                     old_content: Optional[str] = None, new_content: Optional[str] = None,
                     line_start: Optional[int] = None, line_end: Optional[int] = None,
                     description: str = "", tags: List[str] = None,
                     metadata: Dict = None) -> FileChange:
        """Track a file change in the current session."""
        with self._lock:
            rel_path = self._get_relative_path(file_path)
            change = FileChange(
                file_path=rel_path,
                change_type=change_type,
                old_content=old_content,
                new_content=new_content,
                line_start=line_start,
                line_end=line_end,
                description=description,
                tags=tags or [],
                metadata=metadata or {}
            )
            self._pending_changes.append(change)
            return rel_path
    
    def commit_session(self, description: str = "", message: str = "",
                       tags: List[str] = None, author: str = "system",
                       branch: str = "main") -> int:
        """Commit all pending changes as a single history entry."""
        with self._lock:
            if not self._pending_changes:
                return 0
            
            changes = self._pending_changes.copy()
            self._pending_changes.clear()

            change_entry = HistoryChange(
                session_id=self._current_session,
                timestamp=datetime.now(),
                changes=[asdict(c) for c in changes],
                description=description,
                message=message,
                tags=tags or [],
                author=author,
                branch=branch,
                status=ChangeStatus.COMMITTED
            )
            
            change_id = self._save_change(change_entry)
            
            # Save file snapshots for modified files
            for change in changes:
                if change.new_content is not None:
                    self._save_file_snapshot(change.file_path, change.new_content, change_id)
            
            return change_id
    
    def _save_change(self, change: HistoryChange) -> int:
        """Save change to database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT INTO history_changes 
                (session_id, timestamp, author, branch, changes_json, description, 
                 message, tags, status, parent_ids, tags_list, metadata, hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                change.session_id,
                change.timestamp.isoformat(),
                change.author,
                change.branch,
                json.dumps(change.changes),
                change.description,
                change.message,
                json.dumps(change.tags),
                change.status.value,
                json.dumps(change.parent_ids),
                json.dumps(change.tags_list),
                json.dumps(change.metadata),
                change.hash
            ))
            return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    
    def _save_file_snapshot(self, file_path: str, content: str, change_id: int):
        """Save file snapshot for potential revert."""
        try:
            content_hash = hashlib.sha256(content.encode()).hexdigest()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO file_snapshots (file_path, content_hash, content, change_id)
                    VALUES (?, ?, ?, ?)
                """, (file_path, hashlib.sha256(content.encode()).hexdigest(), content, change_id))
        except Exception as e:
            logging.warning(f"Failed to save file snapshot: {e}")
    
    def get_history(self, limit: int = 100, branch: str = "main",
                    since: Optional[datetime] = None,
                    author: Optional[str] = None,
                    tags: List[str] = None) -> List[Dict]:
        """Get history with filtering."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                query = "SELECT * FROM history_changes WHERE 1=1"
                params = []
                
                if branch:
                    query += " AND branch = ?"
                    params.append(branch)
                
                if since:
                    query += " AND timestamp >= ?"
                    params.append(since.isoformat())
                
                if author:
                    query += " AND author = ?"
                    params.append(author)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                results = []
                for row in cursor.fetchall():
                    row_dict = dict(row)
                    row_dict['changes'] = json.loads(row['changes_json'])
                    row_dict['tags'] = json.loads(row_dict['tags'])
                    row_dict['parent_ids'] = json.loads(row_dict['parent_ids'])
                    row_dict['tags_list'] = json.loads(row_dict['tags_list'])
                    row_dict['metadata'] = json.loads(row_dict['metadata'])
                    results.append(row_dict)
                return results
    
    def get_change_details(self, change_id: int) -> Optional[Dict]:
        """Get full details of a specific change."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("SELECT * FROM history_changes WHERE id = ?", (change_id,))
                row = cursor.fetchone()
                if not row:
                    return None
                
                row_dict = dict(row)
                row_dict['changes'] = json.loads(row['changes_json'])
                row_dict['tags'] = json.loads(row['tags'])
                row_dict['parent_ids'] = json.loads(row['parent_ids'])
                row_dict['tags_list'] = json.loads(row_dict['tags_list'])
                row_dict['metadata'] = json.loads(row_dict['metadata'])
                return row_dict
    
    def get_file_history(self, file_path: str, limit: int = 50) -> List[Dict]:
        """Get history for a specific file."""
        with self._lock:
            rel_path = self._get_relative_path(file_path)
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT h.* FROM history_changes h
                    JOIN json_each(h.changes_json) je
                    WHERE json_extract(je.value, '$.file_path') = ?
                    ORDER BY h.timestamp DESC LIMIT ?
                """, (file_path, limit))
                
                results = []
                for row in cursor.fetchall():
                    row_dict = dict(row)
                    row_dict['changes'] = json.loads(row['changes_json'])
                    row_dict['tags'] = json.loads(row_dict['tags'])
                    row_dict['parent_ids'] = json.loads(row_dict['parent_ids'])
                    row_dict['tags_list'] = json.loads(row_dict['tags_list'])
                    row_dict['metadata'] = json.loads(row_dict['metadata'])
                    results.append(row_dict)
                return results
    
    def revert_change(self, change_id: int, reason: str = "", 
                      author: str = "system") -> int:
        """Revert a specific change by creating a revert commit."""
        with self._lock:
            # Get the change to revert
            change = self.get_change_details(change_id)
            if not change:
                raise ValueError(f"Change {change_id} not found")
            
            if change['status'] == 'reverted':
                raise ValueError(f"Change {change_id} already reverted")
            
            # Create revert changes by reversing each file change
            revert_changes = []
            for change_data in change['changes']:
                revert_change = FileChange(
                    file_path=change_data['file_path'],
                    change_type=ChangeType.REVERT,
                    old_content=change_data.get('new_content'),
                    new_content=change_data.get('old_content'),
                    line_start=change_data.get('line_start'),
                    line_end=change_data.get('line_end'),
                    description=f"Revert: {change_data.get('description', '')}",
                    tags=['revert', f'reverts_{change_id}'],
                    metadata={
                        'reverts_change_id': change_id,
                        'original_change_type': change_data['change_type']
                    }
                )
                revert_changes.append(revert_change)
            
            # Apply the revert changes
            for rc in revert_changes:
                self._apply_file_change(rc)
            
            # Create revert commit
            revert_change = HistoryChange(
                session_id=self._generate_session_id(),
                timestamp=datetime.now(),
                changes=[asdict(rc) for rc in revert_changes],
                description=f"Revert change #{change_id}: {reason}",
                message=f"Reverted change #{change_id}. Reason: {reason}",
                tags=['revert', f'reverts_{change_id}'],
                author='system',
                branch='main',
                parent_ids=[change_id]
            )
            
            revert_id = self._save_change(revert_change)
            
            # Log the revert
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT INTO revert_log (reverted_change_id, revert_change_id, reason)
                    VALUES (?, ?, ?)
                """, (change_id, revert_id, reason))
            
            # Update original change status
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE history_changes SET status = ? WHERE id = ?
                """, (ChangeStatus.REVERTED.value, change_id))
            
            return revert_id
    
    def _apply_file_change(self, change: FileChange):
        """Apply a file change to disk."""
        file_path = self.repo_root / change.file_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        if change.change_type == ChangeType.DELETE:
            if file_path.exists():
                file_path.unlink()
        else:
            content = change.new_content or ""
            file_path.write_text(content, encoding='utf-8')
    
    def preview_revert(self, change_id: int) -> Dict:
        """Preview what a revert would do without applying."""
        change = self.get_change_details(change_id)
        if not change:
            raise ValueError(f"Change {change_id} not found")
        
        preview = {
            'change_id': change_id,
            'original_change': change,
            'files_affected': [],
            'conflicts': [],
            'can_revert': True
        }
        
        for change_data in change['changes']:
            file_path = Path(change_data['file_path'])
            if file_path.exists():
                current_content = file_path.read_text(encoding='utf-8')
                expected_old = change_data.get('old_content', '')
                if current_content != change_data.get('new_content', ''):
                    preview['conflicts'].append({
                        'file': change_data['file_path'],
                        'issue': 'Content has been modified since the change',
                        'current_preview': current_content[:200],
                        'expected_old': change_data.get('old_content', '')[:200]
                    })
                    preview['can_revert'] = False
            
            preview['files_affected'].append({
                'file': change_data['file_path'],
                'original_change_type': change_data['change_type'],
                'revert_action': 'restore_previous' if change_data.get('old_content') else 'delete'
            })
        
        return preview
    
    def get_file_at_change(self, change_id: int, file_path: str) -> Optional[str]:
        """Get file content as it existed after a specific change."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT content FROM file_snapshots 
                WHERE change_id <= ? AND file_path = ?
                ORDER BY timestamp DESC LIMIT 1
            """, (change_id, file_path))
            row = conn.fetchone()
            return row[0] if row else None
    
    def diff_changes(self, change_id1: int, change_id2: int) -> str:
        """Generate diff between two changes."""
        c1 = self.get_change_details(change_id)
        c2 = self.get_change_details(change_id2)
        
        if not c1 or not c2:
            raise ValueError("One or both changes not found")
        
        diffs = []
        for c1_change in c1['changes']:
            for c2_change in c2['changes']:
                if c1_change['file_path'] == c2_change['file_path']:
                    old = c1_change.get('new_content', '')
                    new = c2_change.get('new_content', '')
                    diff = difflib.unified_diff(
                        old.splitlines(keepends=True),
                        new.splitlines(keepends=True),
                        fromfile=f"Change {c1['id']}: {c1_change['file_path']}",
                        tofile=f"Change {c2['id']}: {c2_change['file_path']}"
                    )
                    diffs.append(''.join(diff))
        
        return '\n'.join(diffs) if diffs else "No differences found"
    
    def create_branch(self, name: str, base_change_id: int, 
                      description: str = "", parent_branch: str = "main") -> int:
        """Create a new branch from a specific change."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT * FROM history_changes WHERE id = ?", (base_change_id,))
                base = cursor.fetchone()
                if not base:
                    raise ValueError(f"Base change {base_change_id} not found")
                
                conn.execute("""
                    INSERT INTO change_branches (name, base_change_id, parent_branch, description)
                    VALUES (?, ?, ?, ?)
                """, (name, base_change_id, parent_branch, description))
                return conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    
    def switch_branch(self, branch_name: str) -> bool:
        """Switch current branch."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT * FROM change_branches WHERE name = ? AND is_active = 1", (branch_name,))
                branch = cursor.fetchone()
                if not branch:
                    return False
                self._current_branch = branch_name
                return True
    
    def tag_change(self, change_id: int, tag: str) -> bool:
        """Add a tag to a change."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT 1 FROM history_changes WHERE id = ?", (change_id,))
                if not cursor.fetchone():
                    return False
                conn.execute("""
                    INSERT OR IGNORE INTO change_tags (change_id, tag) VALUES (?, ?)
                """, (change_id, tag))
                return True
    
    def get_changes_by_tag(self, tag: str, limit: int = 100) -> List[Dict]:
        """Get all changes with a specific tag."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.execute("""
                    SELECT h.* FROM history_changes h
                    JOIN change_tags ct ON h.id = ct.change_id
                    WHERE ct.tag = ?
                    ORDER BY h.timestamp DESC LIMIT ?
                """, (tag, limit))
                
                results = []
                for row in cursor.fetchall():
                    row_dict = dict(row)
                    row_dict['changes'] = json.loads(row['changes_json'])
                    row_dict['tags'] = json.loads(row_dict['tags'])
                    row_dict['parent_ids'] = json.loads(row_dict['parent_ids'])
                    row_dict['tags_list'] = json.loads(row_dict['tags_list'])
                    row_dict['metadata'] = json.loads(row_dict['metadata'])
                    results.append(row_dict)
                return results
    
    def annotate_change(self, change_id: int, annotation: str, author: str = "system") -> bool:
        """Add an annotation to a change."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT 1 FROM history_changes WHERE id = ?", (change_id,))
                if not cursor.fetchone():
                    return False
                conn.execute("""
                    INSERT INTO change_annotations (change_id, annotation, author)
                    VALUES (?, ?, ?)
                """, (change_id, annotation, author))
                return True
    
    def get_annotations(self, change_id: int) -> List[Dict]:
        """Get all annotations for a change."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT * FROM change_annotations WHERE change_id = ? ORDER BY timestamp
            """, (change_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_revert_log(self, limit: int = 50) -> List[Dict]:
        """Get history of reverts."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("""
                SELECT r.*, h1.description as original_desc, h2.description as revert_desc
                FROM revert_log r
                JOIN history_changes h1 ON r.reverted_change_id = h1.id
                JOIN history_changes h2 ON r.revert_change_id = h2.id
                ORDER BY r.timestamp DESC LIMIT ?
            """, (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_branches(self) -> List[Dict]:
        """Get all branches."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM change_branches WHERE is_active = 1 ORDER BY created_at")
            return [dict(row) for row in cursor.fetchall()]
    
    def _get_relative_path(self, file_path: str) -> str:
        """Get relative path from repo root."""
        try:
            return str(Path(file_path).resolve().relative_to(self.repo_root))
        except ValueError:
            return file_path
    
    def export_history(self, filepath: str, branch: str = "main") -> bool:
        """Export history to JSON file."""
        try:
            history = self.get_history(limit=10000, branch=branch)
            data = {
                'exported_at': datetime.now().isoformat(),
                'branch': branch,
                'total_changes': len(filepath),
                'changes': history
            }
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            logging.error(f"Failed to export history: {e}")
            return False
    
    def import_history(self, filepath: str, merge: bool = True) -> int:
        """Import history from JSON file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            imported = 0
            for change_data in data.get('changes', []):
                # Check if already exists
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute("SELECT 1 FROM history_changes WHERE hash = ?", (change_data.get('hash'),))
                    if cursor.fetchone():
                        continue  # Skip duplicates
                
                change = HistoryChange(
                    session_id=change_data['session_id'],
                    timestamp=datetime.fromisoformat(change_data['timestamp']),
                    author=change_data['author'],
                    branch=change_data.get('branch', 'main'),
                    changes=change_data['changes'],
                    description=change_data.get('description', ''),
                    message=change_data.get('message', ''),
                    tags=change_data.get('tags', []),
                    parent_ids=change_data.get('parent_ids', []),
                    tags_list=change_data.get('tags_list', []),
                    metadata=change_data.get('metadata', {}),
                    hash=change_data.get('hash', '')
                )
                self._save_change(change)
                imported += 1
            
            return imported
        except Exception as e:
            logging.error(f"Failed to import history: {e}")
            return 0
    
    def cleanup_old_changes(self, days: int = 90, keep_tagged: bool = True) -> int:
        """Remove old changes, optionally keeping tagged ones."""
        with self._lock:
            with sqlite3.connect(self.db_path) as conn:
                cutoff = (datetime.now() - timedelta(days=days)).isoformat()
                
                if keep_tagged:
                    conn.execute("""
                        DELETE FROM history_changes 
                        WHERE timestamp < ? AND id NOT IN (
                            SELECT change_id FROM change_tags
                        )
                    """, (cutoff,))
                else:
                    conn.execute("DELETE FROM history_changes WHERE timestamp < ?", (cutoff,))
                
                deleted = conn.total_changes
                return deleted


# Global history manager instance
_history_manager: Optional[HistoryManager] = None

def get_history_manager(db_path: str = "history.db", repo_root: str = ".") -> HistoryManager:
    """Get global history manager instance."""
    global _history_manager
    if _history_manager is None:
        _history_manager = HistoryManager(db_path, repo_root)
    return _history_manager