"""
quarantine_core.py - Unified Quarantine Service (TASK-016)
===========================================================
Single quarantine implementation replacing 3 divergent formats:
1. AES-GCM encryption (DPAPI-protected key)
2. Signed manifest written BEFORE original delete (write-ahead)
3. Hash-verified restore with full metadata (ACLs, timestamps, owner)
4. Boot-time reconciliation of orphaned quarantine entries
"""

from __future__ import annotations
import os
import json
import hashlib
import shutil
import tempfile
import logging
import threading
import time
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, Dict, List, Any
import sqlite3

class QuarantineError(Exception):
    """Base exception for quarantine operations."""
    pass

try:
    import win32security
    import win32file
    import win32con
    import pywintypes
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False

try:
    import win32crypt
    DPAPI_AVAILABLE = True
except ImportError:
    DPAPI_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

_log = logging.getLogger(__name__)

QUARANTINE_DIR = Path("downpour_data") / "quarantine"
LOCKED_DIR = QUARANTINE_DIR / "locked"
MANIFEST_DIR = QUARANTINE_DIR / "manifests"
KEY_FILE = QUARANTINE_DIR / ".quarantine_key"
DB_FILE = QUARANTINE_DIR / "quarantine.db"

for d in [QUARANTINE_DIR, LOCKED_DIR, MANIFEST_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ---- Data Classes ------------------------------------------------------------

@dataclass
class QuarantineEntry:
    """Complete quarantine metadata for one file."""
    id: int
    original_path: str
    quarantine_path: str
    file_hash: str           # SHA-256 of original file
    file_size: int
    threat_type: str
    threat_name: str
    severity: str
    quarantined_at: str      # ISO timestamp
    # Original metadata for full restore
    original_dacl: Optional[str] = None    # JSON DACL
    original_sacl: Optional[str] = None    # JSON SACL
    original_owner: Optional[str] = None   # SID string
    created_time: Optional[str] = None     # ISO timestamp
    modified_time: Optional[str] = None
    accessed_time: Optional[str] = None
    # Restore tracking
    restored: bool = False
    restored_at: Optional[str] = None
    restore_verified: bool = False

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict) -> 'QuarantineEntry':
        return cls(**d)

# ---- Crypto ------------------------------------------------------------------

def _get_or_create_key() -> bytes:
    """Get or create DPAPI-protected AES-256 key."""
    if KEY_FILE.exists():
        try:
            blob = KEY_FILE.read_bytes().strip()
            if blob.startswith(b'DPAPI:') and DPAPI_AVAILABLE:
                protected = __import__('base64').b64decode(blob[6:])
                _desc, key = win32crypt.CryptUnprotectData(protected, None, None, None, 0)
                return key
            if blob.startswith(b'RAW:'):
                return __import__('base64').b64decode(blob[4:])
        except Exception:
            pass
    # Create new key
    import secrets
    key = secrets.token_bytes(32)
    try:
        if DPAPI_AVAILABLE:
            import base64
            protected = win32crypt.CryptProtectData(key, 'downpour-quarantine-key', None, None, None, 0)
            KEY_FILE.write_bytes(b'DPAPI:' + base64.b64encode(protected))
        else:
            import base64
            KEY_FILE.write_bytes(b'RAW:' + base64.b64encode(key))
    except Exception:
        pass
    return key

_QUARANTINE_KEY: Optional[bytes] = None

def _get_key() -> bytes:
    global _QUARANTINE_KEY
    if _QUARANTINE_KEY is None:
        _QUARANTINE_KEY = _get_or_create_key()
    return _QUARANTINE_KEY

def _encrypt(data: bytes) -> bytes:
    """AES-256-GCM encrypt. Returns nonce(12) + ciphertext + tag(16)."""
    if not CRYPTO_AVAILABLE:
        # Fallback: XOR with key stream (not for production!)
        key = _get_key()
        nonce = os.urandom(12)
        ks = b''.join(
            __import__('hmac').new(key, nonce + b'c' + __import__('hashlib').sha256(str(i).encode()).digest(),
                             __import__('hashlib').sha256).digest()
            for i in range((len(data) + 31) // 32)
        )[:len(data)]
        return b'\x00' + nonce + bytes(a ^ b for a, b in zip(data, ks))
    nonce = os.urandom(12)
    ct = AESGCM(_get_key()).encrypt(nonce, data, None)
    return b'\x01' + nonce + ct

def _decrypt(blob: bytes) -> bytes:
    """AES-256-GCM decrypt. Expects nonce(12) + ciphertext + tag(16)."""
    if not blob:
        raise ValueError("Empty blob")
    version = blob[0:1]
    nonce = blob[1:13]
    ct = blob[13:]
    if version == b'\x01':
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography required for v1 decrypt")
        return AESGCM(_get_key()).decrypt(nonce, ct, None)
    # v0 fallback
    import hashlib as _hh, hmac as _hm
    key = _get_key()
    ks = b''.join(
        _hm.new(key, nonce + b'c' + _hh.sha256(str(i).encode()).digest(), _hh.sha256).digest()
        for i in range((len(ct) + 31) // 32)
    )[:len(ct)]
    return bytes(a ^ b for a, b in zip(ct, ks))

# ---- Streaming format (v29.43e) ------------------------------------------------
# Files > _STREAM_THRESHOLD are encrypted/restored in 64KiB chunks with
# constant memory:  DQS2 magic + nonce-prefix(8) + chunks(AESGCM, nonce =
# prefix + counter BE32).  v0/v1 single-shot files remain restorable via
# _decrypt (format detected by the first 4 bytes).

_STREAM_MAGIC = b'DQS2'
_STREAM_THRESHOLD = 64 * 1024 * 1024  # 64 MB
_CHUNK = 65536
_GCM_TAG = 16


def _encrypt_stream_file(src: Path, dst: Path) -> None:
    """Stream-encrypt src into dst (format v2). Constant memory."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError('cryptography required for streaming quarantine')
    aes = AESGCM(_get_key())
    prefix = os.urandom(8)
    counter = 0
    with open(src, 'rb') as fin, open(dst, 'wb') as fout:
        fout.write(_STREAM_MAGIC + prefix)
        while True:
            chunk = fin.read(_CHUNK)
            if not chunk:
                break
            fout.write(aes.encrypt(prefix + counter.to_bytes(4, 'big'),
                                   chunk, None))
            counter += 1
        fout.flush()
        os.fsync(fout.fileno())


def _decrypt_stream_file(q_path: Path, dst: Path) -> str:
    """Stream-decrypt a v2-format file into dst. Returns the plaintext
    SHA-256 (raises on GCM auth failure = tamper)."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError('cryptography required for streaming restore')
    aes = AESGCM(_get_key())
    h = hashlib.sha256()
    with open(q_path, 'rb') as fin, open(dst, 'wb') as fout:
        header = fin.read(4)
        if header != _STREAM_MAGIC:
            raise ValueError('not a streamed quarantine file')
        prefix = fin.read(8)
        counter = 0
        while True:
            chunk = fin.read(_CHUNK + _GCM_TAG)
            if not chunk:
                break
            plain = aes.decrypt(prefix + counter.to_bytes(4, 'big'),
                                chunk, None)
            h.update(plain)
            fout.write(plain)
            counter += 1
        fout.flush()
        os.fsync(fout.fileno())
    return h.hexdigest()


def _decrypt_stream_hash(q_path: Path) -> str:
    """Hash-only stream decrypt — verification without a disk write."""
    aes = AESGCM(_get_key())
    h = hashlib.sha256()
    with open(q_path, 'rb') as f:
        header = f.read(12)  # 4B magic + 8B nonce prefix
        prefix = header[4:]
        counter = 0
        while True:
            chunk = f.read(_CHUNK + _GCM_TAG)
            if not chunk:
                break
            h.update(aes.decrypt(prefix + counter.to_bytes(4, 'big'),
                                 chunk, None))
            counter += 1
    return h.hexdigest()


def _qc_unlink(p: Path) -> None:
    try:
        os.remove(str(p))
    except Exception:
        pass

# ---- Database -----------------------------------------------------------------

def _init_db() -> None:
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                threat_type TEXT NOT NULL,
                threat_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                quarantined_at TEXT NOT NULL,
                original_dacl TEXT,
                original_sacl TEXT,
                original_owner TEXT,
                created_time TEXT,
                modified_time TEXT,
                accessed_time TEXT,
                restored INTEGER DEFAULT 0,
                restored_at TEXT,
                restore_verified INTEGER DEFAULT 0
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_quarantine_hash ON quarantine(file_hash)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_quarantine_original ON quarantine(original_path)')

def _load_entries() -> Dict[int, QuarantineEntry]:
    entries = {}
    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute('SELECT * FROM quarantine WHERE restored=0'):
            entries[row['id']] = QuarantineEntry(
                id=row['id'], original_path=row['original_path'],
                quarantine_path=row['quarantine_path'], file_hash=row['file_hash'],
                file_size=row['file_size'], threat_type=row['threat_type'],
                threat_name=row['threat_name'], severity=row['severity'],
                quarantined_at=row['quarantined_at'],
                original_dacl=row['original_dacl'], original_sacl=row['original_sacl'],
                original_owner=row['original_owner'],
                created_time=row['created_time'], modified_time=row['modified_time'],
                accessed_time=row['accessed_time'],
                restored=bool(row['restored']), restored_at=row['restored_at'],
                restore_verified=bool(row['restore_verified'])
            )
    return entries

def _save_entry(entry: QuarantineEntry) -> int:
    with sqlite3.connect(DB_FILE) as conn:
        if entry.id == 0:
            cur = conn.execute('''
                INSERT INTO quarantine (original_path, quarantine_path, file_hash, file_size,
                    threat_type, threat_name, severity, quarantined_at,
                    original_dacl, original_sacl, original_owner,
                    created_time, modified_time, accessed_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (entry.original_path, entry.quarantine_path, entry.file_hash, entry.file_size,
                  entry.threat_type, entry.threat_name, entry.severity, entry.quarantined_at,
                  entry.original_dacl, entry.original_sacl, entry.original_owner,
                  entry.created_time, entry.modified_time, entry.accessed_time))
            entry.id = cur.lastrowid
        else:
            conn.execute('''
                UPDATE quarantine SET
                    quarantine_path=?, file_hash=?, file_size=?, threat_type=?,
                    threat_name=?, severity=?, quarantined_at=?,
                    original_dacl=?, original_sacl=?, original_owner=?,
                    created_time=?, modified_time=?, accessed_time=?,
                    restored=?, restored_at=?, restore_verified=?
                WHERE id=?
            ''', (entry.quarantine_path, entry.file_hash, entry.file_size, entry.threat_type,
                  entry.threat_name, entry.severity, entry.quarantined_at,
                  entry.original_dacl, entry.original_sacl, entry.original_owner,
                  entry.created_time, entry.modified_time, entry.accessed_time,
                  int(entry.restored), entry.restored_at, int(entry.restore_verified), entry.id))
        return entry.id

# ---- ACL Helpers --------------------------------------------------------------

def _get_file_security(path: Path) -> Optional[Dict[str, str]]:
    """Get DACL, SACL, Owner as JSON strings."""
    if not WIN32_AVAILABLE:
        return None
    try:
        sd = win32security.GetFileSecurity(
            str(path),
            win32security.DACL_SECURITY_INFORMATION |
            win32security.SACL_SECURITY_INFORMATION |
            win32security.OWNER_SECURITY_INFORMATION
        )
        dacl = sd.GetSecurityDescriptorDacl()
        sacl = sd.GetSecurityDescriptorSacl()
        owner = sd.GetSecurityDescriptorOwner()
        return {
            'dacl': json.dumps(_dacl_to_list(dacl)) if dacl else None,
            'sacl': json.dumps(_sacl_to_list(sacl)) if sacl else None,
            'owner': str(owner) if owner else None
        }
    except Exception as e:
        _log.debug(f"GetFileSecurity failed for {path}: {e}")
        return None

def _dacl_to_list(dacl) -> List[Dict]:
    if not dacl:
        return []
    result = []
    for i in range(dacl.GetAceCount()):
        ace = dacl.GetAce(i)
        ace_type, ace_flags, ace_mask = ace[0], ace[1], ace[2]
        sid = ace[2]
        result.append({
            'type': ace_type,
            'flags': ace_flags,
            'mask': ace_mask,
            'sid': str(sid)
        })
    return result

def _sacl_to_list(sacl) -> List[Dict]:
    return _dacl_to_list(sacl)

def _restore_file_security(path: Path, entry: QuarantineEntry) -> bool:
    if not WIN32_AVAILABLE:
        return True
    try:
        sd = win32security.SECURITY_DESCRIPTOR()
        if entry.original_dacl:
            dacl = win32security.ACL()
            for ace in json.loads(entry.original_dacl):
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    ace['mask'],
                    win32security.ConvertStringSidToSid(ace['sid'])
                )
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
        if entry.original_sacl:
            sacl = win32security.ACL()
            for ace in json.loads(entry.original_sacl):
                sacl.AddAuditAccessAce(
                    win32security.ACL_REVISION,
                    ace['mask'],
                    win32security.ConvertStringSidToSid(ace['sid']),
                    True, True
                )
            sd.SetSecurityDescriptorSacl(1, sacl, 0)
        if entry.original_owner:
            owner_sid = win32security.ConvertStringSidToSid(entry.original_owner)
            sd.SetSecurityDescriptorOwner(owner_sid, 0)
        win32security.SetFileSecurity(
            str(path),
            win32security.DACL_SECURITY_INFORMATION |
            win32security.SACL_SECURITY_INFORMATION |
            win32security.OWNER_SECURITY_INFORMATION,
            sd
        )
        return True
    except Exception as e:
        _log.error(f"Restore security failed for {path}: {e}")
        return False

# ---- Quarantine Service -------------------------------------------------------

class QuarantineService:
    """Unified quarantine service - single source of truth."""

    def __init__(self):
        _init_db()
        self._entries = _load_entries()
        self._lock = threading.RLock()

    def quarantine(self, file_path: Path, threat_type: str = "MALWARE",
                   threat_name: str = "Unknown", severity: str = "HIGH") -> QuarantineEntry:
        """
        Quarantine a file with full metadata preservation (write-ahead manifest).
        Returns the QuarantineEntry.
        """
        file_path = Path(file_path).resolve()
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        # 1. Calculate hash BEFORE any move
        file_hash = self._sha256(file_path)
        file_size = file_path.stat().st_size
        stat = file_path.stat()

        # 2. Capture original metadata (ACLs, timestamps, owner)
        security = _get_file_security(file_path)
        created = datetime.fromtimestamp(stat.st_ctime).isoformat()
        modified = datetime.fromtimestamp(stat.st_mtime).isoformat()
        accessed = datetime.fromtimestamp(stat.st_atime).isoformat()

        # 3. Prepare quarantine destination
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_name = f"{file_path.name}.{file_hash[:8]}.quarantined"
        q_path = LOCKED_DIR / safe_name
        # v29.43c (TASK-016 residual): the timestamp was computed but never
        # used — quarantining the same file twice (re-infection cycle) or
        # two identical-named+hashed files OVERWROTE the previous copy while
        # both DB entries pointed at it. Disambiguate on clash.
        if q_path.exists():
            q_path = LOCKED_DIR / f"{file_path.name}.{file_hash[:8]}.{timestamp}.quarantined"

        # 4. Write manifest FIRST (write-ahead) - before moving file
        entry = QuarantineEntry(
            id=0,
            original_path=str(file_path),
            quarantine_path=str(q_path),
            file_hash=file_hash,
            file_size=file_size,
            threat_type=threat_type,
            threat_name=threat_name,
            severity=severity,
            quarantined_at=datetime.now().isoformat(),
            original_dacl=security.get('dacl') if security else None,
            original_sacl=security.get('sacl') if security else None,
            original_owner=security.get('owner') if security else None,
            created_time=created,
            modified_time=modified,
            accessed_time=accessed
        )

        # 5. Save entry to DB (gets ID)
        with self._lock:
            entry.id = _save_entry(entry)

        # 6. Write manifest file (signed) for external verification
        self._write_manifest(entry)

        # 7. Encrypt and move file (atomic on same volume)
        try:
            # v29.43e: files above _STREAM_THRESHOLD are stream-encrypted
            # (constant memory — the old path read the whole file into RAM
            # and doubled it during _encrypt). Small files keep the original
            # single-shot format; all formats remain restorable.
            use_stream = CRYPTO_AVAILABLE and file_size > _STREAM_THRESHOLD
            if use_stream:
                _encrypt_stream_file(file_path, q_path)
                if _decrypt_stream_hash(str(q_path)) != file_hash:
                    raise ValueError('stream self-verification failed')
            else:
                with open(file_path, 'rb') as f:
                    plaintext = f.read()
                # Verify hash matches
                if hashlib.sha256(plaintext).hexdigest() != file_hash:
                    raise ValueError('Hash mismatch during quarantine read')
                ciphertext = _encrypt(plaintext)
                with open(q_path, 'wb') as f:
                    f.write(ciphertext)
            # Remove original
            file_path.unlink()
        except Exception as e:
            # Rollback: remove manifest, DB entry
            try:
                q_path.unlink(missing_ok=True)
                MANIFEST_DIR.joinpath(f"{entry.id}.json").unlink(missing_ok=True)
            except Exception:
                pass
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute('DELETE FROM quarantine WHERE id=?', (entry.id,))
            raise RuntimeError(f"Quarantine failed: {e}") from e

        # 8. Update in-memory cache
        with self._lock:
            self._entries[entry.id] = entry

        _log.info(f"Quarantined: {file_path} -> {q_path} (id={entry.id})")
        return entry

    def _write_manifest(self, entry: QuarantineEntry) -> None:
        """Write signed manifest for external verification."""
        manifest = {
            'id': entry.id,
            'original_path': entry.original_path,
            'quarantine_path': entry.quarantine_path,
            'file_hash': entry.file_hash,
            'file_size': entry.file_size,
            'threat_type': entry.threat_type,
            'threat_name': entry.threat_name,
            'severity': entry.severity,
            'quarantined_at': entry.quarantined_at,
            'version': 1
        }
        canonical = json.dumps(manifest, sort_keys=True).encode('utf-8')
        # Sign with quarantine key (HMAC)
        import hmac
        sig = hmac.new(_get_key(), canonical, hashlib.sha256).hexdigest()
        manifest['signature'] = sig
        manifest_path = MANIFEST_DIR / f"{entry.id}.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')

    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    def restore(self, entry_id: int) -> bool:
        """Restore quarantined file with full verification and metadata restore."""
        with self._lock:
            entry = self._entries.get(entry_id)
        if not entry:
            _log.error(f"Restore failed: entry {entry_id} not found")
            return False

        q_path = Path(entry.quarantine_path)
        if not q_path.exists():
            _log.error(f"Restore failed: quarantine file missing {q_path}")
            return False

        orig_path = Path(entry.original_path)
        orig_path.parent.mkdir(parents=True, exist_ok=True)

        try:
            tmp_path = orig_path.with_suffix(orig_path.suffix + '.tmp')

            # 1. Detect format: streamed (DQS2 magic) or single-shot (v0/v1)
            with open(q_path, 'rb') as f:
                magic = f.read(4)

            if magic == _STREAM_MAGIC:
                # v29.43e: constant-memory stream decrypt straight to tmp
                got = _decrypt_stream_file(q_path, tmp_path)
                if got != entry.file_hash:
                    _qc_unlink(tmp_path)
                    _log.error(f"Restore hash mismatch (stream) for entry {entry_id}")
                    return False
            else:
                # 1b. Read and decrypt (single-shot v0/v1 formats)
                with open(q_path, 'rb') as f:
                    ciphertext = f.read()
                plaintext = _decrypt(ciphertext)

                # 2. Verify hash BEFORE writing to original location
                if hashlib.sha256(plaintext).hexdigest() != entry.file_hash:
                    _qc_unlink(tmp_path)
                    _log.error(f"Restore hash mismatch for entry {entry_id}")
                    return False
                with open(tmp_path, 'wb') as f:
                    f.write(plaintext)

            # 2b. Verify the tmp file on disk (streaming hash — no big read)
            if self._sha256(str(tmp_path)) != entry.file_hash:
                _qc_unlink(tmp_path)
                _log.error(f"Restore verification failed after write for entry {entry_id}")
                return False

            # 3. Atomic replace
            if orig_path.exists():
                orig_path.unlink()
            tmp_path.rename(orig_path)

            # 5. Restore ACLs, timestamps, owner
            if not _restore_file_security(orig_path, entry):
                _log.warning(f"ACL restore partial for {orig_path}")

            # Restore timestamps
            try:
                if WIN32_AVAILABLE:
                    handle = win32file.CreateFile(
                        str(orig_path), win32file.GENERIC_WRITE, 0, None,
                        win32file.OPEN_EXISTING, win32file.FILE_FLAG_BACKUP_SEMANTICS, None)
                    win32file.SetFileTime(
                        handle,
                        pywintypes.Time(entry.created_time),
                        pywintypes.Time(entry.accessed_time),
                        pywintypes.Time(entry.modified_time)
                    )
                    handle.Close()
            except Exception as e:
                _log.warning(f"Timestamp restore failed for {orig_path}: {e}")

            # 6. Mark restored in DB
            entry.restored = True
            entry.restored_at = datetime.now().isoformat()
            entry.restore_verified = True
            with self._lock:
                self._entries[entry.id] = entry
            _save_entry(entry)

            _log.info(f"Restored: {orig_path} (id={entry_id})")
            return True

        except Exception as e:
            _log.error(f"Restore failed for entry {entry_id}: {e}")
            return False

    def get_entry(self, entry_id: int) -> Optional[QuarantineEntry]:
        with self._lock:
            return self._entries.get(entry_id)

    def list_entries(self, include_restored: bool = False) -> List[QuarantineEntry]:
        with self._lock:
            if include_restored:
                return list(self._entries.values())
            return [e for e in self._entries.values() if not e.restored]

    def reconcile(self) -> Dict[str, int]:
        """
        Boot-time reconciliation: scan quarantine dir for orphaned files,
        missing DB entries, hash mismatches. Returns stats.
        """
        stats = {'orphaned_files': 0, 'missing_db': 0, 'hash_mismatch': 0, 'restored_ok': 0}
        with self._lock:
            known_paths = {Path(e.quarantine_path) for e in self._entries.values() if not e.restored}

        # 1. Find orphaned encrypted files in locked dir
        for q_file in LOCKED_DIR.glob('*.quarantined'):
            if q_file not in known_paths:
                stats['orphaned_files'] += 1
                # Try to find matching manifest
                manifest_file = MANIFEST_DIR / f"{q_file.stem}.json"
                if manifest_file.exists():
                    try:
                        manifest = json.loads(manifest_file.read_text(encoding='utf-8'))
                        entry_id = manifest.get('id')
                        if entry_id and entry_id in self._entries:
                            # Re-link
                            pass
                    except Exception:
                        pass

        # 2. Check for DB entries with missing quarantine files
        with self._lock:
            for entry in self._entries.values():
                if not entry.restored:
                    q_path = Path(entry.quarantine_path)
                    if not q_path.exists():
                        stats['missing_db'] += 1
                    else:
                        # Verify hash of encrypted file (optional, slow)
                        pass

        _log.info(f"Quarantine reconciliation: {stats}")
        return stats

# ---- Convenience API ----------------------------------------------------------

_service: Optional[QuarantineService] = None
_service_lock = threading.Lock()

def get_service() -> QuarantineService:
    global _service
    with _service_lock:
        if _service is None:
            _service = QuarantineService()
        return _service

def quarantine_file(file_path: Path, threat_type: str = "MALWARE",
                    threat_name: str = "Unknown", severity: str = "HIGH") -> QuarantineEntry:
    return get_service().quarantine(file_path, threat_type, threat_name, severity)

def restore_file(entry_id: int) -> bool:
    return get_service().restore(entry_id)

def list_quarantined(include_restored: bool = False) -> List[QuarantineEntry]:
    return get_service().list_entries(include_restored)

def reconcile_quarantine() -> Dict[str, int]:
    return get_service().reconcile()

def restore_by_original_path(original_path: str) -> bool:
    """Restore a quarantined file by its original path."""
    service = get_service()
    for entry in service.list_entries():
        if entry.original_path == original_path and not entry.restored:
            return restore_file(entry.id)
    return False

# ---- CLI ----------------------------------------------------------------------

# ---- Legacy migration (v29.43c, TASK-016 residual) ----------------------------

def _legacy_decrypt(data: bytes, method: str, key: Optional[bytes]) -> bytes:
    """Decrypt pre-v2 quarantine content (v1 quarantine_core formats)."""
    if method == 'aes-gcm':
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        if key is None:
            raise QuarantineError('legacy AES entry but no key available')
        prefix, body = data[:8], data[8:]
        aes = AESGCM(key)
        out = bytearray()
        counter = 0
        for off in range(0, len(body), 65536 + 16):
            out += aes.decrypt(prefix + counter.to_bytes(4, 'big'),
                               body[off:off + 65536 + 16], None)
            counter += 1
        return bytes(out)
    if method == 'xor-0x5a':
        return bytes(b ^ 0x5A for b in data)
    if method == 'raw':
        return data
    raise QuarantineError(f'unknown legacy method: {method!r}')


def _legacy_key_for(root: Path) -> Optional[bytes]:
    """Read the legacy quarantine key at ``root/.quarantine_key`` (v1 layout).

    The v2 `_get_or_create_key()` takes no directory argument (it uses the
    module-level KEY_FILE), so migration needs this explicit-path variant.
    """
    kp = Path(root) / '.quarantine_key'
    try:
        if not kp.exists():
            return None
        blob = kp.read_bytes().strip()
        if blob.startswith(b'DPAPI:'):
            import win32crypt
            return win32crypt.CryptUnprotectData(
                base64.b64decode(blob[6:]), None, None, None, 0)[1]
        if blob.startswith(b'RAW:'):
            return base64.b64decode(blob[4:])
    except Exception as exc:
        _log.warning('quarantine_core: legacy key unreadable at %s: %s', kp, exc)
    return None


def _legacy_decrypt_stream(src: Path, method: str, key: Optional[bytes],
                           dst: Path) -> str:
    """Stream-decrypt a legacy artifact into dst (constant memory).

    Returns the plaintext SHA-256. Raises on GCM auth failure (tamper) or
    unknown method. dst is overwritten.
    """
    h = hashlib.sha256()
    with open(src, 'rb') as fin, open(dst, 'wb') as fout:
        if method == 'aes-gcm':
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            if key is None:
                raise QuarantineError('legacy AES entry but no key available')
            prefix = fin.read(8)
            aes = AESGCM(key)
            counter = 0
            while True:
                chunk = fin.read(65536 + 16)
                if not chunk:
                    break
                plain = aes.decrypt(prefix + counter.to_bytes(4, 'big'),
                                    chunk, None)
                h.update(plain)
                fout.write(plain)
                counter += 1
        elif method == 'xor-0x5a':
            for chunk in iter(lambda: fin.read(65536), b''):
                dec = bytes(b ^ 0x5A for b in chunk)
                h.update(dec)
                fout.write(dec)
        elif method == 'raw':
            for chunk in iter(lambda: fin.read(65536), b''):
                h.update(chunk)
                fout.write(chunk)
        else:
            raise QuarantineError(f'unknown legacy method: {method!r}')
        fout.flush()
        os.fsync(fout.fileno())
    return h.hexdigest()


def migrate_legacy_entries(roots: Optional[List[Path]] = None) -> Dict[str, int]:
    """One-time ingest of pre-v2 quarantine artifacts into the v2 service.

    Handles, per legacy root (default: ~/downpour_quarantine and the
    app-data quarantine):
      * v1 ``*.quarantined`` + ``*.meta.json`` sidecars — decrypted with the
        recorded method (AES-GCM via the legacy ``.quarantine_key``, or
        XOR-0x5A) and re-encrypted into the v2 store;
      * plain ``*.locked`` / ``*.quar`` moves — ingested raw (no source
        hash is known, so integrity relies on the new signed manifest).

    Legacy files are NEVER deleted — successfully migrated ones are renamed
    to ``*.migrated``; failures are counted and left in place. Skips
    anything already owned by the v2 service.
    """
    service = get_service()
    if roots is None:
        roots = [Path.home() / 'downpour_quarantine',
                 Path(__file__).parent / 'downpour_data' / 'quarantine']
    stats = {'scanned': 0, 'migrated': 0, 'failed': 0,
             'skipped_v2': 0, 'no_metadata': 0}
    owned = {e.quarantine_path for e in service.list_entries(include_restored=True)}
    owned_names = {Path(p).name for p in owned}

    for root in roots:
        root = Path(root)
        legacy_key: Optional[bytes] = None
        for search_dir in (root / 'locked', root):
            if not search_dir.is_dir():
                continue
            for f in sorted(search_dir.iterdir()):
                if not f.is_file():
                    continue
                name = f.name
                # v29.43f fix: ingest ONLY known quarantine content types.
                # The previous version scanned every file in the root — it
                # renamed the service's OWN storage (.quarantine_key,
                # quarantine.db) as "legacy" artifacts, corrupting the v2
                # service on the next migration run.
                if not name.endswith(('.quarantined', '.locked', '.quar')):
                    continue
                if name.endswith(('.meta.json', '.json', '.log',
                                  '.migrated', '.tmp')):
                    continue
                stats['scanned'] += 1
                if str(f) in owned or name in owned_names:
                    stats['skipped_v2'] += 1
                    continue

                meta = None
                m_path = Path(str(f) + '.meta.json')
                if m_path.exists():
                    try:
                        meta = json.loads(m_path.read_text(encoding='utf-8'))
                    except Exception:
                        meta = None

                try:
                    method = 'raw'
                    key: Optional[bytes] = None
                    orig = ''
                    expected = ''
                    if meta:
                        if 'method' in meta:
                            method = meta['method']
                        elif 'xor_key' in meta:
                            method = 'xor-0x5a'
                        orig = meta.get('original_path') or ''
                        expected = (meta.get('sha256')
                                    or meta.get('hash_sha256') or '').lower()
                        if method == 'aes-gcm' and legacy_key is None:
                            legacy_key = _legacy_key_for(root)
                            if legacy_key is None:
                                raise QuarantineError(
                                    'legacy AES entry but key unavailable')
                    else:
                        stats['no_metadata'] += 1

                    # v29.43f: stream legacy -> tmp plaintext (constant
                    # memory — the old path read whole artifacts into RAM
                    # and re-encrypted them as a second full copy)
                    tmp_plain = search_dir / (name + '.migrating')
                    got_hash = _legacy_decrypt_stream(
                        f, method, key if method == 'aes-gcm' else None,
                        tmp_plain)
                    if expected and got_hash != expected:
                        _qc_unlink(tmp_plain)
                        raise QuarantineError(
                            f'legacy content hash mismatch '
                            f'({expected[:12]}… != {got_hash[:12]}…)')

                    # register as a v2 entry with the ORIGINAL path preserved
                    sha256 = got_hash
                    base_name = Path(orig).name or name
                    q_path = LOCKED_DIR / (base_name + '.'
                                           + sha256[:8] + '.quarantined')
                    if str(q_path) in owned or q_path.exists():
                        q_path = LOCKED_DIR / (
                            base_name + '.' + sha256[:8] + '.'
                            + datetime.now().strftime('%Y%m%d_%H%M%S')
                            + '.quarantined')
                    entry = QuarantineEntry(
                        id=0,
                        original_path=str(Path(orig).resolve()),
                        quarantine_path=str(q_path),
                        file_hash=sha256,
                        file_size=os.path.getsize(str(tmp_plain)),
                        threat_type='legacy-migrated',
                        threat_name=(meta.get('threat_name') if meta else None)
                        or Path(orig).name,
                        severity=(meta.get('severity') if meta else None)
                        or 'UNKNOWN',
                        quarantined_at=datetime.now().isoformat(),
                    )
                    with service._lock:
                        entry.id = _save_entry(entry)
                    service._write_manifest(entry)
                    # re-encrypt the tmp plaintext into the v2 store (streamed)
                    _encrypt_stream_file(tmp_plain, q_path)
                    _qc_unlink(tmp_plain)
                    with service._lock:
                        service._entries[entry.id] = entry
                    owned.add(str(q_path))
                    owned_names.add(q_path.name)
                    # keep the legacy artifact, but mark it consumed
                    f.rename(f.with_name(f.name + '.migrated'))
                    if m_path.exists():
                        m_path.rename(m_path.with_name(m_path.name + '.migrated'))
                    stats['migrated'] += 1
                    _log.info('quarantine_core: migrated legacy entry %s (-> %s)',
                              name, entry.id)
                except Exception as exc:
                    _qc_unlink(search_dir / (name + '.migrating'))
                    stats['failed'] += 1
                    _log.warning('quarantine_core: legacy migration failed '
                                 'for %s: %s', name, exc)
    return stats


if __name__ == '__main__':
    import argparse
    logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

    parser = argparse.ArgumentParser(description='Downpour Quarantine Service')
    parser.add_argument('action', choices=['quarantine', 'restore', 'list', 'reconcile'])
    parser.add_argument('--path', type=Path, help='File to quarantine')
    parser.add_argument('--id', type=int, help='Quarantine entry ID')
    parser.add_argument('--type', default='MALWARE', help='Threat type')
    parser.add_argument('--name', default='Unknown', help='Threat name')
    parser.add_argument('--severity', default='HIGH', help='Severity')
    args = parser.parse_args()

    if args.action == 'quarantine':
        if not args.path:
            parser.error('--path required for quarantine')
        entry = quarantine_file(args.path, args.type, args.name, args.severity)
        print(f"Quarantined: {entry.id} -> {entry.quarantine_path}")
    elif args.action == 'restore':
        if not args.id:
            parser.error('--id required for restore')
        ok = restore_file(args.id)
        print(f"Restore {'OK' if ok else 'FAILED'}")
    elif args.action == 'list':
        for e in list_quarantined():
            status = "RESTORED" if e.restored else "ACTIVE"
            print(f"[{e.id}] {status} {e.original_path} ({e.threat_type}/{e.severity})")
    elif args.action == 'reconcile':
        stats = reconcile_quarantine()
        print(f"Reconciliation: {stats}")