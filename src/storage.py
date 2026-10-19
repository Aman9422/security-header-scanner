"""
Storage Module
~~~~~~~~~~~~~~

Storage and persistence for scan results.
"""

import json
import os
import re
import sqlite3
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any

from .scanner import ScanResult

try:
    import fcntl
except ImportError:  # Windows: thread-level locking remains available.
    fcntl = None


SCAN_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SQLITE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
MAX_STORAGE_QUERY_LIMIT = 10_000
MAX_CLEANUP_DAYS = 3650


def _validate_retention(max_history, auto_cleanup_days):
    if max_history is not None and (
        isinstance(max_history, bool) or not isinstance(max_history, int) or not 1 <= max_history <= 1_000_000
    ):
        raise ValueError("max_history must be between 1 and 1000000, or None")
    if auto_cleanup_days is not None and (
        isinstance(auto_cleanup_days, bool)
        or not isinstance(auto_cleanup_days, int)
        or not 1 <= auto_cleanup_days <= MAX_CLEANUP_DAYS
    ):
        raise ValueError(f"auto_cleanup_days must be between 1 and {MAX_CLEANUP_DAYS}, or None")


def _valid_scan_id(scan_id):
    return isinstance(scan_id, str) and bool(SCAN_ID_PATTERN.fullmatch(scan_id))


def _saved_at_order(info):
    """Return a safe insertion-order tie breaker for a JSON index entry."""
    value = info.get("saved_at_ns", 0) if isinstance(info, dict) else 0
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


class Storage:
    """
    Base storage class for scan results.
    """

    def save(self, result: ScanResult) -> bool:
        """Save a scan result"""
        raise NotImplementedError

    def get(self, scan_id: str) -> Optional[ScanResult]:
        """Get a scan result by ID"""
        raise NotImplementedError

    def get_all(self, limit: int = 100) -> List[ScanResult]:
        """Get all scan results"""
        raise NotImplementedError

    def get_by_url(self, url: str, limit: int = 10) -> List[ScanResult]:
        """Get scan results for a URL"""
        raise NotImplementedError

    def delete(self, scan_id: str) -> bool:
        """Delete a scan result"""
        raise NotImplementedError

    def cleanup(self, days: int = 30) -> int:
        """Clean up old scan results"""
        raise NotImplementedError


class JSONStorage(Storage):
    """Atomic JSON-file storage with thread/process-safe index updates."""

    def __init__(
        self,
        storage_path: str = "./data/scans",
        max_history: Optional[int] = 1000,
        auto_cleanup_days: Optional[int] = 30,
    ):
        _validate_retention(max_history, auto_cleanup_days)
        if not isinstance(storage_path, (str, os.PathLike)) or not str(storage_path).strip() or len(str(storage_path)) > 4096 or any(ord(ch) < 32 for ch in str(storage_path)):
            raise ValueError("storage_path must be a non-empty path of at most 4096 characters")
        self.storage_path = Path(storage_path)
        directory_existed = self.storage_path.exists()
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix" and not directory_existed:
            os.chmod(self.storage_path, 0o700)
        self.index_file = self.storage_path / "index.json"
        self.lock_file = self.storage_path / ".storage.lock"
        self.max_history = max_history
        self.auto_cleanup_days = auto_cleanup_days
        self._lock = threading.RLock()
        self._ensure_index()
        self._enforce_retention()

    @contextmanager
    def _locked(self):
        """Serialize index/file transactions, including across Unix processes."""
        with self._lock:
            lock_handle = open(self.lock_file, "a+", encoding="utf-8")
            try:
                if os.name == "posix":
                    os.fchmod(lock_handle.fileno(), 0o600)
                if fcntl is not None:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
                lock_handle.close()

    def _ensure_index(self):
        with self._locked():
            if not self.index_file.exists():
                self._save_index({})

    def _load_index(self) -> Dict[str, Dict]:
        try:
            with open(self.index_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError, TypeError):
            return {}

    def _atomic_write_json(self, path: Path, value: Any):
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=self.storage_path,
                prefix=f".{path.name}.", suffix=".tmp", delete=False,
            ) as handle:
                temp_path = Path(handle.name)
                json.dump(value, handle, indent=2, default=str)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
        finally:
            if temp_path is not None and temp_path.exists():
                temp_path.unlink()

    def _save_index(self, index: Dict):
        self._atomic_write_json(self.index_file, index)

    def _get_scan_file(self, scan_id: str) -> Path:
        if not _valid_scan_id(scan_id):
            raise ValueError("Invalid scan ID")
        return self.storage_path / f"{scan_id}.json"

    def _read_result(self, scan_id: str) -> Optional[ScanResult]:
        try:
            with open(self._get_scan_file(scan_id), "r", encoding="utf-8") as handle:
                return ScanResult.from_dict(json.load(handle))
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    def _prune_index(self, index: Dict[str, Dict], cutoff_days: Optional[int] = None):
        cutoff = datetime.now() - timedelta(days=cutoff_days) if cutoff_days is not None else None
        retained = {}
        expired = set()
        for scan_id, info in index.items():
            if not _valid_scan_id(scan_id) or not isinstance(info, dict):
                expired.add(scan_id)
                continue
            timestamp = info.get("timestamp", "")
            try:
                parsed_timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError):
                expired.add(scan_id)
                continue
            if cutoff is not None and parsed_timestamp < cutoff:
                expired.add(scan_id)
            else:
                retained[scan_id] = info

        removed = set(expired)
        if self.max_history is not None and len(retained) > self.max_history:
            ordered = [
                item for _, item in sorted(
                    enumerate(retained.items()),
                    key=lambda indexed: (
                        indexed[1][1].get("timestamp", ""),
                        _saved_at_order(indexed[1][1]),
                        indexed[0],
                    ),
                    reverse=True,
                )
            ]
            keep_ids = {scan_id for scan_id, _ in ordered[:self.max_history]}
            removed.update(set(retained) - keep_ids)
            retained = {scan_id: info for scan_id, info in ordered if scan_id in keep_ids}
        return retained, removed, expired

    def _remove_scan_files(self, scan_ids):
        for scan_id in scan_ids:
            try:
                self._get_scan_file(scan_id).unlink(missing_ok=True)
            except (OSError, ValueError):
                continue

    def _enforce_retention(self):
        with self._locked():
            index = self._load_index()
            retained, removed, _ = self._prune_index(index, self.auto_cleanup_days)
            if removed or retained != index:
                self._save_index(retained)
                self._remove_scan_files(removed)
            if os.name == "posix":
                os.chmod(self.index_file, 0o600)
                for scan_id in retained:
                    scan_file = self._get_scan_file(scan_id)
                    if scan_file.exists():
                        os.chmod(scan_file, 0o600)

    def save(self, result: ScanResult) -> bool:
        """Atomically save a scan and update retention/index state."""
        try:
            if not _valid_scan_id(result.id):
                return False
            with self._locked():
                self._atomic_write_json(self._get_scan_file(result.id), result.to_dict())
                index = self._load_index()
                index[result.id] = {
                    "url": result.url,
                    "timestamp": result.timestamp,
                    "percentage_score": result.percentage_score,
                    "grade": result.grade,
                    "file": f"{result.id}.json",
                    "saved_at_ns": time.time_ns(),
                }
                retained, removed, _ = self._prune_index(index, self.auto_cleanup_days)
                self._save_index(retained)
                self._remove_scan_files(removed)
            return True
        except Exception:
            return False

    def get(self, scan_id: str) -> Optional[ScanResult]:
        """Get a scan result by ID."""
        if not _valid_scan_id(scan_id):
            return None
        with self._locked():
            return self._read_result(scan_id)

    def get_all(self, limit: int = 100) -> List[ScanResult]:
        """Get recent scans in deterministic newest-first order."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_STORAGE_QUERY_LIMIT:
            return []
        with self._locked():
            index = self._load_index()
            ordered = [
                item for _, item in sorted(
                    enumerate(index.items()),
                    key=lambda indexed: (
                        indexed[1][1].get("timestamp", "") if isinstance(indexed[1][1], dict) else "",
                        _saved_at_order(indexed[1][1]) if isinstance(indexed[1][1], dict) else 0,
                        indexed[0],
                    ),
                    reverse=True,
                )[:limit]
            ]
            return [result for scan_id, _ in ordered if (result := self._read_result(scan_id))]

    def get_by_url(self, url: str, limit: int = 10) -> List[ScanResult]:
        """Get scans for an exact URL (case-insensitive)."""
        if not isinstance(url, str) or not url or len(url) > 2048 or isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_STORAGE_QUERY_LIMIT:
            return []
        with self._locked():
            index = self._load_index()
            matching = [
                (scan_id, info) for scan_id, info in index.items()
                if isinstance(info, dict) and str(info.get("url", "")).lower() == url.lower()
            ]
            ordered = [
                item for _, item in sorted(
                    enumerate(matching),
                    key=lambda indexed: (
                        indexed[1][1].get("timestamp", ""),
                        _saved_at_order(indexed[1][1]),
                        indexed[0],
                    ),
                    reverse=True,
                )[:limit]
            ]
            return [result for scan_id, _ in ordered if (result := self._read_result(scan_id))]

    def delete(self, scan_id: str) -> bool:
        """Delete one scan without exposing storage paths to the caller."""
        if not _valid_scan_id(scan_id):
            return False
        try:
            with self._locked():
                index = self._load_index()
                index.pop(scan_id, None)
                self._save_index(index)
                self._remove_scan_files([scan_id])
            return True
        except Exception:
            return False

    def cleanup(self, days: int = 30) -> int:
        """Delete scans older than ``days`` while retaining the configured cap."""
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_CLEANUP_DAYS:
            raise ValueError(f"days must be an integer between 1 and {MAX_CLEANUP_DAYS}")
        with self._locked():
            index = self._load_index()
            retained, removed, expired = self._prune_index(index, days)
            self._save_index(retained)
            self._remove_scan_files(removed)
            return len(expired)


class SQLiteStorage(Storage):
    """SQLite storage using WAL, bounded busy waits, and configured retention."""

    def __init__(
        self,
        storage_path: str = "./data/scans.db",
        max_history: Optional[int] = 1000,
        auto_cleanup_days: Optional[int] = 30,
    ):
        _validate_retention(max_history, auto_cleanup_days)
        if not isinstance(storage_path, (str, os.PathLike)) or not str(storage_path).strip() or len(str(storage_path)) > 4096 or any(ord(ch) < 32 for ch in str(storage_path)):
            raise ValueError("storage_path must be a non-empty path of at most 4096 characters")
        path = Path(storage_path)
        if (path.exists() and path.is_dir()) or path.suffix.lower() not in SQLITE_SUFFIXES:
            path = path / "scans.db"
        self.storage_path = path
        parent_existed = self.storage_path.parent.exists()
        self.storage_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix" and not parent_existed:
            os.chmod(self.storage_path.parent, 0o700)
        if not self.storage_path.exists():
            try:
                descriptor = os.open(str(self.storage_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        if os.name == "posix" and self.storage_path.exists():
            os.chmod(self.storage_path, 0o600)
        self.max_history = max_history
        self.auto_cleanup_days = auto_cleanup_days
        self._lock = threading.RLock()
        self._init_db()

    @contextmanager
    def _connection(self):
        conn = sqlite3.connect(str(self.storage_path), timeout=30)
        conn.execute("PRAGMA busy_timeout = 30000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        """Initialize the schema and apply retention after opening the database."""
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    scan_duration_ms REAL,
                    http_status_code INTEGER,
                    final_url TEXT,
                    headers_found TEXT,
                    total_score INTEGER,
                    max_score INTEGER,
                    percentage_score REAL,
                    grade TEXT,
                    risk_level TEXT,
                    summary TEXT,
                    error TEXT,
                    scan_data TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_url ON scans(url)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON scans(timestamp)")
            self._apply_retention(conn, self.auto_cleanup_days)

    def _apply_retention(self, conn, cutoff_days: Optional[int]):
        if cutoff_days is not None:
            cutoff = datetime.now() - timedelta(days=cutoff_days)
            conn.execute(
                "DELETE FROM scans WHERE timestamp < ?",
                (cutoff.strftime("%Y-%m-%d %H:%M:%S"),),
            )
        if self.max_history is not None:
            conn.execute(
                "DELETE FROM scans WHERE id NOT IN ("
                "SELECT id FROM scans ORDER BY timestamp DESC, rowid DESC LIMIT ?)",
                (self.max_history,),
            )

    def save(self, result: ScanResult) -> bool:
        """Save a scan and atomically apply retention in the same transaction."""
        if not _valid_scan_id(result.id):
            return False
        try:
            data = result.to_dict()
            with self._lock, self._connection() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO scans
                    (id, url, timestamp, scan_duration_ms, http_status_code, final_url,
                     headers_found, total_score, max_score, percentage_score, grade,
                     risk_level, summary, error, scan_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.id,
                    result.url,
                    result.timestamp,
                    result.scan_duration_ms,
                    result.http_status_code,
                    result.final_url,
                    json.dumps(result.headers_found),
                    result.total_score,
                    result.max_score,
                    result.percentage_score,
                    result.grade,
                    result.risk_level,
                    json.dumps(result.summary),
                    result.error,
                    json.dumps(data),
                ))
                self._apply_retention(conn, self.auto_cleanup_days)
            return True
        except Exception:
            return False

    def get(self, scan_id: str) -> Optional[ScanResult]:
        """Get a scan result by ID."""
        if not _valid_scan_id(scan_id):
            return None
        try:
            with self._connection() as conn:
                row = conn.execute("SELECT scan_data FROM scans WHERE id = ?", (scan_id,)).fetchone()
                return ScanResult.from_dict(json.loads(row[0])) if row else None
        except (sqlite3.Error, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    def get_all(self, limit: int = 100) -> List[ScanResult]:
        """Get recent scans in newest-first order."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_STORAGE_QUERY_LIMIT:
            return []
        results = []
        try:
            with self._connection() as conn:
                rows = conn.execute(
                    "SELECT scan_data FROM scans ORDER BY timestamp DESC, rowid DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            for row in rows:
                results.append(ScanResult.from_dict(json.loads(row[0])))
        except (sqlite3.Error, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return []
        return results

    def get_by_url(self, url: str, limit: int = 10) -> List[ScanResult]:
        """Get scans for an exact URL (case-insensitive)."""
        if not isinstance(url, str) or not url or len(url) > 2048 or isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_STORAGE_QUERY_LIMIT:
            return []
        results = []
        try:
            with self._connection() as conn:
                rows = conn.execute(
                    "SELECT scan_data FROM scans WHERE url = ? COLLATE NOCASE "
                    "ORDER BY timestamp DESC, rowid DESC LIMIT ?",
                    (url, limit),
                ).fetchall()
            for row in rows:
                results.append(ScanResult.from_dict(json.loads(row[0])))
        except (sqlite3.Error, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return []
        return results

    def delete(self, scan_id: str) -> bool:
        """Delete one scan by ID."""
        if not _valid_scan_id(scan_id):
            return False
        try:
            with self._lock, self._connection() as conn:
                conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            return True
        except sqlite3.Error:
            return False

    def cleanup(self, days: int = 30) -> int:
        """Delete aged scans and preserve the configured history cap."""
        if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MAX_CLEANUP_DAYS:
            raise ValueError(f"days must be an integer between 1 and {MAX_CLEANUP_DAYS}")
        cutoff = datetime.now() - timedelta(days=days)
        with self._lock, self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM scans WHERE timestamp < ?",
                (cutoff.strftime("%Y-%m-%d %H:%M:%S"),),
            )
            deleted = max(0, cursor.rowcount)
            self._apply_retention(conn, None)
        return deleted


def get_storage(
    storage_type: str = "json",
    storage_path: str = "./data/scans",
    max_history: Optional[int] = 1000,
    auto_cleanup_days: Optional[int] = 30,
) -> Storage:
    """Create configured JSON or SQLite storage; reject unknown backends."""
    if not isinstance(storage_type, str):
        raise ValueError("storage_type must be 'json' or 'sqlite'")
    if not isinstance(storage_path, (str, os.PathLike)) or not str(storage_path).strip() or any(ord(ch) < 32 for ch in str(storage_path)):
        raise ValueError("storage_path must be a non-empty path")
    backend = storage_type.lower()
    if backend == "sqlite":
        return SQLiteStorage(storage_path, max_history, auto_cleanup_days)
    if backend == "json":
        return JSONStorage(storage_path, max_history, auto_cleanup_days)
    raise ValueError("storage_type must be 'json' or 'sqlite'")
