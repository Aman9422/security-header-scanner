"""
Storage Module
~~~~~~~~~~~~~~

Storage and persistence for scan results.
"""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Dict, Any
from dataclasses import asdict

from .scanner import ScanResult


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
    """
    JSON file-based storage for scan results.
    """
    
    def __init__(self, storage_path: str = "./data/scans"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.index_file = self.storage_path / "index.json"
        self._ensure_index()
    
    def _ensure_index(self):
        """Ensure index file exists"""
        if not self.index_file.exists():
            self._save_index({})
    
    def _load_index(self) -> Dict[str, Dict]:
        """Load index from file"""
        try:
            with open(self.index_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _save_index(self, index: Dict):
        """Save index to file"""
        with open(self.index_file, 'w', encoding='utf-8') as f:
            json.dump(index, f, indent=2)
    
    def _get_scan_file(self, scan_id: str) -> Path:
        """Get file path for a scan"""
        return self.storage_path / f"{scan_id}.json"
    
    def save(self, result: ScanResult) -> bool:
        """Save a scan result"""
        try:
            # Save scan data
            scan_file = self._get_scan_file(result.id)
            with open(scan_file, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2, default=str)
            
            # Update index
            index = self._load_index()
            index[result.id] = {
                "url": result.url,
                "timestamp": result.timestamp,
                "percentage_score": result.percentage_score,
                "grade": result.grade,
                "file": f"{result.id}.json",
            }
            self._save_index(index)
            
            return True
        except Exception:
            return False
    
    def get(self, scan_id: str) -> Optional[ScanResult]:
        """Get a scan result by ID"""
        try:
            scan_file = self._get_scan_file(scan_id)
            if scan_file.exists():
                with open(scan_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                return ScanResult.from_dict(data)
        except Exception:
            pass
        return None
    
    def get_all(self, limit: int = 100) -> List[ScanResult]:
        """Get all scan results"""
        results = []
        index = self._load_index()
        
        for scan_id, info in sorted(
            index.items(),
            key=lambda x: x[1].get("timestamp", ""),
            reverse=True
        )[:limit]:
            result = self.get(scan_id)
            if result:
                results.append(result)
        
        return results
    
    def get_by_url(self, url: str, limit: int = 10) -> List[ScanResult]:
        """Get scan results for a URL"""
        results = []
        index = self._load_index()
        
        matching = [
            (scan_id, info) for scan_id, info in index.items()
            if info.get("url", "").lower() in url.lower()
        ]
        
        for scan_id, info in sorted(
            matching,
            key=lambda x: x[1].get("timestamp", ""),
            reverse=True
        )[:limit]:
            result = self.get(scan_id)
            if result:
                results.append(result)
        
        return results
    
    def delete(self, scan_id: str) -> bool:
        """Delete a scan result"""
        try:
            scan_file = self._get_scan_file(scan_id)
            if scan_file.exists():
                scan_file.unlink()
            
            index = self._load_index()
            if scan_id in index:
                del index[scan_id]
                self._save_index(index)
            
            return True
        except Exception:
            return False
    
    def cleanup(self, days: int = 30) -> int:
        """Clean up old scan results"""
        cutoff = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")
        
        index = self._load_index()
        to_delete = [
            scan_id for scan_id, info in index.items()
            if info.get("timestamp", "") < cutoff_str
        ]
        
        for scan_id in to_delete:
            self.delete(scan_id)
        
        return len(to_delete)


class SQLiteStorage(Storage):
    """
    SQLite-based storage for scan results.
    """
    
    def __init__(self, storage_path: str = "./data/scans.db"):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize database schema"""
        with sqlite3.connect(self.storage_path) as conn:
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
            conn.commit()
    
    def save(self, result: ScanResult) -> bool:
        """Save a scan result"""
        try:
            with sqlite3.connect(self.storage_path) as conn:
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
                    json.dumps(result.to_dict()),
                ))
                conn.commit()
            return True
        except Exception:
            return False
    
    def get(self, scan_id: str) -> Optional[ScanResult]:
        """Get a scan result by ID"""
        try:
            with sqlite3.connect(self.storage_path) as conn:
                conn.row_factory = sqlite3.Row
                row = conn.execute(
                    "SELECT scan_data FROM scans WHERE id = ?",
                    (scan_id,)
                ).fetchone()
                
                if row:
                    data = json.loads(row['scan_data'])
                    return ScanResult.from_dict(data)
        except Exception:
            pass
        return None
    
    def get_all(self, limit: int = 100) -> List[ScanResult]:
        """Get all scan results"""
        results = []
        try:
            with sqlite3.connect(self.storage_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT scan_data FROM scans ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                ).fetchall()
                
                for row in rows:
                    data = json.loads(row['scan_data'])
                    results.append(ScanResult.from_dict(data))
        except Exception:
            pass
        return results
    
    def get_by_url(self, url: str, limit: int = 10) -> List[ScanResult]:
        """Get scan results for a URL"""
        results = []
        try:
            with sqlite3.connect(self.storage_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT scan_data FROM scans WHERE url LIKE ? ORDER BY timestamp DESC LIMIT ?",
                    (f"%{url}%", limit)
                ).fetchall()
                
                for row in rows:
                    data = json.loads(row['scan_data'])
                    results.append(ScanResult.from_dict(data))
        except Exception:
            pass
        return results
    
    def delete(self, scan_id: str) -> bool:
        """Delete a scan result"""
        try:
            with sqlite3.connect(self.storage_path) as conn:
                conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
                conn.commit()
            return True
        except Exception:
            return False
    
    def cleanup(self, days: int = 30) -> int:
        """Clean up old scan results"""
        try:
            cutoff = datetime.now() - timedelta(days=days)
            with sqlite3.connect(self.storage_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM scans WHERE timestamp < ?",
                    (cutoff.strftime("%Y-%m-%d %H:%M:%S"),)
                )
                conn.commit()
            return cursor.rowcount
        except Exception:
            return 0


def get_storage(storage_type: str = "json", storage_path: str = "./data/scans") -> Storage:
    """
    Factory function to get storage instance.
    
    Args:
        storage_type: Type of storage (json or sqlite)
        storage_path: Path for storage
        
    Returns:
        Storage instance
    """
    if storage_type.lower() == "sqlite":
        return SQLiteStorage(storage_path)
    return JSONStorage(storage_path)
