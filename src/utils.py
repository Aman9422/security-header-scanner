"""
Utilities
~~~~~~~~~

Common utility functions for the security header scanner.
"""

import hashlib
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path
import json


def generate_id() -> str:
    """Generate a unique scan ID"""
    return str(uuid.uuid4())[:8]


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format timestamp for display"""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def normalize_url(url: str) -> str:
    """Normalize URL by adding scheme if missing"""
    url = url.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://", "//")):
        url = "https://" + url
    return url


def get_color_for_status(status: str) -> str:
    """Get ANSI color code for status"""
    colors = {
        "present": "\033[92m",    # Green
        "weak": "\033[93m",       # Yellow
        "misconfigured": "\033[91m",  # Red
        "missing": "\033[91m",    # Red
        "error": "\033[91m",      # Red
    }
    return colors.get(status.lower(), "\033[0m")


def get_emoji_for_status(status: str) -> str:
    """Get emoji for header status"""
    emojis = {
        "present": "✅",
        "weak": "⚠️",
        "misconfigured": "❌",
        "missing": "❌",
        "error": "🚨",
    }
    return emojis.get(status.lower(), "❓")


def get_emoji_for_grade(grade: str) -> str:
    """Get emoji for letter grade"""
    if grade.startswith("A"):
        return "🏆"
    elif grade.startswith("B"):
        return "👍"
    elif grade.startswith("C"):
        return "⚠️"
    elif grade.startswith("D"):
        return "🚨"
    else:
        return "💀"


def format_percentage(value: float) -> str:
    """Format percentage with one decimal place"""
    return f"{value:.1f}%"


def truncate_string(s: str, max_length: int = 50) -> str:
    """Truncate string with ellipsis"""
    if len(s) <= max_length:
        return s
    return s[:max_length - 3] + "..."


def load_json_file(filepath: str) -> Optional[Dict]:
    """Load JSON from file"""
    try:
        path = Path(filepath)
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return None


def save_json_file(filepath: str, data: Any) -> bool:
    """Save data to JSON file"""
    try:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception:
        return False


def parse_urls_from_file(filepath: str) -> List[str]:
    """Parse URLs from a text file"""
    urls = []
    try:
        path = Path(filepath)
        if path.exists():
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Support both plain URLs and URL:ALIAS format
                        if ':' in line and '://' not in line:
                            url = line.split(':')[0]
                        else:
                            url = line
                        if url:
                            urls.append(normalize_url(url))
    except Exception:
        pass
    return urls


def calculate_hash(data: str) -> str:
    """Calculate SHA256 hash of string"""
    return hashlib.sha256(data.encode()).hexdigest()


def format_duration(ms: float) -> str:
    """Format duration in milliseconds"""
    if ms < 1000:
        return f"{ms:.0f}ms"
    elif ms < 60000:
        return f"{ms/1000:.1f}s"
    else:
        return f"{ms/60000:.1f}m"


def merge_dicts(*dicts: Dict) -> Dict:
    """Merge multiple dictionaries"""
    result = {}
    for d in dicts:
        if d:
            result.update(d)
    return result


def filter_none_values(d: Dict) -> Dict:
    """Remove None values from dictionary"""
    return {k: v for k, v in d.items() if v is not None}


def chunks(lst: List, n: int) -> List[List]:
    """Split list into chunks of size n"""
    return [lst[i:i + n] for i in range(0, len(lst), n)]


class ProgressTracker:
    """Simple progress tracking for batch operations"""
    
    def __init__(self, total: int):
        self.total = total
        self.current = 0
        self.start_time = datetime.now()
    
    def update(self, increment: int = 1) -> float:
        """Update progress and return percentage"""
        self.current += increment
        elapsed = (datetime.now() - self.start_time).total_seconds()
        if self.current > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            return remaining
        return 0
    
    @property
    def percentage(self) -> float:
        """Get current percentage"""
        if self.total == 0:
            return 100.0
        return (self.current / self.total) * 100
    
    @property
    def is_complete(self) -> bool:
        """Check if complete"""
        return self.current >= self.total
