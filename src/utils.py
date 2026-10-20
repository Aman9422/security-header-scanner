"""
Utilities
~~~~~~~~~

Common utility functions for the security header scanner.
"""

import hashlib
import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit, urlunsplit
import json


def generate_id() -> str:
    """Generate a collision-resistant, UUID-based scan ID."""
    return str(uuid.uuid4())


_SENSITIVE_QUERY_COMPONENTS = {
    "auth", "authorization", "cookie", "credential", "jwt", "key", "password",
    "passwd", "pwd", "secret", "session", "signature", "sig", "token",
}
_SENSITIVE_QUERY_COMPOUNDS = {
    "accesskey", "apikey", "clientsecret", "idtoken", "privatekey", "refreshtoken",
}
_URL_IN_TEXT_RE = re.compile(r"(?i)https?://\S+")


def _is_sensitive_query_key(raw_key: str) -> bool:
    key = unquote_plus(raw_key)
    key = re.sub(r"([a-z0-9])([A-Z])", lambda match: match.group(1) + "_" + match.group(2), key).lower()
    parts = [part for part in re.split(r"[^a-z0-9]+", key) if part]
    components = set(parts)
    compact = "".join(parts)
    return bool(components & _SENSITIVE_QUERY_COMPONENTS) or compact in _SENSITIVE_QUERY_COMPOUNDS


def redact_sensitive_url(url: Optional[str]) -> Optional[str]:
    """Redact values of sensitive query parameters without changing the scan URL."""
    if not isinstance(url, str):
        return url
    try:
        parsed = urlsplit(url)
    except ValueError:
        return url
    pieces = re.split(r"([&;])", parsed.query)
    for index in range(0, len(pieces), 2):
        if not pieces[index]:
            continue
        raw_key, separator, _ = pieces[index].partition("=")
        if _is_sensitive_query_key(raw_key):
            pieces[index] = raw_key + (separator or "=") + "%5BREDACTED%5D"
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "".join(pieces), parsed.fragment))


def redact_sensitive_urls_in_text(text: Optional[str], known_urls=()) -> Optional[str]:
    """Redact query secrets in URLs embedded in exception or diagnostic text."""
    if not isinstance(text, str):
        return text
    safe_text = text
    for url in known_urls:
        if isinstance(url, str) and url:
            safe_text = safe_text.replace(url, redact_sensitive_url(url))
    return _URL_IN_TEXT_RE.sub(lambda match: redact_sensitive_url(match.group(0)), safe_text)


def url_lookup_key(url: str) -> str:
    """Return a case-insensitive opaque key for URL history matching."""
    return hashlib.sha256(url.casefold().encode("utf-8")).hexdigest()


def format_timestamp(dt: Optional[datetime] = None) -> str:
    """Format timestamp for display"""
    if dt is None:
        dt = datetime.now()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def normalize_http_url(url: str, default_scheme: str = "https") -> str:
    """Validate and canonicalize an HTTP(S) URL, optionally adding a scheme."""
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise ValueError("URL must be a non-empty string of at most 2048 characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in url):
        raise ValueError("URL contains control characters")
    if default_scheme not in {"http", "https"}:
        raise ValueError("Default scheme must be http or https")

    value = url.strip()
    if value.startswith("//"):
        value = f"{default_scheme}:{value}"
    elif "://" not in value:
        value = f"{default_scheme}://{value}"
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("URL or port is invalid") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Only HTTP(S) URLs are supported")
    if not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("URL must include a hostname and must not include credentials")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("URL port must be between 1 and 65535")

    hostname = parsed.hostname.rstrip(".")
    try:
        hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid internationalized hostname") from exc
    if ":" in hostname:
        if "%" in hostname:
            raise ValueError("Scoped IPv6 addresses are not supported")
        try:
            ipaddress.ip_address(hostname)
        except ValueError as exc:
            raise ValueError("Invalid IP address") from exc
        host_part = f"[{hostname}]"
    else:
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            labels = hostname.split(".")
            if len(hostname) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                for label in labels
            ):
                raise ValueError("Invalid DNS hostname")
        host_part = hostname
    netloc = f"{host_part}:{port}" if port is not None else host_part
    return urlunsplit((scheme, netloc, parsed.path, parsed.query, ""))


def normalize_url(url: str) -> str:
    """Normalize a website URL by adding HTTPS when no scheme is provided."""
    return normalize_http_url(url)


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
                            try:
                                urls.append(normalize_url(url))
                            except ValueError:
                                continue
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
