"""
Directory Scanner Module
~~~~~~~~~~~~~~~~~~~~~~~

Discovers directories and sensitive files on web servers.
"""

import requests
import re
import hashlib
import math
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from urllib.parse import urljoin, urlsplit
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import normalize_http_url


@dataclass
class DiscoveredPath:
    """Information about a discovered path"""
    path: str
    status_code: int
    content_length: int
    is_directory: bool
    content_type: Optional[str]
    is_sensitive: bool
    sensitivity_reason: str


@dataclass
class DirectoryScanResult:
    """Complete directory scan result"""
    base_url: str
    scanned_paths: int
    found_paths: int
    sensitive_paths: List[DiscoveredPath]
    scan_duration: float
    overall_score: int
    issues: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "base_url": self.base_url,
            "scanned_paths": self.scanned_paths,
            "found_paths": self.found_paths,
            "sensitive_paths": [
                {
                    "path": p.path,
                    "status_code": p.status_code,
                    "is_sensitive": p.is_sensitive,
                    "reason": p.sensitivity_reason,
                }
                for p in self.sensitive_paths
            ],
            "scan_duration_seconds": self.scan_duration,
            "overall_score": self.overall_score,
            "issues": self.issues,
            "recommendations": self.recommendations,
        }


class DirectoryScanner:
    """
    Scans for directories and sensitive files.

    Usage:
        scanner = DirectoryScanner()
        result = scanner.scan("https://example.com")
        for path in result.found_paths:
            print(path.path)
    """

    # Common sensitive paths
    SENSITIVE_PATHS = {
        # Admin panels
        "/admin": "Admin panel",
        "/administrator": "Administrator access",
        "/wp-admin": "WordPress admin",
        "/cpanel": "cPanel access",
        "/phpmyadmin": "phpMyAdmin database interface",
        "/pma": "phpMyAdmin",
        "/myadmin": "phpMyAdmin",

        # Configuration files
        "/.env": "Environment variables (may contain secrets)",
        "/.git/config": "Git repository configuration",
        "/.git/HEAD": "Git repository information",
        "/.gitignore": "Git ignore file",
        "/config.php": "PHP configuration file",
        "/configuration.php": "Joomla config",
        "/wp-config.php": "WordPress configuration",
        "/settings.py": "Python settings file",
        "/.htaccess": "Apache configuration",
        "/web.config": "IIS configuration",
        "/nginx.conf": "Nginx configuration",

        # Backup files
        "/backup": "Backup directory",
        "/backups": "Backup directory",
        "/backup.zip": "Backup archive",
        "/backup.tar": "Backup archive",
        "/database.sql": "Database dump",
        "/dump.sql": "Database dump",
        "/db.sql": "Database dump",

        # Documentation
        "/README.md": "Project README",
        "/readme.txt": "Readme file",
        "/CHANGELOG": "Changelog",
        "/LICENSE": "License file",
        "/docs": "Documentation directory",
        "/documentation": "Documentation directory",
        "/api/docs": "API documentation",
        "/swagger": "Swagger API docs",
        "/api/swagger": "Swagger UI",

        # Login pages
        "/login": "Login page",
        "/signin": "Sign in page",
        "/auth": "Authentication endpoint",
        "/oauth": "OAuth endpoints",
        "/auth/login": "Login page",
        "/account": "User account page",
        "/user": "User pages",
        "/profile": "User profile",

        # Sensitive APIs
        "/api": "API directory",
        "/api/v1": "API v1",
        "/api/v2": "API v2",
        "/api/users": "User API",
        "/api/admin": "Admin API",
        "/graphql": "GraphQL endpoint",
        "/graphql/console": "GraphQL playground",

        # Error/debug pages
        "/debug": "Debug mode",
        "/test": "Test page",
        "/debug=true": "Debug enabled",
        "/phpinfo": "PHPInfo page",
        "/info.php": "PHPInfo page",
        "/server-status": "Apache server status",
        "/server-info": "Apache server info",

        # Version control
        "/.svn": "Subversion repository",
        "/.git": "Git repository",
        "/.hg": "Mercurial repository",

        # Monitoring
        "/monitor": "Monitoring page",
        "/status": "Status page",
        "/health": "Health check",
        "/metrics": "Metrics endpoint",
        "/actuator": "Spring Boot actuator",
        "/actuator/health": "Health endpoint",

        # Cloud
        "/.aws/credentials": "AWS credentials",
        "/.aws/config": "AWS configuration",
        "/.docker/config.json": "Docker config",
    }

    # Paths that expose data or diagnostics when directly accessible; ordinary
    # login, API, documentation, and health endpoints are not data leaks by themselves.
    CONFIDENTIAL_PATHS = {
        "/.env", "/.git/config", "/.git/HEAD", "/.gitignore", "/.git",
        "/.svn", "/.hg", "/config.php", "/configuration.php", "/wp-config.php",
        "/settings.py", "/.htaccess", "/web.config", "/nginx.conf",
        "/backup", "/backups", "/backup.zip", "/backup.tar", "/database.sql",
        "/dump.sql", "/db.sql", "/debug", "/debug=true", "/phpinfo", "/info.php",
        "/server-status", "/server-info", "/metrics", "/actuator", "/actuator/health",
        "/.aws/credentials", "/.aws/config", "/.docker/config.json",
    }
    SENSITIVE_CONTENT_PATTERNS = (
        (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.IGNORECASE), "Private key material found"),
        (re.compile(r"\bAKIA[0-9A-Z]{16}\b", re.IGNORECASE), "AWS access key ID found"),
        (re.compile(r"\b(?:password|passwd|secret|api[_-]?key)\b\s*[:=]\s*[\"']?[^\s\"';]{12,}", re.IGNORECASE), "Credential-like value found"),
    )
    MAX_RESPONSE_BYTES = 64 * 1024

    # Common directory wordlist
    COMMON_DIRECTORIES = [
        # Common paths
        "", "index", "index.html", "index.php",
        "home", "about", "contact", "services", "products",
        "blog", "news", "forum", "support", "help",
        "admin", "login", "logout", "register", "signup",
        "user", "users", "account", "accounts", "profile",
        "dashboard", "panel", "control", "manage", "management",

        # Development
        "api", "api/v1", "api/v2", "rest", "graphql",
        "docs", "documentation", "swagger", "api-docs",
        "test", "tests", "testing", "demo", "sandbox",
        "dev", "development", "stage", "staging", "preview",

        # Assets
        "assets", "static", "css", "js", "javascript",
        "images", "img", "pictures", "photos", "uploads",
        "files", "downloads", "media", "public", "storage",

        # System
        "backup", "backups", "old", "archive", "archives",
        "logs", "log", "tmp", "temp", "cache",
        "config", "configuration", "settings", "private",
    ]

    def __init__(
        self,
        timeout: int = 5,
        max_workers: int = 20,
        user_agent: str = "Mozilla/5.0 (compatible; SecurityScanner)",
        max_response_bytes: int = 64 * 1024,
    ):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0.1 <= timeout <= 120:
            raise ValueError("timeout must be between 0.1 and 120 seconds")
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or not 1 <= max_workers <= 100:
            raise ValueError("max_workers must be an integer between 1 and 100")
        if (
            not isinstance(user_agent, str)
            or not user_agent.strip()
            or len(user_agent) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in user_agent)
        ):
            raise ValueError("user_agent must be a printable string of at most 256 characters")
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or not 1 <= max_response_bytes <= 10 * 1024 * 1024:
            raise ValueError("max_response_bytes must be an integer between 1 and 10485760")
        self.timeout = float(timeout)
        self.max_workers = max_workers
        self.user_agent = user_agent.strip()
        self.max_response_bytes = max_response_bytes
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})

    @staticmethod
    def _normalize_base_url(base_url: str) -> str:
        """Validate and canonicalize an HTTP(S) scan URL."""
        normalized = normalize_http_url(base_url)
        parsed = urlsplit(normalized)
        return parsed._replace(query="", fragment="").geturl().rstrip("/")

    def scan(
        self,
        base_url: str,
        check_sensitive: bool = True,
        check_directories: bool = True,
        progress_callback: Optional[Callable] = None
    ) -> DirectoryScanResult:
        """
        Scan for directories and sensitive files.

        Args:
            base_url: Base URL to scan
            check_sensitive: Check for sensitive paths
            check_directories: Check common directories
            progress_callback: Optional callback for progress updates

        Returns:
            DirectoryScanResult with discovered paths
        """
        import time
        if not isinstance(check_sensitive, bool) or not isinstance(check_directories, bool):
            raise ValueError("check_sensitive and check_directories must be booleans")
        if progress_callback is not None and not callable(progress_callback):
            raise ValueError("progress_callback must be callable")

        start_time = time.time()

        try:
            base_url = self._normalize_base_url(base_url)
        except ValueError as exc:
            return DirectoryScanResult(
                base_url=str(base_url or ""), scanned_paths=0, found_paths=0,
                sensitive_paths=[], scan_duration=0, overall_score=0,
                issues=[str(exc)], recommendations=[],
            )

        paths_to_check = []

        if check_sensitive:
            paths_to_check.extend(self.SENSITIVE_PATHS.keys())

        if check_directories:
            paths_to_check.extend(self.COMMON_DIRECTORIES)

        # Remove duplicates
        paths_to_check = list(dict.fromkeys(paths_to_check))

        results: List[DiscoveredPath] = []
        sensitive_results: List[DiscoveredPath] = []
        completed_count = 0

        def fetch_page(url: str):
            """Fetch only a bounded prefix so hostile responses cannot exhaust memory."""
            with self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=True,
                stream=True,
            ) as response:
                status = response.status_code
                content_type = response.headers.get("Content-Type", "") or ""
                body = bytearray()
                for chunk in response.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    remaining = self.max_response_bytes - len(body)
                    body.extend(chunk[:remaining])
                    if len(body) >= self.max_response_bytes:
                        break
                return status, content_type, bytes(body), getattr(response, "encoding", None) or "utf-8"

        # Many single-page applications return the same 200 page for every
        # unknown path. Probe one random path and suppress exact catch-all matches.
        baseline_signature = None
        try:
            baseline = fetch_page(urljoin(base_url + "/", f"__scanner_missing_{uuid.uuid4().hex}"))
            if baseline[0] not in {404, 410}:
                baseline_signature = (
                    baseline[0], baseline[1].lower(), len(baseline[2]),
                    hashlib.sha256(baseline[2]).digest(),
                )
        except requests.exceptions.RequestException:
            pass
        except Exception:
            pass

        def check_path(path: str) -> Optional[DiscoveredPath]:
            """Check a single path"""
            try:
                url = urljoin(base_url + "/", path.lstrip("/"))
                status, content_type, body, encoding = fetch_page(url)
                signature = (
                    status, content_type.lower(), len(body), hashlib.sha256(body).digest(),
                )
                if baseline_signature is not None and signature == baseline_signature:
                    return None
                content = body.decode(encoding, errors="replace")

                # A path is only a disclosure when sensitive data is actually
                # accessible (2xx), not merely because an auth gate returned 401/403.
                is_sensitive = False
                sensitivity_reason = ""
                if status in {200, 206} and path in self.CONFIDENTIAL_PATHS:
                    is_sensitive = True
                    sensitivity_reason = self.SENSITIVE_PATHS.get(path, "Sensitive file or diagnostic endpoint")
                if status in {200, 206}:
                    for pattern, reason in self.SENSITIVE_CONTENT_PATTERNS:
                        if pattern.search(content):
                            is_sensitive = True
                            sensitivity_reason = reason
                            break

                is_directory = status in {200, 206, 403} and (
                    path.endswith("/") or "text/html" in content_type.lower()
                )
                return DiscoveredPath(
                    path=path,
                    status_code=status,
                    content_length=len(body),
                    is_directory=is_directory,
                    content_type=content_type,
                    is_sensitive=is_sensitive,
                    sensitivity_reason=sensitivity_reason,
                )
            except requests.exceptions.RequestException:
                return None
            except Exception:
                return None

        # Scan paths concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_path = {
                executor.submit(check_path, path): path
                for path in paths_to_check
            }

            for future in as_completed(future_to_path):
                result = future.result()
                completed_count += 1
                if result and result.status_code not in {404, 410}:
                    results.append(result)
                    if result.is_sensitive:
                        sensitive_results.append(result)
                if progress_callback:
                    progress_callback(completed_count, len(paths_to_check))

        results.sort(key=lambda item: item.path)
        sensitive_results.sort(key=lambda item: item.path)
        duration = time.time() - start_time

        # Generate findings
        issues = []
        recommendations = []

        for path in sensitive_results:
            issues.append(f"Sensitive path found: {path.path} ({path.sensitivity_reason})")
            recommendations.append(f"Secure or remove: {path.path}")

        if len(sensitive_results) > 5:
            issues.append("Multiple sensitive paths exposed")
            recommendations.append("Review and secure all sensitive endpoints")

        # Calculate score
        score = self._calculate_score(results, sensitive_results)

        return DirectoryScanResult(
            base_url=base_url,
            scanned_paths=len(paths_to_check),
            found_paths=len(results),
            sensitive_paths=sensitive_results,
            scan_duration=round(duration, 2),
            overall_score=score,
            issues=issues,
            recommendations=recommendations,
        )

    def _calculate_score(
        self,
        found_paths: List[DiscoveredPath],
        sensitive_paths: List[DiscoveredPath]
    ) -> int:
        """Calculate security score based on findings"""
        score = 100

        # Deduct for sensitive paths
        score -= len(sensitive_paths) * 15

        # Deduct for found paths
        if len(found_paths) > 20:
            score -= 20
        elif len(found_paths) > 10:
            score -= 10

        # Check for critical findings
        critical_paths = [p for p in sensitive_paths if any(
            x in p.path.lower() for x in [".env", ".git", "config", "backup", "credentials"]
        )]
        score -= len(critical_paths) * 20

        return max(0, score)

    def quick_scan(self, base_url: str) -> List[str]:
        """
        Quick scan for common sensitive paths.

        Returns:
            List of found sensitive paths
        """
        result = self.scan(base_url, check_directories=False)
        return [p.path for p in result.sensitive_paths]


def scan_directories(url: str) -> DirectoryScanResult:
    """Quick function to scan directories"""
    scanner = DirectoryScanner()
    return scanner.scan(url)
