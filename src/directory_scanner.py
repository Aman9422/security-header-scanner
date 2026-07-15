"""
Directory Scanner Module
~~~~~~~~~~~~~~~~~~~~~~~

Discovers directories and sensitive files on web servers.
"""

import requests
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Callable
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


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
        user_agent: str = "Mozilla/5.0 (compatible; SecurityScanner)"
    ):
        self.timeout = timeout
        self.max_workers = max_workers
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
    
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
        import threading
        
        start_time = time.time()
        
        # Normalize URL
        base_url = base_url.rstrip("/")
        if not base_url.startswith("http"):
            base_url = "https://" + base_url
        
        paths_to_check = []
        
        if check_sensitive:
            paths_to_check.extend(self.SENSITIVE_PATHS.keys())
        
        if check_directories:
            paths_to_check.extend(self.COMMON_DIRECTORIES)
        
        # Remove duplicates
        paths_to_check = list(set(paths_to_check))
        
        results: List[DiscoveredPath] = []
        sensitive_results: List[DiscoveredPath] = []
        scanned_count = 0
        lock = threading.Lock()
        
        def check_path(path: str) -> Optional[DiscoveredPath]:
            """Check a single path"""
            try:
                url = urljoin(base_url + "/", path.lstrip("/"))
                response = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=True
                )
                
                status = response.status_code
                content_length = len(response.content)
                content_type = response.headers.get("Content-Type", "")
                
                # Determine if it's a directory
                is_directory = status in [200, 403] and (
                    path.endswith("/") or
                    "text/html" in content_type or
                    content_length > 0
                )
                
                # Check sensitivity
                is_sensitive = False
                sensitivity_reason = ""
                
                if path in self.SENSITIVE_PATHS:
                    is_sensitive = True
                    sensitivity_reason = self.SENSITIVE_PATHS[path]
                
                # Check for sensitive content in response
                if status == 200:
                    content = response.text.lower()
                    sensitive_keywords = {
                        "password": "Contains password reference",
                        "secret": "Contains secret reference",
                        "api_key": "Contains API key reference",
                        "private_key": "Contains private key",
                        "aws_access": "Contains AWS credentials",
                        "database": "Contains database reference",
                    }
                    for keyword, reason in sensitive_keywords.items():
                        if keyword in content:
                            is_sensitive = True
                            sensitivity_reason = reason
                            break
                
                return DiscoveredPath(
                    path=path,
                    status_code=status,
                    content_length=content_length,
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
                if result and result.status_code != 404:
                    with lock:
                        scanned_count += 1
                        if result.status_code in [200, 301, 302, 403]:
                            results.append(result)
                            if result.is_sensitive:
                                sensitive_results.append(result)
                
                if progress_callback:
                    progress_callback(scanned_count, len(paths_to_check))
        
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
