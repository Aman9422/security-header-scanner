"""
Subdomain Scanner Module
~~~~~~~~~~~~~~~~~~~~~~~~

Discovers subdomains for a given domain.
"""

import asyncio
import aiohttp
import socket
import ipaddress
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from urllib.parse import quote, urlsplit


@dataclass
class DiscoveredSubdomain:
    """Information about a discovered subdomain"""
    subdomain: str
    ip_address: Optional[str]
    is_alive: bool
    has_https: bool
    http_status: Optional[int]
    services: List[str] = field(default_factory=list)


@dataclass
class SubdomainScanResult:
    """Complete subdomain scan result"""
    domain: str
    subdomains: List[DiscoveredSubdomain]
    total_found: int
    alive_count: int
    dead_count: int
    scan_duration: float
    overall_score: int
    issues: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "total_found": self.total_found,
            "alive_count": self.alive_count,
            "dead_count": self.dead_count,
            "scan_duration_seconds": self.scan_duration,
            "overall_score": self.overall_score,
            "subdomains": [
                {
                    "subdomain": s.subdomain,
                    "ip": s.ip_address,
                    "is_alive": s.is_alive,
                    "has_https": s.has_https,
                    "http_status": s.http_status,
                    "services": s.services,
                }
                for s in self.subdomains if s.is_alive
            ],
            "issues": self.issues,
            "recommendations": self.recommendations,
        }


class SubdomainScanner:
    """
    Discovers subdomains for a domain.
    
    Usage:
        scanner = SubdomainScanner()
        result = scanner.scan("example.com")
        for sub in result.alive_subdomains:
            print(sub.subdomain)
    """
    
    # Common subdomain wordlist
    COMMON_SUBDOMAINS = [
        # Infrastructure
        "www", "mail", "ftp", "localhost", "webmail", "smtp",
        "pop", "ns1", "dns", "ns2", "dns1", "dns2",
        "admin", "administrator", "login", "logout",
        
        # Security sensitive
        "auth", "secure", "security", "certificate",
        "antivirus", "firewall", "waf", "ids", "ips",
        
        # Development
        "dev", "development", "test", "testing", "staging",
        "stage", "demo", "beta", "preview", "sandbox",
        
        # Services
        "api", "api1", "api2", "api3", "rest", "graphql",
        "app", "apps", "application", "mobile", "m",
        "cdn", "static", "assets", "images", "img",
        
        # Cloud services
        "cloud", "aws", "azure", "gcp", "digitalocean",
        "heroku", "cloudfront", "s3", "ec2", "lambda",
        
        # Common web apps
        "blog", "forum", "news", "status", "monitor",
        "status", "health", "metrics", "grafana", "kibana",
        
        # Business
        "shop", "store", "cart", "checkout", "pay",
        "payment", "billing", "invoice", "accounting",
        
        # Admin panels
        "cpanel", "whm", "plesk", "webmin", "phpmyadmin",
        "mysql", "postgresql", "mongodb", "redis", "elasticsearch",
        
        # Old/deprecated
        "old", "legacy", "archive", "backup", "backups",
        "v1", "v2", "v3", "version", "previous",
        
        # Miscellaneous
        "git", "gitlab", "github", "bitbucket", "svn",
        "jenkins", "travis", "circleci", "jira", "confluence",
        "support", "help", "docs", "documentation", "wiki",
    ]
    
    # Smaller, representative list used by the CLI's --quick option.
    QUICK_SUBDOMAINS = ["www", "api", "mail", "dev", "staging", "admin", "app", "cdn", "test", "status", "shop", "blog"]
    # Ports to check
    COMMON_PORTS = [80, 443, 8080, 8443]
    MAX_WORDLIST_SIZE = 500
    
    def __init__(self, timeout: int = 5, max_concurrent: int = 50):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= 60:
            raise ValueError("timeout must be between 0.1 and 60 seconds")
        if isinstance(max_concurrent, bool) or not isinstance(max_concurrent, int) or not 1 <= max_concurrent <= 200:
            raise ValueError("max_concurrent must be an integer between 1 and 200")
        self.timeout = float(timeout)
        self.max_concurrent = max_concurrent
        self.session = None

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Extract and validate a DNS name, optionally supplied as an HTTP(S) URL."""
        if not isinstance(domain, str) or not domain.strip() or len(domain) > 2048:
            raise ValueError("A non-empty domain or HTTP(S) URL of at most 2048 characters is required")
        if any(ord(character) < 32 for character in domain):
            raise ValueError("Domain contains control characters")
        value = domain.strip()
        parsed = urlsplit(value if "://" in value else f"//{value}")
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP(S) URLs or bare domain names are supported")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("Credentials are not allowed in a domain URL")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid port in domain URL") from exc
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Domain URL must contain a hostname")
        try:
            hostname = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Invalid internationalized DNS hostname") from exc
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("A DNS domain is required, not an IP address")
        if not hostname or any(not label for label in hostname.split(".")):
            raise ValueError("Invalid DNS hostname")
        labels = hostname.split(".")
        if len(labels) < 2 or len(hostname) > 253:
            raise ValueError("A fully-qualified DNS domain is required")
        if any(
            len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError("Invalid DNS hostname")
        return hostname

    @staticmethod
    def _error_result(domain: Any, message: str) -> SubdomainScanResult:
        return SubdomainScanResult(
            domain=str(domain or ""),
            subdomains=[],
            total_found=0,
            alive_count=0,
            dead_count=0,
            scan_duration=0,
            overall_score=0,
            issues=[message],
            recommendations=[],
        )
    
    async def _check_subdomain_async(self, subdomain: str, base_domain: str) -> DiscoveredSubdomain:
        """Resolve a candidate and probe HTTP(S) endpoints for real status codes."""
        full_domain = f"{subdomain}.{base_domain}"
        result = DiscoveredSubdomain(
            subdomain=full_domain,
            ip_address=None,
            is_alive=False,
            has_https=False,
            http_status=None,
        )
        if self.session is None:
            raise RuntimeError("Subdomain scan session has not been initialized")

        try:
            loop = asyncio.get_running_loop()
            addresses = await asyncio.wait_for(
                loop.getaddrinfo(full_domain, None, type=socket.SOCK_STREAM),
                timeout=self.timeout,
            )
            if not addresses:
                return result
            result.ip_address = addresses[0][4][0]
        except (OSError, asyncio.TimeoutError):
            return result

        for port in self.COMMON_PORTS:
            scheme = "https" if port in (443, 8443) else "http"
            service = f"{scheme.upper()}:{port}" if port not in (80, 443) else scheme.upper()
            try:
                async with self.session.get(
                    f"{scheme}://{full_domain}:{port}/",
                    allow_redirects=False,
                    ssl=False,
                ) as response:
                    result.is_alive = True
                    result.services.append(service)
                    if scheme == "https":
                        result.has_https = True
                    if result.http_status is None:
                        result.http_status = response.status
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                continue
        return result
    
    def scan(self, domain: str, wordlist: List[str] = None) -> SubdomainScanResult:
        """
        Scan for subdomains.
        
        Args:
            domain: Base domain to scan (e.g., example.com)
            wordlist: Optional custom subdomain wordlist
            
        Returns:
            SubdomainScanResult with discovered subdomains
        """
        import time
        start_time = time.time()
        
        # Normalize the in-scope base domain before constructing any probe names.
        try:
            base_domain = self._normalize_domain(domain)
        except ValueError as exc:
            return self._error_result(domain, str(exc))
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]

        if wordlist is None:
            candidates = self.COMMON_SUBDOMAINS
        elif isinstance(wordlist, (list, tuple)):
            candidates = wordlist
        else:
            return self._error_result(domain, "Wordlist must be a list or tuple of DNS labels")
        if len(candidates) > self.MAX_WORDLIST_SIZE:
            return self._error_result(domain, f"Wordlist exceeds the {self.MAX_WORDLIST_SIZE}-label limit")

        normalized_wordlist = []
        for candidate in candidates:
            if not isinstance(candidate, str):
                return self._error_result(domain, "Wordlist entries must be DNS labels")
            label = candidate.strip().lower()
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
                return self._error_result(domain, f"Invalid subdomain label: {candidate!r}")
            normalized_wordlist.append(label)
        normalized_wordlist = list(dict.fromkeys(normalized_wordlist))

        try:
            asyncio.get_running_loop()
        except RuntimeError:
            results = asyncio.run(self._scan_all_async(base_domain, normalized_wordlist))
        else:
            raise RuntimeError("SubdomainScanner.scan() cannot run inside an active event loop")
        
        # Analyze results
        alive_subdomains = [r for r in results if r.is_alive]
        dead_subdomains = [r for r in results if not r.is_alive]
        
        duration = time.time() - start_time
        
        # Generate findings
        issues = []
        recommendations = []
        
        if len(alive_subdomains) > 20:
            issues.append(f"Large attack surface: {len(alive_subdomains)} subdomains discovered")
            recommendations.append("Consider reducing the number of exposed subdomains")
        
        # Check for sensitive subdomains
        sensitive_patterns = {
            "dev": "Development environment exposed",
            "test": "Test environment exposed",
            "staging": "Staging environment exposed",
            "admin": "Admin panel subdomain found",
            "cpanel": "Hosting control panel exposed",
            "phpmyadmin": "Database admin panel exposed",
            "jenkins": "CI/CD system exposed",
            "internal": "Internal system exposed",
            "old": "Old/deprecated subdomain found",
            "backup": "Backup subdomain found",
        }
        
        for sub in alive_subdomains:
            for pattern, issue in sensitive_patterns.items():
                if pattern in sub.subdomain.lower():
                    issues.append(f"{issue}: {sub.subdomain}")
                    recommendations.append(f"Secure or remove exposed {pattern} subdomain")
        
        # Calculate score
        score = self._calculate_score(len(alive_subdomains), issues)
        
        return SubdomainScanResult(
            domain=base_domain,
            subdomains=results,
            total_found=len(results),
            alive_count=len(alive_subdomains),
            dead_count=len(dead_subdomains),
            scan_duration=round(duration, 2),
            overall_score=score,
            issues=issues,
            recommendations=recommendations,
        )
    
    async def _scan_all_async(self, base_domain: str, wordlist: List[str]) -> List[DiscoveredSubdomain]:
        """Scan candidates with bounded HTTP concurrency and a managed session."""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)

        async def bounded_check(subdomain: str):
            async with semaphore:
                return await self._check_subdomain_async(subdomain, base_domain)

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            self.session = session
            try:
                results = await asyncio.gather(
                    *(bounded_check(subdomain) for subdomain in wordlist),
                    return_exceptions=True,
                )
            finally:
                self.session = None
        return [result for result in results if isinstance(result, DiscoveredSubdomain)]
    
    def _calculate_score(self, alive_count: int, issues: List[str]) -> int:
        """Calculate security score based on findings"""
        score = 100
        
        # Deduct for number of subdomains
        if alive_count > 30:
            score -= 30
        elif alive_count > 20:
            score -= 20
        elif alive_count > 10:
            score -= 10
        elif alive_count > 5:
            score -= 5
        
        # Deduct for sensitive findings
        sensitive_count = sum(1 for i in issues if "exposed" in i.lower())
        score -= sensitive_count * 15
        
        # Deduct for other issues
        score -= len(issues) * 5
        
        return max(0, score)
    
    def scan_from_crtsh(self, domain: str) -> List[str]:
        """
        Get subdomains from Certificate Transparency logs (crt.sh).
        
        Note: This is informational only and requires internet access.
        """
        subdomains = []
        try:
            domain = self._normalize_domain(domain)
        except ValueError:
            return subdomains
        
        try:
            import requests
            url = f"https://crt.sh/?q={quote(f'%.{domain}', safe='')}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # Clean and deduplicate
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(f".{domain}") and sub != domain:
                            subdomains.append(sub)
            
            # Remove duplicates
            subdomains = list(set(subdomains))
            
        except Exception:
            pass
        
        return subdomains


def scan_subdomains(domain: str) -> SubdomainScanResult:
    """Quick function to scan subdomains"""
    scanner = SubdomainScanner()
    return scanner.scan(domain)
