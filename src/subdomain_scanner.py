"""
Subdomain Scanner Module
~~~~~~~~~~~~~~~~~~~~~~~~

Discovers subdomains for a given domain.
"""

import asyncio
import aiohttp
import socket
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse


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
    
    # Ports to check
    COMMON_PORTS = [80, 443, 8080, 8443]
    
    def __init__(self, timeout: int = 5, max_concurrent: int = 50):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.session = None
    
    async def _check_subdomain_async(self, subdomain: str, base_domain: str) -> DiscoveredSubdomain:
        """Check if a subdomain is alive"""
        full_domain = f"{subdomain}.{base_domain}"
        
        result = DiscoveredSubdomain(
            subdomain=full_domain,
            ip_address=None,
            is_alive=False,
            has_https=False,
            http_status=None,
        )
        
        try:
            # Resolve IP
            try:
                ip = socket.gethostbyname(full_domain)
                result.ip_address = ip
            except socket.gaierror:
                return result
            
            # Check common ports
            for port in self.COMMON_PORTS:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(full_domain, port),
                        timeout=self.timeout
                    )
                    writer.close()
                    await writer.wait_closed()
                    
                    result.is_alive = True
                    result.http_status = 200 if port in [80, 8080] else 443
                    result.has_https = port in [443, 8443]
                    
                    # Detect services
                    if port == 443:
                        result.services.append("HTTPS")
                    elif port == 80:
                        result.services.append("HTTP")
                    
                    break  # Found one working, no need to check more
                except:
                    continue
            
        except Exception:
            pass
        
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
        
        # Parse domain
        if not domain:
            return SubdomainScanResult(
                domain=domain,
                subdomains=[],
                total_found=0,
                alive_count=0,
                dead_count=0,
                scan_duration=0,
                overall_score=0,
                issues=["Invalid domain provided"],
                recommendations=[],
            )
        
        # Extract base domain
        parts = domain.replace("https://", "").replace("http://", "").split("/")
        base_domain = parts[0]
        
        # Remove www if present
        if base_domain.startswith("www."):
            base_domain = base_domain[4:]
        
        wordlist = wordlist or self.COMMON_SUBDOMAINS
        
        # Run async scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            results = loop.run_until_complete(
                self._scan_all_async(base_domain, wordlist)
            )
        finally:
            loop.close()
        
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
        """Scan all subdomains concurrently"""
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def bounded_check(subdomain: str):
            async with semaphore:
                return await self._check_subdomain_async(subdomain, base_domain)
        
        tasks = [bounded_check(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_results = [r for r in results if isinstance(r, DiscoveredSubdomain)]
        return valid_results
    
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
            import requests
            url = f"https://crt.sh/?q=%.{domain}&output=json"
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
