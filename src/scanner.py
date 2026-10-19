"""
Security Header Scanner Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Core scanning functionality for analyzing security headers.
"""

import math
import threading
import time
import requests
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Dict, List, Optional, Any, Tuple
from urllib.parse import urlsplit

from .headers import (
    SecurityHeader,
    HeaderRegistry,
    HeaderStatus,
    DEFAULT_HEADER_REGISTRY,
    Remediation,
    Severity
)
from .analyzer import HeaderAnalyzer
from .utils import generate_id, normalize_http_url, format_timestamp
from .pinned_http import PinnedAddressAdapter


@dataclass
class HeaderResult:
    """Result of a single header scan"""
    header_name: str
    display_name: str
    status: HeaderStatus
    value: Optional[str]
    score: int
    weight: int
    description: str
    remediation: Optional[Remediation]
    raw_header: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "name": self.header_name,
            "display_name": self.display_name,
            "status": self.status.value,
            "value": self.value,
            "score": self.score,
            "weight": self.weight,
            "description": self.description,
            "remediation": {
                "severity": self.remediation.severity.value if self.remediation else None,
                "action": self.remediation.action if self.remediation else None,
                "example": self.remediation.example if self.remediation else None,
                "resources": self.remediation.resources if self.remediation else [],
            } if self.remediation else None,
        }


@dataclass
class ScanResult:
    """Complete result of a security header scan"""
    id: str
    url: str
    timestamp: str
    scan_duration_ms: float
    http_status_code: Optional[int]
    final_url: Optional[str]
    headers_found: Dict[str, str]
    header_results: List[HeaderResult]
    total_score: int
    max_score: int
    percentage_score: float
    grade: str
    risk_level: str
    summary: Dict[str, int]
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "url": self.url,
            "timestamp": self.timestamp,
            "scan_duration_ms": self.scan_duration_ms,
            "http_status_code": self.http_status_code,
            "final_url": self.final_url,
            "headers_found": self.headers_found,
            "header_results": [h.to_dict() for h in self.header_results],
            "score": {
                "total": self.total_score,
                "max": self.max_score,
                "percentage": self.percentage_score,
                "grade": self.grade,
            },
            "risk_level": self.risk_level,
            "summary": self.summary,
            "error": self.error,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        """Create from dictionary"""
        return cls(
            id=data["id"],
            url=data["url"],
            timestamp=data["timestamp"],
            scan_duration_ms=data["scan_duration_ms"],
            http_status_code=data["http_status_code"],
            final_url=data["final_url"],
            headers_found=data["headers_found"],
            header_results=[
                HeaderResult(
                    header_name=h["name"],
                    display_name=h["display_name"],
                    status=HeaderStatus(h["status"]),
                    value=h["value"],
                    score=h["score"],
                    weight=h["weight"],
                    description=h["description"],
                    remediation=Remediation(
                        severity=Severity(h["remediation"]["severity"]) if h["remediation"] and h["remediation"]["severity"] else Severity.INFO,
                        action=h["remediation"]["action"] if h["remediation"] else "",
                        example=h["remediation"]["example"] if h["remediation"] else "",
                        resources=h["remediation"]["resources"] if h["remediation"] else [],
                    ) if h["remediation"] else None,
                )
                for h in data["header_results"]
            ],
            total_score=data["score"]["total"],
            max_score=data["score"]["max"],
            percentage_score=data["score"]["percentage"],
            grade=data["score"]["grade"],
            risk_level=data["risk_level"],
            summary=data["summary"],
            error=data.get("error"),
        )


class SecurityHeaderScanner:
    """
    Main scanner class for analyzing security headers.
    
    Usage:
        scanner = SecurityHeaderScanner()
        result = scanner.scan("https://example.com")
        print(f"Score: {result.percentage_score}%")
    """
    
    # Known security header names (case-insensitive mapping)
    SECURITY_HEADERS = {
        # Modern headers
        "content-security-policy": "content-security-policy",
        "strict-transport-security": "strict-transport-security",
        "x-frame-options": "x-frame-options",
        "x-content-type-options": "x-content-type-options",
        "referrer-policy": "referrer-policy",
        "permissions-policy": "permissions-policy",
        "cross-origin-opener-policy": "cross-origin-opener-policy",
        "cross-origin-resource-policy": "cross-origin-resource-policy",
        "cross-origin-embedder-policy": "cross-origin-embedder-policy",
        "cross-origin-embedder-policy-report-only": "cross-origin-embedder-policy",
        
        # Legacy/alternative names
        "x-xss-protection": "x-xss-protection",
        "x-permitted-cross-domain-policies": "x-permitted-cross-domain-policies",
        "expect-ct": "expect-ct",
        "feature-policy": "permissions-policy",
        "content-security-policy-report-only": "content-security-policy",
    }
    
    def __init__(
        self,
        timeout: int = 30,
        max_retries: int = 3,
        user_agent: Optional[str] = None,
        follow_redirects: bool = True,
        rate_limit_delay: float = 1.0,
        registry: Optional[HeaderRegistry] = None,
        analyzer: Optional[HeaderAnalyzer] = None,
        max_batch_size: int = 100,
        trust_env: bool = True,
        address_resolver: Optional[Callable[[str, int], List[str]]] = None,
    ):
        """
        Initialize the security header scanner.
        
        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            user_agent: Custom user agent string
            follow_redirects: Whether to follow HTTP redirects
            rate_limit_delay: Delay between requests in seconds
            registry: Custom header registry (uses default if None)
            analyzer: Custom header analyzer (uses default if None)
            max_batch_size: Maximum number of targets accepted by batch_scan
            address_resolver: Optional resolver returning validated IPs to pin on connect
        """
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0.1 <= timeout <= 300:
            raise ValueError("timeout must be between 0.1 and 300 seconds")
        if isinstance(max_retries, bool) or not isinstance(max_retries, int) or not 1 <= max_retries <= 10:
            raise ValueError("max_retries must be an integer between 1 and 10")
        if isinstance(rate_limit_delay, bool) or not isinstance(rate_limit_delay, (int, float)) or not math.isfinite(rate_limit_delay) or not 0 <= rate_limit_delay <= 60:
            raise ValueError("rate_limit_delay must be between 0 and 60 seconds")
        if isinstance(max_batch_size, bool) or not isinstance(max_batch_size, int) or not 1 <= max_batch_size <= 1000:
            raise ValueError("max_batch_size must be an integer between 1 and 1000")
        if not isinstance(follow_redirects, bool):
            raise ValueError("follow_redirects must be a boolean")
        if not isinstance(trust_env, bool):
            raise ValueError("trust_env must be a boolean")
        if address_resolver is not None and not callable(address_resolver):
            raise ValueError("address_resolver must be callable")
        if user_agent is None:
            user_agent = "SecurityHeadersScanner/2.0"
        if (
            not isinstance(user_agent, str)
            or not user_agent.strip()
            or len(user_agent) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in user_agent)
        ):
            raise ValueError("user_agent must be a printable string of at most 256 characters")

        self.timeout = float(timeout)
        self.max_retries = max_retries
        self.user_agent = user_agent.strip()
        self.follow_redirects = follow_redirects
        self.trust_env = trust_env
        self.address_resolver = address_resolver
        self.rate_limit_delay = float(rate_limit_delay)
        self.max_batch_size = max_batch_size
        self.registry = registry or DEFAULT_HEADER_REGISTRY
        self.analyzer = analyzer or HeaderAnalyzer()
        self._last_request_time = 0.0
        self._rate_lock = threading.Lock()
        self._seen_headers: set = set()  # Track seen headers to avoid duplicates
    
    def _rate_limit(self):
        """Apply thread-safe spacing between outbound requests."""
        with self._rate_lock:
            now = time.monotonic()
            wait = self.rate_limit_delay - (now - self._last_request_time)
            if wait > 0:
                time.sleep(wait)
            self._last_request_time = time.monotonic()
    
    def _normalize_url(self, url: str) -> str:
        """Normalize and validate an HTTP(S) scan URL."""
        return normalize_http_url(url)
    
    def _get_response_headers(self, url: str) -> Tuple[Optional[int], Dict[str, str], Optional[str], Optional[str]]:
        """
        Fetch response headers with a bounded body and explicit proxy policy.

        Returns:
            Tuple of (status_code, headers_dict, final_url, error_message)
        """
        self._rate_limit()
        session = requests.Session()
        session.trust_env = self.trust_env
        session.headers.update({"User-Agent": self.user_agent})
        try:
            if self.address_resolver is not None:
                parsed_url = urlsplit(url)
                host = parsed_url.hostname
                port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
                if not host:
                    raise ValueError("Pinned scan URL must include a hostname")
                addresses = self.address_resolver(host, port)
                adapter = PinnedAddressAdapter(host, port, addresses)
                session.mount("http://", adapter)
                session.mount("https://", adapter)
        except Exception:
            session.close()
            raise
        error = "Request failed"
        try:
            for attempt in range(self.max_retries):
                try:
                    response = session.get(
                        url,
                        timeout=self.timeout,
                        allow_redirects=self.follow_redirects,
                        verify=True,
                        stream=True,
                    )
                    try:
                        normalized_headers = {key.lower(): value for key, value in response.headers.items()}
                        return response.status_code, normalized_headers, response.url, None
                    finally:
                        response.close()
                except requests.exceptions.Timeout:
                    error = f"Request timeout after {self.timeout}s"
                except requests.exceptions.ConnectionError as exc:
                    error = f"Connection error: {exc}"
                except requests.exceptions.RequestException as exc:
                    error = f"Request error: {exc}"
                except Exception as exc:
                    error = f"Unexpected error: {exc}"

                if attempt < self.max_retries - 1:
                    time.sleep(0.5 * (attempt + 1))
            return None, {}, None, error
        finally:
            session.close()
    
    def _find_security_header(self, header_name: str, headers: Dict[str, str]) -> Optional[str]:
        """Find a security header value in response headers"""
        # Direct match
        if header_name in headers:
            return headers[header_name]
        
        # Check aliases
        for resp_header, value in headers.items():
            if resp_header == header_name:
                return value
            # Check if the response header maps to our security header
            if self.SECURITY_HEADERS.get(resp_header) == header_name:
                return value
        
        return None
    
    def _calculate_header_score(self, status: HeaderStatus, weight: int) -> int:
        """Calculate score contribution for a header"""
        scores = {
            HeaderStatus.PRESENT: 100,      # Full score
            HeaderStatus.WEAK: 50,          # Partial score
            HeaderStatus.MISCONFIGURED: -50,  # Negative score
            HeaderStatus.MISSING: -100,     # No score, but weighted
        }
        base_score = scores.get(status, 0)
        return int((base_score / 100) * weight)
    
    def _generate_summary(self, header_results: List[HeaderResult]) -> Dict[str, int]:
        """Generate summary counts"""
        summary = {
            "total": len(header_results),
            "present": 0,
            "weak": 0,
            "misconfigured": 0,
            "missing": 0,
        }
        
        for result in header_results:
            summary[result.status.value] += 1
        
        return summary
    
    def scan(self, url: str) -> ScanResult:
        """
        Scan a URL for security headers.
        
        Args:
            url: The URL to scan
            
        Returns:
            ScanResult object with complete scan information
        """
        scan_id = generate_id()
        start_time = time.time()
        url = self._normalize_url(url)
        
        try:
            # Fetch headers
            status_code, headers, final_url, error = self._get_response_headers(url)
            
            if error:
                return ScanResult(
                    id=scan_id,
                    url=url,
                    timestamp=format_timestamp(),
                    scan_duration_ms=(time.time() - start_time) * 1000,
                    http_status_code=None,
                    final_url=final_url,
                    headers_found={},
                    header_results=[],
                    total_score=0,
                    max_score=0,
                    percentage_score=0,
                    grade="F",
                    risk_level="error",
                    summary={"total": 0, "present": 0, "weak": 0, "misconfigured": 0, "missing": 0},
                    error=error,
                )
            
            # Analyze each security header
            header_results: List[HeaderResult] = []
            seen_headers: set = set()  # Track to avoid duplicates
            
            for header_def in self.registry.get_all():
                # Skip duplicates
                if header_def.name in seen_headers:
                    continue
                seen_headers.add(header_def.name)
                
                # Find the header value
                header_value = None
                header_name_used = None
                
                # Special handling for CSP - check active CSP first, then CSPRO
                if header_def.name == "content-security-policy":
                    # Check for active CSP
                    header_value = headers.get("content-security-policy")
                    header_name_used = "content-security-policy"
                    
                    # If no active CSP, check CSPRO
                    if not header_value:
                        csp_ro = headers.get("content-security-policy-report-only")
                        if csp_ro:
                            header_value = csp_ro
                            header_name_used = "content-security-policy-report-only"
                else:
                    header_value = self._find_security_header(header_def.name, headers)
                    header_name_used = header_def.name
                
                # Validate and get status
                status, _ = header_def.validate(header_value, header_name_used)
                
                # Calculate score
                score = self._calculate_header_score(status, header_def.weight)
                
                # Get remediation if needed
                remediation = header_def.get_remediation(status) if status != HeaderStatus.PRESENT else None
                
                result = HeaderResult(
                    header_name=header_def.name,
                    display_name=header_def.display_name,
                    status=status,
                    value=header_value,
                    score=score,
                    weight=header_def.weight,
                    description=header_def.description,
                    remediation=remediation,
                    raw_header=headers.get(header_def.name),
                )
                
                header_results.append(result)
            
            # Calculate total scores
            total_score = sum(r.score for r in header_results)
            max_score = sum(r.weight for r in header_results)
            percentage_score = self.analyzer.calculate_percentage_score(total_score, max_score)
            grade = self.analyzer.get_grade(percentage_score)
            risk_level = self.analyzer.get_risk_level(percentage_score)
            summary = self._generate_summary(header_results)
            
            # Filter for security-related headers only
            security_headers = {
                k.replace("-", "_"): v 
                for k, v in headers.items() 
                if any(sec in k.lower() for sec in [
                    "security", "content-security", "strict-transport",
                    "x-frame", "x-content", "x-xss", "referrer",
                    "permissions", "feature", "cross-origin", "cache",
                    "expect", "permitted"
                ])
            }
            
            return ScanResult(
                id=scan_id,
                url=url,
                timestamp=format_timestamp(),
                scan_duration_ms=(time.time() - start_time) * 1000,
                http_status_code=status_code,
                final_url=final_url,
                # Store only security-relevant response headers. Persisting all
                # response headers can retain session cookies or other secrets.
                headers_found=security_headers,
                header_results=header_results,
                total_score=total_score,
                max_score=max_score,
                percentage_score=round(percentage_score, 1),
                grade=grade,
                risk_level=risk_level,
                summary=summary,
            )
            
        except Exception as e:
            return ScanResult(
                id=scan_id,
                url=url,
                timestamp=format_timestamp(),
                scan_duration_ms=(time.time() - start_time) * 1000,
                http_status_code=None,
                final_url=None,
                headers_found={},
                header_results=[],
                total_score=0,
                max_score=0,
                percentage_score=0,
                grade="F",
                risk_level="error",
                summary={"total": 0, "present": 0, "weak": 0, "misconfigured": 0, "missing": 0},
                error=str(e),
            )
    
    def batch_scan(
        self,
        urls: List[str],
        callback: Optional[Callable[[int, int, ScanResult], None]] = None,
    ) -> List[ScanResult]:
        """
        Scan multiple URLs.
        
        Args:
            urls: List of URLs to scan
            callback: Optional callback function called after each scan
            
        Returns:
            List of ScanResult objects
        """
        if not isinstance(urls, (list, tuple)):
            raise ValueError("urls must be a list or tuple")
        if not urls:
            raise ValueError("urls must not be empty")
        if len(urls) > self.max_batch_size:
            raise ValueError(f"Batch size exceeds maximum of {self.max_batch_size}")
        if any(not isinstance(url, str) or not url.strip() for url in urls):
            raise ValueError("Every batch URL must be a non-empty string")
        if callback is not None and not callable(callback):
            raise ValueError("callback must be callable")
        results = []
        
        for i, url in enumerate(urls):
            try:
                result = self.scan(url)
            except Exception as exc:
                result = ScanResult(
                    id=generate_id(),
                    url=url,
                    timestamp=format_timestamp(),
                    scan_duration_ms=0,
                    http_status_code=None,
                    final_url=None,
                    headers_found={},
                    header_results=[],
                    total_score=0,
                    max_score=0,
                    percentage_score=0,
                    grade="F",
                    risk_level="error",
                    summary={"total": 0, "present": 0, "weak": 0, "misconfigured": 0, "missing": 0},
                    error=str(exc),
                )
            results.append(result)
            if callback is not None:
                callback(i + 1, len(urls), result)
        
        return results
    
    def compare_scans(self, scan1: ScanResult, scan2: ScanResult) -> Dict[str, Any]:
        """Compare scores, raw header presence, and per-header security scores."""
        if scan1.error or scan2.error:
            raise ValueError("Failed scans cannot be compared")

        def canonical_header(name: str) -> str:
            return name.lower().replace("_", "-").strip()

        known_headers = {
            canonical_header(name) for name in self.SECURITY_HEADERS
        } | {
            canonical_header(header.name) for header in self.registry.get_all()
        }
        first_found = {
            canonical_header(name) for name, value in scan1.headers_found.items()
            if value and canonical_header(name) in known_headers
        }
        second_found = {
            canonical_header(name) for name, value in scan2.headers_found.items()
            if value and canonical_header(name) in known_headers
        }
        first_scores = {canonical_header(header.header_name): header.score for header in scan1.header_results}
        second_scores = {canonical_header(header.header_name): header.score for header in scan2.header_results}

        improved = []
        regressed = []
        for name in sorted(first_scores.keys() | second_scores.keys()):
            first_score = first_scores.get(name, 0)
            second_score = second_scores.get(name, 0)
            if second_score > first_score:
                improved.append(name)
            elif second_score < first_score:
                regressed.append(name)

        return {
            "url1": scan1.url,
            "url2": scan2.url,
            "score_change": round(scan2.percentage_score - scan1.percentage_score, 1),
            "grade_change": scan2.grade != scan1.grade,
            "grade_from": scan1.grade,
            "grade_to": scan2.grade,
            "headers_improved": improved,
            "headers_regressed": regressed,
            "headers_added": sorted(second_found - first_found),
            "headers_removed": sorted(first_found - second_found),
        }
