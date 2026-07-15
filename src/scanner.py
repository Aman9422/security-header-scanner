"""
Security Header Scanner Engine
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Core scanning functionality for analyzing security headers.
"""

import time
import requests
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from .headers import (
    SecurityHeader,
    HeaderRegistry,
    HeaderStatus,
    DEFAULT_HEADER_REGISTRY,
    Remediation,
    Severity
)
from .analyzer import HeaderAnalyzer
from .utils import generate_id, normalize_url, format_timestamp


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
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent or "SecurityHeadersScanner/2.0"
        self.follow_redirects = follow_redirects
        self.rate_limit_delay = rate_limit_delay
        self.registry = registry or DEFAULT_HEADER_REGISTRY
        self.analyzer = analyzer or HeaderAnalyzer()
        
        self._last_request_time = 0.0
        self._seen_headers: set = set()  # Track seen headers to avoid duplicates
    
    def _rate_limit(self):
        """Apply rate limiting between requests"""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self._last_request_time = time.time()
    
    def _normalize_url(self, url: str) -> str:
        """Normalize and validate URL"""
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url
    
    def _get_response_headers(self, url: str) -> tuple[Optional[int], Dict[str, str], Optional[str], Optional[str]]:
        """
        Fetch headers from URL.
        
        Returns:
            Tuple of (status_code, headers_dict, final_url, error_message)
        """
        self._rate_limit()
        
        headers = {"User-Agent": self.user_agent}
        
        for attempt in range(self.max_retries):
            try:
                response = requests.head(
                    url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    verify=True,
                )
                
                # Convert headers to lowercase keys
                normalized_headers = {
                    k.lower(): v for k, v in response.headers.items()
                }
                
                return (
                    response.status_code,
                    normalized_headers,
                    response.url,
                    None
                )
                
            except requests.exceptions.Timeout:
                error = f"Request timeout after {self.timeout}s"
            except requests.exceptions.ConnectionError as e:
                error = f"Connection error: {str(e)}"
            except requests.exceptions.RequestException as e:
                error = f"Request error: {str(e)}"
            except Exception as e:
                error = f"Unexpected error: {str(e)}"
            
            if attempt < self.max_retries - 1:
                time.sleep(0.5 * (attempt + 1))  # Exponential backoff
        
        return None, {}, None, error
    
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
                header_value = self._find_security_header(header_def.name, headers)
                
                # Validate and get status
                status, _ = header_def.validate(header_value)
                
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
                headers_found=headers,
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
    
    def batch_scan(self, urls: List[str], callback: Optional[callable] = None) -> List[ScanResult]:
        """
        Scan multiple URLs.
        
        Args:
            urls: List of URLs to scan
            callback: Optional callback function called after each scan
            
        Returns:
            List of ScanResult objects
        """
        results = []
        
        for i, url in enumerate(urls):
            try:
                result = self.scan(url)
                results.append(result)
                
                if callback:
                    callback(i + 1, len(urls), result)
                    
            except Exception as e:
                # Create error result for failed scans
                error_result = ScanResult(
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
                    error=str(e),
                )
                results.append(error_result)
                
                if callback:
                    callback(i + 1, len(urls), error_result)
        
        return results
    
    def compare_scans(self, scan1: ScanResult, scan2: ScanResult) -> Dict[str, Any]:
        """
        Compare two scan results.
        
        Returns:
            Dictionary with comparison details
        """
        return {
            "url1": scan1.url,
            "url2": scan2.url,
            "score_change": scan2.percentage_score - scan1.percentage_score,
            "grade_change": scan2.grade != scan1.grade,
            "headers_improved": [],
            "headers_regressed": [],
            "headers_added": [],
            "headers_removed": [],
        }
