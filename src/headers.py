"""
Security Headers Definitions and Validators
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module defines all security headers, their expected values,
validation rules, and remediation suggestions.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Callable, Any


class HeaderStatus(Enum):
    """Status of a security header"""
    PRESENT = "present"
    WEAK = "weak"
    MISCONFIGURED = "misconfigured"
    MISSING = "missing"


class Severity(Enum):
    """Severity level of a header issue"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class HeaderDirective:
    """A directive within a security header value"""
    name: str
    value: Optional[str] = None
    required: bool = False


@dataclass
class Remediation:
    """Remediation suggestion for a header issue"""
    severity: Severity
    action: str
    example: str
    resources: List[str] = field(default_factory=list)


@dataclass
class SecurityHeader:
    """
    Represents a security header with its validation rules and remediation.
    """
    name: str
    display_name: str
    description: str
    check_function: Callable[[str], HeaderStatus]
    remediation: Dict[HeaderStatus, Remediation]
    weight: int = 10
    category: str = "general"
    aliases: List[str] = field(default_factory=list)
    
    def validate(self, value: Optional[str]) -> tuple[HeaderStatus, Dict[str, Any]]:
        """Validate header value and return status with details"""
        if value is None:
            return HeaderStatus.MISSING, {}
        return self.check_function(value), {}
    
    def get_remediation(self, status: HeaderStatus) -> Remediation:
        """Get remediation for a given status"""
        return self.remediation.get(status, Remediation(
            severity=Severity.INFO,
            action="No action needed",
            example=""
        ))


class HeaderRegistry:
    """
    Registry of all security headers to check.
    """
    
    def __init__(self):
        self._headers: Dict[str, SecurityHeader] = {}
        self._register_all_headers()
    
    def _register_all_headers(self):
        """Register all security headers"""
        headers = [
            self._create_strict_transport_security(),
            self._create_content_security_policy(),
            self._create_x_frame_options(),
            self._create_x_content_type_options(),
            self._create_x_xss_protection(),
            self._create_referrer_policy(),
            self._create_permissions_policy(),
            self._create_cross_origin_opener_policy(),
            self._create_cross_origin_resource_policy(),
            self._create_cross_origin_embedder_policy(),
            self._create_cache_control(),
            self._create_x_permitted_cross_domain_policies(),
            self._create_expect_ct(),
        ]
        
        for header in headers:
            self.register(header)
    
    def register(self, header: SecurityHeader):
        """Register a security header (main name only, aliases point to same header)"""
        self._headers[header.name.lower()] = header
        for alias in header.aliases:
            # Only add alias if not already registered as a main header
            if alias.lower() not in self._headers:
                self._headers[alias.lower()] = header
    
    def get(self, name: str) -> Optional[SecurityHeader]:
        """Get a header by name"""
        return self._headers.get(name.lower())
    
    def get_all(self) -> List[SecurityHeader]:
        """Get all registered headers (unique by main name)"""
        seen = set()
        result = []
        for h in self._headers.values():
            if h.name not in seen:
                seen.add(h.name)
                result.append(h)
        return result
    
    def get_check_order(self) -> List[str]:
        """Get headers in check order"""
        return [h.name for h in sorted(
            self._headers.values(),
            key=lambda x: x.weight,
            reverse=True
        )]
    
    def _create_strict_transport_security(self) -> SecurityHeader:
        """Create Strict-Transport-Security header definition"""
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            # Check for max-age (required)
            max_age_match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
            if not max_age_match:
                return HeaderStatus.MISCONFIGURED
            
            max_age = int(max_age_match.group(1))
            
            # Check if max-age is sufficient (at least 31536000 = 1 year)
            if max_age < 31536000:
                return HeaderStatus.WEAK
            
            # Check for includeSubDomains
            has_subdomains = 'includesubdomains' in value.lower()
            
            # Check for preload (bonus)
            has_preload = 'preload' in value.lower()
            
            if has_subdomains and has_preload and max_age >= 63072000:
                return HeaderStatus.PRESENT
            elif has_subdomains or max_age >= 31536000:
                return HeaderStatus.PRESENT
            else:
                return HeaderStatus.WEAK
        
        return SecurityHeader(
            name="strict-transport-security",
            display_name="Strict-Transport-Security",
            description="Forces HTTPS connections and prevents protocol downgrade attacks.",
            check_function=check,
            weight=15,
            category="transport",
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.HIGH,
                    action="Add Strict-Transport-Security header",
                    example="max-age=31536000; includeSubDomains; preload",
                    resources=[
                        "https://hstspreload.org/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.MEDIUM,
                    action="Increase max-age and add includeSubDomains",
                    example="max-age=63072000; includeSubDomains; preload",
                    resources=["https://hstspreload.org/"]
                ),
                HeaderStatus.MISCONFIGURED: Remediation(
                    severity=Severity.HIGH,
                    action="Fix HSTS configuration - ensure max-age is set correctly",
                    example="max-age=31536000; includeSubDomains",
                    resources=["https://hstspreload.org/"]
                ),
            }
        )
    
    def _create_content_security_policy(self) -> SecurityHeader:
        """Create Content-Security-Policy header definition"""
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            # Required directives for a good CSP
            required_directives = ['default-src']
            recommended_directives = ['script-src', 'style-src', 'img-src', 'font-src']
            
            # Check if it's report-only (less secure)
            if value.startswith("report-uri") or "report-to" in value.lower():
                return HeaderStatus.WEAK
            
            # Check for unsafe directives (indicates weak CSP)
            unsafe_patterns = ["'unsafe-inline'", "'unsafe-eval'", "*", "data:"]
            unsafe_count = sum(1 for p in unsafe_patterns if p in value)
            
            # Check for basic allow-all (*)
            if value.strip() == "*" or value == "default-src *":
                return HeaderStatus.MISCONFIGURED
            
            # Check for required directives presence
            has_default_src = 'default-src' in value
            
            if unsafe_count >= 2:
                return HeaderStatus.MISCONFIGURED
            elif unsafe_count == 1:
                return HeaderStatus.WEAK
            elif has_default_src:
                # Check for restrictive directives
                restrictive_count = sum(1 for d in recommended_directives if d in value)
                if restrictive_count >= 3:
                    return HeaderStatus.PRESENT
                return HeaderStatus.WEAK
            else:
                return HeaderStatus.WEAK
        
        return SecurityHeader(
            name="content-security-policy",
            display_name="Content-Security-Policy",
            description="Prevents XSS and injection attacks by controlling resource loading.",
            check_function=check,
            weight=25,
            category="xss",
            aliases=["content-security-policy-report-only"],
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.HIGH,
                    action="Add a restrictive Content-Security-Policy header",
                    example="default-src 'self'; script-src 'self' 'nonce-{random}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                        "https://csp-evaluator.withgoogle.com/"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.MEDIUM,
                    action="Remove unsafe-inline/unsafe-eval and add nonce or hash",
                    example="default-src 'self'; script-src 'self' 'nonce-rAnd0m'",
                    resources=[
                        "https://csp-evaluator.withgoogle.com/",
                        "https://hacks.mozilla.org/2016/04/you-might-not-need-a-content-security-policy/"
                    ]
                ),
                HeaderStatus.MISCONFIGURED: Remediation(
                    severity=Severity.CRITICAL,
                    action="Remove permissive wildcard (*) and unsafe directives",
                    example="default-src 'none'; script-src 'self'; style-src 'self'",
                    resources=["https://csp-evaluator.withgoogle.com/"]
                ),
            }
        )
    
    def _create_x_frame_options(self) -> SecurityHeader:
        """Create X-Frame-Options header definition"""
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            value_upper = value.upper()
            if value_upper == "DENY":
                return HeaderStatus.PRESENT
            elif value_upper == "SAMEORIGIN":
                return HeaderStatus.PRESENT
            elif value_upper.startswith("ALLOW-FROM "):
                # ALLOW-FROM is deprecated and not supported by most browsers
                return HeaderStatus.WEAK
            else:
                return HeaderStatus.MISCONFIGURED
        
        return SecurityHeader(
            name="x-frame-options",
            display_name="X-Frame-Options",
            description="Prevents clickjacking by controlling iframe embedding.",
            check_function=check,
            weight=15,
            category="clickjacking",
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.HIGH,
                    action="Add X-Frame-Options header",
                    example="X-Frame-Options: DENY",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.MEDIUM,
                    action="Replace deprecated ALLOW-FROM with SAMEORIGIN or DENY",
                    example="X-Frame-Options: SAMEORIGIN",
                    resources=["https://caniuse.com/x-frame-options"]
                ),
                HeaderStatus.MISCONFIGURED: Remediation(
                    severity=Severity.HIGH,
                    action="Fix X-Frame-Options value",
                    example="X-Frame-Options: DENY",
                    resources=[]
                ),
            }
        )
    
    def _create_x_content_type_options(self) -> SecurityHeader:
        """Create X-Content-Type-Options header definition"""
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            if value.lower().strip() == "nosniff":
                return HeaderStatus.PRESENT
            else:
                return HeaderStatus.MISCONFIGURED
        
        return SecurityHeader(
            name="x-content-type-options",
            display_name="X-Content-Type-Options",
            description="Prevents MIME-type sniffing attacks.",
            check_function=check,
            weight=10,
            category="mime",
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.MEDIUM,
                    action="Add X-Content-Type-Options header",
                    example="X-Content-Type-Options: nosniff",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
                    ]
                ),
                HeaderStatus.MISCONFIGURED: Remediation(
                    severity=Severity.MEDIUM,
                    action="Fix X-Content-Type-Options value",
                    example="X-Content-Type-Options: nosniff",
                    resources=[]
                ),
            }
        )
    
    def _create_x_xss_protection(self) -> SecurityHeader:
        """Create X-XSS-Protection header definition"""
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            # Parse the value
            parts = value.split(';')
            if not parts:
                return HeaderStatus.MISCONFIGURED
            
            mode = parts[0].strip()
            
            if mode == "0":
                return HeaderStatus.WEAK  # Disabled
            elif mode == "1":
                if len(parts) > 1 and 'block' in parts[1].lower():
                    return HeaderStatus.PRESENT
                return HeaderStatus.WEAK  # Enabled but not blocking
            elif mode == "1; mode=block":
                return HeaderStatus.PRESENT
            else:
                return HeaderStatus.MISCONFIGURED
        
        return SecurityHeader(
            name="x-xss-protection",
            display_name="X-XSS-Protection",
            description="Legacy XSS filter (deprecated but still checked).",
            check_function=check,
            weight=5,
            category="xss",
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.LOW,
                    action="Add X-XSS-Protection header (deprecated, CSP preferred)",
                    example="X-XSS-Protection: 1; mode=block",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.LOW,
                    action="Enable blocking mode",
                    example="X-XSS-Protection: 1; mode=block",
                    resources=[]
                ),
            }
        )
    
    def _create_referrer_policy(self) -> SecurityHeader:
        """Create Referrer-Policy header definition"""
        
        VALID_POLICIES = [
            'no-referrer',
            'no-referrer-when-downgrade',
            'origin',
            'origin-when-cross-origin',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin',
            'unsafe-url',
        ]
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            value_lower = value.lower().strip()
            
            if value_lower in VALID_POLICIES:
                if value_lower in ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin']:
                    return HeaderStatus.PRESENT
                elif value_lower == 'unsafe-url':
                    return HeaderStatus.MISCONFIGURED
                else:
                    return HeaderStatus.WEAK if value_lower == 'no-referrer-when-downgrade' else HeaderStatus.PRESENT
            else:
                return HeaderStatus.MISCONFIGURED
        
        return SecurityHeader(
            name="referrer-policy",
            display_name="Referrer-Policy",
            description="Controls how much referrer information is shared.",
            check_function=check,
            weight=10,
            category="privacy",
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.MEDIUM,
                    action="Add Referrer-Policy header",
                    example="Referrer-Policy: strict-origin-when-cross-origin",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.LOW,
                    action="Consider a more restrictive policy",
                    example="Referrer-Policy: strict-origin-when-cross-origin",
                    resources=[]
                ),
                HeaderStatus.MISCONFIGURED: Remediation(
                    severity=Severity.MEDIUM,
                    action="Use a valid Referrer-Policy value",
                    example="Referrer-Policy: strict-origin-when-cross-origin",
                    resources=[]
                ),
            }
        )
    
    def _create_permissions_policy(self) -> SecurityHeader:
        """Create Permissions-Policy header definition"""
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            # Check for common restricted features
            restricted_features = [
                'geolocation', 'camera', 'microphone', 
                'usb', 'fullscreen', 'payment'
            ]
            
            found_features = [f for f in restricted_features if f in value.lower()]
            
            if len(found_features) >= 3:
                return HeaderStatus.PRESENT
            elif len(found_features) >= 1:
                return HeaderStatus.WEAK
            else:
                return HeaderStatus.WEAK  # Policy exists but no restrictions
        
        return SecurityHeader(
            name="permissions-policy",
            display_name="Permissions-Policy",
            description="Controls which browser features can be used.",
            check_function=check,
            weight=10,
            category="permissions",
            aliases=["feature-policy", "permissions-policy"],
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.MEDIUM,
                    action="Add Permissions-Policy header",
                    example="Permissions-Policy: geolocation=(), camera=(), microphone=()",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.LOW,
                    action="Restrict more browser features",
                    example="Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(self)",
                    resources=[]
                ),
            }
        )
    
    def _create_cross_origin_opener_policy(self) -> SecurityHeader:
        """Create Cross-Origin-Opener-Policy header definition"""
        
        VALID_VALUES = ['same-origin', 'same-origin-allow-popups', 'unsafe-none']
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            value_lower = value.lower().strip()
            
            if value_lower == 'same-origin':
                return HeaderStatus.PRESENT
            elif value_lower == 'same-origin-allow-popups':
                return HeaderStatus.PRESENT
            elif value_lower in VALID_VALUES:
                return HeaderStatus.WEAK
            else:
                return HeaderStatus.MISCONFIGURED
        
        return SecurityHeader(
            name="cross-origin-opener-policy",
            display_name="Cross-Origin-Opener-Policy",
            description="Isolates browsing context to prevent cross-origin attacks.",
            check_function=check,
            weight=8,
            category="isolation",
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.MEDIUM,
                    action="Add Cross-Origin-Opener-Policy header",
                    example="Cross-Origin-Opener-Policy: same-origin",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.LOW,
                    action="Consider using same-origin for better isolation",
                    example="Cross-Origin-Opener-Policy: same-origin",
                    resources=[]
                ),
            }
        )
    
    def _create_cross_origin_resource_policy(self) -> SecurityHeader:
        """Create Cross-Origin-Resource-Policy header definition"""
        
        VALID_VALUES = ['same-origin', 'same-site', 'cross-origin']
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            value_lower = value.lower().strip()
            
            if value_lower in VALID_VALUES:
                if value_lower == 'same-origin':
                    return HeaderStatus.PRESENT
                elif value_lower == 'same-site':
                    return HeaderStatus.PRESENT
                else:
                    return HeaderStatus.WEAK
            else:
                return HeaderStatus.MISCONFIGURED
        
        return SecurityHeader(
            name="cross-origin-resource-policy",
            display_name="Cross-Origin-Resource-Policy",
            description="Controls which origins can load this resource.",
            check_function=check,
            weight=5,
            category="resource-sharing",
            aliases=[],
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.LOW,
                    action="Add Cross-Origin-Resource-Policy header",
                    example="Cross-Origin-Resource-Policy: same-origin",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.INFO,
                    action="Consider restricting to same-origin or same-site",
                    example="Cross-Origin-Resource-Policy: same-origin",
                    resources=[]
                ),
            }
        )
    
    def _create_cross_origin_embedder_policy(self) -> SecurityHeader:
        """Create Cross-Origin-Embedder-Policy header definition"""
        
        VALID_VALUES = ['require-corp', 'credentialless', 'unsafe-none']
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            value_lower = value.lower().strip()
            
            if value_lower == 'require-corp':
                return HeaderStatus.PRESENT
            elif value_lower == 'credentialless':
                return HeaderStatus.PRESENT
            elif value_lower in VALID_VALUES:
                return HeaderStatus.WEAK
            else:
                return HeaderStatus.MISCONFIGURED
        
        return SecurityHeader(
            name="cross-origin-embedder-policy",
            display_name="Cross-Origin-Embedder-Policy",
            description="Controls resource embedding behavior.",
            check_function=check,
            weight=5,
            category="embedding",
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.MEDIUM,
                    action="Add Cross-Origin-Embedder-Policy header",
                    example="Cross-Origin-Embedder-Policy: require-corp",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.LOW,
                    action="Consider using require-corp for better isolation",
                    example="Cross-Origin-Embedder-Policy: require-corp",
                    resources=[]
                ),
            }
        )
    
    def _create_cache_control(self) -> SecurityHeader:
        """Create Cache-Control header definition"""
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            value_lower = value.lower()
            
            # Check for no-store (best for sensitive data)
            if 'no-store' in value_lower:
                return HeaderStatus.PRESENT
            # Check for private with max-age
            elif 'private' in value_lower and 'max-age' in value_lower:
                return HeaderStatus.WEAK
            # Check for public caching (potentially dangerous for sensitive data)
            elif 'public' in value_lower:
                return HeaderStatus.MISCONFIGURED
            else:
                return HeaderStatus.WEAK
        
        return SecurityHeader(
            name="cache-control",
            display_name="Cache-Control",
            description="Controls caching of sensitive data.",
            check_function=check,
            weight=8,
            category="privacy",
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.LOW,
                    action="Add Cache-Control header for sensitive pages",
                    example="Cache-Control: no-store, no-cache, must-revalidate, private",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.LOW,
                    action="Add no-store for sensitive data",
                    example="Cache-Control: no-store, private",
                    resources=[]
                ),
                HeaderStatus.MISCONFIGURED: Remediation(
                    severity=Severity.HIGH,
                    action="Remove public caching for sensitive data",
                    example="Cache-Control: no-store, private",
                    resources=[]
                ),
            }
        )
    
    def _create_x_permitted_cross_domain_policies(self) -> SecurityHeader:
        """Create X-Permitted-Cross-Domain-Policies header definition"""
        
        VALID_VALUES = ['none', 'master-only', 'by-content-type', 'all', 'none']
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            value_lower = value.lower().strip()
            
            if value_lower == 'none':
                return HeaderStatus.PRESENT
            elif value_lower in ['master-only', 'by-content-type']:
                return HeaderStatus.WEAK
            elif value_lower == 'all':
                return HeaderStatus.MISCONFIGURED
            else:
                return HeaderStatus.MISCONFIGURED
        
        return SecurityHeader(
            name="x-permitted-cross-domain-policies",
            display_name="X-Permitted-Cross-Domain-Policies",
            description="Controls Adobe Flash/ACRF cross-domain requests.",
            check_function=check,
            weight=3,
            category="cross-domain",
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.LOW,
                    action="Add X-Permitted-Cross-Domain-Policies header",
                    example="X-Permitted-Cross-Domain-Policies: none",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Permitted-Cross-Domain-Policies"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.LOW,
                    action="Restrict to none for maximum security",
                    example="X-Permitted-Cross-Domain-Policies: none",
                    resources=[]
                ),
                HeaderStatus.MISCONFIGURED: Remediation(
                    severity=Severity.MEDIUM,
                    action="Set to none to block all cross-domain policies",
                    example="X-Permitted-Cross-Domain-Policies: none",
                    resources=[]
                ),
            }
        )
    
    def _create_expect_ct(self) -> SecurityHeader:
        """Create Expect-CT header definition"""
        
        def check(value: str) -> HeaderStatus:
            if not value:
                return HeaderStatus.MISSING
            
            value_lower = value.lower()
            
            # Check for enforce (strongest)
            has_enforce = 'enforce' in value_lower
            
            # Check for max-age
            max_age_match = re.search(r'max-age=(\d+)', value_lower)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 86400:  # Less than 1 day
                    return HeaderStatus.WEAK
            else:
                return HeaderStatus.MISCONFIGURED
            
            if has_enforce:
                return HeaderStatus.PRESENT
            else:
                return HeaderStatus.WEAK
        
        return SecurityHeader(
            name="expect-ct",
            display_name="Expect-CT",
            description="Enforces Certificate Transparency requirements.",
            check_function=check,
            weight=5,
            category="certificate",
            remediation={
                HeaderStatus.MISSING: Remediation(
                    severity=Severity.LOW,
                    action="Add Expect-CT header",
                    example="Expect-CT: enforce, max-age=86400",
                    resources=[
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"
                    ]
                ),
                HeaderStatus.WEAK: Remediation(
                    severity=Severity.LOW,
                    action="Add enforce directive",
                    example="Expect-CT: enforce, max-age=86400",
                    resources=[]
                ),
            }
        )


# Global registry instance
DEFAULT_HEADER_REGISTRY = HeaderRegistry()
