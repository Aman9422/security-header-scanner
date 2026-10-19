"""
Technology Fingerprinter Module
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Detects technologies, frameworks, CMS, and libraries used by a website.
"""

import math
import requests
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from .utils import normalize_http_url


@dataclass
class Technology:
    """Detected technology information"""
    name: str
    category: str
    version: Optional[str] = None
    confidence: str = "high"  # high, medium, low
    evidence: str = ""


@dataclass
class FingerprintResult:
    """Complete fingerprinting result"""
    url: str
    technologies: List[Technology]
    server: Optional[str]
    powered_by: Optional[str]
    x_powered_by: Optional[str]
    frontend_frameworks: List[str]
    backend_technologies: List[str]
    cms_platform: Optional[str]
    javascript_libs: List[str]
    overall_score: int
    risk_level: str
    issues: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "server": self.server,
            "technologies": [
                {
                    "name": t.name,
                    "category": t.category,
                    "version": t.version,
                    "confidence": t.confidence,
                }
                for t in self.technologies
            ],
            "frontend_frameworks": self.frontend_frameworks,
            "backend_technologies": self.backend_technologies,
            "cms_platform": self.cms_platform,
            "javascript_libs": self.javascript_libs,
            "overall_score": self.overall_score,
            "risk_level": self.risk_level,
            "issues": self.issues,
            "recommendations": self.recommendations,
        }


class TechnologyFingerprinter:
    """
    Detects technologies used by a website.
    
    Usage:
        fingerprinter = TechnologyFingerprinter()
        result = fingerprinter.fingerprint("https://example.com")
        for tech in result.technologies:
            print(f"{tech.name} ({tech.category})")
    """
    
    # Technology signatures
    TECHNOLOGY_SIGNATURES = {
        # Frontend Frameworks
        "React": {
            "category": "JavaScript Framework",
            "patterns": [
                (r"react\.js", r"react\.min\.js", "react-dom"),
                (r"_reactFiber", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"),
            ],
            "files": ["react.production.min.js", "react.development.js"],
        },
        "Vue.js": {
            "category": "JavaScript Framework",
            "patterns": [
                (r"vue\d*\.min\.js", r"Vue\.js", r"__vue__"),
            ],
            "files": ["vue.min.js", "vue.js"],
        },
        "Angular": {
            "category": "JavaScript Framework",
            "patterns": [
                (r"angular\d*\.min\.js", r"ng-app", r"angular."),
            ],
            "files": ["angular.min.js", "angular.js"],
        },
        "jQuery": {
            "category": "JavaScript Library",
            "patterns": [
                (r"jquery-\d*\.\d*\.\d*\.min\.js", r"jquery\.\d*\.\d*\.min\.js"),
            ],
            "files": ["jquery.min.js", "jquery.js"],
        },
        "Bootstrap": {
            "category": "CSS Framework",
            "patterns": [
                (r"bootstrap\-\d*\.\d*\.\d*\.min\.css", r"bootstrap\.\d*\.\d*\.min\.css"),
            ],
            "files": ["bootstrap.min.css", "bootstrap.js"],
        },
        "Tailwind CSS": {
            "category": "CSS Framework",
            "patterns": [
                (r"tailwindcss", r"tailwind\.min\.css"),
            ],
            "files": ["tailwindcss", "app.css"],
        },
        "Next.js": {
            "category": "JavaScript Framework",
            "patterns": [
                (r"next/", r"next\.js", r"_next/static"),
            ],
            "files": ["next/", "_next/"],
        },
        "Nuxt.js": {
            "category": "JavaScript Framework",
            "patterns": [
                (r"nuxt/", r"_nuxt/"),
            ],
            "files": ["_nuxt/"],
        },
        
        # Backend Technologies
        "Node.js": {
            "category": "Backend",
            "patterns": [
                (r"X-Powered-By.*Node",),
            ],
            "headers": ["X-Powered-By"],
        },
        "PHP": {
            "category": "Backend",
            "patterns": [
                (r"X-Powered-By.*PHP", r"PHPSESSID"),
            ],
            "headers": ["X-Powered-By"],
        },
        "Python": {
            "category": "Backend",
            "patterns": [
                (r"X-Powered-By.*Python", r"__python"),
            ],
            "headers": ["X-Powered-By"],
        },
        "Ruby": {
            "category": "Backend",
            "patterns": [
                (r"X-Powered-By.*Ruby",),
            ],
            "headers": ["X-Powered-By"],
        },
        "ASP.NET": {
            "category": "Backend",
            "patterns": [
                (r"X-Powered-By.*ASP\.NET", r"__RequestVerificationToken"),
            ],
            "headers": ["X-Powered-By"],
        },
        "Express": {
            "category": "Backend Framework",
            "patterns": [
                (r"X-Powered-By.*Express",),
            ],
            "headers": ["X-Powered-By"],
        },
        "Django": {
            "category": "Backend Framework",
            "patterns": [
                (r"csrftoken", r"__django",),
            ],
            "cookies": ["csrftoken"],
        },
        "Flask": {
            "category": "Backend Framework",
            "patterns": [
                (r"X-Powered-By.*Flask",),
            ],
            "headers": ["X-Powered-By"],
        },
        
        # CMS Platforms
        "WordPress": {
            "category": "CMS",
            "patterns": [
                (r"wp-content", r"wp-includes", r"wordpress", r"wp-"),
            ],
            "files": ["wp-content", "wp-includes"],
        },
        "Drupal": {
            "category": "CMS",
            "patterns": [
                (r"drupal", r"drupalgap",),
            ],
            "files": ["modules/", "sites/default"],
        },
        "Joomla": {
            "category": "CMS",
            "patterns": [
                (r"joomla", r"com_content",),
            ],
            "files": ["administrator/"],
        },
        "Shopify": {
            "category": "E-commerce CMS",
            "patterns": [
                (r"shopify", r"cdn\.shopify\.com"),
            ],
            "files": ["cdn.shopify.com"],
        },
        
        # Web Servers
        "Apache": {
            "category": "Web Server",
            "patterns": [
                (r"Apache/\d*\.\d*\.\d*",),
            ],
            "headers": ["Server"],
        },
        "Nginx": {
            "category": "Web Server",
            "patterns": [
                (r"nginx/\d*\.\d*",),
            ],
            "headers": ["Server"],
        },
        "Microsoft IIS": {
            "category": "Web Server",
            "patterns": [
                (r"Microsoft-IIS/\d*\.\d*", r"IIS"),
            ],
            "headers": ["Server"],
        },
        
        # CDNs and Proxies
        "Cloudflare": {
            "category": "CDN/WAF",
            "patterns": [
                (r"cf-ray", r"__cfduid", r"cloudflare"),
            ],
            "headers": ["Server"],
        },
        "AWS CloudFront": {
            "category": "CDN",
            "patterns": [
                (r"cloudfront", r"X-Amz-Cf-"),
            ],
            "headers": ["Server"],
        },
        "Akamai": {
            "category": "CDN",
            "patterns": [
                (r"akamai", r"akamaighost"),
            ],
        },
        "Google Cloud": {
            "category": "Cloud Platform",
            "patterns": [
                (r"google", r"gstatic", r"_gac"),
            ],
        },
    }
    
    def __init__(self, timeout: int = 30, max_response_bytes: int = 2 * 1024 * 1024):
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0.1 <= timeout <= 300:
            raise ValueError("timeout must be between 0.1 and 300 seconds")
        if isinstance(max_response_bytes, bool) or not isinstance(max_response_bytes, int) or not 1 <= max_response_bytes <= 50 * 1024 * 1024:
            raise ValueError("max_response_bytes must be an integer between 1 and 52428800")
        self.timeout = float(timeout)
        self.max_response_bytes = max_response_bytes
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Security Header Scanner Bot)"
        })
    
    def fingerprint(self, url: str) -> FingerprintResult:
        """
        Fingerprint technologies used by a website.
        
        Args:
            url: URL to analyze
            
        Returns:
            FingerprintResult with detected technologies
        """
        result = FingerprintResult(
            url=url,
            technologies=[],
            server=None,
            powered_by=None,
            x_powered_by=None,
            frontend_frameworks=[],
            backend_technologies=[],
            cms_platform=None,
            javascript_libs=[],
            overall_score=100,
            risk_level="low",
            issues=[],
            recommendations=[],
        )
        
        try:
            url = normalize_http_url(url)
            result.url = url

            body = bytearray()
            with self.session.get(url, timeout=self.timeout, verify=True, stream=True) as response:
                for chunk in response.iter_content(chunk_size=65536):
                    if not chunk:
                        continue
                    remaining = self.max_response_bytes - len(body)
                    body.extend(chunk[:remaining])
                    if len(body) >= self.max_response_bytes:
                        break
                encoding = response.encoding or "utf-8"
                headers = {k.lower(): v for k, v in response.headers.items()}
                cookies = response.cookies
            html_content = bytes(body).decode(encoding, errors="replace")
            
            # Extract server info
            result.server = headers.get("server")
            result.powered_by = headers.get("x-powered-by")
            result.x_powered_by = headers.get("x-aspnet-version")
            
            # Analyze HTML content
            technologies = self._analyze_content(html_content, headers, cookies)
            result.technologies = technologies
            
            # Categorize technologies
            for tech in technologies:
                if tech.category == "JavaScript Framework":
                    result.frontend_frameworks.append(tech.name)
                elif tech.category in ["Backend", "Backend Framework"]:
                    result.backend_technologies.append(tech.name)
                elif tech.category == "CMS":
                    result.cms_platform = tech.name
                elif tech.category == "JavaScript Library":
                    result.javascript_libs.append(tech.name)
            
            # Generate security findings
            result.issues, result.recommendations = self._analyze_security_findings(
                technologies, headers
            )
            result.overall_score = self._calculate_score(result.issues)
            result.risk_level = self._get_risk_level(result.issues)
            
        except Exception as e:
            result.issues.append(f"Fingerprinting failed: {str(e)}")
            result.overall_score = 0
            result.risk_level = "unknown"
        
        return result
    
    def _analyze_content(self, html: str, headers: Dict, cookies: Dict) -> List[Technology]:
        """Analyze HTML content for technology signatures"""
        detected = []
        
        # Check header-based signatures
        for tech_name, tech_info in self.TECHNOLOGY_SIGNATURES.items():
            # Check headers
            if "headers" in tech_info:
                for header_name in tech_info["headers"]:
                    header_value = headers.get(header_name.lower(), "")
                    if header_value:
                        header_evidence = f"{header_name}: {header_value}"
                        for pattern in tech_info["patterns"]:
                            for p in pattern:
                                if re.search(p, header_evidence, re.IGNORECASE):
                                    detected.append(Technology(
                                        name=tech_name,
                                        category=tech_info["category"],
                                        confidence="high",
                                        evidence=f"Header {header_name}: {header_value[:50]}"
                                    ))
                                    break
            
            # Check cookies
            if "cookies" in tech_info:
                for cookie_name in tech_info["cookies"]:
                    if cookie_name in cookies:
                        detected.append(Technology(
                            name=tech_name,
                            category=tech_info["category"],
                            confidence="high",
                            evidence=f"Cookie: {cookie_name}"
                        ))
            
            # Check HTML content patterns
            for pattern_group in tech_info["patterns"]:
                for pattern in pattern_group:
                    if re.search(pattern, html, re.IGNORECASE):
                        # Version is set only by technology-specific evidence below.
                        detected.append(Technology(
                            name=tech_name,
                            category=tech_info["category"],
                            version=None,
                            confidence="high",
                            evidence=f"Found pattern in HTML"
                        ))
                        break
        
        # Check for common version disclosure patterns
        version_patterns = {
            "jQuery": r'jquery[^\d]{0,40}(\d+\.\d+\.\d+)',
            "PHP": r'X-Powered-By.*?PHP[/\s]*(\d+\.\d+\.\d+)',
            "Python": r'X-Powered-By.*?Python[/\s]*(\d+\.\d+)',
            "React": r'react(?:-dom)?(?:@|[-/])v?(\d+\.\d+(?:\.\d+)?)',
            "WordPress": r'wp-includes.*?ver=(\d+\.\d+\.\d+)',
        }
        
        for tech_name, pattern in version_patterns.items():
            match = re.search(pattern, html + str(headers), re.IGNORECASE)
            if match:
                # Update existing or add new
                existing = next((t for t in detected if t.name == tech_name), None)
                if existing:
                    existing.version = match.group(1)
                else:
                    detected.append(Technology(
                        name=tech_name,
                        category=self.TECHNOLOGY_SIGNATURES.get(tech_name, {}).get("category", "Unknown"),
                        version=match.group(1),
                        confidence="medium",
                        evidence=f"Version found: {match.group(1)}"
                    ))
        
        unique = {}
        for tech in detected:
            existing = unique.get(tech.name)
            if existing is None:
                unique[tech.name] = tech
            elif existing.version is None and tech.version is not None:
                existing.version = tech.version
        return list(unique.values())
    
    def _analyze_security_findings(self, technologies: List[Technology], headers: Dict) -> tuple:
        """Analyze technologies for security issues"""
        issues = []
        recommendations = []
        
        # Compare each detected version against its own declared minimum.
        outdated_tech = {
            "jquery": ((3, 0, 0), "jQuery < 3.0", "Upgrade jQuery to a supported version"),
            "php": ((8, 0, 0), "PHP < 8.0", "Upgrade PHP to a supported version"),
            "react": ((18, 0, 0), "React < 18.0", "Upgrade React to a supported version"),
        }
        for tech in technologies:
            policy = outdated_tech.get(tech.name.lower())
            if not policy or not tech.version:
                continue
            minimum, label, recommendation = policy
            match = re.match(r"^\s*v?(\d+(?:\.\d+)*)", tech.version, re.IGNORECASE)
            if not match:
                continue
            version = tuple(int(part) for part in match.group(1).split("."))
            version = (version + (0, 0, 0))[:3]
            if version < minimum:
                issues.append(f"{tech.name} {tech.version} is outdated and below the supported minimum ({label})")
                recommendations.append(recommendation)
        
        # Check for technology disclosure
        if headers.get("x-powered-by"):
            issues.append(f"Technology disclosure: {headers['x-powered-by']}")
            recommendations.append("Remove X-Powered-By header to reduce information leakage")
        
        if headers.get("server"):
            server = headers["server"]
            if any(ws in server.lower() for ws in ["apache", "nginx", "iis"]):
                # These are commonly shown, but check for version
                if re.search(r'/\d+\.\d+', server):
                    issues.append(f"Server version disclosed: {server}")
                    recommendations.append("Hide server version in production")
        
        return issues, recommendations
    
    def _calculate_score(self, issues: List[str]) -> int:
        """Calculate security score based on issues"""
        score = 100
        for issue in issues:
            if "disclosure" in issue.lower():
                score -= 15
            elif "outdated" in issue.lower():
                score -= 25
            elif "vulnerable" in issue.lower():
                score -= 30
            else:
                score -= 10
        return max(0, score)
    
    def _get_risk_level(self, issues: List[str]) -> str:
        """Determine risk level based on issues"""
        if not issues:
            return "low"
        
        high_severity = sum(1 for i in issues if "outdated" in i.lower() or "vulnerable" in i.lower())
        if high_severity >= 2:
            return "high"
        elif high_severity >= 1:
            return "medium"
        else:
            return "low"
