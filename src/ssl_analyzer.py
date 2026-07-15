"""
SSL/TLS Analyzer Module
~~~~~~~~~~~~~~~~~~~~~~

Analyzes SSL/TLS certificate and configuration.
"""

import ssl
import socket
import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse


@dataclass
class CertificateInfo:
    """SSL Certificate information"""
    subject: str
    issuer: str
    valid_from: str
    valid_until: str
    days_remaining: int
    serial_number: str
    signature_algorithm: str
    public_key_algorithm: str
    key_size: int
    is_expired: bool
    is_valid: bool


@dataclass
class TLSAnalysis:
    """TLS configuration analysis"""
    tls_version: str
    cipher_suite: str
    cipher_bits: int
    is_secure: bool
    issues: List[str]
    recommendations: List[str]


@dataclass
class SSLResult:
    """Complete SSL/TLS analysis result"""
    host: str
    port: int
    is_reachable: bool
    certificate: Optional[CertificateInfo]
    tls_analysis: Optional[TLSAnalysis]
    overall_score: int
    grade: str
    issues: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "is_reachable": self.is_reachable,
            "certificate": {
                "subject": self.certificate.subject if self.certificate else None,
                "issuer": self.certificate.issuer if self.certificate else None,
                "valid_from": self.certificate.valid_from if self.certificate else None,
                "valid_until": self.certificate.valid_until if self.certificate else None,
                "days_remaining": self.certificate.days_remaining if self.certificate else None,
                "is_expired": self.certificate.is_expired if self.certificate else None,
                "key_size": self.certificate.key_size if self.certificate else None,
            } if self.certificate else None,
            "tls_version": self.tls_analysis.tls_version if self.tls_analysis else None,
            "cipher_suite": self.tls_analysis.cipher_suite if self.tls_analysis else None,
            "is_secure": self.tls_analysis.is_secure if self.tls_analysis else False,
            "overall_score": self.overall_score,
            "grade": self.grade,
            "issues": self.issues,
            "recommendations": self.recommendations,
        }


class SSLAnalyzer:
    """
    SSL/TLS Certificate and Configuration Analyzer.
    
    Usage:
        analyzer = SSLAnalyzer()
        result = analyzer.analyze("example.com", 443)
        print(f"Grade: {result.grade}")
    """
    
    # Secure TLS versions
    SECURE_TLS_VERSIONS = {
        "TLSv1.3": 100,
        "TLSv1.2": 90,
    }
    
    # Weak TLS versions
    WEAK_TLS_VERSIONS = {
        "TLSv1.1": 50,
        "TLSv1.0": 20,
        "SSLv3": 0,
        "SSLv2": 0,
    }
    
    # Secure cipher suites (simplified check)
    SECURE_CIPHERS = [
        "AES", "CHACHA", "GCM", "SHA256", "SHA384",
    ]
    
    # Weak cipher suites
    WEAK_CIPHERS = [
        "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT",
    ]
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
    
    def analyze(self, host: str, port: int = 443) -> SSLResult:
        """
        Analyze SSL/TLS configuration for a host.
        
        Args:
            host: Hostname to analyze
            port: Port number (default 443)
            
        Returns:
            SSLResult with complete analysis
        """
        result = SSLResult(
            host=host,
            port=port,
            is_reachable=False,
            certificate=None,
            tls_analysis=None,
            overall_score=0,
            grade="F",
            issues=[],
            recommendations=[],
        )
        
        try:
            # Get certificate info
            cert_info = self._get_certificate(host, port)
            result.certificate = cert_info
            result.is_reachable = True
            
            # Get TLS info
            tls_info = self._get_tls_info(host, port)
            result.tls_analysis = tls_info
            
            # Calculate overall score
            result.issues, result.recommendations = self._analyze_findings(cert_info, tls_info)
            result.overall_score = self._calculate_score(cert_info, tls_info, result.issues)
            result.grade = self._get_grade(result.overall_score)
            
        except Exception as e:
            result.issues.append(f"Connection failed: {str(e)}")
            result.recommendations.append("Ensure the host is reachable and port is open")
        
        return result
    
    def _get_certificate(self, host: str, port: int) -> CertificateInfo:
        """Get SSL certificate information"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                cipher = ssock.cipher()
                
                # Parse certificate
                cert_dict = ssock.getpeercert()
                
                # Extract subject safely
                try:
                    subject_raw = cert_dict.get('subject', [])
                    if subject_raw:
                        if isinstance(subject_raw, list):
                            subject = {}
                            for item in subject_raw:
                                if isinstance(item, tuple):
                                    for k, v in item:
                                        subject[k] = v
                                elif isinstance(item, dict):
                                    subject.update(item)
                            subject_str = ", ".join(f"{k}={v}" for k, v in subject.items()) if subject else str(subject_raw)
                        else:
                            subject_str = str(subject_raw)
                    else:
                        subject_str = "Unknown"
                except:
                    subject_str = "Unknown"
                
                # Extract issuer safely
                try:
                    issuer_raw = cert_dict.get('issuer', [])
                    if issuer_raw:
                        if isinstance(issuer_raw, list):
                            issuer = {}
                            for item in issuer_raw:
                                if isinstance(item, tuple):
                                    for k, v in item:
                                        issuer[k] = v
                                elif isinstance(item, dict):
                                    issuer.update(item)
                            issuer_str = ", ".join(f"{k}={v}" for k, v in issuer.items()) if issuer else str(issuer_raw)
                        else:
                            issuer_str = str(issuer_raw)
                    else:
                        issuer_str = "Unknown"
                except:
                    issuer_str = "Unknown"
                
                # Parse dates
                not_before = cert_dict.get('notBefore', '')
                not_after = cert_dict.get('notAfter', '')
                
                try:
                    valid_from = datetime.datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                except:
                    valid_from = datetime.datetime.now()
                
                try:
                    valid_until = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                except:
                    valid_until = datetime.datetime.now()
                
                # Calculate days remaining
                now = datetime.datetime.now(valid_until.tzinfo) if valid_until.tzinfo else datetime.datetime.now()
                days_remaining = (valid_until.replace(tzinfo=None) - now.replace(tzinfo=None)).days
                
                # Check if expired
                is_expired = valid_until < now
                
                # Get cipher info
                cipher_name = cipher[0] if cipher else "Unknown"
                cipher_bits = cipher[2] if cipher else 0
                
                return CertificateInfo(
                    subject=subject_str,
                    issuer=issuer_str,
                    valid_from=valid_from.strftime("%Y-%m-%d %H:%M:%S"),
                    valid_until=valid_until.strftime("%Y-%m-%d %H:%M:%S"),
                    days_remaining=days_remaining,
                    serial_number=cert_dict.get('serialNumber', 'Unknown'),
                    signature_algorithm="SHA256" if "sha" in str(cert_dict).lower() else "Unknown",
                    public_key_algorithm="RSA" if "rsa" in str(cert_dict).lower() else "Unknown",
                    key_size=cipher_bits,
                    is_expired=is_expired,
                    is_valid=not is_expired,
                )
    
    def _get_tls_info(self, host: str, port: int) -> TLSAnalysis:
        """Get TLS configuration info"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        issues = []
        recommendations = []
        
        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                tls_version = ssock.version()
                
                cipher_name = cipher[0] if cipher else "Unknown"
                cipher_bits = cipher[2] if cipher else 0
                
                # Check TLS version
                is_secure = tls_version in self.SECURE_TLS_VERSIONS
                
                if tls_version in self.WEAK_TLS_VERSIONS:
                    issues.append(f"Weak TLS version: {tls_version}")
                    recommendations.append(f"Upgrade from {tls_version} to TLSv1.2 or TLSv1.3")
                
                # Check cipher
                has_weak_cipher = any(wc in cipher_name.upper() for wc in self.WEAK_CIPHERS)
                if has_weak_cipher:
                    issues.append(f"Weak cipher suite: {cipher_name}")
                    recommendations.append("Use modern cipher suites (AES-GCM, ChaCha20)")
                
                # Check for secure cipher
                has_secure_cipher = any(sc in cipher_name.upper() for sc in self.SECURE_CIPHERS)
                if not has_secure_cipher and not has_weak_cipher:
                    issues.append(f"Unknown cipher suite: {cipher_name}")
                
                return TLSAnalysis(
                    tls_version=tls_version,
                    cipher_suite=cipher_name,
                    cipher_bits=cipher_bits,
                    is_secure=is_secure and not has_weak_cipher,
                    issues=issues,
                    recommendations=recommendations,
                )
    
    def _analyze_findings(self, cert: CertificateInfo, tls: TLSAnalysis) -> tuple:
        """Analyze findings and generate recommendations"""
        issues = []
        recommendations = []
        
        # Certificate issues
        if cert.is_expired:
            issues.append("Certificate has EXPIRED")
            recommendations.append("Renew SSL certificate immediately")
        
        if cert.days_remaining < 30:
            issues.append(f"Certificate expires in {cert.days_remaining} days")
            recommendations.append("Renew certificate before expiration")
        
        # Check certificate chain
        if "Let's Encrypt" in cert.issuer:
            pass  # Let's Encrypt is trusted
        elif "DigiCert" in cert.issuer or "GlobalSign" in cert.issuer:
            pass  # Premium CA
        else:
            issues.append(f"Certificate issuer: {cert.issuer}")
        
        # Combine issues from TLS analysis
        issues.extend(tls.issues)
        recommendations.extend(tls.recommendations)
        
        return issues, recommendations
    
    def _calculate_score(self, cert: CertificateInfo, tls: TLSAnalysis, issues: List[str]) -> int:
        """Calculate overall SSL/TLS security score"""
        score = 100
        
        # Deduct for issues
        for issue in issues:
            if "EXPIRED" in issue:
                score -= 50
            elif "expires in" in issue:
                days = int(''.join(filter(str.isdigit, issue)))
                if days < 7:
                    score -= 30
                elif days < 30:
                    score -= 15
            elif "Weak TLS" in issue:
                score -= 40
            elif "Weak cipher" in issue:
                score -= 30
            else:
                score -= 10
        
        return max(0, score)
    
    def _get_grade(self, score: int) -> str:
        """Get letter grade from score"""
        if score >= 90:
            return "A+"
        elif score >= 80:
            return "A"
        elif score >= 70:
            return "B"
        elif score >= 60:
            return "C"
        elif score >= 40:
            return "D"
        else:
            return "F"
