"""
SSL/TLS Analyzer Module
~~~~~~~~~~~~~~~~~~~~~~

Analyzes SSL/TLS certificate and configuration.
"""

import ipaddress
import math
import ssl
import socket
import datetime
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlsplit

from .utils import normalize_http_url

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa


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
    is_not_yet_valid: bool = False
    is_trusted: bool = False
    hostname_matches: bool = False
    verification_error: Optional[str] = None


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
                "is_not_yet_valid": self.certificate.is_not_yet_valid if self.certificate else None,
                "is_valid": self.certificate.is_valid if self.certificate else None,
                "is_trusted": self.certificate.is_trusted if self.certificate else None,
                "hostname_matches": self.certificate.hostname_matches if self.certificate else None,
                "verification_error": self.certificate.verification_error if self.certificate else None,
                "serial_number": self.certificate.serial_number if self.certificate else None,
                "signature_algorithm": self.certificate.signature_algorithm if self.certificate else None,
                "public_key_algorithm": self.certificate.public_key_algorithm if self.certificate else None,
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
        "TLSv1": 20,
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
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0.1 <= timeout <= 120:
            raise ValueError("timeout must be between 0.1 and 120 seconds")
        self.timeout = float(timeout)
    
    def analyze(self, host: str, port: int = 443) -> SSLResult:
        """
        Analyze SSL/TLS configuration for a host.
        
        Args:
            host: Hostname to analyze
            port: Port number (default 443)
            
        Returns:
            SSLResult with complete analysis
        """
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        if not isinstance(host, str) or not host.strip() or len(host) > 2048:
            raise ValueError("host must be a non-empty hostname or IP address")
        host_input = host.strip()
        if host_input.count(":") >= 2 and not host_input.startswith("[") and "://" not in host_input:
            host_input = f"[{host_input}]"
        try:
            parsed_host = urlsplit(normalize_http_url(host_input))
        except ValueError as exc:
            raise ValueError("host must be a valid hostname or IP address") from exc
        if parsed_host.path not in {"", "/"} or parsed_host.query:
            raise ValueError("Provide a hostname or IP address without a path or query")
        if parsed_host.port is not None:
            if port == 443:
                port = parsed_host.port
            elif port != parsed_host.port:
                raise ValueError("Conflicting ports were supplied")
        if not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        host = parsed_host.hostname

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
        """Fetch and parse certificate DER, then verify trust and hostname."""
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)

        if not cert_der:
            raise ssl.SSLError("Peer did not provide a certificate")
        certificate = x509.load_der_x509_certificate(cert_der)

        valid_from = certificate.not_valid_before_utc
        valid_until = certificate.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
        is_expired = now > valid_until
        is_not_yet_valid = now < valid_from
        days_remaining = (valid_until - now).days

        public_key = certificate.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_algorithm = "RSA"
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            key_algorithm = "EC"
        elif isinstance(public_key, dsa.DSAPublicKey):
            key_algorithm = "DSA"
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            key_algorithm = "Ed25519"
        elif isinstance(public_key, ed448.Ed448PublicKey):
            key_algorithm = "Ed448"
        else:
            key_algorithm = type(public_key).__name__

        trusted, trust_error = self._verify_certificate_chain(host, port)
        hostname_matches = self._certificate_matches_hostname(certificate, host)
        date_valid = not is_expired and not is_not_yet_valid
        verification_error = trust_error
        if not hostname_matches:
            verification_error = "Certificate hostname does not match target"
        is_valid = date_valid and trusted and hostname_matches

        subject = certificate.subject.rfc4514_string() or "Unknown"
        issuer = certificate.issuer.rfc4514_string() or "Unknown"
        try:
            signature_algorithm = certificate.signature_algorithm_oid._name or certificate.signature_algorithm_oid.dotted_string
        except Exception:
            signature_algorithm = "Unknown"

        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            valid_from=valid_from.strftime("%Y-%m-%d %H:%M:%S UTC"),
            valid_until=valid_until.strftime("%Y-%m-%d %H:%M:%S UTC"),
            days_remaining=days_remaining,
            serial_number=hex(certificate.serial_number),
            signature_algorithm=signature_algorithm,
            public_key_algorithm=key_algorithm,
            key_size=getattr(public_key, "key_size", 0),
            is_expired=is_expired,
            is_valid=is_valid,
            is_not_yet_valid=is_not_yet_valid,
            is_trusted=trusted,
            hostname_matches=hostname_matches,
            verification_error=verification_error,
        )

    def _verify_certificate_chain(self, host: str, port: int) -> Tuple[bool, Optional[str]]:
        """Verify the peer chain against the system trust store."""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host):
                    return True, None
        except (OSError, ssl.SSLError) as exc:
            return False, str(exc)

    @staticmethod
    def _certificate_matches_hostname(certificate: x509.Certificate, host: str) -> bool:
        """Match the target against SAN entries, including single-label wildcards."""
        try:
            san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        except x509.ExtensionNotFound:
            # Modern TLS identity checks require SAN; do not trust a legacy CN.
            return False

        try:
            target_ip = ipaddress.ip_address(host)
        except ValueError:
            target = ".".join(label.encode("idna").decode("ascii").lower() for label in host.rstrip(".").split("."))
            for entry in san:
                if not isinstance(entry, x509.DNSName):
                    continue
                pattern = entry.value.rstrip(".").lower()
                if pattern.startswith("*.") and pattern.count("*") == 1:
                    suffix = ".".join(
                        label.encode("idna").decode("ascii").lower()
                        for label in pattern[2:].split(".")
                    )
                    target_parts = target.split(".")
                    suffix_parts = suffix.split(".")
                    if len(target_parts) == len(suffix_parts) + 1 and target_parts[1:] == suffix_parts:
                        return True
                else:
                    try:
                        normalized = ".".join(
                            label.encode("idna").decode("ascii").lower()
                            for label in pattern.split(".")
                        )
                    except UnicodeError:
                        continue
                    if target == normalized:
                        return True
            return False
        else:
            return any(isinstance(entry, x509.IPAddress) and entry.value == target_ip for entry in san)

    def _probe_weak_tls_versions(self, host: str, port: int) -> List[str]:
        """Probe whether the server still accepts TLS 1.0 or TLS 1.1."""
        supported = []
        probes = (
            ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None), "TLSv1"),
            ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None), "TLSv1.1"),
        )
        for label, version, negotiated_name in probes:
            if version is None:
                continue
            try:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version
                try:
                    context.set_ciphers("ALL:@SECLEVEL=0")
                except ssl.SSLError:
                    pass
                with socket.create_connection((host, port), timeout=min(self.timeout, 2)) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        if ssock.version() == negotiated_name:
                            supported.append(label)
            except (OSError, ssl.SSLError, ValueError):
                continue
        return supported

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
                
                # Record the negotiated version and separately probe legacy
                # versions; a modern negotiated connection alone does not prove
                # that obsolete protocols are disabled server-side.
                weak_versions = self._probe_weak_tls_versions(host, port)
                is_secure = tls_version in self.SECURE_TLS_VERSIONS and not weak_versions
                if tls_version in self.WEAK_TLS_VERSIONS:
                    issues.append(f"Weak TLS version negotiated: {tls_version}")
                    recommendations.append(f"Upgrade from {tls_version} to TLSv1.2 or TLSv1.3")
                for weak_version in weak_versions:
                    issues.append(f"Weak TLS version supported: {weak_version}")
                    recommendations.append(f"Disable {weak_version}; allow TLSv1.2 or TLSv1.3")
                
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
                    is_secure=is_secure and has_secure_cipher and not has_weak_cipher,
                    issues=issues,
                    recommendations=recommendations,
                )
    
    def _analyze_findings(self, cert: CertificateInfo, tls: TLSAnalysis) -> tuple:
        """Analyze findings and generate recommendations"""
        issues = []
        recommendations = []
        
        # Certificate validity is based on dates, system trust, and target name;
        # the CA brand alone is not a trust signal.
        if cert.is_expired:
            issues.append("Certificate has EXPIRED")
            recommendations.append("Renew SSL certificate immediately")
        elif cert.is_not_yet_valid:
            issues.append("Certificate is not yet valid")
            recommendations.append("Check certificate validity dates and server clock")
        elif cert.days_remaining < 30:
            issues.append(f"Certificate expires in {cert.days_remaining} days")
            recommendations.append("Renew certificate before expiration")

        if not cert.is_trusted:
            issues.append("Certificate chain is not trusted")
            recommendations.append("Install a complete chain from a trusted certificate authority")
        if not cert.hostname_matches:
            issues.append("Certificate hostname does not match the target")
            recommendations.append("Issue a certificate whose SAN matches the scanned hostname")
        
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
