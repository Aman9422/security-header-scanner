"""
Tests for Security Headers Scanner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import pytest
import responses
from unittest.mock import patch, MagicMock
import json

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanner import SecurityHeaderScanner, ScanResult, HeaderResult
from src.headers import HeaderStatus, HeaderRegistry, DEFAULT_HEADER_REGISTRY
from src.analyzer import HeaderAnalyzer
from src.reporter import ReportGenerator


class TestHeaderRegistry:
    """Test cases for HeaderRegistry"""
    
    def test_registry_has_headers(self):
        """Test that registry has security headers"""
        registry = HeaderRegistry()
        headers = registry.get_all()
        assert len(headers) > 0
    
    def test_get_header_by_name(self):
        """Test getting a header by name"""
        header = DEFAULT_HEADER_REGISTRY.get("strict-transport-security")
        assert header is not None
        assert header.display_name == "Strict-Transport-Security"
    
    def test_get_nonexistent_header(self):
        """Test getting a header that doesn't exist"""
        header = DEFAULT_HEADER_REGISTRY.get("nonexistent-header")
        assert header is None


class TestHeaderValidation:
    """Test cases for header validation"""
    
    def test_hsts_present(self):
        """Test HSTS header validation - present"""
        header = DEFAULT_HEADER_REGISTRY.get("strict-transport-security")
        status, _ = header.validate("max-age=31536000; includeSubDomains")
        assert status == HeaderStatus.PRESENT
    
    def test_hsts_weak(self):
        """Test HSTS header validation - weak (low max-age)"""
        header = DEFAULT_HEADER_REGISTRY.get("strict-transport-security")
        status, _ = header.validate("max-age=86400")
        assert status == HeaderStatus.WEAK
    
    def test_hsts_missing(self):
        """Test HSTS header validation - missing"""
        header = DEFAULT_HEADER_REGISTRY.get("strict-transport-security")
        status, _ = header.validate(None)
        assert status == HeaderStatus.MISSING
    
    def test_x_frame_options_deny(self):
        """Test X-Frame-Options with DENY"""
        header = DEFAULT_HEADER_REGISTRY.get("x-frame-options")
        status, _ = header.validate("DENY")
        assert status == HeaderStatus.PRESENT
    
    def test_x_frame_options_sameorigin(self):
        """Test X-Frame-Options with SAMEORIGIN"""
        header = DEFAULT_HEADER_REGISTRY.get("x-frame-options")
        status, _ = header.validate("SAMEORIGIN")
        assert status == HeaderStatus.PRESENT
    
    def test_x_content_type_options(self):
        """Test X-Content-Type-Options validation"""
        header = DEFAULT_HEADER_REGISTRY.get("x-content-type-options")
        status, _ = header.validate("nosniff")
        assert status == HeaderStatus.PRESENT
        
        status, _ = header.validate("invalid")
        assert status == HeaderStatus.MISCONFIGURED
    
    def test_csp_weak_with_unsafe_inline(self):
        """Test CSP with unsafe-inline is weak"""
        header = DEFAULT_HEADER_REGISTRY.get("content-security-policy")
        status, _ = header.validate("default-src 'self' 'unsafe-inline'")
        assert status == HeaderStatus.WEAK
    
    def test_csp_present_restrictive(self):
        """Test CSP with restrictive settings"""
        header = DEFAULT_HEADER_REGISTRY.get("content-security-policy")
        # CSP needs default-src plus multiple restrictive directives
        status, _ = header.validate("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'")
        assert status == HeaderStatus.PRESENT


class TestScanner:
    """Test cases for SecurityHeaderScanner"""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance"""
        return SecurityHeaderScanner(timeout=5, max_retries=1)
    
    def test_normalize_url_with_scheme(self, scanner):
        """Test URL normalization with scheme"""
        url = scanner._normalize_url("https://example.com")
        assert url == "https://example.com"
    
    def test_normalize_url_without_scheme(self, scanner):
        """Test URL normalization without scheme"""
        url = scanner._normalize_url("example.com")
        assert url == "https://example.com"
    
    def test_calculate_header_score_present(self, scanner):
        """Test score calculation for present header"""
        score = scanner._calculate_header_score(HeaderStatus.PRESENT, 15)
        assert score == 15
    
    def test_calculate_header_score_missing(self, scanner):
        """Test score calculation for missing header"""
        score = scanner._calculate_header_score(HeaderStatus.MISSING, 15)
        assert score == -15
    
    def test_calculate_header_score_weak(self, scanner):
        """Test score calculation for weak header"""
        score = scanner._calculate_header_score(HeaderStatus.WEAK, 15)
        assert score == 7  # 50% of weight, floored


class TestAnalyzer:
    """Test cases for HeaderAnalyzer"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance"""
        return HeaderAnalyzer()
    
    def test_calculate_percentage_score(self, analyzer):
        """Test percentage score calculation"""
        # Normal case: score of 50 out of 100
        score = analyzer.calculate_percentage_score(50, 100)
        assert score == 50.0  # (50/100)*100 = 50
    
    def test_calculate_percentage_score_zero(self, analyzer):
        """Test percentage with zero max score"""
        score = analyzer.calculate_percentage_score(0, 0)
        assert score == 0.0
    
    def test_get_grade_a(self, analyzer):
        """Test grade A"""
        assert analyzer.get_grade(95) == "A+"
        assert analyzer.get_grade(85) == "A"
        assert analyzer.get_grade(80) == "A-"
    
    def test_get_grade_b(self, analyzer):
        """Test grade B"""
        assert analyzer.get_grade(75) == "B+"
        assert analyzer.get_grade(70) == "B"
        assert analyzer.get_grade(65) == "B-"
    
    def test_get_grade_f(self, analyzer):
        """Test grade F"""
        assert analyzer.get_grade(30) == "F"
        assert analyzer.get_grade(0) == "F"
    
    def test_get_risk_level(self, analyzer):
        """Test risk level assignment"""
        assert analyzer.get_risk_level(95) == "excellent"
        assert analyzer.get_risk_level(80) == "good"
        assert analyzer.get_risk_level(60) == "medium"
        assert analyzer.get_risk_level(30) == "low"
        assert analyzer.get_risk_level(10) == "critical"


class TestReporter:
    """Test cases for ReportGenerator"""
    
    @pytest.fixture
    def sample_result(self):
        """Create a sample scan result"""
        return ScanResult(
            id="test123",
            url="https://example.com",
            timestamp="2024-01-15 10:30:00",
            scan_duration_ms=150.5,
            http_status_code=200,
            final_url="https://example.com",
            headers_found={"content-type": "text/html"},
            header_results=[
                HeaderResult(
                    header_name="strict-transport-security",
                    display_name="Strict-Transport-Security",
                    status=HeaderStatus.PRESENT,
                    value="max-age=31536000",
                    score=15,
                    weight=15,
                    description="Forces HTTPS connections",
                    remediation=None,
                ),
                HeaderResult(
                    header_name="x-frame-options",
                    display_name="X-Frame-Options",
                    status=HeaderStatus.MISSING,
                    value=None,
                    score=-15,
                    weight=15,
                    description="Prevents clickjacking",
                    remediation=None,
                ),
            ],
            total_score=0,
            max_score=30,
            percentage_score=50.0,
            grade="C",
            risk_level="medium",
            summary={"total": 2, "present": 1, "weak": 0, "misconfigured": 0, "missing": 1},
        )
    
    @pytest.fixture
    def reporter(self):
        """Create reporter instance"""
        return ReportGenerator()
    
    def test_generate_text_report(self, reporter, sample_result):
        """Test text report generation"""
        report = reporter.generate(sample_result, "text")
        assert "example.com" in report
        assert "50.0%" in report
        assert "C" in report
    
    def test_generate_json_report(self, reporter, sample_result):
        """Test JSON report generation"""
        report = reporter.generate(sample_result, "json")
        data = json.loads(report)
        assert data["url"] == "https://example.com"
        assert data["score"]["percentage"] == 50.0
    
    def test_generate_html_report(self, reporter, sample_result):
        """Test HTML report generation"""
        report = reporter.generate(sample_result, "html")
        assert "example.com" in report
        assert "50.0%" in report
    
    def test_generate_csv_report(self, reporter, sample_result):
        """Test CSV report generation"""
        report = reporter.generate(sample_result, "csv")
        lines = report.split("\n")
        assert "Header,Status,Score" in lines[0]
        assert "Strict-Transport-Security" in report
    
    def test_generate_markdown_report(self, reporter, sample_result):
        """Test Markdown report generation"""
        report = reporter.generate(sample_result, "markdown")
        assert "Security Headers Scan Report" in report
        assert "example.com" in report


class TestScanResult:
    """Test cases for ScanResult"""
    
    def test_to_dict(self):
        """Test converting ScanResult to dictionary"""
        result = ScanResult(
            id="test123",
            url="https://example.com",
            timestamp="2024-01-15 10:30:00",
            scan_duration_ms=100.0,
            http_status_code=200,
            final_url="https://example.com",
            headers_found={},
            header_results=[],
            total_score=50,
            max_score=100,
            percentage_score=75.0,
            grade="B",
            risk_level="good",
            summary={"total": 0, "present": 0, "weak": 0, "misconfigured": 0, "missing": 0},
        )
        
        data = result.to_dict()
        assert data["id"] == "test123"
        assert data["url"] == "https://example.com"
        assert data["score"]["percentage"] == 75.0
        assert data["score"]["grade"] == "B"
    
    def test_from_dict(self):
        """Test creating ScanResult from dictionary"""
        data = {
            "id": "test123",
            "url": "https://example.com",
            "timestamp": "2024-01-15 10:30:00",
            "scan_duration_ms": 100.0,
            "http_status_code": 200,
            "final_url": "https://example.com",
            "headers_found": {},
            "header_results": [],
            "score": {
                "total": 50,
                "max": 100,
                "percentage": 75.0,
                "grade": "B",
            },
            "risk_level": "good",
            "summary": {"total": 0, "present": 0, "weak": 0, "misconfigured": 0, "missing": 0},
        }
        
        result = ScanResult.from_dict(data)
        assert result.id == "test123"
        assert result.url == "https://example.com"
        assert result.percentage_score == 75.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
