"""
Header Analyzer
~~~~~~~~~~~~~~~~

Analysis and scoring utilities for security headers.
"""

import math
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

from .headers import HeaderStatus, Severity


@dataclass
class RiskAssessment:
    """Complete risk assessment for a scan"""
    overall_risk: str
    risk_score: int
    risk_factors: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]
    compliance_status: Dict[str, bool]


class HeaderAnalyzer:
    """
    Analyzer for security header scan results.
    
    Provides scoring, grading, risk assessment, and recommendations.
    """
    
    # Grade thresholds
    GRADE_THRESHOLDS = {
        "A+": 95,
        "A": 85,
        "A-": 80,
        "B+": 75,
        "B": 70,
        "B-": 65,
        "C+": 60,
        "C": 55,
        "C-": 50,
        "D": 40,
        "F": 0,
    }
    
    # Higher security scores mean lower operational risk.
    RISK_THRESHOLDS = {
        "low": 75,
        "medium": 50,
        "high": 25,
        "critical": 0,
    }
    
    # Compliance standards
    COMPLIANCE_STANDARDS = {
        "pci-dss": ["strict-transport-security", "x-content-type-options"],
        "hipaa": ["strict-transport-security", "x-content-type-options", "cache-control"],
        "owasp": [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
        ],
        "gdpr": ["strict-transport-security", "cache-control", "referrer-policy"],
    }
    
    def __init__(self, risk_thresholds: Optional[Dict[str, float]] = None):
        thresholds = dict(self.RISK_THRESHOLDS if risk_thresholds is None else risk_thresholds)
        levels = ("critical", "high", "medium", "low")
        if not set(levels).issubset(thresholds):
            raise ValueError("risk_thresholds must define critical, high, medium, and low")
        values = [thresholds[level] for level in levels]
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
            or not 0 <= value <= 100
            for value in values
        ) or values != sorted(values):
            raise ValueError("risk thresholds must be ordered numbers between 0 and 100")
        self.risk_thresholds = {level: thresholds[level] for level in levels}
    
    def calculate_percentage_score(self, total_score: int, max_score: int) -> float:
        """
        Calculate percentage score from raw scores.
        
        Args:
            total_score: Total score obtained
            max_score: Maximum possible score
            
        Returns:
            Percentage score (0-100)
        """
        if max_score == 0:
            return 0.0
        
        # Contributions range from -weight (missing) to +weight (present).
        # Map [-100, +100] to [0, 100], then clamp the final score.
        raw_percentage = (total_score / max_score) * 100
        normalized = (raw_percentage + 100) / 2
        return max(0.0, min(100.0, normalized))
    
    def get_grade(self, percentage_score: float) -> str:
        """
        Get letter grade from percentage score.
        
        Args:
            percentage_score: Score as percentage (0-100)
            
        Returns:
            Letter grade (A+ to F)
        """
        for grade, threshold in sorted(
            self.GRADE_THRESHOLDS.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            if percentage_score >= threshold:
                return grade
        return "F"
    
    def get_risk_level(self, percentage_score: float) -> str:
        """
        Get risk level from percentage score.
        
        Args:
            percentage_score: Score as percentage (0-100)
            
        Returns:
            Risk level string
        """
        for level, threshold in sorted(
            self.risk_thresholds.items(),
            key=lambda x: x[1],
            reverse=True
        ):
            if percentage_score >= threshold:
                return level
        return "critical"
    
    def assess_risk(self, header_results: List[Any]) -> RiskAssessment:
        """
        Perform comprehensive risk assessment.
        
        Args:
            header_results: List of HeaderResult objects
            
        Returns:
            RiskAssessment with detailed analysis
        """
        risk_factors = []
        recommendations = []
        
        # Analyze each header
        for result in header_results:
            if result.status == HeaderStatus.MISSING:
                risk_factors.append({
                    "header": result.display_name,
                    "issue": "Header not present",
                    "severity": "high",
                    "impact": "Application vulnerable to related attacks",
                })
                
                recommendations.append({
                    "header": result.display_name,
                    "priority": "high",
                    "action": f"Add {result.display_name} header",
                    "reason": result.description,
                })
                
            elif result.status == HeaderStatus.MISCONFIGURED:
                risk_factors.append({
                    "header": result.display_name,
                    "issue": "Header misconfigured",
                    "severity": "medium",
                    "impact": "Header may not provide expected protection",
                })
                
                recommendations.append({
                    "header": result.display_name,
                    "priority": "medium",
                    "action": "Fix header configuration",
                    "reason": "Current configuration may be ineffective",
                })
                
            elif result.status == HeaderStatus.WEAK:
                risk_factors.append({
                    "header": result.display_name,
                    "issue": "Header has weak configuration",
                    "severity": "low",
                    "impact": "Reduced protection effectiveness",
                })
                
                recommendations.append({
                    "header": result.display_name,
                    "priority": "low",
                    "action": "Strengthen header configuration",
                    "reason": "Consider more restrictive settings",
                })
        
        # Calculate overall risk score
        risk_score = 100 - (len([r for r in header_results if r.status != HeaderStatus.PRESENT]) * 10)
        risk_score = max(0, min(100, risk_score))
        
        # Determine overall risk level
        overall_risk = self.get_risk_level(
            sum(r.score for r in header_results if r.status == HeaderStatus.PRESENT) /
            max(1, sum(r.weight for r in header_results)) * 100
        )
        
        return RiskAssessment(
            overall_risk=overall_risk,
            risk_score=risk_score,
            risk_factors=risk_factors,
            recommendations=recommendations,
            compliance_status={},
        )
    
    def check_compliance(self, header_results: List[Any]) -> Dict[str, bool]:
        """
        Check compliance against various standards.
        
        Args:
            header_results: List of HeaderResult objects
            
        Returns:
            Dictionary of compliance status per standard
        """
        compliance = {}
        
        for standard, required_headers in self.COMPLIANCE_STANDARDS.items():
            compliance[standard] = all(
                any(
                    r.header_name == h and r.status == HeaderStatus.PRESENT
                    for r in header_results
                )
                for h in required_headers
            )
        
        return compliance
    
    def generate_summary(self, header_results: List[Any]) -> Dict[str, Any]:
        """
        Generate executive summary of scan results.
        
        Args:
            header_results: List of HeaderResult objects
            
        Returns:
            Summary dictionary
        """
        summary = {
            "total_headers_checked": len(header_results),
            "headers_passed": len([r for r in header_results if r.status == HeaderStatus.PRESENT]),
            "headers_warning": len([r for r in header_results if r.status == HeaderStatus.WEAK]),
            "headers_failed": len([r for r in header_results if r.status in [HeaderStatus.MISSING, HeaderStatus.MISCONFIGURED]]),
            "pass_rate": 0.0,
            "top_issues": [],
            "quick_wins": [],
        }
        
        if summary["total_headers_checked"] > 0:
            summary["pass_rate"] = round(
                summary["headers_passed"] / summary["total_headers_checked"] * 100,
                1
            )
        
        # Identify top issues (missing and misconfigured)
        for result in sorted(
            header_results,
            key=lambda r: (r.status.value == "missing", r.weight),
            reverse=True
        )[:5]:
            if result.status != HeaderStatus.PRESENT:
                summary["top_issues"].append({
                    "header": result.display_name,
                    "status": result.status.value,
                    "weight": result.weight,
                })
        
        # Quick wins (high-weight issues that are easy to fix)
        for result in header_results:
            if result.status != HeaderStatus.PRESENT and result.weight >= 15:
                summary["quick_wins"].append({
                    "header": result.display_name,
                    "status": result.status.value,
                    "weight": result.weight,
                })
        
        return summary
    
    def compare_to_benchmark(self, percentage_score: float) -> Dict[str, Any]:
        """
        Compare score to industry benchmarks.
        
        Args:
            percentage_score: Score to compare
            
        Returns:
            Comparison dictionary
        """
        benchmarks = {
            "google": 85,
            "apple": 90,
            "microsoft": 80,
            "github": 75,
            "cloudflare": 95,
            "owasp_recommended": 85,
        }
        
        comparison = {}
        for name, benchmark in benchmarks.items():
            diff = percentage_score - benchmark
            if diff >= 10:
                status = "significantly_above"
            elif diff >= 0:
                status = "above"
            elif diff >= -10:
                status = "below"
            else:
                status = "significantly_below"
            
            comparison[name] = {
                "benchmark": benchmark,
                "difference": round(diff, 1),
                "status": status,
            }
        
        return comparison
