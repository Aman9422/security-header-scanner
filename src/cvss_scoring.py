"""
CVSS Scoring Engine
~~~~~~~~~~~~~~~~~~

Calculates CVSS (Common Vulnerability Scoring System) scores.
Reference: https://www.first.org/cvss/
"""

from dataclasses import dataclass
from decimal import Decimal, ROUND_CEILING
from typing import Dict, List, Optional, Any
from enum import Enum


class Severity(Enum):
    """CVSS Severity levels"""
    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class AttackVector(Enum):
    """Network accessibility of exploit"""
    NETWORK = "N"      # Remotely exploitable
    ADJACENT = "A"    # Adjacent network
    LOCAL = "L"        # Local access required
    PHYSICAL = "P"     # Physical access required


class AttackComplexity(Enum):
    """Conditions beyond attacker control"""
    LOW = "L"          # No special conditions
    HIGH = "H"         # Requires special conditions


class PrivilegesRequired(Enum):
    """Level of privileges needed"""
    NONE = "N"         # No privileges
    LOW = "L"          # Some privileges
    HIGH = "H"         # Full control


class UserInteraction(Enum):
    """Whether user interaction required"""
    NONE = "N"         # No user interaction
    REQUIRED = "R"     # User must interact


class Scope(Enum):
    """Whether vulnerable component is same as impacted"""
    UNCHANGED = "U"    # Same scope
    CHANGED = "C"      # Scope changed


class CIA(Enum):
    """Confidentiality, Integrity, Availability impact"""
    HIGH = "H"
    LOW = "L"
    NONE = "N"


@dataclass
class CVSSScore:
    """Complete CVSS v3.1 score breakdown"""
    vector_string: str
    
    # Base Score Metrics
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality_impact: CIA
    integrity_impact: CIA
    availability_impact: CIA
    
    # Calculated Scores
    base_score: float
    temporal_score: Optional[float]
    environmental_score: Optional[float]
    
    # Ratings
    base_severity: Severity
    temporal_severity: Optional[Severity]
    environmental_severity: Optional[Severity]
    
    # Detailed breakdown
    impact_score: float
    exploitability_score: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector_string": self.vector_string,
            "base_score": round(self.base_score, 1),
            "temporal_score": round(self.temporal_score, 1) if self.temporal_score is not None else None,
            "environmental_score": round(self.environmental_score, 1) if self.environmental_score is not None else None,
            "base_severity": self.base_severity.value,
            "impact_score": round(self.impact_score, 2),
            "exploitability_score": round(self.exploitability_score, 2),
        }


@dataclass
class Vulnerability:
    """Represents a security vulnerability"""
    id: str
    title: str
    description: str
    affected_component: str
    cvss_score: Optional[CVSSScore]
    cwe_id: Optional[str]
    remediation: str
    references: List[str]
    is_critical: bool
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "affected_component": self.affected_component,
            "cvss": self.cvss_score.to_dict() if self.cvss_score else None,
            "cwe_id": self.cwe_id,
            "remediation": self.remediation,
            "is_critical": self.is_critical,
        }


class CVSSCalculator:
    """
    CVSS v3.1 Calculator.
    
    Usage:
        calc = CVSSCalculator()
        
        # Calculate from vector string
        score = calc.calculate_from_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        
        # Or calculate manually
        score = calc.calculate(
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
            scope=Scope.UNCHANGED,
            confidentiality_impact=CIA.HIGH,
            integrity_impact=CIA.HIGH,
            availability_impact=CIA.HIGH,
        )
    """
    
    # Weight tables for CVSS 3.1
    AV_WEIGHTS = {
        AttackVector.NETWORK: 0.85,
        AttackVector.ADJACENT: 0.62,
        AttackVector.LOCAL: 0.55,
        AttackVector.PHYSICAL: 0.20,
    }
    
    AC_WEIGHTS = {
        AttackComplexity.LOW: 0.77,
        AttackComplexity.HIGH: 0.44,
    }
    
    PR_WEIGHTS_SCOPE_UNCHANGED = {
        PrivilegesRequired.NONE: 0.85,
        PrivilegesRequired.LOW: 0.62,
        PrivilegesRequired.HIGH: 0.27,
    }
    
    PR_WEIGHTS_SCOPE_CHANGED = {
        PrivilegesRequired.NONE: 0.85,
        PrivilegesRequired.LOW: 0.68,
        PrivilegesRequired.HIGH: 0.50,
    }
    
    UI_WEIGHTS = {
        UserInteraction.NONE: 0.85,
        UserInteraction.REQUIRED: 0.62,
    }
    
    CIA_WEIGHTS = {
        CIA.NONE: 0,
        CIA.LOW: 0.22,
        CIA.HIGH: 0.56,
    }
    
    def __init__(self):
        self.vector_prefix = "CVSS:3.1/"
    
    def calculate(
        self,
        attack_vector: AttackVector,
        attack_complexity: AttackComplexity,
        privileges_required: PrivilegesRequired,
        user_interaction: UserInteraction,
        scope: Scope,
        confidentiality_impact: CIA,
        integrity_impact: CIA,
        availability_impact: CIA,
    ) -> CVSSScore:
        """
        Calculate CVSS score from individual metrics.
        
        Returns:
            CVSSScore with calculated values
        """
        # Build vector string
        vector = self._build_vector(
            attack_vector, attack_complexity, privileges_required,
            user_interaction, scope, confidentiality_impact,
            integrity_impact, availability_impact
        )
        
        # Calculate impact score
        impact = self._calculate_impact(
            scope, confidentiality_impact, integrity_impact, availability_impact
        )
        
        # Calculate exploitability
        exploitability = self._calculate_exploitability(
            attack_vector, attack_complexity, privileges_required,
            user_interaction, scope
        )
        
        # CVSS v3.1 base score formula and mandated round-up to one decimal.
        if impact <= 0:
            base_score = 0.0
        elif scope == Scope.UNCHANGED:
            base_score = self._roundup(min(impact + exploitability, 10.0))
        else:
            base_score = self._roundup(min(1.08 * (impact + exploitability), 10.0))

        # Temporal/environmental metrics are not supplied by the base vector.
        temporal_score = None
        environmental_score = None
        
        # Get severities
        base_severity = self._get_severity(base_score)
        
        return CVSSScore(
            vector_string=vector,
            attack_vector=attack_vector,
            attack_complexity=attack_complexity,
            privileges_required=privileges_required,
            user_interaction=user_interaction,
            scope=scope,
            confidentiality_impact=confidentiality_impact,
            integrity_impact=integrity_impact,
            availability_impact=availability_impact,
            base_score=base_score,
            temporal_score=temporal_score,
            environmental_score=environmental_score,
            base_severity=base_severity,
            temporal_severity=None,
            environmental_severity=None,
            impact_score=round(impact, 2),
            exploitability_score=round(exploitability, 2),
        )
    
    def calculate_from_vector(self, vector_string: str) -> CVSSScore:
        """
        Calculate CVSS score from vector string.
        
        Example vector:
        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        """
        # Parse vector
        metrics = self._parse_vector(vector_string)
        
        # Convert to enums
        av = AttackVector(metrics.get("AV", "N"))
        ac = AttackComplexity(metrics.get("AC", "L"))
        pr = PrivilegesRequired(metrics.get("PR", "N"))
        ui = UserInteraction(metrics.get("UI", "N"))
        s = Scope(metrics.get("S", "U"))
        c = CIA(metrics.get("C", "N"))
        i = CIA(metrics.get("I", "N"))
        a = CIA(metrics.get("A", "N"))
        
        return self.calculate(av, ac, pr, ui, s, c, i, a)
    
    def _build_vector(
        self,
        av: AttackVector,
        ac: AttackComplexity,
        pr: PrivilegesRequired,
        ui: UserInteraction,
        s: Scope,
        c: CIA,
        i: CIA,
        a: CIA,
    ) -> str:
        """Build CVSS vector string"""
        return (
            f"{self.vector_prefix}"
            f"AV:{av.value}/"
            f"AC:{ac.value}/"
            f"PR:{pr.value}/"
            f"UI:{ui.value}/"
            f"S:{s.value}/"
            f"C:{c.value}/"
            f"I:{i.value}/"
            f"A:{a.value}"
        )
    
    def _parse_vector(self, vector: str) -> Dict[str, str]:
        """Parse and strictly validate a complete CVSS v3.1 base vector."""
        if not isinstance(vector, str) or len(vector) > 256 or not vector.startswith("CVSS:3.1/"):
            raise ValueError("Only complete CVSS:3.1 base vectors up to 256 characters are supported")

        required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        metrics: Dict[str, str] = {}
        for part in vector[len("CVSS:3.1/"):].split("/"):
            if part.count(":") != 1:
                raise ValueError(f"Invalid CVSS metric: {part!r}")
            key, value = part.split(":", 1)
            if key in metrics:
                raise ValueError(f"Duplicate CVSS metric: {key}")
            metrics[key] = value

        missing = required - metrics.keys()
        unsupported = metrics.keys() - required
        if missing:
            raise ValueError(f"Missing required CVSS metrics: {', '.join(sorted(missing))}")
        if unsupported:
            raise ValueError(f"Unsupported CVSS metrics: {', '.join(sorted(unsupported))}")
        return metrics
    
    def _calculate_impact(
        self,
        scope: Scope,
        c: CIA,
        i: CIA,
        a: CIA,
    ) -> float:
        """Calculate impact subscore"""
        c_val = self.CIA_WEIGHTS[c]
        i_val = self.CIA_WEIGHTS[i]
        a_val = self.CIA_WEIGHTS[a]
        
        iss = 1 - ((1 - c_val) * (1 - i_val) * (1 - a_val))
        if scope == Scope.UNCHANGED:
            return 6.42 * iss
        return 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    @staticmethod
    def _roundup(score: float) -> float:
        """Apply CVSS v3.1's round-up rule to one decimal place."""
        return float(Decimal(str(score)).quantize(Decimal("0.1"), rounding=ROUND_CEILING))
    
    def _calculate_exploitability(
        self,
        av: AttackVector,
        ac: AttackComplexity,
        pr: PrivilegesRequired,
        ui: UserInteraction,
        s: Scope,
    ) -> float:
        """Calculate exploitability subscore"""
        av_val = self.AV_WEIGHTS[av]
        ac_val = self.AC_WEIGHTS[ac]
        
        if s == Scope.UNCHANGED:
            pr_val = self.PR_WEIGHTS_SCOPE_UNCHANGED[pr]
        else:
            pr_val = self.PR_WEIGHTS_SCOPE_CHANGED[pr]
        
        ui_val = self.UI_WEIGHTS[ui]
        
        exploitability = (
            8.22 * av_val * ac_val * pr_val * ui_val
        )
        
        return exploitability
    
    def _get_severity(self, score: float) -> Severity:
        """Get severity rating from score"""
        if score == 0:
            return Severity.NONE
        elif score < 4.0:
            return Severity.LOW
        elif score < 7.0:
            return Severity.MEDIUM
        elif score < 9.0:
            return Severity.HIGH
        else:
            return Severity.CRITICAL


def quick_cvss_score(
    attack_vector: str = "N",
    attack_complexity: str = "L",
    privileges_required: str = "N",
    user_interaction: str = "N",
    scope: str = "U",
    confidentiality: str = "H",
    integrity: str = "H",
    availability: str = "H",
) -> float:
    """
    Quick CVSS score calculation.
    
    Args:
        attack_vector: N (Network), A (Adjacent), L (Local), P (Physical)
        attack_complexity: L (Low), H (High)
        privileges_required: N (None), L (Low), H (High)
        user_interaction: N (None), R (Required)
        scope: U (Unchanged), C (Changed)
        confidentiality: N (None), L (Low), H (High)
        integrity: N (None), L (Low), H (High)
        availability: N (None), L (Low), H (High)
    
    Returns:
        CVSS base score (0.0 - 10.0)
    """
    calc = CVSSCalculator()
    
    av = AttackVector(attack_vector)
    ac = AttackComplexity(attack_complexity)
    pr = PrivilegesRequired(privileges_required)
    ui = UserInteraction(user_interaction)
    s = Scope(scope)
    c = CIA(confidentiality)
    i = CIA(integrity)
    a = CIA(availability)
    
    result = calc.calculate(av, ac, pr, ui, s, c, i, a)
    return result.base_score
