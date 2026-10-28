"""Risk scoring for KASA security findings."""

from __future__ import annotations

from typing import ClassVar

from kasa.models.finding import Finding, Severity
from kasa.models.risk import RiskAssessment, RiskRating


class RiskScorer:
    """Calculate a deterministic overall risk assessment."""

    _SEVERITY_POINTS: ClassVar[dict[Severity, int]] = {
        Severity.INFO: 0,
        Severity.LOW: 5,
        Severity.MEDIUM: 15,
        Severity.HIGH: 30,
        Severity.CRITICAL: 50,
    }

    def assess(self, findings: list[Finding]) -> RiskAssessment:
        """Calculate risk from security findings."""
        score = sum(self._SEVERITY_POINTS[finding.severity] for finding in findings)

        return RiskAssessment(
            score=score,
            rating=self._rating_for_score(score),
            finding_count=len(findings),
        )

    @staticmethod
    def _rating_for_score(score: int) -> RiskRating:
        """Map a numeric score to an overall risk rating."""
        if score >= 50:
            return RiskRating.CRITICAL
        if score >= 30:
            return RiskRating.HIGH
        if score >= 15:
            return RiskRating.MEDIUM
        return RiskRating.LOW
