"""Tests for KASA risk scoring."""

from kasa.analyzers.risk import RiskScorer
from kasa.models.finding import Finding, Severity
from kasa.models.risk import RiskRating


def make_finding(severity: Severity) -> Finding:
    """Create a test finding."""
    return Finding(
        id="TEST-001",
        title="Test finding",
        description="Test finding",
        severity=severity,
        category="test",
    )


def test_empty_findings_have_zero_score() -> None:
    result = RiskScorer().assess([])

    assert result.score == 0
    assert result.rating == RiskRating.LOW
    assert result.finding_count == 0


def test_low_findings_produce_low_risk() -> None:
    findings = [
        make_finding(Severity.LOW),
        make_finding(Severity.LOW),
    ]

    result = RiskScorer().assess(findings)

    assert result.score == 10
    assert result.rating == RiskRating.LOW


def test_medium_finding_produces_medium_risk() -> None:
    result = RiskScorer().assess([make_finding(Severity.MEDIUM)])

    assert result.score == 15
    assert result.rating == RiskRating.MEDIUM


def test_high_finding_produces_high_risk() -> None:
    result = RiskScorer().assess([make_finding(Severity.HIGH)])

    assert result.score == 30
    assert result.rating == RiskRating.HIGH


def test_critical_finding_produces_critical_risk() -> None:
    result = RiskScorer().assess([make_finding(Severity.CRITICAL)])

    assert result.score == 50
    assert result.rating == RiskRating.CRITICAL
