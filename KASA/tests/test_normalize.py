"""Tests for KASA finding normalization."""

from kasa.analyzers.normalize import FindingNormalizer
from kasa.models.finding import Finding, Severity


def make_finding(
    finding_id: str,
    severity: Severity = Severity.LOW,
) -> Finding:
    """Create a test finding."""
    return Finding(
        id=finding_id,
        title=f"Finding {finding_id}",
        description="Test finding",
        severity=severity,
        category="test",
    )


def test_empty_findings_return_empty_list() -> None:
    result = FindingNormalizer().normalize([])

    assert result == []


def test_findings_are_sorted_by_id() -> None:
    findings = [
        make_finding("TEST-003"),
        make_finding("TEST-001"),
        make_finding("TEST-002"),
    ]

    result = FindingNormalizer().normalize(findings)

    assert [finding.id for finding in result] == [
        "TEST-001",
        "TEST-002",
        "TEST-003",
    ]


def test_duplicate_ids_are_removed() -> None:
    findings = [
        make_finding("TEST-001"),
        make_finding("TEST-001"),
        make_finding("TEST-002"),
    ]

    result = FindingNormalizer().normalize(findings)

    assert [finding.id for finding in result] == [
        "TEST-001",
        "TEST-002",
    ]


def test_first_duplicate_is_replaced_by_latest() -> None:
    findings = [
        make_finding("TEST-001", Severity.LOW),
        make_finding("TEST-001", Severity.HIGH),
    ]

    result = FindingNormalizer().normalize(findings)

    assert len(result) == 1
    assert result[0].severity == Severity.HIGH
