"""Tests for structured analysis results."""

from kasa.models.analysis import AnalysisResult
from kasa.models.finding import Finding, FindingEvidence, Severity


def test_empty_analysis_result() -> None:
    result = AnalysisResult()

    assert result.total == 0
    assert result.findings == []


def test_analysis_result_counts_severity() -> None:
    findings = [
        Finding(
            id="TEST-001",
            title="Low finding",
            description="Test",
            severity=Severity.LOW,
            category="test",
        ),
        Finding(
            id="TEST-002",
            title="Medium finding",
            description="Test",
            severity=Severity.MEDIUM,
            category="test",
        ),
        Finding(
            id="TEST-003",
            title="Another low finding",
            description="Test",
            severity=Severity.LOW,
            category="test",
        ),
    ]

    result = AnalysisResult(findings=findings)

    assert result.total == 3
    assert result.severity_counts["low"] == 2
    assert result.severity_counts["medium"] == 1
    assert result.severity_counts["high"] == 0


def test_finding_can_contain_structured_evidence() -> None:
    finding = Finding(
        id="TEST-001",
        title="Test finding",
        description="Test",
        severity=Severity.LOW,
        category="test",
        evidence_keys=["filesystem.mounts"],
        evidence=[
            FindingEvidence(
                key="filesystem.mount",
                value={
                    "mount_point": "/tmp",  # noqa: S108
                    "options": ["rw", "relatime"],
                },
            )
        ],
    )

    assert finding.evidence_keys == ["filesystem.mounts"]
    assert finding.evidence[0].key == "filesystem.mount"
    assert finding.evidence[0].value["mount_point"] == "/tmp"  # noqa: S108
