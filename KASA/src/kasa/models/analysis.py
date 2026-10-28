"""Structured security analysis results."""

from __future__ import annotations

from collections import Counter

from pydantic import BaseModel, ConfigDict, Field

from kasa.models.finding import Finding, Severity


class AnalysisResult(BaseModel):
    """Complete result produced by KASA security analyzers."""

    model_config = ConfigDict(extra="forbid")

    findings: list[Finding] = Field(default_factory=list)

    @property
    def total(self) -> int:
        """Return the total number of findings."""
        return len(self.findings)

    @property
    def severity_counts(self) -> dict[str, int]:
        """Return finding counts grouped by severity."""
        counts = Counter(finding.severity.value for finding in self.findings)
        return {severity.value: counts.get(severity.value, 0) for severity in Severity}
