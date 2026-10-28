"""Finding normalization and deduplication for KASA."""

from __future__ import annotations

from kasa.models.finding import Finding


class FindingNormalizer:
    """Normalize and deduplicate security findings deterministically."""

    def normalize(self, findings: list[Finding]) -> list[Finding]:
        """Return unique findings in deterministic order."""
        unique: dict[str, Finding] = {}

        for finding in findings:
            unique[finding.id] = finding

        return sorted(
            unique.values(),
            key=lambda finding: finding.id,
        )
