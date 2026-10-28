"""Filesystem security analyzer."""

from __future__ import annotations

from kasa.analyzers.base import Analyzer
from kasa.models.finding import Finding, FindingEvidence, Severity
from kasa.models.snapshot import SystemSnapshot

TMP_MOUNT_POINT = "/tmp"  # noqa: S108


class FilesystemAnalyzer(Analyzer):
    """Analyze filesystem mount security."""

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Analyze filesystem mounts for security issues."""
        findings: list[Finding] = []

        for mount in snapshot.filesystems.mounts:
            mount_point = mount.mount_point
            options = mount.options

            if mount_point != TMP_MOUNT_POINT:
                continue

            if "noexec" in options:
                continue

            findings.append(
                Finding(
                    id="KASA-FS-001",
                    title="Temporary directory is executable",
                    description=(
                        "The /tmp filesystem is mounted without the noexec option."
                    ),
                    severity=Severity.LOW,
                    category="filesystem-hardening",
                    evidence_keys=["filesystem.mounts"],
                    evidence=[
                        FindingEvidence(
                            key="filesystem.mount",
                            value=mount.model_dump(mode="json"),
                        )
                    ],
                    recommendation=(
                        "Consider mounting /tmp with noexec where "
                        "compatible with system requirements."
                    ),
                )
            )

        return findings
