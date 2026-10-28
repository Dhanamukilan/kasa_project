"""Kernel security analyzer."""

from __future__ import annotations

from kasa.analyzers.base import Analyzer
from kasa.models.finding import Finding, FindingEvidence, Severity
from kasa.models.snapshot import SystemSnapshot


class KernelAnalyzer(Analyzer):
    """Analyze security-relevant kernel runtime state."""

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Analyze kernel security controls."""
        findings: list[Finding] = []

        self._check_lockdown(findings, snapshot)

        return findings

    @staticmethod
    def _check_lockdown(
        findings: list[Finding],
        snapshot: SystemSnapshot,
    ) -> None:
        """Check the actual runtime kernel lockdown state."""
        lockdown = next(
            (
                item
                for item in snapshot.kernel.evidence
                if item.key == "kernel.lockdown"
            ),
            None,
        )

        if lockdown is None:
            return

        if lockdown.status.value != "available":
            return

        if not isinstance(lockdown.value, dict):
            return

        mode = lockdown.value.get("active_mode")

        if mode != "none":
            return

        command_line = snapshot.kernel.command_line or ""

        findings.append(
            Finding(
                id="KASA-KERNEL-001",
                title="Kernel lockdown is not enabled",
                description=("The running kernel reports lockdown mode as none."),
                severity=Severity.LOW,
                category="kernel-hardening",
                evidence_keys=[
                    "kernel.lockdown",
                    "kernel.command_line",
                ],
                evidence=[
                    FindingEvidence(
                        key="kernel.lockdown",
                        value={
                            "raw": lockdown.value.get("raw"),
                            "mode": mode,
                        },
                    ),
                    FindingEvidence(
                        key="kernel.command_line",
                        value={
                            "command_line": command_line,
                        },
                    ),
                ],
                recommendation=(
                    "Evaluate whether kernel lockdown should be enabled "
                    "for this system."
                ),
            )
        )
