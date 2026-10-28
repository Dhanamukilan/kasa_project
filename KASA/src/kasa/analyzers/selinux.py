"""SELinux runtime security analyzer."""

from __future__ import annotations

from kasa.analyzers.base import Analyzer
from kasa.models.finding import Finding, FindingEvidence, Severity
from kasa.models.snapshot import SystemSnapshot


class SELinuxAnalyzer(Analyzer):
    """Analyze the runtime SELinux enforcement state."""

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Analyze SELinux enforcement mode from collected kernel evidence."""
        findings: list[Finding] = []

        self._check_selinux_mode(findings, snapshot)

        return findings

    @staticmethod
    def _check_selinux_mode(
        findings: list[Finding],
        snapshot: SystemSnapshot,
    ) -> None:
        """Raise a finding when SELinux is present but not enforcing."""
        selinux = next(
            (item for item in snapshot.kernel.evidence if item.key == "kernel.selinux"),
            None,
        )

        if selinux is None:
            return

        if selinux.status.value != "available":
            return

        if not isinstance(selinux.value, dict):
            return

        mode = selinux.value.get("mode")

        if mode != "permissive":
            return

        findings.append(
            Finding(
                id="KASA-SELINUX-001",
                title="SELinux is not enforcing",
                description=(
                    "SELinux is loaded and active but is running in permissive "
                    "mode. Policy violations are logged but not denied."
                ),
                severity=Severity.MEDIUM,
                category="selinux",
                evidence_keys=["kernel.selinux"],
                evidence=[
                    FindingEvidence(
                        key="kernel.selinux",
                        value={
                            "mode": mode,
                            "policy_version": selinux.value.get("policy_version"),
                        },
                    )
                ],
                recommendation=(
                    "Set SELinux to enforcing mode so that policy violations are "
                    "actively denied rather than only logged. Run "
                    "'setenforce 1' for an immediate change and set "
                    "SELINUX=enforcing in /etc/selinux/config for persistence "
                    "across reboots."
                ),
            )
        )
