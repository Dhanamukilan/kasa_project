"""Kernel configuration security analyzer."""

from __future__ import annotations

from kasa.analyzers.base import Analyzer
from kasa.models.finding import Finding, FindingEvidence, Severity
from kasa.models.snapshot import SystemSnapshot


class KernelConfigAnalyzer(Analyzer):
    """Analyze security-relevant kernel configuration options."""

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Analyze kernel hardening configuration."""
        findings: list[Finding] = []

        config = self._get_config(snapshot)

        self._check_option(
            findings,
            config,
            "CONFIG_RANDOMIZE_BASE",
            "KASLR is disabled",
            "Kernel address space layout randomization is not enabled.",
            "kernel-hardening",
            Severity.MEDIUM,
            "Consider enabling CONFIG_RANDOMIZE_BASE.",
        )

        self._check_option(
            findings,
            config,
            "CONFIG_STACKPROTECTOR",
            "Kernel stack protection is disabled",
            "Kernel stack protector support is not enabled.",
            "kernel-hardening",
            Severity.MEDIUM,
            "Consider enabling an appropriate kernel stack protector.",
        )

        self._check_option(
            findings,
            config,
            "CONFIG_STRICT_KERNEL_RWX",
            "Strict kernel memory permissions are disabled",
            "Strict kernel RWX permissions are not enabled.",
            "kernel-hardening",
            Severity.MEDIUM,
            "Consider enabling CONFIG_STRICT_KERNEL_RWX.",
        )

        self._check_option(
            findings,
            config,
            "CONFIG_STRICT_MODULE_RWX",
            "Strict module memory permissions are disabled",
            "Strict RWX permissions for kernel modules are not enabled.",
            "kernel-hardening",
            Severity.MEDIUM,
            "Consider enabling CONFIG_STRICT_MODULE_RWX.",
        )

        return findings

    @staticmethod
    def _get_config(snapshot: SystemSnapshot) -> dict[str, str]:
        """Extract kernel configuration options from collected evidence."""
        for item in snapshot.kernel_config:
            if item.key != "kernel.config":
                continue

            if not isinstance(item.value, dict):
                continue

            options = item.value.get("options")

            if isinstance(options, dict):
                return {str(key): str(value) for key, value in options.items()}

        return {}

    @staticmethod
    def _check_option(
        findings: list[Finding],
        config: dict[str, str],
        option: str,
        title: str,
        description: str,
        category: str,
        severity: Severity,
        recommendation: str,
    ) -> None:
        """Create a finding when a security option is disabled."""
        value = config.get(option)

        if value not in {"n", "0"}:
            return

        findings.append(
            Finding(
                id=f"KASA-CONFIG-{option.removeprefix('CONFIG_')}",
                title=title,
                description=description,
                severity=severity,
                category=category,
                evidence_keys=["kernel.config"],
                evidence=[
                    FindingEvidence(
                        key="kernel.config",
                        value={
                            "option": option,
                            "value": value,
                        },
                    )
                ],
                recommendation=recommendation,
            )
        )
