"""Kernel module security analyzer."""

from __future__ import annotations

from kasa.analyzers.base import Analyzer
from kasa.models.finding import Finding, FindingEvidence, Severity
from kasa.models.snapshot import SystemSnapshot


class ModuleAnalyzer(Analyzer):
    """Analyze kernel module exposure and signing enforcement."""

    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Analyze loaded kernel modules and module signing enforcement."""
        findings: list[Finding] = []

        loaded_modules = snapshot.modules.loaded

        if loaded_modules:
            findings.append(
                Finding(
                    id="KASA-MODULE-001",
                    title="Loadable kernel modules are active",
                    description=(
                        f"{len(loaded_modules)} kernel modules are currently loaded."
                    ),
                    severity=Severity.INFO,
                    category="kernel-modules",
                    evidence_keys=["module.inventory"],
                    evidence=[
                        FindingEvidence(
                            key="module.inventory",
                            value={
                                "count": len(loaded_modules),
                                "modules": [
                                    module.model_dump(mode="json")
                                    for module in loaded_modules
                                ],
                            },
                        )
                    ],
                    recommendation=(
                        "Review loaded modules and disable unnecessary "
                        "kernel components where appropriate."
                    ),
                )
            )

        config = self._get_kernel_config(snapshot)

        if not config:
            return findings

        if config.get("CONFIG_MODULES") == "n":
            return findings

        module_sig = config.get("CONFIG_MODULE_SIG")
        module_sig_force = config.get("CONFIG_MODULE_SIG_FORCE")

        command_line = snapshot.kernel.command_line or ""
        module_sig_enforce = "module.sig_enforce=1" in command_line

        signing_enforced = module_sig_force == "y" or module_sig_enforce

        if not signing_enforced:
            findings.append(
                Finding(
                    id="KASA-MODULE-002",
                    title="Kernel module signature enforcement is disabled",
                    description=(
                        "The kernel does not enforce valid signatures for "
                        "loadable kernel modules."
                    ),
                    severity=Severity.MEDIUM,
                    category="kernel-modules",
                    evidence_keys=[
                        "kernel.config",
                        "kernel.command_line",
                    ],
                    evidence=[
                        FindingEvidence(
                            key="module.signing",
                            value={
                                "config_module_sig": module_sig,
                                "config_module_sig_force": module_sig_force,
                                "module_sig_enforce": module_sig_enforce,
                            },
                        )
                    ],
                    recommendation=(
                        "Consider enabling CONFIG_MODULE_SIG_FORCE or "
                        "module.sig_enforce=1 to require validly signed "
                        "kernel modules."
                    ),
                )
            )

        return findings

    @staticmethod
    def _get_kernel_config(snapshot: SystemSnapshot) -> dict[str, str]:
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
