"""Tests for kernel module security analysis."""

from kasa.analyzers.modules import ModuleAnalyzer
from kasa.collectors.modules import KernelModule, ModuleInventory, ModuleState
from kasa.models.evidence import (
    EvidenceItem,
    EvidenceSource,
    KernelInfo,
    KernelSnapshot,
)
from kasa.models.snapshot import SystemSnapshot


def make_snapshot(
    config: dict[str, str],
    command_line: str = "",
) -> SystemSnapshot:
    """Create a minimal system snapshot for module tests."""
    return SystemSnapshot(
        kernel=KernelSnapshot(
            kernel=KernelInfo(
                release="test",
                version="test",
                machine="x86_64",
                node="test",
                system="Linux",
                processor="test",
            ),
            command_line=command_line,
            evidence=[],
        ),
        kernel_config=[
            EvidenceItem(
                key="kernel.config",
                value={"options": config},
                status="available",
                source=EvidenceSource(
                    path="/boot/config-test",
                    description="Test kernel configuration.",
                ),
            )
        ],
        modules=ModuleInventory(
            loaded=[
                KernelModule(
                    name="test_module",
                    state=ModuleState.LOADED,
                    size=123,
                    reference_count=0,
                    dependencies=[],
                    source="/proc/modules",
                )
            ]
        ),
        filesystems={},
    )


def test_module_signing_enforcement_enabled_by_config() -> None:
    snapshot = make_snapshot(
        {
            "CONFIG_MODULE_SIG": "y",
            "CONFIG_MODULE_SIG_FORCE": "y",
        }
    )

    findings = ModuleAnalyzer().analyze(snapshot)

    assert not any(finding.id == "KASA-MODULE-002" for finding in findings)


def test_module_signing_enforcement_enabled_by_command_line() -> None:
    snapshot = make_snapshot(
        {
            "CONFIG_MODULE_SIG": "y",
            "CONFIG_MODULE_SIG_FORCE": "n",
        },
        command_line="quiet module.sig_enforce=1",
    )

    findings = ModuleAnalyzer().analyze(snapshot)

    assert not any(finding.id == "KASA-MODULE-002" for finding in findings)


def test_module_signing_enforcement_disabled_creates_finding() -> None:
    snapshot = make_snapshot(
        {
            "CONFIG_MODULE_SIG": "y",
            "CONFIG_MODULE_SIG_FORCE": "n",
        }
    )

    findings = ModuleAnalyzer().analyze(snapshot)

    finding = next(finding for finding in findings if finding.id == "KASA-MODULE-002")

    assert finding.severity.value == "medium"
    assert finding.evidence[0].key == "module.signing"
    assert finding.evidence[0].value["config_module_sig"] == "y"
    assert finding.evidence[0].value["config_module_sig_force"] == "n"
    assert finding.evidence[0].value["module_sig_enforce"] is False


def test_module_inventory_has_structured_evidence() -> None:
    snapshot = make_snapshot(
        {
            "CONFIG_MODULE_SIG": "y",
            "CONFIG_MODULE_SIG_FORCE": "y",
        }
    )

    findings = ModuleAnalyzer().analyze(snapshot)

    finding = next(finding for finding in findings if finding.id == "KASA-MODULE-001")

    assert finding.evidence[0].key == "module.inventory"
    assert finding.evidence[0].value["count"] == 1
    assert finding.evidence[0].value["modules"][0]["name"] == "test_module"


def test_missing_kernel_config_does_not_create_false_finding() -> None:
    snapshot = make_snapshot({})

    findings = ModuleAnalyzer().analyze(snapshot)

    assert not any(finding.id == "KASA-MODULE-002" for finding in findings)


def test_missing_module_sig_force_is_not_treated_as_enforced() -> None:
    snapshot = make_snapshot(
        {
            "CONFIG_MODULE_SIG": "y",
            "CONFIG_MODULE_SIG_ALL": "y",
        }
    )

    findings = ModuleAnalyzer().analyze(snapshot)

    finding = next(finding for finding in findings if finding.id == "KASA-MODULE-002")

    assert finding.severity.value == "medium"
    assert finding.evidence[0].value["config_module_sig"] == "y"
    assert finding.evidence[0].value["config_module_sig_force"] is None
    assert finding.evidence[0].value["module_sig_enforce"] is False


def test_modules_disabled_config_produces_no_signing_finding() -> None:
    snapshot = make_snapshot(
        {
            "CONFIG_MODULES": "n",
            "CONFIG_MODULE_SIG": "n",
        }
    )

    findings = ModuleAnalyzer().analyze(snapshot)

    assert not any(finding.id == "KASA-MODULE-002" for finding in findings)


def test_malformed_kernel_config_evidence_produces_no_finding() -> None:
    snapshot = SystemSnapshot(
        kernel=KernelSnapshot(
            kernel=KernelInfo(
                release="test",
                version="test",
                machine="x86_64",
                node="test",
                system="Linux",
                processor="test",
            ),
            evidence=[],
        ),
        kernel_config=[
            EvidenceItem(
                key="kernel.config",
                value="malformed-not-a-dict",
                status="available",
                source=EvidenceSource(
                    path="/boot/config-test",
                    description="Test",
                ),
            )
        ],
        modules=ModuleInventory(),
        filesystems={},
    )

    findings = ModuleAnalyzer().analyze(snapshot)

    assert not any(finding.id == "KASA-MODULE-002" for finding in findings)
