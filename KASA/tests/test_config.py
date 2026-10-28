"""Tests for kernel configuration security analysis."""

from kasa.analyzers.config import KernelConfigAnalyzer
from kasa.collectors.filesystem import FilesystemInventory
from kasa.collectors.modules import ModuleInventory
from kasa.models.evidence import (
    EvidenceItem,
    EvidenceSource,
    EvidenceStatus,
    KernelInfo,
    KernelSnapshot,
)
from kasa.models.snapshot import SystemSnapshot


def make_snapshot(config: dict[str, str]) -> SystemSnapshot:
    """Create a minimal snapshot containing kernel configuration."""
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
            command_line="",
        ),
        kernel_config=[
            EvidenceItem(
                key="kernel.config",
                value={"options": config},
                status=EvidenceStatus.AVAILABLE,
                source=EvidenceSource(
                    path="/proc/config.gz",
                    description="Kernel configuration.",
                ),
            )
        ],
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
    )


def test_enabled_kernel_hardening_options_create_no_findings() -> None:
    snapshot = make_snapshot(
        {
            "CONFIG_RANDOMIZE_BASE": "y",
            "CONFIG_STACKPROTECTOR": "y",
            "CONFIG_STRICT_KERNEL_RWX": "y",
            "CONFIG_STRICT_MODULE_RWX": "y",
        }
    )

    findings = KernelConfigAnalyzer().analyze(snapshot)

    assert findings == []


def test_disabled_kernel_hardening_options_create_findings() -> None:
    snapshot = make_snapshot(
        {
            "CONFIG_RANDOMIZE_BASE": "n",
            "CONFIG_STACKPROTECTOR": "n",
            "CONFIG_STRICT_KERNEL_RWX": "n",
            "CONFIG_STRICT_MODULE_RWX": "n",
        }
    )

    findings = KernelConfigAnalyzer().analyze(snapshot)

    assert len(findings) == 4

    ids = {finding.id for finding in findings}

    assert ids == {
        "KASA-CONFIG-RANDOMIZE_BASE",
        "KASA-CONFIG-STACKPROTECTOR",
        "KASA-CONFIG-STRICT_KERNEL_RWX",
        "KASA-CONFIG-STRICT_MODULE_RWX",
    }


def test_disabled_option_contains_structured_evidence() -> None:
    snapshot = make_snapshot(
        {
            "CONFIG_RANDOMIZE_BASE": "n",
        }
    )

    findings = KernelConfigAnalyzer().analyze(snapshot)

    finding = findings[0]

    assert finding.id == "KASA-CONFIG-RANDOMIZE_BASE"
    assert finding.severity.value == "medium"
    assert finding.evidence_keys == ["kernel.config"]

    assert finding.evidence[0].key == "kernel.config"
    assert finding.evidence[0].value == {
        "option": "CONFIG_RANDOMIZE_BASE",
        "value": "n",
    }


def test_zero_value_is_treated_as_disabled() -> None:
    snapshot = make_snapshot(
        {
            "CONFIG_RANDOMIZE_BASE": "0",
        }
    )

    findings = KernelConfigAnalyzer().analyze(snapshot)

    assert len(findings) == 1
    assert findings[0].id == "KASA-CONFIG-RANDOMIZE_BASE"


def test_missing_kernel_configuration_does_not_create_false_findings() -> None:
    snapshot = make_snapshot({})

    findings = KernelConfigAnalyzer().analyze(snapshot)

    assert findings == []
