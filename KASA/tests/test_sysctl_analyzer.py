"""Tests for SysctlAnalyzer."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from kasa.analyzers.sysctl import SysctlAnalyzer
from kasa.models.evidence import (
    EvidenceItem,
    EvidenceSource,
    EvidenceStatus,
    KernelInfo,
    KernelSnapshot,
)
from kasa.models.finding import Severity
from kasa.models.snapshot import SystemSnapshot


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_DUMMY_KERNEL = KernelInfo(
    release="6.0.0-test",
    version="#1 SMP",
    machine="x86_64",
    node="testnode",
    system="Linux",
    processor="",
)

_DUMMY_SNAPSHOT_KERNEL = KernelSnapshot(kernel=_DUMMY_KERNEL)


def _make_sysctl_item(
    key: str,
    value: str,
    status: EvidenceStatus = EvidenceStatus.AVAILABLE,
) -> EvidenceItem:
    return EvidenceItem(
        key=f"sysctl.{key}",
        value=value if status == EvidenceStatus.AVAILABLE else None,
        status=status,
        source=EvidenceSource(path=f"/proc/sys/{key.replace('.', '/')}", description=""),
        collected_at=datetime.now(UTC),
    )


def _snapshot_with_sysctls(params: dict[str, str]) -> SystemSnapshot:
    """Build a SystemSnapshot with specific sysctl values."""
    from kasa.collectors.filesystem import FilesystemInventory
    from kasa.collectors.modules import ModuleInventory

    items = [_make_sysctl_item(key, value) for key, value in params.items()]

    return SystemSnapshot(
        kernel=_DUMMY_SNAPSHOT_KERNEL,
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
        sysctl_params=items,
    )


# ---------------------------------------------------------------------------
# No false positives when values are hardened
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key, good_value",
    [
        ("kernel.kptr_restrict", "2"),
        ("kernel.dmesg_restrict", "1"),
        ("kernel.randomize_va_space", "2"),
        ("kernel.yama.ptrace_scope", "1"),
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("vm.mmap_min_addr", "65536"),
    ],
)
def test_no_finding_when_sysctl_is_hardened(key: str, good_value: str) -> None:
    """No finding should be raised when a sysctl is at its hardened value."""
    snapshot = _snapshot_with_sysctls({key: good_value})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    # The finding for this specific key should NOT be present.
    assert not any(key.split(".")[-1].upper() in fid for fid in ids)


# ---------------------------------------------------------------------------
# Findings produced for insecure values
# ---------------------------------------------------------------------------


def test_kptr_restrict_finding_when_zero() -> None:
    snapshot = _snapshot_with_sysctls({"kernel.kptr_restrict": "0"})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    assert "KASA-SYSCTL-KPTR_RESTRICT" in ids


def test_dmesg_restrict_finding_when_zero() -> None:
    snapshot = _snapshot_with_sysctls({"kernel.dmesg_restrict": "0"})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    assert "KASA-SYSCTL-DMESG_RESTRICT" in ids


def test_aslr_finding_when_not_full() -> None:
    snapshot = _snapshot_with_sysctls({"kernel.randomize_va_space": "1"})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    assert "KASA-SYSCTL-ASLR" in ids


def test_ptrace_scope_finding_when_zero() -> None:
    snapshot = _snapshot_with_sysctls({"kernel.yama.ptrace_scope": "0"})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    assert "KASA-SYSCTL-PTRACE_SCOPE" in ids


def test_rp_filter_finding_when_disabled() -> None:
    snapshot = _snapshot_with_sysctls({"net.ipv4.conf.all.rp_filter": "0"})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    assert "KASA-SYSCTL-RP_FILTER" in ids


def test_icmp_redirects_finding_when_enabled() -> None:
    snapshot = _snapshot_with_sysctls({"net.ipv4.conf.all.accept_redirects": "1"})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    assert "KASA-SYSCTL-ICMP_REDIRECTS" in ids


def test_tcp_syncookies_finding_when_disabled() -> None:
    snapshot = _snapshot_with_sysctls({"net.ipv4.tcp_syncookies": "0"})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    assert "KASA-SYSCTL-TCP_SYNCOOKIES" in ids


def test_mmap_min_addr_finding_when_too_low() -> None:
    snapshot = _snapshot_with_sysctls({"vm.mmap_min_addr": "4096"})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    assert "KASA-SYSCTL-MMAP_MIN_ADDR" in ids


def test_mmap_min_addr_no_finding_when_exactly_at_threshold() -> None:
    snapshot = _snapshot_with_sysctls({"vm.mmap_min_addr": "65536"})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    assert "KASA-SYSCTL-MMAP_MIN_ADDR" not in ids


def test_mmap_min_addr_no_finding_when_above_threshold() -> None:
    snapshot = _snapshot_with_sysctls({"vm.mmap_min_addr": "131072"})
    findings = SysctlAnalyzer().analyze(snapshot)
    ids = [f.id for f in findings]
    assert "KASA-SYSCTL-MMAP_MIN_ADDR" not in ids


# ---------------------------------------------------------------------------
# Severity checks
# ---------------------------------------------------------------------------


def test_mmap_min_addr_is_high_severity() -> None:
    snapshot = _snapshot_with_sysctls({"vm.mmap_min_addr": "0"})
    findings = SysctlAnalyzer().analyze(snapshot)
    mmap_finding = next(f for f in findings if f.id == "KASA-SYSCTL-MMAP_MIN_ADDR")
    assert mmap_finding.severity == Severity.HIGH


def test_aslr_finding_is_medium_severity() -> None:
    snapshot = _snapshot_with_sysctls({"kernel.randomize_va_space": "0"})
    findings = SysctlAnalyzer().analyze(snapshot)
    aslr_finding = next(f for f in findings if f.id == "KASA-SYSCTL-ASLR")
    assert aslr_finding.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Unavailable / error sysctls produce no false findings
# ---------------------------------------------------------------------------


def test_unavailable_sysctl_produces_no_finding() -> None:
    """A sysctl that could not be read should not generate a finding."""
    items = [
        _make_sysctl_item(
            "kernel.kptr_restrict", "", EvidenceStatus.UNAVAILABLE
        )
    ]
    from kasa.collectors.filesystem import FilesystemInventory
    from kasa.collectors.modules import ModuleInventory

    snapshot = SystemSnapshot(
        kernel=_DUMMY_SNAPSHOT_KERNEL,
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
        sysctl_params=items,
    )
    findings = SysctlAnalyzer().analyze(snapshot)
    assert not any("KPTR_RESTRICT" in f.id for f in findings)


def test_error_sysctl_produces_no_finding() -> None:
    """A sysctl with ERROR status should not generate a finding."""
    items = [
        _make_sysctl_item("kernel.kptr_restrict", "", EvidenceStatus.ERROR)
    ]
    from kasa.collectors.filesystem import FilesystemInventory
    from kasa.collectors.modules import ModuleInventory

    snapshot = SystemSnapshot(
        kernel=_DUMMY_SNAPSHOT_KERNEL,
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
        sysctl_params=items,
    )
    findings = SysctlAnalyzer().analyze(snapshot)
    assert not any("KPTR_RESTRICT" in f.id for f in findings)


# ---------------------------------------------------------------------------
# Finding structure
# ---------------------------------------------------------------------------


def test_sysctl_finding_has_evidence() -> None:
    """Every sysctl finding must carry structured evidence."""
    snapshot = _snapshot_with_sysctls({"kernel.kptr_restrict": "0"})
    findings = SysctlAnalyzer().analyze(snapshot)
    finding = next(f for f in findings if f.id == "KASA-SYSCTL-KPTR_RESTRICT")
    assert finding.evidence
    ev = finding.evidence[0]
    assert ev.key.startswith("sysctl.")
    assert isinstance(ev.value, dict)
    assert "actual" in ev.value
    assert "expected" in ev.value


def test_sysctl_finding_has_recommendation() -> None:
    """Every sysctl finding must have a remediation recommendation."""
    snapshot = _snapshot_with_sysctls({"kernel.kptr_restrict": "0"})
    findings = SysctlAnalyzer().analyze(snapshot)
    finding = next(f for f in findings if f.id == "KASA-SYSCTL-KPTR_RESTRICT")
    assert finding.recommendation


def test_sysctl_analyzer_registered_in_package() -> None:
    """SysctlAnalyzer must be exported from kasa.analyzers."""
    from kasa.analyzers import SysctlAnalyzer as _SA

    assert _SA is SysctlAnalyzer


def test_sysctl_analyzer_is_in_cli_pipeline() -> None:
    """The CLI analyze command must include SysctlAnalyzer in its pipeline."""
    import inspect

    import kasa.cli as cli_module

    source = inspect.getsource(cli_module)
    assert "SysctlAnalyzer" in source
