"""Tests for the kernel collector and analyzer."""

from pathlib import Path

import pytest

from kasa.analyzers.kernel import KernelAnalyzer
from kasa.collectors.filesystem import FilesystemInventory
from kasa.collectors.kernel import KernelCollector
from kasa.collectors.modules import ModuleInventory
from kasa.models.evidence import (
    EvidenceItem,
    EvidenceSource,
    EvidenceStatus,
    KernelInfo,
    KernelSnapshot,
)
from kasa.models.snapshot import SystemSnapshot


def test_kernel_collector_returns_kernel_information() -> None:
    snapshot = KernelCollector().collect()

    assert snapshot.kernel.release
    assert snapshot.kernel.version
    assert snapshot.kernel.machine
    assert snapshot.kernel.system


def test_kernel_collector_contains_command_line_evidence() -> None:
    snapshot = KernelCollector().collect()

    assert snapshot.evidence

    command_line = next(
        item for item in snapshot.evidence if item.key == "kernel.command_line"
    )

    assert command_line.source.path == str(Path("/proc/cmdline"))


def test_kernel_collector_contains_lockdown_evidence() -> None:
    snapshot = KernelCollector().collect()

    lockdown = next(item for item in snapshot.evidence if item.key == "kernel.lockdown")

    assert lockdown.source.path == str(Path("/sys/kernel/security/lockdown"))
    assert lockdown.status.value in {"available", "unavailable", "error"}


def test_parse_lockdown_state_integrity() -> None:
    assert (
        KernelCollector._parse_lockdown_state("none [integrity] confidentiality")
        == "integrity"
    )


def test_parse_lockdown_state_confidentiality() -> None:
    assert (
        KernelCollector._parse_lockdown_state("none integrity [confidentiality]")
        == "confidentiality"
    )


def test_parse_lockdown_state_none() -> None:
    assert (
        KernelCollector._parse_lockdown_state("[none] integrity confidentiality")
        == "none"
    )


def make_kernel_snapshot(active_mode: str) -> SystemSnapshot:
    """Create a minimal snapshot containing lockdown evidence."""
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
            command_line="BOOT_IMAGE=test",
            lockdown=active_mode,
            evidence=[
                EvidenceItem(
                    key="kernel.lockdown",
                    value={
                        "raw": f"none [{active_mode}] confidentiality",
                        "active_mode": active_mode,
                    },
                    status=EvidenceStatus.AVAILABLE,
                    source=EvidenceSource(
                        path="/sys/kernel/security/lockdown",
                        description="Current kernel lockdown state.",
                    ),
                )
            ],
        ),
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
    )


def test_kernel_analyzer_reports_disabled_lockdown() -> None:
    snapshot = make_kernel_snapshot("none")

    findings = KernelAnalyzer().analyze(snapshot)

    assert len(findings) == 1
    assert findings[0].id == "KASA-KERNEL-001"
    assert findings[0].severity.value == "low"


def test_kernel_analyzer_does_not_report_integrity_lockdown() -> None:
    snapshot = make_kernel_snapshot("integrity")

    findings = KernelAnalyzer().analyze(snapshot)

    assert findings == []


def test_kernel_analyzer_does_not_report_confidentiality_lockdown() -> None:
    snapshot = make_kernel_snapshot("confidentiality")

    findings = KernelAnalyzer().analyze(snapshot)

    assert findings == []


def test_kernel_analyzer_missing_lockdown_evidence_produces_no_finding() -> None:
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
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
    )

    findings = KernelAnalyzer().analyze(snapshot)

    assert findings == []


def test_kernel_analyzer_unavailable_lockdown_evidence_produces_no_finding() -> None:
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
            evidence=[
                EvidenceItem(
                    key="kernel.lockdown",
                    value=None,
                    status=EvidenceStatus.UNAVAILABLE,
                    source=EvidenceSource(
                        path="/sys/kernel/security/lockdown",
                        description="Current kernel lockdown state.",
                    ),
                )
            ],
        ),
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
    )

    findings = KernelAnalyzer().analyze(snapshot)

    assert findings == []


def test_kernel_analyzer_error_lockdown_evidence_produces_no_finding() -> None:
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
            evidence=[
                EvidenceItem(
                    key="kernel.lockdown",
                    value=None,
                    status=EvidenceStatus.ERROR,
                    source=EvidenceSource(
                        path="/sys/kernel/security/lockdown",
                        description="Current kernel lockdown state.",
                    ),
                    error="Permission denied",
                )
            ],
        ),
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
    )

    findings = KernelAnalyzer().analyze(snapshot)

    assert findings == []


def test_kernel_analyzer_malformed_lockdown_evidence_produces_no_finding() -> None:
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
            evidence=[
                EvidenceItem(
                    key="kernel.lockdown",
                    value="not-a-dict",
                    status=EvidenceStatus.AVAILABLE,
                    source=EvidenceSource(
                        path="/sys/kernel/security/lockdown",
                        description="Current kernel lockdown state.",
                    ),
                )
            ],
        ),
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
    )

    findings = KernelAnalyzer().analyze(snapshot)

    assert findings == []


def test_kernel_collector_contains_lsm_evidence() -> None:
    snapshot = KernelCollector().collect()

    lsm = next(item for item in snapshot.evidence if item.key == "kernel.lsm")

    assert lsm.source.path == str(Path("/sys/kernel/security/lsm"))
    assert lsm.status.value in {"available", "unavailable", "error"}


def test_parse_lsm_state() -> None:
    raw = "lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm"

    assert KernelCollector._parse_lsm_state(raw) == [
        "lockdown",
        "capability",
        "yama",
        "selinux",
        "bpf",
        "landlock",
        "ipe",
        "ima",
        "evm",
    ]


def test_parse_lsm_state_ignores_empty_entries() -> None:
    raw = "lockdown,, capability, ,selinux,"

    assert KernelCollector._parse_lsm_state(raw) == [
        "lockdown",
        "capability",
        "selinux",
    ]


def test_parse_lsm_state_whitespace_and_empty() -> None:
    assert KernelCollector._parse_lsm_state("  \n  ,  , \t ") == []
    assert KernelCollector._parse_lsm_state("") == []


def test_collect_lsm_success(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful read of /sys/kernel/security/lsm produces structured evidence."""

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._LSM:
            return "lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm\n"
        return original_read_text(self, **kwargs)

    original_read_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    active, evidence, error = KernelCollector()._collect_lsm()

    assert error is None
    assert evidence.key == "kernel.lsm"
    assert evidence.status == EvidenceStatus.AVAILABLE
    assert active == [
        "lockdown",
        "capability",
        "yama",
        "selinux",
        "bpf",
        "landlock",
        "ipe",
        "ima",
        "evm",
    ]
    assert evidence.value == {
        "raw": "lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm",
        "active": active,
    }


def test_collect_lsm_missing_interface(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing /sys/kernel/security/lsm produces UNAVAILABLE status and error."""

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._LSM:
            raise FileNotFoundError(self)
        return original_read_text(self, **kwargs)

    original_read_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    active, evidence, error = KernelCollector()._collect_lsm()

    assert active is None
    assert error is not None
    assert "Active LSM interface unavailable" in error
    assert evidence.status == EvidenceStatus.UNAVAILABLE
    assert evidence.key == "kernel.lsm"
    assert evidence.value is None


def test_collect_lsm_permission_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Permission denied reading /sys/kernel/security/lsm produces ERROR status."""

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._LSM:
            raise PermissionError("Permission denied")
        return original_read_text(self, **kwargs)

    original_read_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    active, evidence, error = KernelCollector()._collect_lsm()

    assert active is None
    assert error is not None
    assert "Permission denied reading active LSMs" in error
    assert evidence.status == EvidenceStatus.ERROR
    assert evidence.key == "kernel.lsm"
    assert evidence.value is None


def test_collect_lsm_os_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """OSError reading /sys/kernel/security/lsm produces ERROR status."""

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._LSM:
            raise OSError("I/O error")
        return original_read_text(self, **kwargs)

    original_read_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    active, evidence, error = KernelCollector()._collect_lsm()

    assert active is None
    assert error is not None
    assert "Unable to read active LSMs" in error
    assert evidence.status == EvidenceStatus.ERROR
    assert evidence.key == "kernel.lsm"
    assert evidence.value is None


# ---------------------------------------------------------------------------
# SELinux evidence tests
# ---------------------------------------------------------------------------


def test_collect_selinux_enforcing(monkeypatch: pytest.MonkeyPatch) -> None:
    """enforce=1 should produce mode='enforcing'."""

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._SELINUX_ENFORCE:
            return "1\n"
        if self == KernelCollector._SELINUX_POLICY_VERSION:
            return "33\n"
        return original_read_text(self, **kwargs)

    original_read_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    collector = KernelCollector()
    result, evidence, error = collector._collect_selinux()

    assert error is None
    assert evidence.key == "kernel.selinux"
    assert evidence.status == EvidenceStatus.AVAILABLE
    assert result is not None
    assert result["enabled"] is True
    assert result["mode"] == "enforcing"
    assert result["policy_version"] == 33


def test_collect_selinux_permissive(monkeypatch: pytest.MonkeyPatch) -> None:
    """enforce=0 should produce mode='permissive'."""

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._SELINUX_ENFORCE:
            return "0\n"
        if self == KernelCollector._SELINUX_POLICY_VERSION:
            return "33\n"
        return original_read_text(self, **kwargs)

    original_read_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    collector = KernelCollector()
    result, evidence, error = collector._collect_selinux()

    assert error is None
    assert evidence.status == EvidenceStatus.AVAILABLE
    assert result is not None
    assert result["mode"] == "permissive"


def test_collect_selinux_policy_version_parsed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Policy version should be parsed as an integer."""

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._SELINUX_ENFORCE:
            return "1"
        if self == KernelCollector._SELINUX_POLICY_VERSION:
            return "  33  "
        return original_read_text(self, **kwargs)

    original_read_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    _, evidence, _ = KernelCollector()._collect_selinux()

    assert evidence.value is not None
    assert evidence.value["policy_version"] == 33


def test_collect_selinux_missing_enforce_interface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FileNotFoundError on enforce path -> UNAVAILABLE evidence and error string."""

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._SELINUX_ENFORCE:
            raise FileNotFoundError(self)
        return original_read_text(self, **kwargs)

    original_read_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    result, evidence, error = KernelCollector()._collect_selinux()

    assert result is None
    assert error is not None
    assert evidence.status == EvidenceStatus.UNAVAILABLE
    assert evidence.key == "kernel.selinux"
    assert evidence.value is None


def test_collect_selinux_invalid_enforce_value(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unexpected enforce value should produce ERROR evidence and an error string."""

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._SELINUX_ENFORCE:
            return "bogus"
        return original_read_text(self, **kwargs)

    original_read_text = Path.read_text
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    result, evidence, error = KernelCollector()._collect_selinux()

    assert result is None
    assert error is not None
    assert "bogus" in error
    assert evidence.status == EvidenceStatus.ERROR


def test_kernel_collector_contains_selinux_evidence() -> None:
    """collect() must include a 'kernel.selinux' EvidenceItem."""
    snapshot = KernelCollector().collect()

    selinux = next(
        (item for item in snapshot.evidence if item.key == "kernel.selinux"),
        None,
    )

    assert selinux is not None
    assert selinux.source.path == str(KernelCollector._SELINUX_ENFORCE)
    assert selinux.status.value in {"available", "unavailable", "error"}


# ---------------------------------------------------------------------------
# IMA evidence tests
# ---------------------------------------------------------------------------


def test_parse_cmdline_params() -> None:
    """_parse_cmdline_params parses prefixed boot arguments into key-value pairs."""
    cmdline = (
        "quiet BOOT_IMAGE=/vmlinuz ima_policy=tcb ima_appraise=enforce ipe.enforce=1"
    )
    params = KernelCollector._parse_cmdline_params(cmdline, "ima")

    assert params == {
        "ima_policy": "tcb",
        "ima_appraise": "enforce",
    }


def test_parse_cmdline_params_empty_or_none() -> None:
    """Empty or None command line returns empty dict."""
    assert KernelCollector._parse_cmdline_params(None, "ima") == {}
    assert KernelCollector._parse_cmdline_params("", "ima") == {}


def test_collect_ima_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Available IMA interface returns structured evidence with metrics."""
    original_exists = Path.exists
    original_read_text = Path.read_text

    def fake_exists(self: Path) -> bool:
        if self in (KernelCollector._IMA, KernelCollector._IMA / "policy"):
            return True
        return original_exists(self)

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._IMA / "runtime_measurements_count":
            return "42\n"
        if self == KernelCollector._IMA / "violations":
            return "0\n"
        return original_read_text(self, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    cmdline = "quiet ima_policy=tcb ima_appraise=enforce"
    val, evidence, error = KernelCollector()._collect_ima(cmdline)

    assert error is None
    assert evidence.key == "kernel.ima"
    assert evidence.status == EvidenceStatus.AVAILABLE
    assert val is not None
    assert val["supported"] is True
    assert val["policy_available"] is True
    assert val["runtime_measurements_count"] == 42
    assert val["violations_count"] == 0
    assert val["boot_parameters"] == {
        "ima_policy": "tcb",
        "ima_appraise": "enforce",
    }
    assert val["appraisal_runtime_state"] == "enforce"


def test_collect_ima_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing IMA paths return UNAVAILABLE status."""
    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self in (KernelCollector._IMA, KernelCollector._IMA_INTEGRITY):
            return False
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    val, evidence, error = KernelCollector()._collect_ima()

    assert val is None
    assert error is not None
    assert "IMA interface unavailable" in error
    assert evidence.status == EvidenceStatus.UNAVAILABLE
    assert evidence.key == "kernel.ima"


def test_collect_ima_permission_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """PermissionError on IMA check returns ERROR status."""
    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._IMA:
            raise PermissionError("Permission denied")
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    val, evidence, error = KernelCollector()._collect_ima()

    assert val is None
    assert error is not None
    assert "Permission denied accessing IMA interface" in error
    assert evidence.status == EvidenceStatus.ERROR
    assert evidence.key == "kernel.ima"


def test_collect_ima_os_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """OSError on IMA check returns ERROR status."""
    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._IMA:
            raise OSError("I/O failure")
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    val, evidence, error = KernelCollector()._collect_ima()

    assert val is None
    assert error is not None
    assert "Unable to access IMA interface" in error
    assert evidence.status == EvidenceStatus.ERROR
    assert evidence.key == "kernel.ima"


def test_kernel_collector_contains_ima_evidence() -> None:
    """collect() must include a 'kernel.ima' EvidenceItem."""
    snapshot = KernelCollector().collect()

    ima = next(
        (item for item in snapshot.evidence if item.key == "kernel.ima"),
        None,
    )

    assert ima is not None
    assert ima.source.path == str(KernelCollector._IMA)
    assert ima.status.value in {"available", "unavailable", "error"}


# ---------------------------------------------------------------------------
# EVM evidence tests
# ---------------------------------------------------------------------------


def test_collect_evm_available_readable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Available readable EVM interface returns structured evidence."""
    original_exists = Path.exists
    original_read_text = Path.read_text

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._EVM:
            return True
        return original_exists(self)

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._EVM:
            return "3\n"
        return original_read_text(self, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    cmdline = "quiet evm=fix"
    val, evidence, error = KernelCollector()._collect_evm(cmdline)

    assert error is None
    assert evidence.key == "kernel.evm"
    assert evidence.status == EvidenceStatus.AVAILABLE
    assert val is not None
    assert val["supported"] is True
    assert val["readable"] is True
    assert val["status_raw"] == "3"
    assert val["status_flags"] == 3
    assert val["active_state"] == "complete"
    assert val["boot_parameters"] == {"evm": "fix"}


def test_collect_evm_available_uninitialized(monkeypatch: pytest.MonkeyPatch) -> None:
    """EVM flag 0 maps to uninitialized active state."""
    original_exists = Path.exists
    original_read_text = Path.read_text

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._EVM:
            return True
        return original_exists(self)

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._EVM:
            return "0\n"
        return original_read_text(self, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    val, evidence, error = KernelCollector()._collect_evm()

    assert error is None
    assert evidence.status == EvidenceStatus.AVAILABLE
    assert val is not None
    assert val["active_state"] == "uninitialized"


def test_collect_evm_unreadable_file_still_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When EVM node exists but cannot be read, evidence is AVAILABLE."""
    original_exists = Path.exists
    original_read_text = Path.read_text

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._EVM:
            return True
        return original_exists(self)

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._EVM:
            raise PermissionError("Permission denied")
        return original_read_text(self, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    val, evidence, error = KernelCollector()._collect_evm()

    assert error is None
    assert evidence.key == "kernel.evm"
    assert evidence.status == EvidenceStatus.AVAILABLE
    assert val is not None
    assert val["readable"] is False
    assert val["status_raw"] is None
    assert val["status_flags"] is None
    assert val["active_state"] == "unknown"


def test_collect_evm_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing EVM paths return UNAVAILABLE status."""
    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self in (KernelCollector._EVM, KernelCollector._EVM_INTEGRITY):
            return False
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    val, evidence, error = KernelCollector()._collect_evm()

    assert val is None
    assert error is not None
    assert "EVM interface unavailable" in error
    assert evidence.status == EvidenceStatus.UNAVAILABLE
    assert evidence.key == "kernel.evm"


def test_collect_evm_permission_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """PermissionError on EVM directory check returns ERROR status."""
    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._EVM:
            raise PermissionError("Permission denied")
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    val, evidence, error = KernelCollector()._collect_evm()

    assert val is None
    assert error is not None
    assert "Permission denied accessing EVM interface" in error
    assert evidence.status == EvidenceStatus.ERROR
    assert evidence.key == "kernel.evm"


def test_collect_evm_os_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """OSError on EVM directory check returns ERROR status."""
    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._EVM:
            raise OSError("I/O error")
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    val, evidence, error = KernelCollector()._collect_evm()

    assert val is None
    assert error is not None
    assert "Unable to access EVM interface" in error
    assert evidence.status == EvidenceStatus.ERROR
    assert evidence.key == "kernel.evm"


def test_kernel_collector_contains_evm_evidence() -> None:
    """collect() must include a 'kernel.evm' EvidenceItem."""
    snapshot = KernelCollector().collect()

    evm = next(
        (item for item in snapshot.evidence if item.key == "kernel.evm"),
        None,
    )

    assert evm is not None
    assert evm.source.path == str(KernelCollector._EVM)
    assert evm.status.value in {"available", "unavailable", "error"}


# ---------------------------------------------------------------------------
# IPE evidence tests
# ---------------------------------------------------------------------------


def test_collect_ipe_available(monkeypatch: pytest.MonkeyPatch) -> None:
    """Available IPE interface returns structured evidence with policies."""
    original_exists = Path.exists
    original_is_dir = Path.is_dir
    original_read_text = Path.read_text

    policy_dir = KernelCollector._IPE / "policies" / "boot_policy"
    active_file = policy_dir / "active"

    def fake_exists(self: Path) -> bool:
        if self in (KernelCollector._IPE, active_file):
            return True
        return original_exists(self)

    def fake_is_dir(self: Path) -> bool:
        if self == KernelCollector._IPE / "policies":
            return True
        return original_is_dir(self)

    def fake_iterdir(self: Path) -> list[Path]:
        if self == KernelCollector._IPE / "policies":
            return [policy_dir]
        return []

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._IPE / "enforce":
            return "1\n"
        if self == KernelCollector._IPE / "success_audit":
            return "1\n"
        if self == active_file:
            return "1\n"
        return original_read_text(self, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)
    monkeypatch.setattr(Path, "is_dir", fake_is_dir)
    monkeypatch.setattr(Path, "iterdir", fake_iterdir)
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    cmdline = "quiet ipe.enforce=1"
    val, evidence, error = KernelCollector()._collect_ipe(cmdline)

    assert error is None
    assert evidence.key == "kernel.ipe"
    assert evidence.status == EvidenceStatus.AVAILABLE
    assert val is not None
    assert val["supported"] is True
    assert val["enforce"] is True
    assert val["success_audit"] is True
    assert val["policies"] == ["boot_policy"]
    assert val["active_policies"] == ["boot_policy"]
    assert val["boot_parameters"] == {"ipe.enforce": "1"}


def test_collect_ipe_available_permissive(monkeypatch: pytest.MonkeyPatch) -> None:
    """IPE enforce=0 and success_audit=0 map to False booleans."""
    original_exists = Path.exists
    original_read_text = Path.read_text

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._IPE:
            return True
        return original_exists(self)

    def fake_read_text(self: Path, **kwargs: object) -> str:
        if self == KernelCollector._IPE / "enforce":
            return "0\n"
        if self == KernelCollector._IPE / "success_audit":
            return "0\n"
        return original_read_text(self, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)
    monkeypatch.setattr(Path, "read_text", fake_read_text)

    val, evidence, error = KernelCollector()._collect_ipe()

    assert error is None
    assert evidence.status == EvidenceStatus.AVAILABLE
    assert val is not None
    assert val["enforce"] is False
    assert val["success_audit"] is False


def test_collect_ipe_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing IPE path returns UNAVAILABLE status."""
    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._IPE:
            return False
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    val, evidence, error = KernelCollector()._collect_ipe()

    assert val is None
    assert error is not None
    assert "IPE interface unavailable" in error
    assert evidence.status == EvidenceStatus.UNAVAILABLE
    assert evidence.key == "kernel.ipe"


def test_collect_ipe_permission_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """PermissionError on IPE directory check returns ERROR status."""
    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._IPE:
            raise PermissionError("Permission denied")
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    val, evidence, error = KernelCollector()._collect_ipe()

    assert val is None
    assert error is not None
    assert "Permission denied accessing IPE interface" in error
    assert evidence.status == EvidenceStatus.ERROR
    assert evidence.key == "kernel.ipe"


def test_collect_ipe_os_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """OSError on IPE directory check returns ERROR status."""
    original_exists = Path.exists

    def fake_exists(self: Path) -> bool:
        if self == KernelCollector._IPE:
            raise OSError("I/O failure")
        return original_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)

    val, evidence, error = KernelCollector()._collect_ipe()

    assert val is None
    assert error is not None
    assert "Unable to access IPE interface" in error
    assert evidence.status == EvidenceStatus.ERROR
    assert evidence.key == "kernel.ipe"


def test_kernel_collector_contains_ipe_evidence() -> None:
    """collect() must include a 'kernel.ipe' EvidenceItem."""
    snapshot = KernelCollector().collect()

    ipe = next(
        (item for item in snapshot.evidence if item.key == "kernel.ipe"),
        None,
    )

    assert ipe is not None
    assert ipe.source.path == str(KernelCollector._IPE)
    assert ipe.status.value in {"available", "unavailable", "error"}
