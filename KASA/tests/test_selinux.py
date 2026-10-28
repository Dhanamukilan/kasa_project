"""Tests for the SELinux analyzer."""

from __future__ import annotations

from kasa.analyzers.selinux import SELinuxAnalyzer
from kasa.collectors.filesystem import FilesystemInventory
from kasa.collectors.modules import ModuleInventory
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

_SELINUX_SOURCE = EvidenceSource(
    path="/sys/fs/selinux/enforce",
    description="SELinux enforcement mode and policy version.",
)


def _make_snapshot(evidence: list[EvidenceItem]) -> SystemSnapshot:
    """Build a minimal SystemSnapshot containing the given kernel evidence."""
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
            evidence=evidence,
        ),
        modules=ModuleInventory(),
        filesystems=FilesystemInventory(),
    )


def _selinux_evidence(
    mode: str | None,
    *,
    status: EvidenceStatus = EvidenceStatus.AVAILABLE,
    policy_version: int | None = 33,
    error: str | None = None,
) -> EvidenceItem:
    """Build a kernel.selinux EvidenceItem."""
    value = (
        {"enabled": True, "mode": mode, "policy_version": policy_version}
        if status == EvidenceStatus.AVAILABLE
        else None
    )
    return EvidenceItem(
        key="kernel.selinux",
        value=value,
        status=status,
        source=_SELINUX_SOURCE,
        error=error,
    )


# ---------------------------------------------------------------------------
# Enforcing: no finding expected
# ---------------------------------------------------------------------------


def test_selinux_enforcing_produces_no_finding() -> None:
    """mode='enforcing' must not produce KASA-SELINUX-001."""
    snapshot = _make_snapshot([_selinux_evidence("enforcing")])
    findings = SELinuxAnalyzer().analyze(snapshot)
    assert findings == []


# ---------------------------------------------------------------------------
# Permissive: KASA-SELINUX-001 expected
# ---------------------------------------------------------------------------


def test_selinux_permissive_produces_finding() -> None:
    """mode='permissive' must produce KASA-SELINUX-001."""
    snapshot = _make_snapshot([_selinux_evidence("permissive")])
    findings = SELinuxAnalyzer().analyze(snapshot)
    assert len(findings) == 1
    assert findings[0].id == "KASA-SELINUX-001"


def test_selinux_permissive_finding_severity_is_medium() -> None:
    """KASA-SELINUX-001 must have MEDIUM severity."""
    snapshot = _make_snapshot([_selinux_evidence("permissive")])
    findings = SELinuxAnalyzer().analyze(snapshot)
    assert findings[0].severity == Severity.MEDIUM


def test_selinux_permissive_finding_references_kernel_selinux_evidence() -> None:
    """KASA-SELINUX-001 must reference the kernel.selinux evidence key."""
    snapshot = _make_snapshot([_selinux_evidence("permissive")])
    findings = SELinuxAnalyzer().analyze(snapshot)
    finding = findings[0]
    assert "kernel.selinux" in finding.evidence_keys
    assert any(e.key == "kernel.selinux" for e in finding.evidence)


# ---------------------------------------------------------------------------
# Unavailable / error / missing / malformed: no finding expected
# ---------------------------------------------------------------------------


def test_selinux_unavailable_evidence_produces_no_finding() -> None:
    """UNAVAILABLE evidence must not produce a finding."""
    evidence = _selinux_evidence(
        None,
        status=EvidenceStatus.UNAVAILABLE,
        policy_version=None,
        error="SELinux interface unavailable: /sys/fs/selinux/enforce",
    )
    snapshot = _make_snapshot([evidence])
    findings = SELinuxAnalyzer().analyze(snapshot)
    assert findings == []


def test_selinux_error_evidence_produces_no_finding() -> None:
    """ERROR evidence must not produce a finding."""
    evidence = _selinux_evidence(
        None,
        status=EvidenceStatus.ERROR,
        policy_version=None,
        error="Permission denied reading SELinux enforce: /sys/fs/selinux/enforce",
    )
    snapshot = _make_snapshot([evidence])
    findings = SELinuxAnalyzer().analyze(snapshot)
    assert findings == []


def test_selinux_missing_evidence_key_produces_no_finding() -> None:
    """Absence of any kernel.selinux evidence must not produce a finding."""
    snapshot = _make_snapshot([])
    findings = SELinuxAnalyzer().analyze(snapshot)
    assert findings == []


def test_selinux_malformed_evidence_value_produces_no_finding() -> None:
    """A non-dict evidence value must be silently skipped."""
    evidence = EvidenceItem(
        key="kernel.selinux",
        value="not-a-dict",
        status=EvidenceStatus.AVAILABLE,
        source=_SELINUX_SOURCE,
    )
    snapshot = _make_snapshot([evidence])
    findings = SELinuxAnalyzer().analyze(snapshot)
    assert findings == []


# ---------------------------------------------------------------------------
# Registration: SELinuxAnalyzer must run in the normal pipeline
# ---------------------------------------------------------------------------


def test_selinux_analyzer_registered_in_pipeline() -> None:
    """SELinuxAnalyzer must be importable from the kasa.analyzers package."""
    from kasa.analyzers import SELinuxAnalyzer as _SELinuxAnalyzer

    assert _SELinuxAnalyzer is SELinuxAnalyzer


def test_selinux_analyzer_is_in_cli_pipeline() -> None:
    """The CLI analyze command must include SELinuxAnalyzer in its analyzer list."""
    import ast
    import pathlib

    cli_source = (
        pathlib.Path(__file__).parent.parent / "src" / "kasa" / "cli.py"
    ).read_text(encoding="utf-8")

    tree = ast.parse(cli_source)

    class _Visitor(ast.NodeVisitor):
        found = False

        def visit_Call(self, node: ast.Call) -> None:
            if isinstance(node.func, ast.Name) and node.func.id == "SELinuxAnalyzer":
                self.found = True
            self.generic_visit(node)

    visitor = _Visitor()
    visitor.visit(tree)
    assert visitor.found, "SELinuxAnalyzer() not found in cli.py analyzers list"
