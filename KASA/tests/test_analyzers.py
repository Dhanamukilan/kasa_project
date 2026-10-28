"""Tests for KASA security analyzers."""

from kasa.analyzers.filesystem import FilesystemAnalyzer
from kasa.analyzers.kernel import KernelAnalyzer
from kasa.analyzers.modules import ModuleAnalyzer
from kasa.collectors.system import SystemCollector
from kasa.models.finding import Severity


def test_kernel_analyzer_returns_findings() -> None:
    snapshot = SystemCollector().collect()

    findings = KernelAnalyzer().analyze(snapshot)

    assert isinstance(findings, list)

    for finding in findings:
        assert finding.id
        assert finding.title
        assert isinstance(finding.severity, Severity)


def test_module_analyzer_returns_findings() -> None:
    snapshot = SystemCollector().collect()

    findings = ModuleAnalyzer().analyze(snapshot)

    assert isinstance(findings, list)


def test_filesystem_analyzer_returns_findings() -> None:
    snapshot = SystemCollector().collect()

    findings = FilesystemAnalyzer().analyze(snapshot)

    assert isinstance(findings, list)
