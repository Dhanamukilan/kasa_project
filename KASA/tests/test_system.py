"""Tests for the system collector."""

from kasa.collectors.system import SystemCollector


def test_system_collector_returns_snapshot() -> None:
    snapshot = SystemCollector().collect()

    assert snapshot.kernel.kernel.release
    assert snapshot.modules is not None
    assert snapshot.filesystems is not None


def test_system_collector_collects_kernel_config() -> None:
    snapshot = SystemCollector().collect()

    assert isinstance(snapshot.kernel_config, list)
