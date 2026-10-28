"""Tests for the SysctlCollector."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from kasa.collectors.sysctl import SysctlCollector
from kasa.models.evidence import EvidenceStatus


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_collector() -> SysctlCollector:
    return SysctlCollector()


# ---------------------------------------------------------------------------
# read_one
# ---------------------------------------------------------------------------


def test_read_one_returns_value(tmp_path: Path) -> None:
    """read_one should return the file content as a stripped string."""
    key_path = tmp_path / "kernel" / "kptr_restrict"
    key_path.parent.mkdir(parents=True)
    key_path.write_text("2\n")

    collector = _make_collector()
    with patch.object(
        collector, "_key_to_path", return_value=key_path
    ):
        value = collector.read_one("kernel.kptr_restrict")

    assert value == "2"


def test_read_one_returns_none_when_missing(tmp_path: Path) -> None:
    """read_one should return None when the file does not exist."""
    collector = _make_collector()
    with patch.object(
        collector, "_key_to_path", return_value=tmp_path / "nonexistent"
    ):
        value = collector.read_one("kernel.nonexistent")

    assert value is None


def test_read_one_returns_none_on_permission_error(tmp_path: Path) -> None:
    """read_one should return None on PermissionError."""
    key_path = tmp_path / "key"
    key_path.write_text("1")

    collector = _make_collector()
    with patch.object(collector, "_key_to_path", return_value=key_path):
        with patch.object(Path, "read_text", side_effect=PermissionError):
            value = collector.read_one("kernel.restricted")

    assert value is None


# ---------------------------------------------------------------------------
# collect – status
# ---------------------------------------------------------------------------


def test_collect_returns_list_of_evidence_items() -> None:
    """collect should always return a list."""
    collector = _make_collector()
    with patch.object(Path, "read_text", side_effect=FileNotFoundError):
        items = collector.collect()
    assert isinstance(items, list)
    assert len(items) > 0


def test_collect_unavailable_status_when_file_missing() -> None:
    """Items for missing sysctl files should have UNAVAILABLE status."""
    collector = _make_collector()
    with patch.object(Path, "read_text", side_effect=FileNotFoundError):
        items = collector.collect()
    for item in items:
        assert item.status == EvidenceStatus.UNAVAILABLE


def test_collect_error_status_on_permission_denied() -> None:
    """Items for permission-restricted sysctls should have ERROR status."""
    collector = _make_collector()
    with patch.object(Path, "read_text", side_effect=PermissionError):
        items = collector.collect()
    for item in items:
        assert item.status == EvidenceStatus.ERROR


def test_collect_available_status_when_readable(tmp_path: Path) -> None:
    """Items where the file is readable should have AVAILABLE status."""
    collector = _make_collector()

    def fake_read_text(*_args: object, **_kwargs: object) -> str:
        return "1\n"

    with patch.object(Path, "read_text", fake_read_text):
        items = collector.collect()

    for item in items:
        assert item.status == EvidenceStatus.AVAILABLE
        assert item.value == "1"


# ---------------------------------------------------------------------------
# collect – evidence item structure
# ---------------------------------------------------------------------------


def test_collect_keys_are_prefixed_with_sysctl() -> None:
    """All evidence item keys must start with 'sysctl.'."""
    collector = _make_collector()
    with patch.object(Path, "read_text", side_effect=FileNotFoundError):
        items = collector.collect()
    for item in items:
        assert item.key.startswith("sysctl.")


def test_collect_error_message_set_on_os_error() -> None:
    """An OSError should produce an ERROR item with an error message."""
    collector = _make_collector()
    with patch.object(Path, "read_text", side_effect=OSError("disk read error")):
        items = collector.collect()
    for item in items:
        assert item.status == EvidenceStatus.ERROR
        assert item.error is not None


def test_collect_covers_known_security_keys() -> None:
    """Collector must include key security sysctl keys."""
    must_include = {
        "kernel.kptr_restrict",
        "kernel.randomize_va_space",
        "net.ipv4.tcp_syncookies",
        "vm.mmap_min_addr",
    }
    collector = _make_collector()
    with patch.object(Path, "read_text", side_effect=FileNotFoundError):
        items = collector.collect()

    collected_keys = {item.key.removeprefix("sysctl.") for item in items}
    assert must_include <= collected_keys


# ---------------------------------------------------------------------------
# Integration: SystemCollector includes sysctl_params
# ---------------------------------------------------------------------------


def test_system_collector_includes_sysctl_params() -> None:
    """SystemSnapshot must contain a sysctl_params list."""
    from kasa.collectors.system import SystemCollector

    with patch.object(Path, "read_text", side_effect=FileNotFoundError):
        # Patch everything that touches the real FS.
        import platform
        with patch.object(platform, "release", return_value="6.0.0-test"), \
             patch.object(platform, "version", return_value="#1 SMP"), \
             patch.object(platform, "machine", return_value="x86_64"), \
             patch.object(platform, "node", return_value="testnode"), \
             patch.object(platform, "system", return_value="Linux"), \
             patch.object(platform, "processor", return_value=""):
            snapshot = SystemCollector().collect()

    assert hasattr(snapshot, "sysctl_params")
    assert isinstance(snapshot.sysctl_params, list)
