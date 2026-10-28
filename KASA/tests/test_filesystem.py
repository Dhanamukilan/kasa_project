"""Tests for the filesystem collector."""

from pathlib import Path

import pytest

from kasa.collectors.filesystem import (
    FilesystemCollector,
    FilesystemMount,
)


def test_parse_mount_line() -> None:
    collector = FilesystemCollector()

    mount = collector._parse_mount_line("/dev/sda1 / ext4 rw,relatime 0 0")

    assert mount == FilesystemMount(
        source="/dev/sda1",
        mount_point="/",
        filesystem_type="ext4",
        options=["rw", "relatime"],
    )


def test_parse_mount_line_without_options() -> None:
    collector = FilesystemCollector()

    mount = collector._parse_mount_line("tmpfs /test-mount tmpfs rw 0 0")

    assert mount.source == "tmpfs"
    assert mount.mount_point == "/test-mount"
    assert mount.filesystem_type == "tmpfs"
    assert mount.options == ["rw"]


def test_invalid_mount_line() -> None:
    collector = FilesystemCollector()

    with pytest.raises(ValueError, match="expected at least 4 fields"):
        collector._parse_mount_line("invalid")


def test_collect_mounts(tmp_path: Path) -> None:
    collector = FilesystemCollector()

    mounts_file = tmp_path / "mounts"
    mounts_file.write_text(
        "/dev/sda1 / ext4 rw,relatime 0 0\n"
        "tmpfs /test-mount tmpfs rw,nosuid,nodev 0 0\n",
        encoding="utf-8",
    )

    collector._PROC_MOUNTS = mounts_file

    mounts, error = collector._collect_mounts()

    assert error is None
    assert len(mounts) == 2

    assert mounts[0].source == "/dev/sda1"
    assert mounts[0].filesystem_type == "ext4"

    assert mounts[1].mount_point == "/test-mount"
    assert mounts[1].options == ["rw", "nosuid", "nodev"]


def test_missing_mounts_are_reported(tmp_path: Path) -> None:
    collector = FilesystemCollector()
    collector._PROC_MOUNTS = tmp_path / "missing"

    mounts, error = collector._collect_mounts()

    assert mounts == []
    assert error is not None
    assert "Mount interface unavailable" in error


def test_collect_supported_filesystems(tmp_path: Path) -> None:
    collector = FilesystemCollector()

    filesystems_file = tmp_path / "filesystems"
    filesystems_file.write_text(
        "nodev\tproc\nnodev\ttmpfs\n\text4\n\tbtrfs\nnodev\tproc\n",
        encoding="utf-8",
    )

    collector._PROC_FILESYSTEMS = filesystems_file

    filesystems, error = collector._collect_supported_filesystems()

    assert error is None
    assert filesystems == [
        "btrfs",
        "ext4",
        "proc",
        "tmpfs",
    ]


def test_missing_supported_filesystems_are_reported(tmp_path: Path) -> None:
    collector = FilesystemCollector()
    collector._PROC_FILESYSTEMS = tmp_path / "missing"

    filesystems, error = collector._collect_supported_filesystems()

    assert filesystems == []
    assert error is not None
    assert "Filesystem interface unavailable" in error


def test_collect_filesystem_inventory() -> None:
    collector = FilesystemCollector()

    inventory = collector.collect()

    assert inventory.mounts
    assert inventory.supported_filesystems
    assert inventory.sources
