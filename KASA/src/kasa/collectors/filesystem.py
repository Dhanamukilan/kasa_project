"""Linux filesystem inventory collector."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from kasa.models.evidence import EvidenceSource


class FilesystemMount(BaseModel):
    """Normalized information about a mounted filesystem."""

    model_config = ConfigDict(extra="forbid")

    source: str
    mount_point: str
    filesystem_type: str
    options: list[str] = Field(default_factory=list)


class FilesystemInventory(BaseModel):
    """Complete filesystem inventory."""

    model_config = ConfigDict(extra="forbid")

    mounts: list[FilesystemMount] = Field(default_factory=list)
    supported_filesystems: list[str] = Field(default_factory=list)
    sources: list[EvidenceSource] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class FilesystemCollector:
    """Collect mounted and kernel-supported filesystem information."""

    _PROC_MOUNTS = Path("/proc/mounts")
    _PROC_FILESYSTEMS = Path("/proc/filesystems")

    def collect(self) -> FilesystemInventory:
        """Collect mounted and supported filesystem information."""
        errors: list[str] = []
        sources: list[EvidenceSource] = []

        mounts, mounts_error = self._collect_mounts()

        if mounts_error is not None:
            errors.append(mounts_error)
        else:
            sources.append(
                EvidenceSource(
                    path=str(self._PROC_MOUNTS),
                    description="Currently mounted filesystems.",
                )
            )

        supported, supported_error = self._collect_supported_filesystems()

        if supported_error is not None:
            errors.append(supported_error)
        else:
            sources.append(
                EvidenceSource(
                    path=str(self._PROC_FILESYSTEMS),
                    description="Filesystem types supported by the running kernel.",
                )
            )

        return FilesystemInventory(
            mounts=mounts,
            supported_filesystems=supported,
            sources=sources,
            errors=errors,
        )

    def _collect_mounts(
        self,
    ) -> tuple[list[FilesystemMount], str | None]:
        """Read currently mounted filesystems from /proc/mounts."""
        try:
            content = self._PROC_MOUNTS.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            return [], f"Mount interface unavailable: {self._PROC_MOUNTS}"
        except PermissionError:
            return [], f"Permission denied reading: {self._PROC_MOUNTS}"
        except OSError as exc:
            return [], f"Unable to read {self._PROC_MOUNTS}: {exc}"

        mounts: list[FilesystemMount] = []

        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue

            try:
                mount = self._parse_mount_line(line)
            except ValueError as exc:
                return (
                    [],
                    f"Invalid /proc/mounts entry at line {line_number}: {exc}",
                )

            mounts.append(mount)

        return mounts, None

    @staticmethod
    def _parse_mount_line(line: str) -> FilesystemMount:
        """Parse a single /proc/mounts line."""
        fields = line.split()

        if len(fields) < 4:
            raise ValueError(f"expected at least 4 fields, got {len(fields)}")

        source = fields[0]
        mount_point = fields[1]
        filesystem_type = fields[2]
        options = [option for option in fields[3].split(",") if option]

        return FilesystemMount(
            source=source,
            mount_point=mount_point,
            filesystem_type=filesystem_type,
            options=options,
        )

    def _collect_supported_filesystems(
        self,
    ) -> tuple[list[str], str | None]:
        """Read filesystem types currently supported by the kernel."""
        try:
            content = self._PROC_FILESYSTEMS.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            return (
                [],
                f"Filesystem interface unavailable: {self._PROC_FILESYSTEMS}",
            )
        except PermissionError:
            return (
                [],
                f"Permission denied reading: {self._PROC_FILESYSTEMS}",
            )
        except OSError as exc:
            return [], f"Unable to read {self._PROC_FILESYSTEMS}: {exc}"

        filesystems: list[str] = []

        for line in content.splitlines():
            fields = line.split()

            if not fields:
                continue

            if fields[0] == "nodev":
                if len(fields) < 2:
                    continue
                filesystem_type = fields[1]
            else:
                filesystem_type = fields[0]

            filesystems.append(filesystem_type)

        return sorted(set(filesystems)), None
