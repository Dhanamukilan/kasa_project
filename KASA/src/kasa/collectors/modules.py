"""Linux kernel module inventory collector."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from kasa.models.evidence import EvidenceSource


class ModuleState(StrEnum):
    """Runtime state of a kernel component."""

    LOADED = "loaded"
    BUILTIN = "builtin"


class KernelModule(BaseModel):
    """Normalized kernel module information."""

    model_config = ConfigDict(extra="forbid")

    name: str
    state: ModuleState
    size: int | None = None
    reference_count: int | None = None
    dependencies: list[str] = Field(default_factory=list)
    source: str


class ModuleInventory(BaseModel):
    """Complete kernel module inventory."""

    model_config = ConfigDict(extra="forbid")

    loaded: list[KernelModule] = Field(default_factory=list)
    builtin: list[str] = Field(default_factory=list)
    sources: list[EvidenceSource] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class ModuleCollector:
    """Collect loaded and built-in kernel module information."""

    _PROC_MODULES = Path("/proc/modules")

    def collect(self, kernel_release: str) -> ModuleInventory:
        """Collect loaded and built-in kernel components."""
        errors: list[str] = []
        sources: list[EvidenceSource] = []

        loaded, loaded_error = self._collect_loaded_modules()

        if loaded_error is not None:
            errors.append(loaded_error)
        else:
            sources.append(
                EvidenceSource(
                    path=str(self._PROC_MODULES),
                    description="Currently loaded kernel modules.",
                )
            )

        builtin, builtin_source, builtin_error = self._collect_builtin_modules(
            kernel_release
        )

        if builtin_error is not None:
            errors.append(builtin_error)

        if builtin_source is not None:
            sources.append(builtin_source)

        return ModuleInventory(
            loaded=loaded,
            builtin=builtin,
            sources=sources,
            errors=errors,
        )

    def _collect_loaded_modules(
        self,
    ) -> tuple[list[KernelModule], str | None]:
        """Read currently loaded modules from /proc/modules."""
        try:
            content = self._PROC_MODULES.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            return [], f"Module interface unavailable: {self._PROC_MODULES}"
        except PermissionError:
            return [], f"Permission denied reading: {self._PROC_MODULES}"
        except OSError as exc:
            return [], f"Unable to read {self._PROC_MODULES}: {exc}"

        modules: list[KernelModule] = []

        for line_number, line in enumerate(content.splitlines(), start=1):
            if not line.strip():
                continue

            try:
                module = self._parse_proc_modules_line(line)
            except ValueError as exc:
                return [], (f"Invalid /proc/modules entry at line {line_number}: {exc}")

            modules.append(module)

        return modules, None

    @staticmethod
    def _parse_proc_modules_line(line: str) -> KernelModule:
        """Parse a single /proc/modules line."""
        fields = line.split()

        if len(fields) < 6:
            raise ValueError(f"expected at least 6 fields, got {len(fields)}")

        name = fields[0]

        try:
            size = int(fields[1])
        except ValueError as exc:
            raise ValueError(f"invalid module size for {name!r}") from exc

        try:
            reference_count = int(fields[2])
        except ValueError as exc:
            raise ValueError(f"invalid reference count for {name!r}") from exc

        dependencies = (
            []
            if fields[3] == "-"
            else [dependency for dependency in fields[3].split(",") if dependency]
        )

        return KernelModule(
            name=name,
            state=ModuleState.LOADED,
            size=size,
            reference_count=reference_count,
            dependencies=dependencies,
            source="/proc/modules",
        )

    def _collect_builtin_modules(
        self,
        kernel_release: str,
    ) -> tuple[list[str], EvidenceSource | None, str | None]:
        """Read modules built directly into the running kernel."""
        path = Path(f"/lib/modules/{kernel_release}/modules.builtin")

        try:
            content = path.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            return (
                [],
                None,
                f"Built-in module metadata unavailable: {path}",
            )
        except PermissionError:
            return (
                [],
                None,
                f"Permission denied reading: {path}",
            )
        except OSError as exc:
            return (
                [],
                None,
                f"Unable to read {path}: {exc}",
            )

        builtin: list[str] = []

        for line in content.splitlines():
            normalized = line.strip()

            if not normalized:
                continue

            module_name = normalized.removesuffix(".ko").replace("/", ".")
            builtin.append(module_name)

        return (
            sorted(set(builtin)),
            EvidenceSource(
                path=str(path),
                description="Kernel components built into the kernel.",
            ),
            None,
        )
