"""System-wide KASA evidence collector."""

from __future__ import annotations

from kasa.collectors.config import KernelConfigCollector
from kasa.collectors.filesystem import FilesystemCollector
from kasa.collectors.kernel import KernelCollector
from kasa.collectors.modules import ModuleCollector
from kasa.collectors.sysctl import SysctlCollector
from kasa.models.snapshot import SystemSnapshot


class SystemCollector:
    """Collect all supported KASA system evidence."""

    def __init__(self) -> None:
        self.kernel = KernelCollector()
        self.kernel_config = KernelConfigCollector()
        self.modules = ModuleCollector()
        self.filesystems = FilesystemCollector()
        self.sysctl = SysctlCollector()

    def collect(self) -> SystemSnapshot:
        """Collect a complete system snapshot."""
        errors: list[str] = []

        kernel_snapshot = self.kernel.collect()

        kernel_config = self.kernel_config.collect(kernel_snapshot.kernel.release)

        module_inventory = self.modules.collect(kernel_snapshot.kernel.release)

        filesystem_inventory = self.filesystems.collect()

        sysctl_params = self.sysctl.collect()

        errors.extend(kernel_snapshot.collection_errors)
        errors.extend(module_inventory.errors)

        return SystemSnapshot(
            kernel=kernel_snapshot,
            kernel_config=kernel_config,
            modules=module_inventory,
            filesystems=filesystem_inventory,
            sysctl_params=sysctl_params,
            errors=errors,
        )
