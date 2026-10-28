"""Top-level KASA system evidence snapshot."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from kasa.collectors.filesystem import FilesystemInventory
from kasa.collectors.modules import ModuleInventory
from kasa.models.evidence import EvidenceItem, KernelSnapshot


class SystemSnapshot(BaseModel):
    """Complete normalized snapshot collected by KASA."""

    model_config = ConfigDict(extra="forbid")

    kernel: KernelSnapshot
    kernel_config: list[EvidenceItem] = Field(default_factory=list)
    modules: ModuleInventory
    filesystems: FilesystemInventory
    sysctl_params: list[EvidenceItem] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
