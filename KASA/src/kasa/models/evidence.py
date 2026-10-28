"""Evidence models collected from a Linux kernel."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvidenceStatus(StrEnum):
    """Status of an evidence collection operation."""

    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


class EvidenceSource(BaseModel):
    """Provenance information for collected evidence."""

    model_config = ConfigDict(extra="forbid")

    path: str
    description: str | None = None


class EvidenceItem(BaseModel):
    """A single normalized piece of kernel evidence."""

    model_config = ConfigDict(extra="forbid")

    key: str
    value: Any
    status: EvidenceStatus
    source: EvidenceSource
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
    )
    error: str | None = None


class KernelInfo(BaseModel):
    """Information describing the currently running kernel."""

    model_config = ConfigDict(extra="forbid")

    release: str
    version: str
    machine: str
    node: str
    system: str
    processor: str


class KernelSnapshot(BaseModel):
    """Normalized snapshot of kernel-level evidence."""

    model_config = ConfigDict(extra="forbid")

    kernel: KernelInfo
    command_line: str | None = None
    lockdown: str | None = None
    evidence: list[EvidenceItem] = Field(default_factory=list)
    collection_errors: list[str] = Field(default_factory=list)
