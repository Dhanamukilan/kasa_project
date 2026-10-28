"""Base interfaces for KASA security analyzers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from kasa.models.finding import Finding
from kasa.models.snapshot import SystemSnapshot


class Analyzer(ABC):
    """Base class for deterministic KASA analyzers."""

    @abstractmethod
    def analyze(self, snapshot: SystemSnapshot) -> list[Finding]:
        """Analyze collected evidence and return security findings."""
        raise NotImplementedError
