"""Risk assessment models for KASA."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class RiskRating(StrEnum):
    """Overall KASA risk rating."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessment(BaseModel):
    """Overall risk assessment produced from security findings."""

    model_config = ConfigDict(extra="forbid")

    score: int
    rating: RiskRating
    finding_count: int
