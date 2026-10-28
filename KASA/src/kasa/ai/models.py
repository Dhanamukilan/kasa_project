"""Pydantic models for AI remediation and attack analysis responses."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class RemediationStep(BaseModel):
    """A single actionable remediation step."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    action: str
    command: str | None = None
    rationale: str


class AttackScenario(BaseModel):
    """A potential attack scenario enabled by one or more security findings."""

    model_config = ConfigDict(extra="forbid")

    name: str
    """Short attack name (e.g. 'Kernel Pointer Leak via /proc/kallsyms')."""

    description: str
    """Step-by-step explanation of how an attacker exploits this."""

    affected_findings: list[str] = Field(
        default_factory=list,
        description="KASA finding IDs that enable this attack.",
    )

    likelihood: str
    """LOW / MEDIUM / HIGH / CRITICAL."""

    impact: str
    """Consequence if exploited (e.g. 'privilege escalation', 'data exfiltration')."""

    attacker_profile: str = "local"
    """'local', 'remote', or 'both'."""


class RemediationReport(BaseModel):
    """Structured AI-generated remediation and attack analysis report."""

    model_config = ConfigDict(extra="forbid")

    summary: str
    overall_risk_assessment: str
    steps: list[RemediationStep] = Field(default_factory=list)
    priority_order: list[str] = Field(
        default_factory=list,
        description="Finding IDs ordered from highest to lowest remediation priority.",
    )
    attack_scenarios: list[AttackScenario] = Field(
        default_factory=list,
        description="Potential attack scenarios enabled by current findings.",
    )
    raw_response: str = Field(
        default="",
        description="Raw text response from the AI model.",
    )
