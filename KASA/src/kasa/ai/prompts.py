"""Prompt construction for KASA AI remediation and attack analysis."""

from __future__ import annotations

import json

from kasa.models.finding import Finding
from kasa.models.risk import RiskAssessment


# ──────────────────────────────────────────────────────────────────
# Full system prompt — used for large cloud models (>7B params)
# that reliably follow complex JSON schema instructions.
# ──────────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """\
You are a senior Linux kernel security engineer AND an expert penetration tester.
You have been given a structured security analysis report produced by KASA
(Kernel Attack Surface Analyzer), which inspects a live Linux system and
produces deterministic security findings about its kernel configuration,
runtime state, loaded modules, filesystem mounts, and sysctl parameters.

Your task is to:
1. Review every security finding in the report.
2. Write a concise overall risk assessment a non-expert can understand.
3. For each finding, produce concrete actionable remediation steps with exact shell commands.
4. Rank findings by remediation priority (highest risk first).
5. Identify 2-5 REALISTIC attack scenarios — specific attack chains an attacker
   could execute against this system RIGHT NOW using the current findings.
   Think offensively:
   - ptrace_scope=0 → any user process can be debugged → memory dumped → secrets stolen
   - kptr_restrict not 2 → /proc/kallsyms leaks kernel symbols → KASLR bypass
   - modules unsigned → malicious LKM can be loaded → rootkit / privilege escalation
   - rp_filter off → IP spoofing → ARP/routing attacks possible
   Chain findings together for multi-step attack paths.

Return ONLY valid JSON with this exact schema — no markdown, no extra text:

{
  "summary": "<1-2 sentence executive summary>",
  "overall_risk_assessment": "<paragraph explaining the combined risk in plain English>",
  "priority_order": ["<finding_id_1>", "<finding_id_2>", ...],
  "steps": [
    {
      "finding_id": "<KASA-RULE-ID>",
      "action": "<what to do in plain English>",
      "command": "<exact shell command, or null>",
      "rationale": "<why this matters>"
    }
  ],
  "attack_scenarios": [
    {
      "name": "<short attack name, e.g. 'KASLR Bypass via Kernel Symbol Leak'>",
      "description": "<step-by-step: what attacker does, what tool/syscall they use, what they gain>",
      "affected_findings": ["<KASA-RULE-ID>", ...],
      "likelihood": "<LOW|MEDIUM|HIGH|CRITICAL>",
      "impact": "<what happens: privilege escalation / data theft / rootkit / DoS / etc>",
      "attacker_profile": "<local|remote|both>"
    }
  ]
}
"""


# ──────────────────────────────────────────────────────────────────
# Simplified prompt — used for small local models (Ollama / <=7B)
# Uses a concrete multi-scenario example so the model copies the schema.
# ──────────────────────────────────────────────────────────────────
_LOCAL_SYSTEM_PROMPT = """\
You are a Linux kernel security expert and penetration tester. \
Analyse ALL the security findings provided and return ONLY a JSON object. \
Do not include markdown, code fences, or any text outside the JSON.

IMPORTANT: You MUST create one attack_scenario entry for EACH finding. \
Cover every finding_id in both the steps and attack_scenarios arrays.

REQUIRED JSON format (copy this exact structure, but expand for ALL findings):
{
  "summary": "one sentence executive summary of overall risk",
  "overall_risk_assessment": "two sentences describing the combined risk in plain English",
  "priority_order": ["FINDING-ID-1", "FINDING-ID-2", "FINDING-ID-3"],
  "steps": [
    {
      "finding_id": "FINDING-ID-1",
      "action": "what to do to fix this",
      "command": "sysctl -w kernel.kptr_restrict=2",
      "rationale": "why this fixes the risk"
    },
    {
      "finding_id": "FINDING-ID-2",
      "action": "what to do to fix this",
      "command": "sysctl -w kernel.yama.ptrace_scope=1",
      "rationale": "why this fixes the risk"
    }
  ],
  "attack_scenarios": [
    {
      "name": "KASLR Bypass via Kernel Symbol Leak",
      "description": "Attacker reads /proc/kallsyms to get kernel addresses, bypassing ASLR to craft exploits",
      "affected_findings": ["FINDING-ID-1"],
      "likelihood": "HIGH",
      "impact": "privilege escalation through kernel exploits",
      "attacker_profile": "local"
    },
    {
      "name": "Process Memory Theft via Ptrace",
      "description": "Attacker attaches to sensitive process using ptrace, dumps memory to steal credentials",
      "affected_findings": ["FINDING-ID-2"],
      "likelihood": "MEDIUM",
      "impact": "credential theft and lateral movement",
      "attacker_profile": "local"
    },
    {
      "name": "Network Spoofing Attack",
      "description": "Attacker sends spoofed IP packets to intercept traffic due to disabled reverse-path filtering",
      "affected_findings": ["FINDING-ID-3"],
      "likelihood": "MEDIUM",
      "impact": "network traffic interception",
      "attacker_profile": "remote"
    }
  ]
}
"""


def build_remediation_prompt(
    findings: list[Finding],
    risk: RiskAssessment,
    kernel_release: str | None = None,
    local_model: bool = False,
) -> tuple[str, str]:
    """Build system and user prompts for KASA AI analysis.

    Args:
        findings: List of security findings.
        risk: Overall risk assessment object.
        kernel_release: Kernel version string.
        local_model: If True, use the simplified prompt for small local models.

    Returns a ``(system_prompt, user_prompt)`` tuple.
    """
    findings_payload = [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]

    user_data: dict[str, object] = {
        "kernel": kernel_release or "unknown",
        "risk_score": risk.score,
        "risk_rating": risk.rating.value,
        "findings": findings_payload,
    }

    if local_model:
        finding_ids = [f.id for f in findings]
        user_prompt = (
            f"Analyse ALL {len(findings)} security findings below. "
            f"Create one remediation step AND one attack scenario for EACH finding.\n"
            f"Finding IDs to cover: {finding_ids}\n\n"
            f"{json.dumps(user_data, indent=2)}\n\n"
            "Return ONLY the JSON response covering every finding_id listed above."
        )
        return _LOCAL_SYSTEM_PROMPT, user_prompt

    # Compact payload for cloud models — strips raw evidence blobs that balloon
    # the prompt to 16k+ tokens and blow the free-tier credit limit.
    compact_findings_payload = [
        {
            "id": f.id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.value,
            "category": f.category,
            "recommendation": f.recommendation,
        }
        for f in findings
    ]

    full_data: dict[str, object] = {
        "kernel_release": kernel_release or "unknown",
        "risk_score": risk.score,
        "risk_rating": risk.rating.value,
        "finding_count": risk.finding_count,
        "findings": compact_findings_payload,
    }

    user_prompt = (
        "Analyse the KASA security findings below. "
        "Produce a prioritised remediation plan AND identify all realistic "
        "attack scenarios an attacker could chain from these findings against "
        "this live Linux system right now.\n\n"
        f"```json\n{json.dumps(full_data, indent=2)}\n```"
    )

    return _SYSTEM_PROMPT, user_prompt
