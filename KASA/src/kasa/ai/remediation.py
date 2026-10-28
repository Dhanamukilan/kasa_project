"""AI-powered remediation advisor for KASA findings."""

from __future__ import annotations

import json
from typing import Any

from kasa.ai.client import AIClient, AIClientError, GeminiClientError, create_client
from kasa.ai.models import AttackScenario, RemediationReport, RemediationStep
from kasa.ai.prompts import build_remediation_prompt
from kasa.models.finding import Finding
from kasa.models.risk import RiskAssessment


class RemediationAdvisor:
    """Orchestrate the full AI remediation pipeline.

    Takes a list of :class:`~kasa.models.finding.Finding` objects and a
    :class:`~kasa.models.risk.RiskAssessment`, calls the configured AI
    provider, parses the structured JSON response, and returns a
    :class:`~kasa.ai.models.RemediationReport`.

    Provider resolution is handled by :func:`~kasa.ai.client.create_client`:
    if neither *client* nor *provider* / *api_key* are given, it auto-detects
    the first available API key from the environment.
    """

    def __init__(
        self,
        client: AIClient | None = None,
        *,
        provider: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        if client is not None:
            self._client = client
            self._provider_name = "custom"
            self._model = model or "unknown"
        else:
            self._client, self._provider_name, self._model = create_client(
                provider=provider,
                model=model,
                api_key=api_key,
            )

    @property
    def provider_name(self) -> str:
        """The resolved provider name (e.g. ``'deepseek'``)."""
        return self._provider_name

    @property
    def model(self) -> str:
        """The resolved model id."""
        return self._model

    def advise(
        self,
        findings: list[Finding],
        risk: RiskAssessment,
        kernel_release: str | None = None,
    ) -> RemediationReport:
        """Generate a structured remediation report from KASA findings.

        Args:
            findings: Normalised list of security findings.
            risk: Overall risk assessment.
            kernel_release: Kernel release string (e.g. ``6.12.0-generic``).

        Returns:
            A :class:`RemediationReport` with prioritised remediation steps and attack scenarios.

        Raises:
            AIClientError: If the API call fails or the response is invalid.
        """
        if not findings:
            return RemediationReport(
                summary="No security findings were detected. The system appears well-hardened.",
                overall_risk_assessment=(
                    "No actionable findings were identified. Continue monitoring "
                    "for configuration drift."
                ),
                steps=[],
                priority_order=[],
                attack_scenarios=[],
                raw_response="",
            )

        system_prompt, user_prompt = build_remediation_prompt(
            findings, risk, kernel_release,
            local_model=(self._provider_name == "ollama"),
        )

        raw = self._client.generate(system_prompt, user_prompt)

        return self._parse_response(raw, findings)

    @staticmethod
    def _parse_response(raw: str, findings: list[Finding]) -> RemediationReport:
        """Parse the model's response into a :class:`RemediationReport`."""
        text = raw.strip()
        if text.startswith("```"):
            lines = text.splitlines()
            lines = lines[1:]  # drop opening fence
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]  # drop closing fence
            text = "\n".join(lines).strip()

        data: Any = None
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            # Try finding first { and last }
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    data = json.loads(text[start : end + 1])
                except json.JSONDecodeError:
                    data = None

            if data is None:
                # Fallback for local models that output markdown or conversational text
                lines = [line.strip() for line in raw.splitlines() if line.strip()]
                extracted_steps: list[RemediationStep] = []
                curr_action = ""
                for line in lines:
                    if line.startswith("#"):
                        curr_action = line.lstrip("# ").strip()
                    elif line.startswith(("-", "*", "1.", "2.", "3.", "4.", "5.")):
                        cleaned = line.lstrip("-*0123456789. ").strip()
                        fid = "GENERAL"
                        for f in findings:
                            if f.id in line or f.id.replace("KASA-", "") in line or f.category in line:
                                fid = f.id
                                break
                        extracted_steps.append(
                            RemediationStep(
                                finding_id=fid,
                                action=cleaned[:120],
                                command=None,
                                rationale=cleaned,
                            )
                        )
                    elif any(
                        line.startswith(cmd)
                        for cmd in ("echo", "sysctl", "mount", "modprobe", "setenforce", "systemctl", "sudo")
                    ):
                        extracted_steps.append(
                            RemediationStep(
                                finding_id="GENERAL",
                                action=curr_action or "Apply kernel hardening command",
                                command=line,
                                rationale="Extracted from local LLM response",
                            )
                        )
                        curr_action = ""

                if extracted_steps:
                    first_paragraph = raw.split("\n\n")[0] if "\n\n" in raw else raw[:300]
                    # One more attempt: look for a JSON fragment containing attack_scenarios
                    fallback_attacks: list[AttackScenario] = []
                    try:
                        start = raw.find("{")
                        end = raw.rfind("}")
                        if start != -1 and end != -1 and end > start:
                            partial = json.loads(raw[start : end + 1])
                            raw_atk = partial.get("attack_scenarios", [])
                            if isinstance(raw_atk, list):
                                for item in raw_atk:
                                    if isinstance(item, dict):
                                        affected = item.get("affected_findings", [])
                                        if not isinstance(affected, list):
                                            affected = [str(affected)]
                                        fallback_attacks.append(
                                            AttackScenario(
                                                name=str(item.get("name", "Attack Scenario")),
                                                description=str(item.get("description", "")),
                                                affected_findings=[str(x) for x in affected],
                                                likelihood=str(item.get("likelihood", "MEDIUM")).upper(),
                                                impact=str(item.get("impact", "")),
                                                attacker_profile=str(item.get("attacker_profile", "local")),
                                            )
                                        )
                    except (json.JSONDecodeError, Exception):
                        pass

                    return RemediationReport(
                        summary=first_paragraph[:250],
                        overall_risk_assessment="Hardening recommendations generated by local LLM.",
                        steps=extracted_steps,
                        priority_order=[s.finding_id for s in extracted_steps],
                        attack_scenarios=fallback_attacks,
                        raw_response=raw,
                    )
                raise AIClientError(
                    f"AI response is not valid JSON: {exc}\nRaw response:\n{raw[:500]}"
                ) from exc

        if not isinstance(data, dict):
            data = {"summary": "Analysis completed", "steps": data if isinstance(data, list) else []}

        finding_ids = {f.id for f in findings}

        # 1. Parse Steps
        steps: list[RemediationStep] = []
        raw_steps = data.get("steps", [])
        if isinstance(raw_steps, list):
            for item in raw_steps:
                if isinstance(item, dict):
                    fid = str(item.get("finding_id", ""))
                    steps.append(
                        RemediationStep(
                            finding_id=fid if fid in finding_ids else (fid or "GENERAL"),
                            action=str(item.get("action", "")),
                            command=item.get("command"),
                            rationale=str(item.get("rationale", "")),
                        )
                    )
                elif isinstance(item, str):
                    steps.append(
                        RemediationStep(
                            finding_id="GENERAL",
                            action=item,
                            command=None,
                            rationale="",
                        )
                    )

        # 2. Parse Attack Scenarios
        attack_scenarios: list[AttackScenario] = []
        raw_attacks = data.get("attack_scenarios", [])
        if isinstance(raw_attacks, list):
            for item in raw_attacks:
                if isinstance(item, dict):
                    affected = item.get("affected_findings", [])
                    if not isinstance(affected, list):
                        affected = [str(affected)]
                    attack_scenarios.append(
                        AttackScenario(
                            name=str(item.get("name", "Attack Scenario")),
                            description=str(item.get("description", "")),
                            affected_findings=[str(x) for x in affected],
                            likelihood=str(item.get("likelihood", "MEDIUM")).upper(),
                            impact=str(item.get("impact", "")),
                            attacker_profile=str(item.get("attacker_profile", "local")),
                        )
                    )
                elif isinstance(item, str):
                    attack_scenarios.append(
                        AttackScenario(
                            name="Potential Attack Vector",
                            description=item,
                            affected_findings=[],
                            likelihood="MEDIUM",
                            impact="System compromise / privilege escalation",
                            attacker_profile="local",
                        )
                    )

        # 3. Priority Order
        priority_order = data.get("priority_order", [])
        if not isinstance(priority_order, list):
            priority_order = []

        return RemediationReport(
            summary=str(data.get("summary", "")),
            overall_risk_assessment=str(data.get("overall_risk_assessment", "")),
            steps=steps,
            priority_order=[str(x) for x in priority_order],
            attack_scenarios=attack_scenarios,
            raw_response=raw,
        )
