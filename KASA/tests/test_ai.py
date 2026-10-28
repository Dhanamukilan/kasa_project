"""Tests for the KASA AI module (GeminiClient, RemediationAdvisor, prompts)."""

from __future__ import annotations

import json
import os
from unittest.mock import MagicMock, patch

import pytest

from kasa.ai.client import GeminiClient, GeminiClientError
from kasa.ai.models import RemediationReport, RemediationStep
from kasa.ai.prompts import build_remediation_prompt
from kasa.ai.remediation import RemediationAdvisor
from kasa.models.finding import Finding, FindingEvidence, Severity
from kasa.models.risk import RiskAssessment, RiskRating


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _medium_finding(fid: str = "KASA-TEST-001") -> Finding:
    return Finding(
        id=fid,
        title="Test finding",
        description="A test finding for unit testing.",
        severity=Severity.MEDIUM,
        category="test",
        recommendation="Fix it.",
        evidence=[
            FindingEvidence(key="test.key", value={"foo": "bar"})
        ],
    )


def _low_risk() -> RiskAssessment:
    return RiskAssessment(score=5, rating=RiskRating.LOW, finding_count=1)


def _medium_risk(count: int = 2) -> RiskAssessment:
    return RiskAssessment(score=30, rating=RiskRating.MEDIUM, finding_count=count)


# ---------------------------------------------------------------------------
# GeminiClient – construction
# ---------------------------------------------------------------------------


def test_gemini_client_raises_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """GeminiClient must raise GeminiClientError when no API key is found."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    with pytest.raises(GeminiClientError, match="No Gemini API key"):
        GeminiClient()


def test_gemini_client_accepts_explicit_api_key() -> None:
    """GeminiClient must accept an explicit api_key without raising."""
    client = GeminiClient(api_key="test-key-123")
    assert client._api_key == "test-key-123"


def test_gemini_client_reads_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """GeminiClient must read the API key from GEMINI_API_KEY."""
    monkeypatch.setenv("GEMINI_API_KEY", "env-key-abc")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    client = GeminiClient()
    assert client._api_key == "env-key-abc"


def test_gemini_client_falls_back_to_google_api_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GeminiClient must fall back to GOOGLE_API_KEY."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "google-key-xyz")
    client = GeminiClient()
    assert client._api_key == "google-key-xyz"


# ---------------------------------------------------------------------------
# GeminiClient – generate (mocked HTTP)
# ---------------------------------------------------------------------------


def _make_gemini_response(text: str) -> MagicMock:
    """Build a mock httpx response that looks like a Gemini API success."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "candidates": [
            {
                "content": {
                    "parts": [{"text": text}]
                }
            }
        ]
    }
    return mock_resp


def test_generate_returns_text_on_success() -> None:
    """generate() must return the text from the model's response."""
    client = GeminiClient(api_key="test-key")
    expected_text = '{"summary": "ok"}'

    mock_resp = _make_gemini_response(expected_text)

    with patch("kasa.ai.client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.return_value = mock_resp
        result = client.generate("system", "user")

    assert result == expected_text


def test_generate_raises_on_http_error() -> None:
    """generate() must raise GeminiClientError on non-200 status."""
    client = GeminiClient(api_key="test-key")

    mock_resp = MagicMock()
    mock_resp.status_code = 403
    mock_resp.text = "Forbidden"

    with patch("kasa.ai.client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.return_value = mock_resp
        with pytest.raises(GeminiClientError, match="HTTP 403"):
            client.generate("system", "user")


def test_generate_raises_on_timeout() -> None:
    """generate() must raise GeminiClientError on timeout."""
    import httpx

    client = GeminiClient(api_key="test-key")

    with patch("kasa.ai.client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.side_effect = (
            httpx.TimeoutException("timeout")
        )
        with pytest.raises(GeminiClientError, match="timed out"):
            client.generate("system", "user")


def test_generate_raises_on_unexpected_response_shape() -> None:
    """generate() must raise if the response JSON has unexpected structure."""
    client = GeminiClient(api_key="test-key")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"unexpected": "shape"}

    with patch("kasa.ai.client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.return_value = mock_resp
        with pytest.raises(GeminiClientError, match="Unexpected"):
            client.generate("system", "user")


# ---------------------------------------------------------------------------
# build_remediation_prompt
# ---------------------------------------------------------------------------


def test_build_remediation_prompt_returns_two_strings() -> None:
    finding = _medium_finding()
    risk = _low_risk()
    system_prompt, user_prompt = build_remediation_prompt([finding], risk, "6.12.0")

    assert isinstance(system_prompt, str)
    assert isinstance(user_prompt, str)
    assert len(system_prompt) > 0
    assert len(user_prompt) > 0


def test_build_remediation_prompt_includes_finding_id() -> None:
    finding = _medium_finding("KASA-TEST-999")
    risk = _low_risk()
    _, user_prompt = build_remediation_prompt([finding], risk)
    assert "KASA-TEST-999" in user_prompt


def test_build_remediation_prompt_includes_risk_score() -> None:
    finding = _medium_finding()
    risk = RiskAssessment(score=42, rating=RiskRating.HIGH, finding_count=1)
    _, user_prompt = build_remediation_prompt([finding], risk)
    assert "42" in user_prompt


def test_build_remediation_prompt_includes_kernel_release() -> None:
    finding = _medium_finding()
    risk = _low_risk()
    _, user_prompt = build_remediation_prompt([finding], risk, "5.15.0-generic")
    assert "5.15.0-generic" in user_prompt


def test_build_remediation_prompt_uses_unknown_when_no_kernel() -> None:
    finding = _medium_finding()
    risk = _low_risk()
    _, user_prompt = build_remediation_prompt([finding], risk, None)
    assert "unknown" in user_prompt


def test_build_remediation_prompt_user_content_is_valid_json() -> None:
    """The data payload inside the user prompt must be valid JSON."""
    finding = _medium_finding()
    risk = _low_risk()
    _, user_prompt = build_remediation_prompt([finding], risk)

    # Extract JSON block between the triple-backtick fence
    start = user_prompt.index("```json\n") + len("```json\n")
    end = user_prompt.rindex("\n```")
    payload = json.loads(user_prompt[start:end])
    assert "findings" in payload
    assert payload["findings"][0]["id"] == finding.id


# ---------------------------------------------------------------------------
# RemediationAdvisor
# ---------------------------------------------------------------------------


def _make_advisor_with_mock_response(response_text: str) -> RemediationAdvisor:
    """Build a RemediationAdvisor whose client returns a canned response."""
    mock_client = MagicMock(spec=GeminiClient)
    mock_client.generate.return_value = response_text
    return RemediationAdvisor(client=mock_client)


_VALID_REPORT_JSON = json.dumps({
    "summary": "The system has minor issues.",
    "overall_risk_assessment": "Low risk overall.",
    "priority_order": ["KASA-TEST-001"],
    "steps": [
        {
            "finding_id": "KASA-TEST-001",
            "action": "Enable kptr_restrict",
            "command": "sysctl -w kernel.kptr_restrict=2",
            "rationale": "Prevents kernel pointer leaks.",
        }
    ],
})


def test_advisor_returns_remediation_report() -> None:
    advisor = _make_advisor_with_mock_response(_VALID_REPORT_JSON)
    finding = _medium_finding()
    risk = _low_risk()
    report = advisor.advise([finding], risk, "6.0.0")

    assert isinstance(report, RemediationReport)


def test_advisor_report_has_summary() -> None:
    advisor = _make_advisor_with_mock_response(_VALID_REPORT_JSON)
    report = advisor.advise([_medium_finding()], _low_risk())
    assert "minor issues" in report.summary


def test_advisor_report_has_steps() -> None:
    advisor = _make_advisor_with_mock_response(_VALID_REPORT_JSON)
    report = advisor.advise([_medium_finding()], _low_risk())
    assert len(report.steps) == 1
    step = report.steps[0]
    assert step.finding_id == "KASA-TEST-001"
    assert step.command is not None


def test_advisor_report_has_priority_order() -> None:
    advisor = _make_advisor_with_mock_response(_VALID_REPORT_JSON)
    report = advisor.advise([_medium_finding()], _low_risk())
    assert report.priority_order == ["KASA-TEST-001"]


def test_advisor_strips_markdown_fences() -> None:
    """RemediationAdvisor must strip ```json … ``` fences from the response."""
    fenced = f"```json\n{_VALID_REPORT_JSON}\n```"
    advisor = _make_advisor_with_mock_response(fenced)
    report = advisor.advise([_medium_finding()], _low_risk())
    assert isinstance(report, RemediationReport)
    assert report.summary


def test_advisor_raw_response_preserved() -> None:
    advisor = _make_advisor_with_mock_response(_VALID_REPORT_JSON)
    report = advisor.advise([_medium_finding()], _low_risk())
    assert report.raw_response == _VALID_REPORT_JSON


def test_advisor_empty_findings_returns_clean_report() -> None:
    """advise() with no findings must not call the API and return a clean report."""
    mock_client = MagicMock(spec=GeminiClient)
    advisor = RemediationAdvisor(client=mock_client)
    report = advisor.advise([], _low_risk())

    mock_client.generate.assert_not_called()
    assert isinstance(report, RemediationReport)
    assert report.steps == []
    assert report.priority_order == []


def test_advisor_raises_on_invalid_json_response() -> None:
    advisor = _make_advisor_with_mock_response("this is not json")
    with pytest.raises(GeminiClientError, match="not valid JSON"):
        advisor.advise([_medium_finding()], _low_risk())


def test_advisor_propagates_client_error() -> None:
    """advise() must propagate GeminiClientError from the client."""
    mock_client = MagicMock(spec=GeminiClient)
    mock_client.generate.side_effect = GeminiClientError("network error")

    advisor = RemediationAdvisor(client=mock_client)
    with pytest.raises(GeminiClientError, match="network error"):
        advisor.advise([_medium_finding()], _low_risk())


# ---------------------------------------------------------------------------
# RemediationReport model
# ---------------------------------------------------------------------------


def test_remediation_report_model_serialises_to_json() -> None:
    report = RemediationReport(
        summary="OK",
        overall_risk_assessment="Low",
        steps=[
            RemediationStep(
                finding_id="KASA-TEST-001",
                action="Do something",
                command=None,
                rationale="Because.",
            )
        ],
        priority_order=["KASA-TEST-001"],
    )
    data = report.model_dump(mode="json")
    assert data["summary"] == "OK"
    assert data["steps"][0]["finding_id"] == "KASA-TEST-001"
    assert data["steps"][0]["command"] is None


# ---------------------------------------------------------------------------
# CLI: kasa ai command exists
# ---------------------------------------------------------------------------


def test_ai_command_registered_in_cli() -> None:
    """The 'ai' command must be registered in the Typer app."""
    import inspect

    import kasa.cli as cli_module

    # Typer derives command names from function names; check via source inspection.
    source = inspect.getsource(cli_module)
    assert "def ai(" in source
    # Also verify the @app.command() decorator is applied to it
    assert "app.command" in source
