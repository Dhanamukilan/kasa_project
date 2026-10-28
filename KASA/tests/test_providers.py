"""Tests for the multi-provider AI system."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from kasa.ai.client import (
    AIClient,
    AIClientError,
    GeminiClient,
    GeminiClientError,
    create_client,
)
from kasa.ai.compat_client import OpenAICompatibleClient, OpenAIClientError
from kasa.ai.providers import (
    PROVIDERS,
    auto_detect,
    detect_provider_from_key,
    get_provider,
    list_providers,
    resolve_model_alias,
)
from kasa.ai.remediation import RemediationAdvisor
from kasa.models.finding import Finding, FindingEvidence, Severity
from kasa.models.risk import RiskAssessment, RiskRating


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _finding(fid: str = "KASA-TEST-001") -> Finding:
    return Finding(
        id=fid,
        title="Test finding",
        description="A unit-test finding.",
        severity=Severity.MEDIUM,
        category="test",
        recommendation="Fix it.",
        evidence=[FindingEvidence(key="test.key", value={"x": 1})],
    )


def _risk() -> RiskAssessment:
    return RiskAssessment(score=15, rating=RiskRating.MEDIUM, finding_count=1)


_VALID_JSON = json.dumps({
    "summary": "All good.",
    "overall_risk_assessment": "Low risk.",
    "priority_order": ["KASA-TEST-001"],
    "steps": [
        {
            "finding_id": "KASA-TEST-001",
            "action": "Do the thing",
            "command": "sysctl -w kernel.kptr_restrict=2",
            "rationale": "Because security.",
        }
    ],
})


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------


def test_provider_list_is_non_empty() -> None:
    assert len(PROVIDERS) >= 5


def test_all_providers_have_required_fields() -> None:
    for p in PROVIDERS:
        assert p.name
        assert p.label
        assert p.base_url
        assert p.env_vars
        assert p.default_model
        assert p.protocol in ("openai", "gemini")


def test_get_provider_returns_config() -> None:
    p = get_provider("deepseek")
    assert p is not None
    assert p.name == "deepseek"


def test_get_provider_is_case_insensitive() -> None:
    p = get_provider("DeepSeek")
    assert p is not None


def test_get_provider_returns_none_for_unknown() -> None:
    assert get_provider("nonexistent_xyz") is None


# ---------------------------------------------------------------------------
# Model aliases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "alias, expected_provider, expected_model_fragment",
    [
        ("qwen3-235b",        "openrouter", "qwen3-235b"),
        ("qwen3.6-227b",      "openrouter", "qwen3-235b"),
        ("deepseek-v3",       "deepseek",   "deepseek-chat"),
        ("deepseek-v4-flash", "deepseek",   "deepseek-chat"),
        ("deepseek-r1",       "deepseek",   "deepseek-reasoner"),
        ("gemini-flash",      "gemini",     "gemini-2.0-flash"),
        ("qwen3-4b",          "ollama",     "qwen2.5:3b"),
        ("ollama",            "ollama",     "qwen2.5:3b"),
    ],
)
def test_resolve_model_alias(
    alias: str, expected_provider: str, expected_model_fragment: str
) -> None:
    result = resolve_model_alias(alias)
    assert result is not None, f"Alias '{alias}' not found"
    provider_name, model_id = result
    assert provider_name == expected_provider
    assert expected_model_fragment in model_id


def test_unknown_alias_returns_none() -> None:
    assert resolve_model_alias("totally-unknown-model-xyz") is None


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------


def test_auto_detect_deepseek_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """DeepSeek key must be detected first when all keys are present."""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-key-abc")
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-xyz")
    monkeypatch.setenv("GEMINI_API_KEY", "gm-key-123")

    result = auto_detect()
    assert result is not None
    provider, key = result
    assert provider.name == "deepseek"
    assert key == "ds-key-abc"


def test_auto_detect_openrouter_when_deepseek_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-xyz")
    monkeypatch.delenv("TOGETHER_API_KEY", raising=False)
    monkeypatch.delenv("TOGETHER_AI_API_KEY", raising=False)
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    result = auto_detect()
    assert result is not None
    provider, key = result
    assert provider.name == "openrouter"
    assert key == "or-key-xyz"


def test_auto_detect_together_key(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in ["DEEPSEEK_API_KEY", "OPENROUTER_API_KEY", "FIREWORKS_API_KEY",
              "GEMINI_API_KEY", "GOOGLE_API_KEY"]:
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("TOGETHER_API_KEY", "ta-key-abc")

    result = auto_detect()
    assert result is not None
    assert result[0].name == "together"


def test_auto_detect_fireworks_key(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in ["DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
              "TOGETHER_API_KEY", "TOGETHER_AI_API_KEY",
              "GEMINI_API_KEY", "GOOGLE_API_KEY"]:
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-key-abc")

    result = auto_detect()
    assert result is not None
    assert result[0].name == "fireworks"


def test_auto_detect_gemini_last_resort(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in ["DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
              "TOGETHER_API_KEY", "TOGETHER_AI_API_KEY",
              "FIREWORKS_API_KEY", "GOOGLE_API_KEY"]:
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gm-key-abc")

    result = auto_detect()
    assert result is not None
    assert result[0].name == "gemini"


def test_auto_detect_returns_none_when_no_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in ["KASA_API_KEY", "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
              "TOGETHER_API_KEY", "TOGETHER_AI_API_KEY",
              "FIREWORKS_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"]:
        monkeypatch.delenv(v, raising=False)

    assert auto_detect() is None


def test_detect_provider_from_key() -> None:
    """detect_provider_from_key must deduce provider from key prefixes."""
    assert detect_provider_from_key("AIzaSyB1234567890abcdef") is not None
    assert detect_provider_from_key("AIzaSyB1234567890abcdef").name == "gemini"

    assert detect_provider_from_key("sk-or-v1-abcdef1234567890") is not None
    assert detect_provider_from_key("sk-or-v1-abcdef1234567890").name == "openrouter"

    assert detect_provider_from_key("fw_3ZX1234567890abcdef") is not None
    assert detect_provider_from_key("fw_3ZX1234567890abcdef").name == "fireworks"

    assert detect_provider_from_key("sk-abcdef123456789012345678") is not None
    assert detect_provider_from_key("sk-abcdef123456789012345678").name == "deepseek"

    assert detect_provider_from_key("0123456789abcdef0123456789abcdef01234567") is not None
    assert detect_provider_from_key("0123456789abcdef0123456789abcdef01234567").name == "together"


def test_auto_detect_kasa_api_key_universal(monkeypatch: pytest.MonkeyPatch) -> None:
    """KASA_API_KEY should auto-detect the provider based on its format."""
    for v in ["DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
              "TOGETHER_API_KEY", "TOGETHER_AI_API_KEY",
              "FIREWORKS_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"]:
        monkeypatch.delenv(v, raising=False)

    # Gemini key via KASA_API_KEY
    monkeypatch.setenv("KASA_API_KEY", "AIzaSyTestKey123")
    res = auto_detect()
    assert res is not None
    assert res[0].name == "gemini"
    assert res[1] == "AIzaSyTestKey123"

    # OpenRouter key via KASA_API_KEY
    monkeypatch.setenv("KASA_API_KEY", "sk-or-v1-testkey123")
    res = auto_detect()
    assert res is not None
    assert res[0].name == "openrouter"

    # DeepSeek key via KASA_API_KEY
    monkeypatch.setenv("KASA_API_KEY", "sk-deepseektestkey123")
    res = auto_detect()
    assert res is not None
    assert res[0].name == "deepseek"


# ---------------------------------------------------------------------------
# list_providers
# ---------------------------------------------------------------------------


def test_list_providers_returns_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    info = list_providers()
    assert len(info) == len(PROVIDERS)
    names = [p["name"] for p in info]
    assert "deepseek" in names
    assert "openrouter" in names
    assert "gemini" in names


def test_list_providers_marks_available(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "test-key")
    info = list_providers()
    ds = next(p for p in info if p["name"] == "deepseek")
    assert ds["available"] is True
    assert ds["key_preview"] is not None


def test_list_providers_marks_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    info = list_providers()
    ds = next(p for p in info if p["name"] == "deepseek")
    assert ds["available"] is False


# ---------------------------------------------------------------------------
# create_client — factory
# ---------------------------------------------------------------------------


def _mock_openai_response(text: str) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}]
    }
    return resp


def test_create_client_with_deepseek_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-test-key")
    for v in ["OPENROUTER_API_KEY", "TOGETHER_API_KEY", "TOGETHER_AI_API_KEY",
              "FIREWORKS_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"]:
        monkeypatch.delenv(v, raising=False)

    client, provider_name, model = create_client()
    assert provider_name == "deepseek"
    assert isinstance(client, OpenAICompatibleClient)


def test_create_client_explicit_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-test-key")
    client, provider_name, model = create_client(provider="openrouter")
    assert provider_name == "openrouter"


def test_create_client_model_alias_deepseek_v4(monkeypatch: pytest.MonkeyPatch) -> None:
    """deepseek-v4-flash alias must resolve to deepseek provider."""
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-key")
    client, provider_name, model = create_client(model="deepseek-v4-flash")
    assert provider_name == "deepseek"
    assert "deepseek-chat" in model


def test_create_client_model_alias_qwen3(monkeypatch: pytest.MonkeyPatch) -> None:
    """qwen3.6-227b alias must resolve to openrouter with Qwen3-235B model."""
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key")
    client, provider_name, model = create_client(model="qwen3.6-227b")
    assert provider_name == "openrouter"
    assert "qwen3-235b" in model


def test_create_client_raises_when_no_key(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in ["DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
              "TOGETHER_API_KEY", "TOGETHER_AI_API_KEY",
              "FIREWORKS_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"]:
        monkeypatch.delenv(v, raising=False)

    with pytest.raises(AIClientError, match="No AI API key"):
        create_client()


def test_create_client_raises_for_unknown_provider() -> None:
    with pytest.raises(AIClientError, match="Unknown provider"):
        create_client(provider="unknown_xyz", api_key="test")


# ---------------------------------------------------------------------------
# OpenAICompatibleClient — HTTP (mocked)
# ---------------------------------------------------------------------------


def test_compat_client_returns_text_on_success() -> None:
    client = OpenAICompatibleClient(
        api_key="test-key",
        base_url="https://api.deepseek.com/v1",
        model="deepseek-chat",
    )
    with patch("kasa.ai.compat_client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.return_value = (
            _mock_openai_response(_VALID_JSON)
        )
        result = client.generate("system", "user")

    assert result == _VALID_JSON


def test_compat_client_raises_on_http_error() -> None:
    client = OpenAICompatibleClient(
        api_key="test-key",
        base_url="https://api.deepseek.com/v1",
        model="deepseek-chat",
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_resp.text = "Unauthorized"

    with patch("kasa.ai.compat_client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.return_value = mock_resp
        with pytest.raises(OpenAIClientError, match="HTTP 401"):
            client.generate("system", "user")


def test_compat_client_raises_on_timeout() -> None:
    import httpx

    client = OpenAICompatibleClient(
        api_key="test-key",
        base_url="https://api.deepseek.com/v1",
        model="deepseek-chat",
    )
    with patch("kasa.ai.compat_client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.side_effect = (
            httpx.TimeoutException("timeout")
        )
        with pytest.raises(OpenAIClientError, match="timed out"):
            client.generate("system", "user")


def test_compat_client_raises_on_content_filter() -> None:
    client = OpenAICompatibleClient(
        api_key="test-key",
        base_url="https://api.deepseek.com/v1",
        model="deepseek-chat",
    )
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"finish_reason": "content_filter", "message": {"content": ""}}]
    }

    with patch("kasa.ai.compat_client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.return_value = mock_resp
        with pytest.raises(OpenAIClientError, match="content filter"):
            client.generate("system", "user")


# ---------------------------------------------------------------------------
# RemediationAdvisor — multi-provider
# ---------------------------------------------------------------------------


def test_advisor_auto_detects_deepseek(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-key-test")
    for v in ["OPENROUTER_API_KEY", "TOGETHER_API_KEY", "TOGETHER_AI_API_KEY",
              "FIREWORKS_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"]:
        monkeypatch.delenv(v, raising=False)

    with patch("kasa.ai.compat_client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.return_value = (
            _mock_openai_response(_VALID_JSON)
        )
        advisor = RemediationAdvisor()
        assert advisor.provider_name == "deepseek"
        report = advisor.advise([_finding()], _risk())

    assert report.summary == "All good."


def test_advisor_explicit_provider_openrouter(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-test")

    with patch("kasa.ai.compat_client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.return_value = (
            _mock_openai_response(_VALID_JSON)
        )
        advisor = RemediationAdvisor(provider="openrouter")
        assert advisor.provider_name == "openrouter"


def test_advisor_model_alias_qwen3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "or-key-test")

    with patch("kasa.ai.compat_client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.return_value = (
            _mock_openai_response(_VALID_JSON)
        )
        advisor = RemediationAdvisor(model="qwen3.6-227b")
        assert advisor.provider_name == "openrouter"
        assert "qwen3-235b" in advisor.model


def test_advisor_model_alias_deepseek_v4_flash(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "ds-key-test")

    with patch("kasa.ai.compat_client.httpx.Client") as mock_httpx:
        mock_httpx.return_value.__enter__.return_value.post.return_value = (
            _mock_openai_response(_VALID_JSON)
        )
        advisor = RemediationAdvisor(model="deepseek-v4-flash")
        assert advisor.provider_name == "deepseek"


def test_advisor_raises_when_no_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    for v in ["DEEPSEEK_API_KEY", "OPENROUTER_API_KEY",
              "TOGETHER_API_KEY", "TOGETHER_AI_API_KEY",
              "FIREWORKS_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"]:
        monkeypatch.delenv(v, raising=False)

    with pytest.raises(AIClientError):
        RemediationAdvisor()


# ---------------------------------------------------------------------------
# Backward-compat — old GeminiClientError is still AIClientError
# ---------------------------------------------------------------------------


def test_gemini_client_error_is_ai_client_error() -> None:
    assert GeminiClientError is AIClientError


# ---------------------------------------------------------------------------
# CLI — kasa providers command
# ---------------------------------------------------------------------------


def test_providers_command_exists_in_cli() -> None:
    import inspect
    import kasa.cli as cli_module

    source = inspect.getsource(cli_module)
    assert "def providers(" in source


def test_ai_command_has_provider_flag() -> None:
    import inspect
    import kasa.cli as cli_module

    source = inspect.getsource(cli_module)
    assert "--provider" in source


def test_ai_command_has_model_flag() -> None:
    import inspect
    import kasa.cli as cli_module

    source = inspect.getsource(cli_module)
    assert "--model" in source
