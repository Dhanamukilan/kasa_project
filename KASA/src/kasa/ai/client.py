"""Unified AI client factory for KASA.

This module exposes a single ``create_client()`` factory that auto-detects
the appropriate provider from environment variables or key format and returns a client
with a uniform ``generate(system_prompt, user_prompt) -> str`` interface.

Supported environment variables:
    KASA_API_KEY            — Universal key (auto-detects provider from key format)
    DEEPSEEK_API_KEY        — DeepSeek (V3 / R1)
    OPENROUTER_API_KEY      — OpenRouter (Qwen3, DeepSeek, Llama, …)
    TOGETHER_API_KEY        — Together AI
    TOGETHER_AI_API_KEY     — Together AI (alternate)
    FIREWORKS_API_KEY       — Fireworks AI
    GEMINI_API_KEY          — Google Gemini
    GOOGLE_API_KEY          — Google Gemini (alternate)
"""

from __future__ import annotations

import json
import os
from typing import Any, Protocol, runtime_checkable

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False

from kasa.ai.providers import (
    ProviderConfig,
    auto_detect,
    detect_provider_from_key,
    get_provider,
    resolve_model_alias,
)


# ---------------------------------------------------------------------------
# Shared error type
# ---------------------------------------------------------------------------


class AIClientError(Exception):
    """Raised when any AI API call fails or is misconfigured."""


# Keep the old name as an alias so existing tests/imports don't break.
GeminiClientError = AIClientError


# ---------------------------------------------------------------------------
# Protocol — any client must implement generate()
# ---------------------------------------------------------------------------


@runtime_checkable
class AIClient(Protocol):
    """Protocol satisfied by GeminiClient and OpenAICompatibleClient."""

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_output_tokens: int = 8192,
    ) -> str: ...


# ---------------------------------------------------------------------------
# Gemini native client
# ---------------------------------------------------------------------------


class GeminiClient:
    """Native Google Gemini REST client (non-OpenAI protocol).

    Prefer :func:`create_client` over instantiating this directly.
    """

    _BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"
    _DEFAULT_MODEL = "gemini-2.0-flash"
    _TIMEOUT = 60.0

    def __init__(
        self,
        api_key: str | None = None,
        model: str = _DEFAULT_MODEL,
        timeout: float = _TIMEOUT,
    ) -> None:
        if not _HTTPX_AVAILABLE:
            raise AIClientError(
                "The 'httpx' package is required for AI features. "
                "Install it with: pip install 'kasa[ai]'"
            )

        resolved_key = (
            api_key
            or os.environ.get("GEMINI_API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
            or os.environ.get("KASA_API_KEY")
        )

        if not resolved_key:
            raise AIClientError(
                "No Gemini API key found. Set the GEMINI_API_KEY environment "
                "variable or pass api_key= explicitly.\n\n"
                "Get a free key at: https://aistudio.google.com/apikey"
            )

        self._api_key = resolved_key
        self._model = model
        self._timeout = timeout

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_output_tokens: int = 8192,
    ) -> str:
        """Call Gemini generateContent and return the text response."""
        url = f"{self._BASE_URL}/{self._model}:generateContent"
        params = {"key": self._api_key}

        payload: dict[str, Any] = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_output_tokens,
                "responseMimeType": "application/json",
            },
            "safetySettings": [
                {
                    "category": "HARM_CATEGORY_DANGEROUS_CONTENT",
                    "threshold": "BLOCK_NONE",
                },
            ],
        }

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(url, params=params, json=payload)
        except httpx.TimeoutException as exc:
            raise AIClientError(
                f"Gemini API request timed out after {self._timeout}s: {exc}"
            ) from exc
        except httpx.RequestError as exc:
            raise AIClientError(
                f"Network error communicating with Gemini API: {exc}"
            ) from exc

        if response.status_code != 200:
            raise AIClientError(
                f"Gemini API returned HTTP {response.status_code}: {response.text[:500]}"
            )

        try:
            data = response.json()
        except Exception as exc:
            raise AIClientError(
                f"Failed to parse Gemini API response as JSON: {exc}"
            ) from exc

        try:
            text: str = data["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise AIClientError(
                f"Unexpected Gemini API response structure: {exc}\n"
                f"Response: {json.dumps(data, indent=2)[:1000]}"
            ) from exc

        return text


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_client(
    *,
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> tuple[AIClient, str, str]:
    """Create and return the best available AI client.

    Resolution order:
    1. If *model* is a known alias (e.g. ``qwen3-235b``, ``deepseek-v4-flash``),
       the alias determines both provider and canonical model id.
    2. If *provider* is given explicitly, that provider is used.
    3. If *api_key* is passed directly, detect the provider from the key format.
    4. Otherwise, environment variables are scanned in priority order:
       KASA_API_KEY (universal key) → DeepSeek → OpenRouter → Together → Fireworks → Gemini.
    5. *api_key* always overrides the environment variable for the resolved provider.

    Args:
        provider:  Provider name (``'deepseek'``, ``'openrouter'``, ``'together'``,
                   ``'fireworks'``, ``'gemini'``).  Auto-detected when omitted.
        model:     Model id or alias.  Uses the provider's default when omitted.
        api_key:   Explicit API key; falls back to env var when omitted.

    Returns:
        ``(client, provider_name, model_id)`` tuple.

    Raises:
        AIClientError: When no API key can be found anywhere.
    """
    from kasa.ai.compat_client import OpenAICompatibleClient

    resolved_provider: ProviderConfig | None = None
    resolved_model: str | None = model
    resolved_key: str | None = api_key

    # Step 1 – resolve model alias → (provider, model)
    if model:
        alias_result = resolve_model_alias(model)
        if alias_result:
            alias_provider_name, resolved_model = alias_result
            if resolved_provider is None and provider is None:
                resolved_provider = get_provider(alias_provider_name)

    # Step 2 – explicit provider override
    if provider and resolved_provider is None:
        resolved_provider = get_provider(provider)
        if resolved_provider is None:
            known = ", ".join(p.name for p in __import__(
                "kasa.ai.providers", fromlist=["PROVIDERS"]
            ).PROVIDERS)
            raise AIClientError(
                f"Unknown provider '{provider}'. Known providers: {known}"
            )

    # Step 3 – if explicit api_key was provided without a provider, detect provider from key format
    if resolved_key and resolved_provider is None:
        key_detected = detect_provider_from_key(resolved_key)
        if key_detected is not None:
            resolved_provider = key_detected

    # Step 4 – auto-detect from environment (including KASA_API_KEY)
    if resolved_provider is None:
        detected = auto_detect()
        if detected is None and resolved_key is None:
            raise AIClientError(
                "No AI API key found in the environment.\n\n"
                "You can provide a single key using any of:\n"
                "  export KASA_API_KEY=\"your-key\"        (auto-detects provider from key)\n"
                "  export DEEPSEEK_API_KEY=\"sk-...\"      (DeepSeek V3 / R1)\n"
                "  export OPENROUTER_API_KEY=\"sk-or-...\" (OpenRouter / Qwen3)\n"
                "  export TOGETHER_API_KEY=\"...\"         (Together AI)\n"
                "  export FIREWORKS_API_KEY=\"fw_...\"     (Fireworks AI)\n"
                "  export GEMINI_API_KEY=\"AIza...\"       (Google Gemini)\n\n"
                "Or pass it directly: kasa ai --api-key \"your-key\""
            )
        if detected is not None:
            resolved_provider, auto_key = detected
            if resolved_key is None:
                resolved_key = auto_key
        else:
            # resolved_key is present but provider wasn't recognized; default to deepseek
            resolved_provider = get_provider("deepseek")

    if resolved_provider is None:
        resolved_provider = get_provider("deepseek")

    if resolved_key is None:
        # Resolve key from env for the explicit provider
        for env_var in resolved_provider.env_vars:
            val = os.environ.get(env_var, "").strip()
            if val:
                resolved_key = val
                break
        if resolved_key is None:
            # Also check KASA_API_KEY as fallback
            val = os.environ.get("KASA_API_KEY", "").strip()
            if val:
                resolved_key = val

    if resolved_key is None:
        if resolved_provider.name == "ollama":
            resolved_key = "ollama"
        else:
            env_var_list = " / ".join(resolved_provider.env_vars + ["KASA_API_KEY"])
            raise AIClientError(
                f"No API key found for provider '{resolved_provider.name}'. "
                f"Set {env_var_list} or use --api-key."
            )

    # Step 5 – use provider default model if not set
    if resolved_model is None:
        resolved_model = resolved_provider.default_model

    # Step 6 – instantiate the right client type
    if resolved_provider.protocol == "gemini":
        client: AIClient = GeminiClient(api_key=resolved_key, model=resolved_model)
    else:
        # Ollama supports a native `format: json` field that forces JSON output
        # from local models that otherwise ignore prompt-based format instructions.
        force_json = resolved_provider.name == "ollama"
        client = OpenAICompatibleClient(
            api_key=resolved_key,
            base_url=resolved_provider.base_url,
            model=resolved_model,
            force_json=force_json,
        )

    return client, resolved_provider.name, resolved_model
