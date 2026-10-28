"""OpenAI-compatible API client for KASA AI remediation.

Works with any provider that exposes an OpenAI-compatible /chat/completions
endpoint — including DeepSeek, OpenRouter, Together AI, Fireworks AI, and
local Ollama models.
"""

from __future__ import annotations

import json
from typing import Any

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False


class OpenAIClientError(Exception):
    """Raised when an OpenAI-compatible API call fails."""


class OpenAICompatibleClient:
    """Thin httpx client for any OpenAI-compatible /chat/completions endpoint.

    Args:
        api_key:    Bearer token for the provider.
        base_url:   Provider's base URL (e.g. ``https://api.deepseek.com/v1``).
        model:      Model identifier for this provider.
        timeout:    Request timeout in seconds.
        extra_headers: Additional HTTP headers (e.g. ``HTTP-Referer`` for OpenRouter).
        force_json: Pass Ollama-style ``"format": "json"`` to force JSON mode.
    """

    _TIMEOUT = 300.0

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        timeout: float = _TIMEOUT,
        extra_headers: dict[str, str] | None = None,
        force_json: bool = False,
    ) -> None:
        if not _HTTPX_AVAILABLE:
            raise OpenAIClientError(
                "The 'httpx' package is required for AI features. "
                "Install it with: pip install 'kasa[ai]'"
            )
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._extra_headers = extra_headers or {}
        self._force_json = force_json

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_output_tokens: int = 2048,
    ) -> str:
        """Call /chat/completions and return the assistant's text content.

        Args:
            system_prompt: System-role instructions.
            user_prompt:   User-role content / data payload.
            temperature:   Sampling temperature.
            max_output_tokens: Max tokens to generate.

        Returns:
            Raw text returned by the model.

        Raises:
            OpenAIClientError: On HTTP errors, network failures, or
                unexpected response shapes.
        """
        url = f"{self._base_url}/chat/completions"

        headers: dict[str, str] = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            # OpenRouter requires these for attribution (harmless on other providers)
            "HTTP-Referer": "https://github.com/DHARSHAN-14/KASA",
            "X-Title": "KASA Kernel Attack Surface Analyzer",
        }
        headers.update(self._extra_headers)

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_output_tokens,
        }

        # Ollama supports a native `format` field that forces strict JSON output.
        # This is the most reliable way to get valid JSON from small local models.
        if self._force_json:
            payload["format"] = "json"

        try:
            with httpx.Client(timeout=self._timeout) as client:
                response = client.post(url, headers=headers, json=payload)
        except httpx.TimeoutException as exc:
            raise OpenAIClientError(
                f"API request timed out after {self._timeout}s "
                f"(model={self._model}): {exc}"
            ) from exc
        except httpx.RequestError as exc:
            raise OpenAIClientError(
                f"Network error communicating with {self._base_url}: {exc}"
            ) from exc

        if response.status_code != 200:
            raise OpenAIClientError(
                f"API returned HTTP {response.status_code} "
                f"(model={self._model}): {response.text[:600]}"
            )

        try:
            data = response.json()
        except Exception as exc:
            raise OpenAIClientError(
                f"Failed to parse API response as JSON: {exc}"
            ) from exc

        # Handle streaming finish_reason or content_filter blocks
        try:
            choice = data["choices"][0]
            finish_reason = choice.get("finish_reason", "")
            if finish_reason == "content_filter":
                raise OpenAIClientError(
                    "Response blocked by content filter "
                    f"(model={self._model}). Try rephrasing the request."
                )
            text: str = choice["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise OpenAIClientError(
                f"Unexpected API response structure: {exc}\n"
                f"Response: {json.dumps(data, indent=2)[:1000]}"
            ) from exc

        return text
