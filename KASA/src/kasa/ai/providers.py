"""Provider registry for KASA AI — auto-detects available API keys.

Supported providers (priority order for auto-detection):
  1. deepseek   — api.deepseek.com         (DEEPSEEK_API_KEY)
  2. openrouter — openrouter.ai            (OPENROUTER_API_KEY)
  3. together   — api.together.xyz         (TOGETHER_API_KEY / TOGETHER_AI_API_KEY)
  4. fireworks  — api.fireworks.ai         (FIREWORKS_API_KEY)
  5. gemini     — generativelanguage...    (GEMINI_API_KEY / GOOGLE_API_KEY)
  6. ollama     — local offline Ollama     (http://127.0.0.1:11434/v1)

Universal Key:
  KASA_API_KEY — works with any provider key; automatically detects the provider
                 from the key format (AIza... -> Gemini, sk-or-... -> OpenRouter,
                 fw_... -> Fireworks, sk-... -> DeepSeek, etc.).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# Built-in default API key (loaded dynamically via .env / environment)
DEFAULT_BUILTIN_API_KEY: str | None = None


@dataclass(frozen=True)
class ProviderConfig:
    """Static configuration for a single AI provider."""

    name: str
    """Short identifier (e.g. 'deepseek')."""

    label: str
    """Human-readable display name."""

    base_url: str
    """OpenAI-compatible base URL (or 'gemini' sentinel for native Gemini)."""

    env_vars: list[str]
    """Environment variable names to check for an API key, in priority order."""

    default_model: str
    """Model used when the user does not specify --model."""

    models: list[str]
    """All known models for this provider (informational)."""

    protocol: str = "openai"
    """
    'openai'  — use the OpenAI-compatible /chat/completions endpoint.
    'gemini'  — use the native Gemini generateContent endpoint.
    """


# ---------------------------------------------------------------------------
# Provider catalogue
# ---------------------------------------------------------------------------

PROVIDERS: list[ProviderConfig] = [
    ProviderConfig(
        name="deepseek",
        label="DeepSeek",
        base_url="https://api.deepseek.com/v1",
        env_vars=["DEEPSEEK_API_KEY"],
        default_model="deepseek-chat",  # maps to DeepSeek-V3 (latest)
        models=[
            "deepseek-chat",       # DeepSeek-V3 — fast, cost-efficient
            "deepseek-reasoner",   # DeepSeek-R1 — chain-of-thought reasoning
        ],
        protocol="openai",
    ),
    ProviderConfig(
        name="openrouter",
        label="OpenRouter",
        base_url="https://openrouter.ai/api/v1",
        env_vars=["OPENROUTER_API_KEY"],
        default_model="qwen/qwen3-235b-a22b",
        models=[
            "qwen/qwen3-235b-a22b",               # Qwen3 235B MoE — 22B active
            "qwen/qwen3-30b-a3b",                  # Qwen3 30B MoE — 3B active (faster)
            "qwen/qwen2.5-72b-instruct",           # Qwen2.5 72B
            "deepseek/deepseek-chat-v3-0324",      # DeepSeek-V3 (March 2024)
            "deepseek/deepseek-r1",                # DeepSeek-R1 reasoning
            "meta-llama/llama-3.3-70b-instruct",   # Llama 3.3 70B
        ],
        protocol="openai",
    ),
    ProviderConfig(
        name="together",
        label="Together AI",
        base_url="https://api.together.xyz/v1",
        env_vars=["TOGETHER_API_KEY", "TOGETHER_AI_API_KEY"],
        default_model="Qwen/Qwen3-235B-A22B",
        models=[
            "Qwen/Qwen3-235B-A22B",               # Qwen3 235B MoE
            "Qwen/Qwen3-30B-A3B",                  # Qwen3 30B MoE
            "Qwen/Qwen2.5-72B-Instruct-Turbo",    # Qwen2.5 72B turbo
            "deepseek-ai/DeepSeek-V3",             # DeepSeek-V3
            "deepseek-ai/DeepSeek-R1",             # DeepSeek-R1
            "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        ],
        protocol="openai",
    ),
    ProviderConfig(
        name="fireworks",
        label="Fireworks AI",
        base_url="https://api.fireworks.ai/inference/v1",
        env_vars=["FIREWORKS_API_KEY"],
        default_model="accounts/fireworks/models/qwen3-235b-a22b",
        models=[
            "accounts/fireworks/models/qwen3-235b-a22b",
            "accounts/fireworks/models/qwen3-30b-a3b",
            "accounts/fireworks/models/deepseek-v3",
            "accounts/fireworks/models/deepseek-r1",
            "accounts/fireworks/models/llama-v3p3-70b-instruct",
        ],
        protocol="openai",
    ),
    ProviderConfig(
        name="gemini",
        label="Google Gemini",
        base_url="https://generativelanguage.googleapis.com/v1beta/models",
        env_vars=["GEMINI_API_KEY", "GOOGLE_API_KEY"],
        default_model="gemini-2.0-flash",
        models=[
            "gemini-2.0-flash",
            "gemini-2.0-flash-thinking-exp",
            "gemini-1.5-pro",
            "gemini-1.5-flash",
        ],
        protocol="gemini",
    ),
    ProviderConfig(
        name="ollama",
        label="Ollama (Local)",
        base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1"),
        env_vars=["OLLAMA_API_KEY", "OLLAMA_HOST"],
        default_model="qwen2.5:3b",
        models=[
            "qwen2.5:3b",
            "qwen2.5:7b",
            "qwen2.5:1.5b",
            "qwen2.5:latest",
            "deepseek-r1:1.5b",
            "deepseek-r1:7b",
            "llama3.2:3b",
        ],
        protocol="openai",
    ),
]

# Fast lookup by name
_PROVIDER_MAP: dict[str, ProviderConfig] = {p.name: p for p in PROVIDERS}

# Model alias normalisation — map user-friendly names to canonical model IDs.
# Keys are lower-cased for case-insensitive matching.
MODEL_ALIASES: dict[str, tuple[str, str]] = {
    # (provider_name, canonical_model_id)
    # DeepSeek aliases
    "deepseek-v3":             ("deepseek", "deepseek-chat"),
    "deepseek-v3-0324":        ("deepseek", "deepseek-chat"),
    "deepseek-chat":           ("deepseek", "deepseek-chat"),
    "deepseek-r1":             ("deepseek", "deepseek-reasoner"),
    "deepseek-reasoner":       ("deepseek", "deepseek-reasoner"),
    # Qwen aliases (Cloud / OpenRouter)
    "qwen3-235b":              ("openrouter", "qwen/qwen3-235b-a22b"),
    "qwen3-235b-a22b":         ("openrouter", "qwen/qwen3-235b-a22b"),
    "qwen3.6-227b":            ("openrouter", "qwen/qwen3-235b-a22b"),
    "qwen3-30b":               ("openrouter", "qwen/qwen3-30b-a3b"),
    "qwen2.5-72b":             ("openrouter", "qwen/qwen2.5-72b-instruct"),
    # Local Ollama Qwen model aliases
    "qwen3-4b":                ("ollama", "qwen2.5:3b"),
    "qwen-local":              ("ollama", "qwen2.5:3b"),
    "qwen2.5:3b":              ("ollama", "qwen2.5:3b"),
    "qwen2.5:7b":              ("ollama", "qwen2.5:7b"),
    "qwen2.5:latest":          ("ollama", "qwen2.5:latest"),
    "ollama":                  ("ollama", "qwen2.5:3b"),
    # DeepSeek v4 Flash — maps to latest DeepSeek-V3 (v4 not released yet)
    "deepseek-v4-flash":       ("deepseek", "deepseek-chat"),
    "deepseek-v4":             ("deepseek", "deepseek-chat"),
    # Gemini aliases
    "gemini-flash":            ("gemini", "gemini-2.0-flash"),
    "gemini-pro":              ("gemini", "gemini-1.5-pro"),
}


def get_provider(name: str) -> ProviderConfig | None:
    """Return a provider config by name, or None if unknown."""
    return _PROVIDER_MAP.get(name.lower())


def resolve_model_alias(alias: str) -> tuple[str, str] | None:
    """Resolve a model alias to (provider_name, model_id), or None if unknown."""
    return MODEL_ALIASES.get(alias.lower())


def detect_provider_from_key(key: str) -> ProviderConfig | None:
    """Detect the provider from the API key format.

    Key format heuristics:
      AIza...      → Google Gemini
      sk-or-...    → OpenRouter
      fw_...       → Fireworks AI
      sk-...       → DeepSeek (OpenAI-style key)
      <32+ hex/alphanumeric> → Together AI
      ollama / local         → Local Ollama
    """
    k = key.strip()
    if k.lower() in ("ollama", "local"):
        return _PROVIDER_MAP.get("ollama")
    if k.startswith("AIza"):
        return _PROVIDER_MAP.get("gemini")
    if k.startswith("sk-or-"):
        return _PROVIDER_MAP.get("openrouter")
    if k.startswith("fw_"):
        return _PROVIDER_MAP.get("fireworks")
    if k.startswith("sk-"):
        return _PROVIDER_MAP.get("deepseek")
    if len(k) >= 32 and k.replace("-", "").replace("_", "").isalnum():
        return _PROVIDER_MAP.get("together")
    return None


def auto_detect() -> tuple[ProviderConfig, str] | None:
    """Scan environment variables and return (provider, api_key) for the first match.

    Checks KASA_API_KEY first (universal key — provider auto-detected from key format).
    Then falls back to provider-specific env vars in priority order:
    DeepSeek → OpenRouter → Together → Fireworks → Gemini → Ollama.
    Finally falls back to the built-in configured default key.

    Returns:
        ``(ProviderConfig, api_key)`` for the active provider,
        or ``None`` if no key is available.
    """
    # 1. Universal KASA_API_KEY — detect provider from key format
    universal_key = os.environ.get("KASA_API_KEY", "").strip()
    if universal_key:
        detected = detect_provider_from_key(universal_key)
        if detected is not None:
            return detected, universal_key

    # 2. Provider-specific env vars (priority order)
    for provider in PROVIDERS:
        for env_var in provider.env_vars:
            key = os.environ.get(env_var, "").strip()
            if key:
                return provider, key

    # 3. Fallback if KASA_API_KEY was set but format was unrecognized
    if universal_key:
        return _PROVIDER_MAP.get("deepseek", PROVIDERS[0]), universal_key

    # 4. Built-in configured default key
    if DEFAULT_BUILTIN_API_KEY and os.environ.get("KASA_TEST_NO_BUILTIN_KEY") != "1":
        detected = detect_provider_from_key(DEFAULT_BUILTIN_API_KEY)
        if detected is not None:
            return detected, DEFAULT_BUILTIN_API_KEY

    return None


def list_providers() -> list[dict[str, Any]]:
    """Return a summary of all providers and their detection status."""
    universal_key = os.environ.get("KASA_API_KEY", "").strip()
    if (
        not universal_key
        and DEFAULT_BUILTIN_API_KEY
        and os.environ.get("KASA_TEST_NO_BUILTIN_KEY") != "1"
    ):
        universal_key = DEFAULT_BUILTIN_API_KEY

    universal_provider = (
        detect_provider_from_key(universal_key) if universal_key else None
    )

    result = []
    for provider in PROVIDERS:
        found_key: str | None = None
        found_var: str | None = None

        if provider.name == "ollama":
            found_key = "local (no auth)"
            found_var = "localhost:11434"
        elif universal_key and (
            universal_provider is None
            or universal_provider.name == provider.name
        ):
            found_key = universal_key[:8] + "…"
            found_var = "BUILT-IN / KASA_API_KEY"
        else:
            for env_var in provider.env_vars:
                val = os.environ.get(env_var, "").strip()
                if val:
                    found_key = val[:8] + "…"
                    found_var = env_var
                    break

        result.append(
            {
                "name": provider.name,
                "label": provider.label,
                "default_model": provider.default_model,
                "env_vars": provider.env_vars,
                "key_found": found_var,
                "key_preview": found_key,
                "available": found_key is not None,
            }
        )
    return result
