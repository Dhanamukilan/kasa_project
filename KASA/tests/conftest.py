"""Pytest configuration and global test fixtures."""

from __future__ import annotations

import pytest


_AI_ENV_VARS = [
    "KASA_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENROUTER_API_KEY",
    "TOGETHER_API_KEY",
    "TOGETHER_AI_API_KEY",
    "FIREWORKS_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
]


@pytest.fixture(autouse=True)
def clean_ai_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure tests run with a clean AI environment by default."""
    for var in _AI_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("KASA_TEST_NO_BUILTIN_KEY", "1")
