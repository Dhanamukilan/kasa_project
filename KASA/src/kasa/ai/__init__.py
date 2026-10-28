"""KASA AI remediation module."""

from kasa.ai.client import (
    AIClient,
    AIClientError,
    GeminiClient,
    GeminiClientError,
    create_client,
)
from kasa.ai.compat_client import OpenAICompatibleClient, OpenAIClientError
from kasa.ai.models import RemediationReport, RemediationStep
from kasa.ai.prompts import build_remediation_prompt
from kasa.ai.providers import (
    PROVIDERS,
    ProviderConfig,
    auto_detect,
    get_provider,
    list_providers,
    resolve_model_alias,
)
from kasa.ai.remediation import RemediationAdvisor

__all__ = [
    # Clients
    "AIClient",
    "AIClientError",
    "GeminiClient",
    "GeminiClientError",
    "OpenAICompatibleClient",
    "OpenAIClientError",
    "create_client",
    # Advisor
    "RemediationAdvisor",
    # Models
    "RemediationReport",
    "RemediationStep",
    # Prompts
    "build_remediation_prompt",
    # Providers
    "PROVIDERS",
    "ProviderConfig",
    "auto_detect",
    "get_provider",
    "list_providers",
    "resolve_model_alias",
]
