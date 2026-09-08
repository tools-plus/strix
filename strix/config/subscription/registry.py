"""The subscription-provider registry.

Adding a provider
-----------------
1. Write ``providers/<name>.py`` with a :class:`~strix.config.subscription.base.
   SubscriptionProvider` subclass: identity constants, :attr:`flow`, :attr:`wire`,
   the flow hooks that :attr:`flow` implies, and :meth:`build_client`.
2. Append an instance to :data:`PROVIDERS` below.

Nothing else needs to change: the CLI, environment validation, the model layer
and telemetry all read the registry. A provider whose backend speaks a wire
protocol not in :class:`~strix.config.subscription.base.Wire` also needs a
branch in :func:`strix.config.models.build_subscription_model`.

Two shapes are already covered end to end. ``chatgpt`` is a browser/loopback
PKCE flow onto an OpenAI *Responses* backend; ``kimi`` is a device-code flow
onto an OpenAI *chat-completions* backend. A provider like xAI's Grok
(SuperGrok / X Premium, device-code against ``accounts.x.ai``, chat-completions
via its CLI proxy, and a plan-specific model slug) is the second shape plus a
:meth:`~strix.config.subscription.base.SubscriptionProvider.model_slug`
override, so it needs no new machinery.

What must not be added
----------------------
Providers whose vendor *prohibits* third-party use of subscription credentials.
Anthropic is the standing example: since February 2026 its Consumer Terms
restrict Claude Free/Pro/Max OAuth tokens to Claude Code and Claude.ai, and the
restriction is enforced server-side. Claude runs on an API key
(``anthropic/...``) through the normal LiteLLM route instead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from strix.config.subscription.base import ContentGuardrailError
from strix.config.subscription.providers.codex import CodexProvider
from strix.config.subscription.providers.kimi import KimiProvider


if TYPE_CHECKING:
    from strix.config.subscription.base import SubscriptionProvider


PROVIDERS: tuple[SubscriptionProvider, ...] = (
    CodexProvider(),
    KimiProvider(),
)


def all_providers() -> tuple[SubscriptionProvider, ...]:
    return PROVIDERS


def get_provider(name: str | None) -> SubscriptionProvider | None:
    """Look a provider up by CLI name, alias, or internal id (case-insensitive)."""
    key = (name or "").strip().lower()
    if not key:
        return None
    for provider in PROVIDERS:
        if key in {provider.cli_name, provider.name, *provider.aliases}:
            return provider
    return None


def provider_names() -> list[str]:
    """CLI names, in registry order, for help text and error messages."""
    return [provider.cli_name for provider in PROVIDERS]


def resolve(model_name: str | None) -> tuple[SubscriptionProvider, str] | None:
    """Return ``(provider, slug)`` for a ``<prefix>/<model>`` STRIX_LLM, or None.

    A prefix with nothing after it is not a subscription model.
    """
    name = (model_name or "").strip()
    if not name:
        return None
    lowered = name.lower()
    for provider in PROVIDERS:
        prefix = provider.model_prefix
        if lowered.startswith(prefix):
            slug = name[len(prefix) :]
            if slug:
                return provider, slug
    return None


def subscription_model(model_name: str | None) -> str | None:
    """The model slug behind a subscription ``STRIX_LLM``, or None."""
    resolved = resolve(model_name)
    return resolved[1] if resolved else None


def provider_for(model_name: str | None) -> SubscriptionProvider | None:
    resolved = resolve(model_name)
    return resolved[0] if resolved else None


def auth_mode(model_name: str | None) -> str:
    return "subscription" if resolve(model_name) else "api_key"


def is_content_guardrail_error(exc: BaseException) -> bool:
    """Whether an error is a terminal content-guardrail refusal from any provider."""
    if isinstance(exc, ContentGuardrailError):
        return True
    return any(provider.is_guardrail_error(exc) for provider in PROVIDERS)


def authenticated_providers() -> list[SubscriptionProvider]:
    return [provider for provider in PROVIDERS if provider.is_authenticated()]
