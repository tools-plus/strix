"""Model-subscription authentication.

Lets Strix run inference on a consumer plan (ChatGPT Plus/Pro, Kimi membership)
instead of a metered API key. A ``<prefix>/<model>`` ``STRIX_LLM`` -- e.g.
``chatgpt/gpt-5.4`` or ``kimi/kimi-k3`` -- selects the provider; sign-in is
``strix auth login <provider>``.

Public surface:

- :func:`resolve` / :func:`subscription_model` / :func:`provider_for` -- map a
  model name onto a provider.
- :func:`auth_mode` -- ``"subscription"`` or ``"api_key"``, for telemetry and costing.
- :func:`get_provider` / :func:`all_providers` / :func:`provider_names` -- registry lookup.
- :class:`SubscriptionProvider`, :class:`AuthFlow`, :class:`Wire` -- the provider contract.
- :class:`SubscriptionAuthError`, :class:`ContentGuardrailError` -- error types.

See :mod:`strix.config.subscription.registry` for how to add a provider.
"""

from strix.config.subscription.base import (
    AuthFlow,
    ContentGuardrailError,
    SubscriptionAuthError,
    SubscriptionProvider,
    Wire,
)
from strix.config.subscription.registry import (
    PROVIDERS,
    all_providers,
    auth_mode,
    authenticated_providers,
    get_provider,
    is_content_guardrail_error,
    provider_for,
    provider_names,
    resolve,
    subscription_model,
)
from strix.config.subscription.store import AUTH_PATH


__all__ = [
    "AUTH_PATH",
    "PROVIDERS",
    "AuthFlow",
    "ContentGuardrailError",
    "SubscriptionAuthError",
    "SubscriptionProvider",
    "Wire",
    "all_providers",
    "auth_mode",
    "authenticated_providers",
    "get_provider",
    "is_content_guardrail_error",
    "provider_for",
    "provider_names",
    "resolve",
    "subscription_model",
]
