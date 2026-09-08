"""xAI Grok subscription auth (SuperGrok / X Premium).

Mirrors the Grok CLI: an OAuth 2.0 device authorization grant (RFC 8628) against
``auth.x.ai``, after which the access token is sent as an ordinary ``Bearer``
token to xAI's public endpoint (``api.x.ai/v1``), which speaks the Responses
protocol. There is no separate subscription host and no model renaming -- the
same endpoint and model ids serve API-key and subscription callers, and the
token alone decides which is billed.

Like Kimi this is a device-code flow, so sign-in works over SSH and inside
containers. The token endpoint is read from xAI's OpenID Connect discovery
document rather than hardcoded, and the discovered value is re-validated on
every use: it is cached in the token store, and a tampered store must not be
able to redirect refresh tokens to another host.

Using a consumer subscription outside xAI's own products is not officially
supported by xAI; the user chooses this path knowingly. The OAuth constants are
the Grok CLI's own public-client values.

Note: xAI gates its OAuth API surface separately from the in-app subscription,
so a sign-in can succeed while inference returns HTTP 403. That is an
entitlement gate, not a stale token -- see :meth:`GrokProvider.error_hint`.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

from strix.config.subscription import oauth
from strix.config.subscription.base import (
    AuthFlow,
    SubscriptionAuthError,
    SubscriptionProvider,
    Wire,
    responses_settings_overrides,
)


if TYPE_CHECKING:
    from openai import AsyncOpenAI


ISSUER = "https://auth.x.ai"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"
DEVICE_CODE_URL = f"{ISSUER}/oauth2/device/code"
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
SCOPE = "openid profile email offline_access grok-cli:access api:access"

DEFAULT_BASE_URL = "https://api.x.ai/v1"

#: Hosts an OAuth endpoint may live on. Only the token endpoint is checked --
#: it is the one that receives refresh tokens.
ALLOWED_ENDPOINT_HOSTS = ("x.ai",)

#: xAI rejects a token close to expiry, so refresh an hour ahead rather than the
#: five minutes that suffices elsewhere.
REFRESH_SKEW_S = 3600


def _base_url() -> str:
    """The inference endpoint, overridable for a gateway or regional endpoint."""
    override = (os.environ.get("XAI_BASE_URL") or "").strip().rstrip("/")
    return override or DEFAULT_BASE_URL


class GrokProvider(SubscriptionProvider):
    name = "xai"
    cli_name = "grok"
    aliases = ("xai", "supergrok")
    display_name = "Grok"
    plan_hint = (
        "Uses your SuperGrok or X Premium subscription for inference instead of a metered API key."
    )
    model_prefix = "grok/"
    example_model = "grok/grok-4.6"

    flow = AuthFlow.DEVICE_CODE
    wire = Wire.OPENAI_RESPONSES
    #: The discovered token endpoint is cached with the tokens it refreshes.
    carry_over_fields = ("token_endpoint",)
    refresh_skew_s = REFRESH_SKEW_S

    # --- endpoint discovery ---------------------------------------------

    def token_endpoint(self, record: dict[str, Any] | None = None) -> str:
        """The token endpoint: the cached one when trustworthy, else rediscovered."""
        cached = (record or {}).get("token_endpoint")
        if isinstance(cached, str) and cached:
            try:
                return oauth.validate_endpoint(
                    cached, allowed_hosts=ALLOWED_ENDPOINT_HOSTS, field="token_endpoint"
                )
            except SubscriptionAuthError:
                # A cached endpoint that no longer validates is discarded, not trusted.
                pass
        discovery = oauth.discover_endpoints(DISCOVERY_URL, allowed_hosts=ALLOWED_ENDPOINT_HOSTS)
        return str(discovery["token_endpoint"])

    # --- flow: device code ----------------------------------------------

    def start_device_authorization(self) -> dict[str, Any]:
        """Request a device+user code pair, resolving the token endpoint up front
        so a discovery failure surfaces before the user goes to their browser."""
        token_endpoint = self.token_endpoint()
        data = oauth.request_device_code(DEVICE_CODE_URL, {"client_id": CLIENT_ID, "scope": SCOPE})
        return {**data, "token_endpoint": token_endpoint}

    def complete_device_authorization(self, authorization: dict[str, Any]) -> dict[str, Any]:
        """Poll until the user approves the code, then return a token record."""
        token_endpoint = authorization["token_endpoint"]
        data = oauth.poll_device_token(
            token_endpoint,
            {
                "grant_type": oauth.DEVICE_GRANT,
                "client_id": CLIENT_ID,
                "device_code": authorization["device_code"],
            },
            interval=authorization.get("interval") or 5,
            expires_in=authorization.get("expires_in") or 900,
        )
        return self.build_record(data, previous={"token_endpoint": token_endpoint})

    def refresh(self, record: dict[str, Any]) -> dict[str, Any]:
        endpoint = self.token_endpoint(record)
        data = oauth.post_form(
            endpoint,
            {
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": record["refresh"],
            },
        )
        return self.build_record(
            data,
            refresh_fallback=record["refresh"],
            previous={**record, "token_endpoint": endpoint},
        )

    # --- inference ------------------------------------------------------

    def build_client(self) -> AsyncOpenAI:
        """An ``AsyncOpenAI`` for xAI's public endpoint. A per-request hook
        re-stamps a fresh bearer token so long scans survive token expiry."""
        import asyncio

        import httpx
        from openai import AsyncOpenAI

        self.get_valid_record()  # fail fast at configure time if the sign-in is dead

        async def _auth_hook(request: httpx.Request) -> None:
            record = await asyncio.to_thread(self.get_valid_record)
            request.headers["Authorization"] = f"Bearer {record['access']}"

        http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(600.0, connect=30.0),
            event_hooks={"request": [_auth_hook]},
        )
        return AsyncOpenAI(
            api_key="strix-xai-oauth",  # placeholder; the hook overwrites Authorization
            base_url=_base_url(),
            http_client=http_client,
        )

    def settings_overrides(self, reasoning_effort: str | None) -> dict[str, Any]:
        """xAI serves the Responses API statelessly and replays encrypted reasoning."""
        return responses_settings_overrides(reasoning_effort)

    def error_hint(self, message: str) -> str | None:
        # xAI allowlists its OAuth API surface separately from the in-app
        # subscription, so a valid sign-in can still be refused. Re-authenticating
        # never clears that, so this must not fall through to the generic
        # "sign in again" hint below.
        if "403" in message and (
            "subscription" in message
            or "resource" in message
            or "not authorized" in message
            or "unauthorized" in message
        ):
            return (
                "xAI accepted your sign-in but refused the request (HTTP 403). xAI gates "
                "API access to specific subscription tiers, and re-signing in will not "
                "change that.\n"
                "  Use an API key instead: set LLM_API_KEY and STRIX_LLM=xai/grok-4.6,\n"
                "  or check your plan at https://x.ai/grok"
            )
        return super().error_hint(message)
