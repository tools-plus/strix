"""ChatGPT (Codex) subscription auth.

Mirrors OpenAI's Codex CLI: OAuth 2.0 + PKCE against ``auth.openai.com``, with the
access token sent as a ``Bearer`` token to ``chatgpt.com/backend-api/codex``. Using
a ChatGPT subscription outside OpenAI's own products is not officially supported by
OpenAI; the user chooses this path knowingly. The OAuth constants are OpenAI's own
Codex CLI values (the backend only accepts that client).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from strix.config.subscription import oauth, store
from strix.config.subscription.base import (
    AuthFlow,
    SubscriptionAuthError,
    SubscriptionProvider,
    Wire,
    responses_settings_overrides,
)


if TYPE_CHECKING:
    from openai import AsyncOpenAI


CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"  # noqa: S105  # nosec B105 - URL, not a secret
CALLBACK_HOST = "localhost"
CALLBACK_PORT = 1455
CALLBACK_PATH = "/auth/callback"
REDIRECT_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}{CALLBACK_PATH}"
SCOPE = "openid profile email offline_access"

CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
ORIGINATOR = "codex_cli_rs"
_ACCOUNT_CLAIM = "https://api.openai.com/auth"


class CodexProvider(SubscriptionProvider):
    name = "codex"
    cli_name = "chatgpt"
    display_name = "ChatGPT"
    plan_hint = "Uses your ChatGPT Plus/Pro plan for inference instead of a metered API key."
    model_prefix = "chatgpt/"
    example_model = "chatgpt/gpt-5.4"

    flow = AuthFlow.LOOPBACK_PKCE
    wire = Wire.OPENAI_RESPONSES
    guardrail_markers = (
        "flagged for possible cybersecurity risk",
        "trusted access for cyber",
    )
    required_record_fields = ("access", "refresh", "account_id")

    callback_port = CALLBACK_PORT
    callback_path = CALLBACK_PATH

    # --- flow: loopback PKCE -------------------------------------------

    def build_authorize_url(self, challenge: str, state: str) -> str:
        return oauth.build_authorize_url(
            AUTHORIZE_URL,
            {
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": SCOPE,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": state,
                "id_token_add_organizations": "true",  # nosec B105 - flag, not a secret
                "codex_cli_simplified_flow": "true",
                "originator": ORIGINATOR,
            },
        )

    def exchange_code(self, code: str, verifier: str) -> dict[str, Any]:
        data = oauth.post_form(
            TOKEN_URL,
            {
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT_URI,
            },
        )
        return self.build_record(data)

    def refresh(self, record: dict[str, Any]) -> dict[str, Any]:
        data = oauth.post_form(
            TOKEN_URL,
            {
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": record["refresh"],
            },
        )
        return self.build_record(data, refresh_fallback=record["refresh"], previous=record)

    def build_record(
        self,
        data: dict[str, Any],
        *,
        refresh_fallback: str | None = None,
        previous: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        record = super().build_record(data, refresh_fallback=refresh_fallback, previous=previous)
        id_token = data.get("id_token")
        account_id = account_id_from_jwt(record["access"]) or account_id_from_jwt(
            id_token if isinstance(id_token, str) else None
        )
        if not account_id:
            raise SubscriptionAuthError(
                "no_account_id", "could not read chatgpt_account_id from token"
            )
        record["account_id"] = account_id
        return record

    # --- inference ------------------------------------------------------

    def build_client(self) -> AsyncOpenAI:
        """An ``AsyncOpenAI`` for the ChatGPT backend. A per-request hook re-stamps a
        fresh bearer token so long scans survive token expiry."""
        import asyncio

        import httpx
        from openai import AsyncOpenAI

        self.get_valid_record()  # fail fast at configure time if the sign-in is dead

        async def _auth_hook(request: httpx.Request) -> None:
            record = await asyncio.to_thread(self.get_valid_record)
            request.headers["Authorization"] = f"Bearer {record['access']}"
            request.headers["chatgpt-account-id"] = record["account_id"]

        http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(600.0, connect=30.0),
            event_hooks={"request": [_auth_hook]},
        )
        return AsyncOpenAI(
            api_key="strix-codex-oauth",  # placeholder; the hook overwrites Authorization
            base_url=CODEX_BASE_URL,
            http_client=http_client,
            default_headers={
                "OpenAI-Beta": "responses=experimental",
                "originator": ORIGINATOR,
            },
        )

    def settings_overrides(self, reasoning_effort: str | None) -> dict[str, Any]:
        """The ChatGPT backend is stateless and wants encrypted reasoning echoed back."""
        return responses_settings_overrides(reasoning_effort)

    def error_hint(self, message: str) -> str | None:
        if "not supported when using codex with a chatgpt account" in message:
            return (
                "This model isn't available on your ChatGPT subscription. "
                f"Set STRIX_LLM to a model your plan includes (e.g. {self.example_model})."
            )
        return super().error_hint(message)


def account_id_from_jwt(token: str | None) -> str | None:
    """Read the account id claim without verifying the JWT (the server enforces
    authenticity on use); it feeds the ``chatgpt-account-id`` header."""
    payload = store.jwt_claims(token)
    if payload is None:
        return None
    auth = payload.get(_ACCOUNT_CLAIM)
    if isinstance(auth, dict):
        account_id = auth.get("chatgpt_account_id")
        if isinstance(account_id, str) and account_id:
            return account_id
    organizations = payload.get("organizations")
    if isinstance(organizations, list) and organizations and isinstance(organizations[0], dict):
        org_id = organizations[0].get("id")
        if isinstance(org_id, str) and org_id:
            return org_id
    return None
