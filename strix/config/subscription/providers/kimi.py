"""Kimi Code subscription auth.

Mirrors Moonshot's Kimi Code CLI: an OAuth 2.0 device authorization grant
(RFC 8628) against ``auth.kimi.com``, with the access token sent as a ``Bearer``
token to Kimi's coding endpoint (``api.kimi.com/coding/v1``), which speaks the
OpenAI chat-completions protocol.

Unlike the ChatGPT flow this never opens a loopback listener: the CLI shows a
short user code, the user approves it on any device, and Strix polls the token
endpoint. That makes it work over SSH and inside containers, where a redirect to
``localhost`` cannot be caught.

Using a consumer Kimi membership outside Moonshot's own products is not
officially supported by Moonshot; the user chooses this path knowingly. The
OAuth constants are Kimi Code's own public-client values.
"""

from __future__ import annotations

import os
import platform
import uuid
from typing import TYPE_CHECKING, Any

from strix.config.subscription import oauth
from strix.config.subscription.base import AuthFlow, SubscriptionProvider, Wire


if TYPE_CHECKING:
    from openai import AsyncOpenAI


CLIENT_ID = "17e5f671-d194-4dfb-9706-5516cb48c098"
DEFAULT_OAUTH_HOST = "https://auth.kimi.com"
DEFAULT_BASE_URL = "https://api.kimi.com/coding/v1"
SCOPE = "offline_access"

# The backend fingerprints its clients. Overridable so a Kimi Code release can be
# tracked without a Strix release.
DEFAULT_CLIENT_VERSION = "1.0.0"
_PLATFORM = "strix"


def _oauth_host() -> str:
    return (os.environ.get("KIMI_CODE_OAUTH_HOST") or DEFAULT_OAUTH_HOST).rstrip("/")


def _base_url() -> str:
    return (os.environ.get("KIMI_CODE_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")


def device_authorization_url() -> str:
    return f"{_oauth_host()}/api/oauth/device_authorization"


def token_url() -> str:
    return f"{_oauth_host()}/api/oauth/token"


def _client_version() -> str:
    return os.environ.get("KIMI_CODE_CLIENT_VERSION") or DEFAULT_CLIENT_VERSION


def device_headers(device_id: str) -> dict[str, str]:
    """The ``X-Msh-*`` client fingerprint Kimi's endpoints expect."""
    return {
        "X-Msh-Platform": _PLATFORM,
        "X-Msh-Version": _client_version(),
        "X-Msh-Device-Name": platform.node() or "strix",
        "X-Msh-Device-Model": platform.machine() or "unknown",
        "X-Msh-Os-Version": f"{platform.system()} {platform.release()}".strip(),
        "X-Msh-Device-Id": device_id,
    }


def new_device_id() -> str:
    return uuid.uuid4().hex


class KimiProvider(SubscriptionProvider):
    name = "kimi"
    cli_name = "kimi"
    aliases = ("kimi-code", "moonshot")
    display_name = "Kimi Code"
    plan_hint = "Uses your Kimi membership for inference instead of a metered API key."
    model_prefix = "kimi/"
    example_model = "kimi/kimi-k3"

    flow = AuthFlow.DEVICE_CODE
    wire = Wire.OPENAI_CHAT

    # --- flow: device code ----------------------------------------------

    def start_device_authorization(self) -> dict[str, Any]:
        """Request a device+user code pair. The returned dict also carries the
        ``device_id`` this login is bound to, which must be threaded into
        :meth:`complete_device_authorization`."""
        device_id = new_device_id()
        data = oauth.request_device_code(
            device_authorization_url(),
            {"client_id": CLIENT_ID, "scope": SCOPE},
            headers=device_headers(device_id),
        )
        return {**data, "device_id": device_id}

    def complete_device_authorization(self, authorization: dict[str, Any]) -> dict[str, Any]:
        """Poll until the user approves the code, then return a token record."""
        device_id = authorization["device_id"]
        data = oauth.poll_device_token(
            token_url(),
            {
                "grant_type": oauth.DEVICE_GRANT,
                "client_id": CLIENT_ID,
                "device_code": authorization["device_code"],
            },
            interval=authorization.get("interval") or 5,
            expires_in=authorization.get("expires_in") or 900,
            headers=device_headers(device_id),
        )
        return self.build_record(data, previous={"device_id": device_id})

    def refresh(self, record: dict[str, Any]) -> dict[str, Any]:
        data = oauth.post_form(
            token_url(),
            {
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "refresh_token": record["refresh"],
            },
            headers=device_headers(self._device_id(record)),
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
        record.setdefault("device_id", new_device_id())
        return record

    @staticmethod
    def _device_id(record: dict[str, Any]) -> str:
        device_id = record.get("device_id")
        return device_id if isinstance(device_id, str) and device_id else new_device_id()

    # --- inference ------------------------------------------------------

    def build_client(self) -> AsyncOpenAI:
        """An ``AsyncOpenAI`` for Kimi's coding endpoint. A per-request hook
        re-stamps a fresh bearer token so long scans survive token expiry."""
        import asyncio

        import httpx
        from openai import AsyncOpenAI

        record = self.get_valid_record()  # fail fast if the sign-in is dead
        device_id = self._device_id(record)

        async def _auth_hook(request: httpx.Request) -> None:
            live = await asyncio.to_thread(self.get_valid_record)
            request.headers["Authorization"] = f"Bearer {live['access']}"

        http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(600.0, connect=30.0),
            event_hooks={"request": [_auth_hook]},
        )
        return AsyncOpenAI(
            api_key="strix-kimi-oauth",  # placeholder; the hook overwrites Authorization
            base_url=_base_url(),
            http_client=http_client,
            default_headers=device_headers(device_id),
        )
