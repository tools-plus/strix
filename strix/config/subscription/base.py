"""Provider-facing contract for model-subscription authentication.

A *subscription provider* lets Strix run inference on a consumer plan (ChatGPT
Plus/Pro, Kimi membership, ...) instead of a metered API key. Each provider
supplies its OAuth constants, its wire protocol, and the small amount of
per-provider behaviour the shared machinery cannot guess; everything else --
the token store, refresh serialization, PKCE, device-code polling -- lives in
this package and is shared.

Providers are selected by a ``<prefix>/<model>`` ``STRIX_LLM`` (``chatgpt/gpt-5.4``,
``kimi/k2.5``); see :mod:`strix.config.subscription.registry`.

Using a consumer subscription outside its vendor's own products is generally not
officially supported; the user chooses this path knowingly. Providers whose
vendor *prohibits* third-party use must not be added here -- see this package's
README notes in ``registry.py``.
"""

from __future__ import annotations

import enum
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from strix.config.subscription import store


if TYPE_CHECKING:
    from openai import AsyncOpenAI


class AuthFlow(enum.Enum):
    """How the user completes sign-in."""

    #: Browser redirect to a one-shot local HTTP server (OAuth 2.0 + PKCE).
    LOOPBACK_PKCE = "loopback_pkce"
    #: Terminal-friendly device authorization grant (RFC 8628).
    DEVICE_CODE = "device_code"


class Wire(enum.Enum):
    """The request protocol the provider's inference backend speaks."""

    OPENAI_RESPONSES = "openai_responses"
    OPENAI_CHAT = "openai_chat"


class SubscriptionAuthError(Exception):
    """Sign-in or token refresh failed. ``code`` is a stable machine-readable tag."""

    def __init__(self, code: str, message: str | None = None) -> None:
        self.code = code
        super().__init__(message or code)


class ContentGuardrailError(Exception):
    """The backend refused a request via its content guardrail.

    Terminal -- retrying identical content never clears the block, so callers
    must not treat it as a transient error.
    """

    def __init__(
        self,
        model: str,
        provider: str,
        original: BaseException | None = None,
    ) -> None:
        self.model = model
        self.provider = provider
        self.original = original
        super().__init__(
            f"'{model}' was blocked by the {provider} content guardrails "
            f"(flagged as a possible cybersecurity risk). "
            f"Set STRIX_LLM to a model that isn't blocked and re-run."
        )


class SubscriptionProvider(ABC):
    """Base class for a model-subscription provider.

    Subclasses declare the identity/OAuth constants as class attributes and
    implement :meth:`build_client` plus whichever flow hooks their
    :attr:`flow` requires.
    """

    # --- identity -------------------------------------------------------
    #: Internal id; the key under which tokens are stored.
    name: str
    #: What the user types: ``strix auth login <cli_name>``.
    cli_name: str
    #: Additional accepted spellings of ``cli_name``.
    aliases: tuple[str, ...] = ()
    #: Human-readable name used in CLI copy.
    display_name: str
    #: One line naming the plan this bills to.
    plan_hint: str
    #: ``STRIX_LLM`` prefix that routes to this provider, including the slash.
    model_prefix: str
    #: A ``<prefix>/<model>`` value to suggest in help text.
    example_model: str

    # --- behaviour ------------------------------------------------------
    flow: AuthFlow
    wire: Wire
    #: Substrings identifying a content-guardrail refusal in an error message.
    guardrail_markers: tuple[str, ...] = ()
    #: Fields a stored record must carry to count as usable.
    required_record_fields: tuple[str, ...] = ("access", "refresh")
    #: Fields preserved across a refresh (device ids, discovered endpoints).
    carry_over_fields: tuple[str, ...] = ()
    #: Refresh this many seconds before the token actually expires. Providers
    #: whose backend rejects a nearly-expired token want a wider margin.
    refresh_skew_s: int = 300

    # --- token store ----------------------------------------------------

    def read_record(self) -> dict[str, Any] | None:
        record = store.read_record(self.name)
        if record is None:
            return None
        if not all(record.get(field) for field in self.required_record_fields):
            return None
        return record

    def is_authenticated(self) -> bool:
        return self.read_record() is not None

    def save_record(self, record: dict[str, Any]) -> None:
        store.save_record(self.name, record)

    def logout(self) -> None:
        store.delete_record(self.name)
        self.reset_client()

    # --- token lifecycle ------------------------------------------------

    def _near_expiry(self, record: dict[str, Any]) -> bool:
        expires_at = record.get("expires_at")
        if not isinstance(expires_at, int | float):
            return True
        return expires_at - self.refresh_skew_s <= time.time()

    def get_valid_record(self) -> dict[str, Any]:
        """Return a live token record, refreshing under the cross-process guard
        if it is at or near expiry."""
        record = self.read_record()
        if record is None:
            raise SubscriptionAuthError(
                "not_authenticated",
                f"not signed in; run: strix auth login {self.cli_name}",
            )
        if not self._near_expiry(record):
            return record
        with store.refresh_guard(self.name):
            record = self.read_record()
            if record is None:
                raise SubscriptionAuthError(
                    "not_authenticated",
                    f"not signed in; run: strix auth login {self.cli_name}",
                )
            if not self._near_expiry(record):
                return record
            try:
                refreshed = self.refresh(record)
            except SubscriptionAuthError:
                # A peer process may have already spent this single-use refresh token.
                latest = self.read_record()
                if (
                    latest
                    and latest.get("refresh") != record.get("refresh")
                    and not self._near_expiry(latest)
                ):
                    return latest
                raise
            self.save_record(refreshed)
            return refreshed

    @abstractmethod
    def refresh(self, record: dict[str, Any]) -> dict[str, Any]:
        """Exchange the record's refresh token for a fresh one."""

    # --- flow hooks -----------------------------------------------------
    # Each provider implements the pair its :attr:`flow` names; the other pair
    # stays unimplemented. The CLI dispatches on :attr:`flow`, so a provider is
    # never asked for a flow it did not declare.

    #: Loopback port the redirect is caught on (``LOOPBACK_PKCE`` only).
    callback_port: int = 0
    #: Path the redirect URI points at (``LOOPBACK_PKCE`` only).
    callback_path: str = "/auth/callback"

    def build_authorize_url(self, challenge: str, state: str) -> str:
        """``LOOPBACK_PKCE``: the URL the user opens to authorize."""
        raise NotImplementedError(self._unsupported(AuthFlow.LOOPBACK_PKCE))

    def exchange_code(self, code: str, verifier: str) -> dict[str, Any]:
        """``LOOPBACK_PKCE``: trade the redirect's code for a token record."""
        raise NotImplementedError(self._unsupported(AuthFlow.LOOPBACK_PKCE))

    def start_device_authorization(self) -> dict[str, Any]:
        """``DEVICE_CODE``: request the device/user code pair to display."""
        raise NotImplementedError(self._unsupported(AuthFlow.DEVICE_CODE))

    def complete_device_authorization(self, authorization: dict[str, Any]) -> dict[str, Any]:
        """``DEVICE_CODE``: poll until approved, then return a token record."""
        raise NotImplementedError(self._unsupported(AuthFlow.DEVICE_CODE))

    def _unsupported(self, flow: AuthFlow) -> str:
        return f"{self.name} does not use the {flow.value} flow (it uses {self.flow.value})"

    def build_record(
        self,
        data: dict[str, Any],
        *,
        refresh_fallback: str | None = None,
        previous: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Turn a token endpoint response into a stored record.

        ``refresh_fallback`` keeps the old refresh token when a refresh
        response omits a rotated one. Subclasses extend this to carry
        provider-specific fields (an account id, a device id) across refreshes.
        """
        access = data.get("access_token")
        refresh = data.get("refresh_token") or refresh_fallback
        expires_in = data.get("expires_in")
        if not isinstance(access, str) or not access:
            raise SubscriptionAuthError("bad_response", "token response missing access_token")
        if not isinstance(refresh, str) or not refresh:
            raise SubscriptionAuthError("bad_response", "token response missing refresh_token")
        ttl = expires_in if isinstance(expires_in, int | float) else 3600
        record = {
            "type": "oauth",
            "provider": self.name,
            "access": access,
            "refresh": refresh,
            "expires_at": time.time() + ttl,
        }
        for field in self.carry_over_fields:
            if previous and previous.get(field):
                record[field] = previous[field]
        return record

    # --- inference ------------------------------------------------------

    def model_slug(self, slug: str) -> str:
        """Map the user-facing model name onto the slug the backend expects.

        Overridden by providers that route a subscription variant (e.g. xAI
        serves ``grok-4.5`` as ``grok-4.5-build`` on a SuperGrok plan).
        """
        return slug

    @abstractmethod
    def build_client(self) -> AsyncOpenAI:
        """Build an ``AsyncOpenAI`` pointed at this provider's backend.

        Implementations must re-stamp credentials per request (an event hook)
        so long scans survive token expiry.
        """

    _client: AsyncOpenAI | None = None

    def get_client(self) -> AsyncOpenAI:
        if self._client is None:
            self._client = self.build_client()
        return self._client

    def reset_client(self) -> None:
        self._client = None

    def settings_overrides(self, reasoning_effort: str | None) -> dict[str, Any]:
        """Per-request ``ModelSettings`` overrides this backend requires.

        Returned as a plain dict so the model layer can build the SDK object
        without this package importing it.
        """
        del reasoning_effort
        return {}

    # --- diagnostics ----------------------------------------------------

    def is_guardrail_error(self, exc: BaseException) -> bool:
        if isinstance(exc, ContentGuardrailError):
            return True
        if not self.guardrail_markers:
            return False
        text = str(exc).lower()
        return any(marker in text for marker in self.guardrail_markers)

    def error_hint(self, message: str) -> str | None:
        """An actionable hint for a known provider error, or None.

        ``message`` is the lower-cased, joined text of the exception chain.
        """
        if (
            "error code: 401" in message
            or "http 401" in message
            or "unauthorized" in message
            or "invalid_grant" in message
        ):
            return (
                f"Your {self.display_name} sign-in has expired or was revoked. Sign in again:\n"
                f"  strix auth login {self.cli_name}"
            )
        return None


def clamp_reasoning_effort(effort: str | None) -> str | None:
    """Map Strix's effort scale onto the three levels these backends accept.

    ``minimal``/``xhigh``/``max`` are Strix extensions; sending them through
    unmapped gets the request rejected.
    """
    if not effort or effort == "none":
        return None
    match effort:
        case "minimal":
            return "low"
        case "xhigh" | "max":
            return "high"
        case _:
            return effort


def responses_settings_overrides(reasoning_effort: str | None) -> dict[str, Any]:
    """Per-request overrides every stateless Responses backend needs.

    ``store=False`` because Strix keeps no server-side conversation, and the
    encrypted reasoning blob must be echoed back for multi-turn reasoning to
    survive.
    """
    overrides: dict[str, Any] = {
        "store": False,
        "response_include": ["reasoning.encrypted_content"],
    }
    effort = clamp_reasoning_effort(reasoning_effort)
    if effort:
        overrides["reasoning_effort"] = effort
    return overrides
