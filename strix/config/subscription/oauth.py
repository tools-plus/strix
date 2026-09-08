"""OAuth primitives shared by subscription providers.

Covers both flow shapes Strix supports: the browser/loopback authorization-code
flow with PKCE (RFC 7636) and the terminal-friendly device authorization grant
(RFC 8628).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import secrets
import time
import urllib.parse
from typing import TYPE_CHECKING, Any

import requests

from strix.config.subscription.base import SubscriptionAuthError


if TYPE_CHECKING:
    from collections.abc import Callable


TOKEN_TIMEOUT_S = 30
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"  # nosec B105

# RFC 8628 §3.5 polling errors that are not terminal.
_PENDING = "authorization_pending"
_SLOW_DOWN = "slow_down"
_SLOW_DOWN_BACKOFF_S = 5


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_pkce() -> tuple[str, str]:
    """Return ``(verifier, challenge)`` for the S256 challenge method."""
    verifier = b64url(secrets.token_bytes(64))
    challenge = b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def create_state() -> str:
    return secrets.token_hex(16)


def build_authorize_url(base: str, params: dict[str, str]) -> str:
    return f"{base}?{urllib.parse.urlencode(params)}"


def parse_redirect_input(value: str) -> tuple[str | None, str | None]:
    """Extract ``(code, state)`` from a pasted redirect URL, ``code#state``,
    query string, or bare code."""
    value = (value or "").strip()
    if not value:
        return None, None
    with contextlib.suppress(ValueError):
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme and parsed.query:
            query = urllib.parse.parse_qs(parsed.query)
            return first(query, "code"), first(query, "state")
    if "#" in value:
        code, _, state = value.partition("#")
        return code or None, state or None
    if "code=" in value:
        query = urllib.parse.parse_qs(value)
        return first(query, "code"), first(query, "state")
    return value, None


def first(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    return values[0] if values else None


def _request(
    url: str,
    payload: dict[str, str],
    headers: dict[str, str] | None,
    timeout: int,
) -> tuple[int, dict[str, Any], str]:
    """POST a form and parse the JSON body. Returns ``(status, data, raw_text)``."""
    try:
        with requests.post(
            url,
            data=payload,
            headers={"Accept": "application/json", **(headers or {})},
            timeout=timeout,
        ) as response:
            status_code = response.status_code
            body = response.content
            detail = response.text[:300] if status_code >= 400 else ""
    except requests.RequestException as exc:
        raise SubscriptionAuthError("unavailable", str(exc)) from exc
    try:
        data = json.loads(body or b"{}")
    except json.JSONDecodeError:
        data = {}
    if not isinstance(data, dict):
        data = {}
    return status_code, data, detail


def post_form(
    url: str,
    payload: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
    timeout: int = TOKEN_TIMEOUT_S,
) -> dict[str, Any]:
    """POST a form to an OAuth endpoint, raising on any HTTP error."""
    status_code, data, detail = _request(url, payload, headers, timeout)
    if status_code >= 400:
        raise SubscriptionAuthError("token_http_error", f"HTTP {status_code}: {detail}")
    if not data:
        raise SubscriptionAuthError("bad_response", "token endpoint returned non-object")
    return data


def request_device_code(
    url: str,
    payload: dict[str, str],
    *,
    headers: dict[str, str] | None = None,
    timeout: int = TOKEN_TIMEOUT_S,
) -> dict[str, Any]:
    """Start a device authorization grant (RFC 8628 §3.2).

    Returns the raw response; callers read ``device_code``, ``user_code``,
    ``verification_uri`` (and optionally ``verification_uri_complete``),
    ``interval`` and ``expires_in``.
    """
    data = post_form(url, payload, headers=headers, timeout=timeout)
    if not data.get("device_code") or not data.get("user_code"):
        raise SubscriptionAuthError(
            "bad_response", "device authorization response missing device_code/user_code"
        )
    return data


def poll_device_token(
    url: str,
    payload: dict[str, str],
    *,
    interval: float,
    expires_in: float,
    headers: dict[str, str] | None = None,
    timeout: int = TOKEN_TIMEOUT_S,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Poll the token endpoint until the user authorizes, or fail (RFC 8628 §3.4-3.5).

    Honours ``authorization_pending`` and ``slow_down``; every other error --
    and the ``expires_in`` deadline -- is terminal.
    """
    interval = max(float(interval or 5), 1.0)
    deadline = now() + max(float(expires_in or 300), 1.0)
    while True:
        if now() >= deadline:
            raise SubscriptionAuthError(
                "device_code_expired", "the device code expired before it was authorized"
            )
        sleep(interval)
        status_code, data, detail = _request(url, payload, headers, timeout)
        if status_code < 400 and data.get("access_token"):
            return data
        error = data.get("error")
        if error == _PENDING:
            continue
        if error == _SLOW_DOWN:
            interval += _SLOW_DOWN_BACKOFF_S
            continue
        if error == "access_denied":
            raise SubscriptionAuthError("access_denied", "the authorization request was denied")
        if error == "expired_token":
            raise SubscriptionAuthError(
                "device_code_expired", "the device code expired before it was authorized"
            )
        if error:
            description = data.get("error_description")
            raise SubscriptionAuthError(str(error), str(description or error))
        raise SubscriptionAuthError("token_http_error", f"HTTP {status_code}: {detail}")


def validate_endpoint(url: str, *, allowed_hosts: tuple[str, ...], field: str) -> str:
    """Reject an OAuth endpoint that is not HTTPS on an expected host.

    Discovered endpoints are cached in the token store, so a tampered or
    hand-edited store could otherwise redirect every future refresh token to an
    attacker's host. Re-validating on each use keeps that closed.
    """
    parsed = urllib.parse.urlparse((url or "").strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise SubscriptionAuthError("bad_endpoint", f"{field} must be an https URL, got: {url!r}")
    host = parsed.hostname.lower()
    if not any(host == allowed or host.endswith(f".{allowed}") for allowed in allowed_hosts):
        raise SubscriptionAuthError(
            "bad_endpoint", f"{field} host {host!r} is not one of {allowed_hosts}"
        )
    return url.strip()


def discover_endpoints(
    discovery_url: str,
    *,
    allowed_hosts: tuple[str, ...],
    timeout: int = TOKEN_TIMEOUT_S,
) -> dict[str, Any]:
    """Fetch an OpenID Connect discovery document and validate its endpoints.

    Providers that publish discovery are read rather than hardcoded, so an
    endpoint move does not need a Strix release.
    """
    try:
        with requests.get(
            discovery_url, headers={"Accept": "application/json"}, timeout=timeout
        ) as response:
            status_code = response.status_code
            body = response.content
            detail = response.text[:300] if status_code >= 400 else ""
    except requests.RequestException as exc:
        raise SubscriptionAuthError("unavailable", str(exc)) from exc
    if status_code >= 400:
        raise SubscriptionAuthError("discovery_failed", f"HTTP {status_code}: {detail}")
    try:
        data = json.loads(body or b"{}")
    except json.JSONDecodeError as exc:
        raise SubscriptionAuthError("discovery_failed", "discovery returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise SubscriptionAuthError("discovery_failed", "discovery returned a non-object")
    token_endpoint = data.get("token_endpoint")
    if not isinstance(token_endpoint, str) or not token_endpoint:
        raise SubscriptionAuthError("discovery_failed", "discovery has no token_endpoint")
    data["token_endpoint"] = validate_endpoint(
        token_endpoint, allowed_hosts=allowed_hosts, field="token_endpoint"
    )
    return data
