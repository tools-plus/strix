"""Tests for the xAI Grok provider: device-code login, OIDC discovery and the
endpoint validation that protects cached refresh targets, plus the 403 tier gate.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest
import requests

from strix.config import subscription
from strix.config.subscription import AuthFlow, Wire, oauth, store
from strix.config.subscription.providers import xai as xai_module
from strix.config.subscription.providers.xai import GrokProvider


if TYPE_CHECKING:
    from pathlib import Path


TOKEN_ENDPOINT = "https://auth.x.ai/oauth2/token"


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home" / ".strix-pentest" / "subscription-auth.json"
    monkeypatch.setattr(store, "AUTH_PATH", path)
    return path


@pytest.fixture
def grok() -> GrokProvider:
    return GrokProvider()


def test_provider_shape(grok: GrokProvider) -> None:
    # Device code onto a Responses backend — the pairing neither ChatGPT nor
    # Kimi covers, and the reason both flow drivers had to be generic.
    assert grok.flow is AuthFlow.DEVICE_CODE
    assert grok.wire is Wire.OPENAI_RESPONSES
    assert grok.model_prefix == "grok/"
    assert subscription.get_provider("grok") is not None


def test_subscription_prefix_does_not_capture_the_api_key_route() -> None:
    # `grok/` is the subscription; `xai/` must stay on the metered LiteLLM path.
    assert subscription.subscription_model("grok/grok-4.6") == "grok-4.6"
    assert subscription.resolve("xai/grok-4.6") is None


def test_refresh_skew_is_wider_than_the_default(grok: GrokProvider) -> None:
    # xAI rejects a nearly-expired token, so it refreshes an hour ahead.
    assert grok.refresh_skew_s == 3600
    assert grok._near_expiry({"expires_at": time.time() + 1800}) is True
    assert grok._near_expiry({"expires_at": time.time() + 7200}) is False


def test_no_model_slug_rewriting(grok: GrokProvider) -> None:
    # xAI serves subscription and API-key callers the same model ids.
    assert grok.model_slug("grok-4.6") == "grok-4.6"


def test_base_url_default_and_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XAI_BASE_URL", raising=False)
    assert xai_module._base_url() == "https://api.x.ai/v1"
    monkeypatch.setenv("XAI_BASE_URL", "https://gateway.example.test/v1/")
    assert xai_module._base_url() == "https://gateway.example.test/v1"


# --- endpoint validation --------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://auth.x.ai/oauth2/token",
        "https://api.x.ai/v1/token",
    ],
)
def test_validate_endpoint_accepts_provider_hosts(url: str) -> None:
    assert oauth.validate_endpoint(url, allowed_hosts=("x.ai",), field="token_endpoint") == url


@pytest.mark.parametrize(
    "url",
    [
        "http://auth.x.ai/oauth2/token",  # not https
        "https://evil.test/oauth2/token",  # foreign host
        "https://x.ai.evil.test/token",  # suffix-confusion
        "",
        "not-a-url",
    ],
)
def test_validate_endpoint_rejects_everything_else(url: str) -> None:
    # A refresh token posted to the wrong host is a credential disclosure, so
    # this must fail closed rather than fall back to a default.
    with pytest.raises(subscription.SubscriptionAuthError) as exc:
        oauth.validate_endpoint(url, allowed_hosts=("x.ai",), field="token_endpoint")
    assert exc.value.code == "bad_endpoint"


def _discovery_response(payload: bytes, status: int = 200) -> Any:
    resp = mock.MagicMock()
    resp.status_code = status
    resp.content = payload
    resp.text = payload.decode()
    resp.__enter__.return_value = resp
    return resp


def test_discovery_reads_and_validates_the_token_endpoint() -> None:
    body = b'{"issuer": "https://auth.x.ai", "token_endpoint": "https://auth.x.ai/oauth2/token"}'
    with mock.patch.object(requests, "get", return_value=_discovery_response(body)):
        data = oauth.discover_endpoints(xai_module.DISCOVERY_URL, allowed_hosts=("x.ai",))
    assert data["token_endpoint"] == TOKEN_ENDPOINT


def test_discovery_rejects_a_foreign_token_endpoint() -> None:
    body = b'{"token_endpoint": "https://evil.test/token"}'
    with (
        mock.patch.object(requests, "get", return_value=_discovery_response(body)),
        pytest.raises(subscription.SubscriptionAuthError) as exc,
    ):
        oauth.discover_endpoints(xai_module.DISCOVERY_URL, allowed_hosts=("x.ai",))
    assert exc.value.code == "bad_endpoint"


def test_discovery_rejects_a_document_without_a_token_endpoint() -> None:
    with (
        mock.patch.object(requests, "get", return_value=_discovery_response(b'{"issuer": "x"}')),
        pytest.raises(subscription.SubscriptionAuthError) as exc,
    ):
        oauth.discover_endpoints(xai_module.DISCOVERY_URL, allowed_hosts=("x.ai",))
    assert exc.value.code == "discovery_failed"


def test_token_endpoint_prefers_a_valid_cached_value(
    grok: GrokProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _no_discovery(*_a: Any, **_k: Any) -> dict[str, Any]:
        msg = "a valid cached endpoint must not trigger discovery"
        raise AssertionError(msg)

    monkeypatch.setattr(oauth, "discover_endpoints", _no_discovery)
    assert grok.token_endpoint({"token_endpoint": TOKEN_ENDPOINT}) == TOKEN_ENDPOINT


def test_token_endpoint_rediscovers_when_the_cached_value_is_untrusted(
    grok: GrokProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A hand-edited or tampered store must not steer the refresh POST.
    monkeypatch.setattr(
        oauth,
        "discover_endpoints",
        lambda *_a, **_k: {"token_endpoint": TOKEN_ENDPOINT},
    )
    assert grok.token_endpoint({"token_endpoint": "https://evil.test/token"}) == TOKEN_ENDPOINT
    assert grok.token_endpoint({}) == TOKEN_ENDPOINT


# --- device-code login ----------------------------------------------------


def test_start_device_authorization_resolves_the_endpoint_first(
    grok: GrokProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    monkeypatch.setattr(
        oauth, "discover_endpoints", lambda *_a, **_k: {"token_endpoint": TOKEN_ENDPOINT}
    )

    def _fake_request(url: str, payload: dict[str, str], **_kwargs: Any) -> dict[str, Any]:
        seen["url"] = url
        seen["payload"] = payload
        return {
            "device_code": "dc",
            "user_code": "ABCD-1234",
            "verification_uri": "https://accounts.x.ai/device",
            "interval": 5,
            "expires_in": 600,
        }

    monkeypatch.setattr(oauth, "request_device_code", _fake_request)
    authorization = grok.start_device_authorization()

    assert seen["url"] == xai_module.DEVICE_CODE_URL
    assert seen["payload"]["client_id"] == xai_module.CLIENT_ID
    assert seen["payload"]["scope"] == xai_module.SCOPE
    # Resolved before the browser step, so discovery failures surface early.
    assert authorization["token_endpoint"] == TOKEN_ENDPOINT


def test_complete_device_authorization_persists_the_endpoint(
    grok: GrokProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fake_poll(url: str, payload: dict[str, str], **_kwargs: Any) -> dict[str, Any]:
        assert url == TOKEN_ENDPOINT
        assert payload["grant_type"] == oauth.DEVICE_GRANT
        return {"access_token": "at", "refresh_token": "rt", "expires_in": 3600}

    monkeypatch.setattr(oauth, "poll_device_token", _fake_poll)
    record = grok.complete_device_authorization(
        {"device_code": "dc", "token_endpoint": TOKEN_ENDPOINT, "interval": 1, "expires_in": 60}
    )

    assert record["access"] == "at"
    assert record["provider"] == "xai"
    assert record["token_endpoint"] == TOKEN_ENDPOINT


def test_refresh_posts_to_the_stored_endpoint(
    grok: GrokProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def _fake_post(url: str, payload: dict[str, str], **_kwargs: Any) -> dict[str, Any]:
        seen["url"] = url
        assert payload["refresh_token"] == "rt"
        assert payload["client_id"] == xai_module.CLIENT_ID
        return {"access_token": "at2", "refresh_token": "rt2", "expires_in": 7200}

    monkeypatch.setattr(oauth, "post_form", _fake_post)
    grok.save_record(
        {
            "type": "oauth",
            "provider": "xai",
            "access": "at",
            "refresh": "rt",
            "token_endpoint": TOKEN_ENDPOINT,
            "expires_at": time.time() - 10,
        }
    )
    record = grok.get_valid_record()

    assert seen["url"] == TOKEN_ENDPOINT
    assert record["access"] == "at2"
    assert record["token_endpoint"] == TOKEN_ENDPOINT


# --- diagnostics ----------------------------------------------------------


def test_403_tier_gate_does_not_suggest_signing_in_again(grok: GrokProvider) -> None:
    # xAI allowlists its OAuth API surface separately from the subscription, so
    # a 403 here is an entitlement gate that re-login never clears. Telling the
    # user to sign in again would send them round a loop.
    hint = grok.error_hint(
        "error code: 403 - you do not have an active grok subscription or resource"
    )
    assert hint is not None
    assert "re-signing in will not" in hint
    assert "sign in again" not in hint.lower()
    assert "xai/grok-4.6" in hint


def test_401_still_suggests_signing_in_again(grok: GrokProvider) -> None:
    hint = grok.error_hint("error code: 401 unauthorized")
    assert hint is not None
    assert "strix-pentest auth login grok" in hint


def test_unrelated_errors_get_no_hint(grok: GrokProvider) -> None:
    assert grok.error_hint("connection reset by peer") is None


def test_settings_overrides_match_the_responses_contract(grok: GrokProvider) -> None:
    overrides = grok.settings_overrides("xhigh")
    assert overrides["store"] is False
    assert overrides["response_include"] == ["reasoning.encrypted_content"]
    assert overrides["reasoning_effort"] == "high"
