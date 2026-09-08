"""Tests for the shared subscription-auth machinery and the ChatGPT (Codex) provider.

Covers PKCE, the token endpoint helper, the provider-keyed store, refresh under
the cross-process guard, and registry resolution.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import TYPE_CHECKING, Any
from unittest import mock

import pytest
import requests

from strix.config import subscription
from strix.config.subscription import oauth, store
from strix.config.subscription.providers import codex as codex_module
from strix.config.subscription.providers.codex import CodexProvider


if TYPE_CHECKING:
    from pathlib import Path


def _fake_jwt(account_id: str) -> str:
    def seg(obj: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    header = seg({"alg": "none"})
    payload = seg({"https://api.openai.com/auth": {"chatgpt_account_id": account_id}})
    return f"{header}.{payload}.sig"


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home" / ".strix" / "subscription-auth.json"
    monkeypatch.setattr(store, "AUTH_PATH", path)
    return path


@pytest.fixture
def codex() -> CodexProvider:
    """A fresh provider instance, so a cached client never leaks between tests."""
    return CodexProvider()


def _patch_token_endpoint(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    """Replace the shared form-POST helper, keeping its ``(url, payload)`` shape."""

    def _post(url: str, payload: dict[str, str], **_kwargs: Any) -> dict[str, Any]:
        assert url == codex_module.TOKEN_URL
        return handler(payload)

    monkeypatch.setattr(oauth, "post_form", _post)


# --- PKCE and redirect parsing -------------------------------------------


def test_pkce_challenge_matches_verifier_and_is_unpadded() -> None:
    verifier, challenge = oauth.generate_pkce()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert challenge == expected
    assert "=" not in verifier
    assert "=" not in challenge


def test_authorize_url_carries_pkce_and_client(codex: CodexProvider) -> None:
    url = codex.build_authorize_url("chal", "st8")
    assert codex_module.AUTHORIZE_URL in url
    assert "code_challenge=chal" in url
    assert "code_challenge_method=S256" in url
    assert f"client_id={codex_module.CLIENT_ID}" in url
    assert "state=st8" in url


def test_post_form_returns_parsed_body() -> None:
    resp = mock.MagicMock()
    resp.status_code = 200
    resp.content = b'{"access_token": "tok"}'
    resp.__enter__.return_value = resp

    with mock.patch.object(requests, "post", return_value=resp) as post:
        data = oauth.post_form(codex_module.TOKEN_URL, {"grant_type": "refresh_token"})

    assert data == {"access_token": "tok"}
    assert post.call_args.kwargs["timeout"] == oauth.TOKEN_TIMEOUT_S


def test_post_form_raises_on_http_error() -> None:
    resp = mock.MagicMock()
    resp.status_code = 400
    resp.content = b'{"error": "invalid_grant"}'
    resp.text = '{"error": "invalid_grant"}'
    resp.__enter__.return_value = resp

    with (
        mock.patch.object(requests, "post", return_value=resp),
        pytest.raises(subscription.SubscriptionAuthError) as exc,
    ):
        oauth.post_form(codex_module.TOKEN_URL, {"grant_type": "refresh_token"})
    assert exc.value.code == "token_http_error"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://localhost:1455/auth/callback?code=AAA&state=BBB", ("AAA", "BBB")),
        ("AAA#BBB", ("AAA", "BBB")),
        ("code=AAA&state=BBB", ("AAA", "BBB")),
        ("AAA", ("AAA", None)),
        ("", (None, None)),
    ],
)
def test_parse_redirect_input(value: str, expected: tuple[str | None, str | None]) -> None:
    assert oauth.parse_redirect_input(value) == expected


# --- registry resolution --------------------------------------------------


@pytest.mark.parametrize(
    ("model", "expected"),
    [
        ("chatgpt/gpt-5.4", "gpt-5.4"),
        ("ChatGPT/GPT-5.5", "GPT-5.5"),
        ("  chatgpt/gpt-5.4  ", "gpt-5.4"),
        ("kimi/kimi-k3", "kimi-k3"),
        ("openai/gpt-5.4", None),  # metered API path
        ("anthropic/claude-opus-4-8", None),
        ("moonshot/kimi-k3", None),  # metered API path, not the subscription
        ("gpt-5.4", None),
        ("chatgpt/", None),
        ("kimi/", None),
        ("", None),
        (None, None),
    ],
)
def test_subscription_model(model: str | None, expected: str | None) -> None:
    assert subscription.subscription_model(model) == expected


def test_resolve_returns_the_owning_provider() -> None:
    resolved = subscription.resolve("chatgpt/gpt-5.4")
    assert resolved is not None
    assert resolved[0].name == "codex"

    resolved = subscription.resolve("kimi/kimi-k3")
    assert resolved is not None
    assert resolved[0].name == "kimi"

    assert subscription.resolve("anthropic/claude-opus-5") is None


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("chatgpt", "codex"),
        ("codex", "codex"),
        ("ChatGPT", "codex"),
        ("kimi", "kimi"),
        ("kimi-code", "kimi"),
        ("moonshot", "kimi"),
        ("gemini", None),
        ("", None),
        (None, None),
    ],
)
def test_get_provider(name: str | None, expected: str | None) -> None:
    provider = subscription.get_provider(name)
    assert (provider.name if provider else None) == expected


def test_provider_prefixes_are_unique() -> None:
    prefixes = [provider.model_prefix for provider in subscription.all_providers()]
    assert len(prefixes) == len(set(prefixes))
    assert all(prefix.endswith("/") for prefix in prefixes)


def test_provider_lookup_keys_do_not_collide_across_providers() -> None:
    # A key claimed by two providers would make `strix auth login <key>` ambiguous.
    # Keys repeated *within* one provider (name == cli_name) are fine.
    seen: set[str] = set()
    for provider in subscription.all_providers():
        keys = {provider.name, provider.cli_name, *provider.aliases}
        assert not (keys & seen), f"provider keys collide: {keys & seen}"
        seen |= keys


def test_auth_mode() -> None:
    assert subscription.auth_mode("chatgpt/gpt-5.4") == "subscription"
    assert subscription.auth_mode("kimi/kimi-k3") == "subscription"
    assert subscription.auth_mode("openai/gpt-5.4") == "api_key"
    assert subscription.auth_mode("anthropic/claude-opus-4-8") == "api_key"
    assert subscription.auth_mode(None) == "api_key"


# --- guardrails -----------------------------------------------------------


def test_is_content_guardrail_error() -> None:
    # The backend's real wording (from a live gpt-5.6-sol block).
    raw = RuntimeError(
        "This content was flagged for possible cybersecurity risk. If this seems "
        "wrong, try rephrasing. To get authorized, join the Trusted Access for Cyber program."
    )
    assert subscription.is_content_guardrail_error(raw) is True
    # The already-typed error is recognized regardless of its message wording.
    typed = subscription.ContentGuardrailError("gpt-5.6-sol", "ChatGPT")
    assert subscription.is_content_guardrail_error(typed) is True
    # Unrelated errors are not misclassified.
    assert subscription.is_content_guardrail_error(RuntimeError("rate limit exceeded")) is False


def test_content_guardrail_error_message() -> None:
    err = subscription.ContentGuardrailError("gpt-5.6-sol", "ChatGPT")
    assert err.model == "gpt-5.6-sol"
    assert "gpt-5.6-sol" in str(err)
    assert "STRIX_LLM" in str(err)


def test_account_id_from_jwt() -> None:
    assert codex_module.account_id_from_jwt(_fake_jwt("acct-42")) == "acct-42"
    assert codex_module.account_id_from_jwt("not-a-jwt") is None
    assert codex_module.account_id_from_jwt("") is None


# --- store ----------------------------------------------------------------


def test_store_roundtrip_and_logout(codex: CodexProvider) -> None:
    assert codex.read_record() is None
    assert codex.is_authenticated() is False

    codex.save_record(
        {
            "type": "oauth",
            "provider": "codex",
            "access": _fake_jwt("acct-42"),
            "refresh": "r1",
            "account_id": "acct-42",
            "expires_at": time.time() + 3600,
        }
    )
    record = codex.read_record()
    assert record is not None
    assert record["account_id"] == "acct-42"
    assert codex.is_authenticated() is True

    codex.logout()
    assert codex.read_record() is None
    codex.logout()  # no-op when already gone


def test_read_record_rejects_incomplete_records(codex: CodexProvider) -> None:
    codex.save_record({"type": "oauth", "access": "a"})  # missing refresh/account
    assert codex.read_record() is None
    assert codex.is_authenticated() is False


def test_store_keeps_providers_independent(codex: CodexProvider) -> None:
    """Signing out of one provider must not disturb another's credentials."""
    kimi = subscription.get_provider("kimi")
    assert kimi is not None

    codex.save_record(
        {
            "type": "oauth",
            "provider": "codex",
            "access": "a",
            "refresh": "r",
            "account_id": "acct",
            "expires_at": time.time() + 3600,
        }
    )
    kimi.save_record(
        {
            "type": "oauth",
            "provider": "kimi",
            "access": "ka",
            "refresh": "kr",
            "expires_at": time.time() + 3600,
        }
    )
    assert codex.is_authenticated() is True
    assert kimi.is_authenticated() is True

    codex.logout()
    assert codex.is_authenticated() is False
    assert kimi.is_authenticated() is True  # untouched

    kimi.logout()
    assert kimi.is_authenticated() is False


# --- token lifecycle ------------------------------------------------------


def test_get_valid_record_returns_stored_when_fresh(
    codex: CodexProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom(_payload: dict[str, str]) -> dict[str, Any]:
        msg = "should not refresh a fresh token"
        raise AssertionError(msg)

    _patch_token_endpoint(monkeypatch, _boom)
    codex.save_record(
        {
            "type": "oauth",
            "provider": "codex",
            "access": "access-fresh",
            "refresh": "r1",
            "account_id": "acct-42",
            "expires_at": time.time() + 3600,
        }
    )
    record = codex.get_valid_record()
    assert record["access"] == "access-fresh"
    assert record["account_id"] == "acct-42"


def test_get_valid_record_refreshes_and_persists_rotation(
    codex: CodexProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}

    def _fake_post(payload: dict[str, str]) -> dict[str, Any]:
        calls["n"] += 1
        assert payload["grant_type"] == "refresh_token"
        assert payload["refresh_token"] == "r1"
        return {"access_token": _fake_jwt("acct-42"), "refresh_token": "r2", "expires_in": 3600}

    _patch_token_endpoint(monkeypatch, _fake_post)
    codex.save_record(
        {
            "type": "oauth",
            "provider": "codex",
            "access": "stale",
            "refresh": "r1",
            "account_id": "acct-42",
            "expires_at": time.time() - 10,  # already expired
        }
    )
    refreshed = codex.get_valid_record()
    assert calls["n"] == 1
    assert refreshed["account_id"] == "acct-42"
    # Rotated refresh token was written back to the store.
    record = codex.read_record()
    assert record is not None
    assert record["refresh"] == "r2"


def test_refresh_keeps_old_token_when_not_rotated(
    codex: CodexProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A refresh response may omit refresh_token when it isn't rotated.
    _patch_token_endpoint(
        monkeypatch,
        lambda _payload: {"access_token": _fake_jwt("acct-42"), "expires_in": 3600},
    )
    codex.save_record(
        {
            "type": "oauth",
            "provider": "codex",
            "access": "stale",
            "refresh": "r1",
            "account_id": "acct-42",
            "expires_at": time.time() - 10,
        }
    )
    assert codex.get_valid_record()["refresh"] == "r1"


def test_get_valid_record_uses_token_rotated_by_another_process(
    codex: CodexProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulate a parallel Strix process rotating the token while we wait for the
    # refresh guard: the pre-guard read sees the stale token, the in-guard read
    # sees the winner's fresh one, so we must NOT exchange the now-dead refresh.
    records = [
        {
            "type": "oauth",
            "provider": "codex",
            "access": "stale",
            "refresh": "r1",
            "account_id": "acct",
            "expires_at": time.time() - 10,
        },
        {
            "type": "oauth",
            "provider": "codex",
            "access": "fresh-from-other-process",
            "refresh": "r2",
            "account_id": "acct",
            "expires_at": time.time() + 3600,
        },
    ]
    calls = {"n": 0}

    def _fake_read() -> dict[str, Any]:
        record = records[min(calls["n"], len(records) - 1)]
        calls["n"] += 1
        return record

    def _boom(_payload: dict[str, str]) -> dict[str, Any]:
        msg = "must not refresh a token another process already rotated"
        raise AssertionError(msg)

    monkeypatch.setattr(codex, "read_record", _fake_read)
    _patch_token_endpoint(monkeypatch, _boom)

    record = codex.get_valid_record()
    assert record["access"] == "fresh-from-other-process"
    assert record["account_id"] == "acct"


def _expired_record(refresh: str, access: str) -> dict[str, Any]:
    return {
        "type": "oauth",
        "provider": "codex",
        "access": access,
        "refresh": refresh,
        "account_id": "acct-42",
        "expires_at": time.time() - 10,
    }


def test_get_valid_record_recovers_when_refresh_loses_race(
    codex: CodexProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Lock failed open: our in-guard read still saw the stale token, so we tried to
    # refresh and lost the race (invalid_grant). By then a peer has saved a fresh
    # token — recover from it instead of failing the scan on the dead one.
    codex.save_record(_expired_record("r1", "stale"))

    def _fake_post(_payload: dict[str, str]) -> dict[str, Any]:
        codex.save_record(
            {
                "type": "oauth",
                "provider": "codex",
                "access": "fresh-from-peer",
                "refresh": "r2",
                "account_id": "acct-42",
                "expires_at": time.time() + 3600,
            }
        )
        raise subscription.SubscriptionAuthError("token_http_error", "HTTP 400: invalid_grant")

    _patch_token_endpoint(monkeypatch, _fake_post)
    record = codex.get_valid_record()
    assert record["access"] == "fresh-from-peer"
    assert record["account_id"] == "acct-42"


def test_get_valid_record_reraises_refresh_error_without_rotation(
    codex: CodexProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Refresh fails and no peer rotated the token: surface the error, don't mask it.
    codex.save_record(_expired_record("r1", "stale"))

    def _fake_post(_payload: dict[str, str]) -> dict[str, Any]:
        raise subscription.SubscriptionAuthError("token_http_error", "HTTP 400: invalid_grant")

    _patch_token_endpoint(monkeypatch, _fake_post)
    with pytest.raises(subscription.SubscriptionAuthError):
        codex.get_valid_record()


def test_get_valid_record_raises_when_not_signed_in(codex: CodexProvider) -> None:
    with pytest.raises(subscription.SubscriptionAuthError) as exc:
        codex.get_valid_record()
    assert exc.value.code == "not_authenticated"
    assert "strix auth login chatgpt" in str(exc.value)


def test_unsupported_flow_hooks_raise(codex: CodexProvider) -> None:
    # Codex is a loopback provider; asking it for the device-code flow is a bug,
    # and must say so rather than silently misbehave.
    with pytest.raises(NotImplementedError, match="device_code"):
        codex.start_device_authorization()


# --- provider settings ----------------------------------------------------


def test_codex_settings_overrides_clamp_reasoning_effort(codex: CodexProvider) -> None:
    # The backend rejects efforts outside low/medium/high, so they are clamped
    # rather than passed through and rejected mid-scan.
    assert codex.settings_overrides("minimal")["reasoning_effort"] == "low"
    assert codex.settings_overrides("xhigh")["reasoning_effort"] == "high"
    assert codex.settings_overrides("max")["reasoning_effort"] == "high"
    assert codex.settings_overrides("medium")["reasoning_effort"] == "medium"
    # "none" means "don't ask for reasoning at all".
    assert "reasoning_effort" not in codex.settings_overrides("none")
    assert "reasoning_effort" not in codex.settings_overrides(None)
    # The stateless-backend requirements are always present.
    overrides = codex.settings_overrides("high")
    assert overrides["store"] is False
    assert overrides["response_include"] == ["reasoning.encrypted_content"]
