"""Tests for the Kimi Code provider: the device authorization grant (RFC 8628),
its polling rules, the device fingerprint, and endpoint overrides.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import pytest

from strix.config import subscription
from strix.config.subscription import AuthFlow, Wire, oauth, store
from strix.config.subscription.providers import kimi as kimi_module
from strix.config.subscription.providers.kimi import KimiProvider


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "home" / ".strix-pentest" / "subscription-auth.json"
    monkeypatch.setattr(store, "AUTH_PATH", path)
    return path


@pytest.fixture
def kimi() -> KimiProvider:
    return KimiProvider()


def test_provider_shape(kimi: KimiProvider) -> None:
    assert kimi.flow is AuthFlow.DEVICE_CODE
    assert kimi.wire is Wire.OPENAI_CHAT
    assert kimi.model_prefix == "kimi/"
    assert subscription.get_provider("kimi") is not None


def test_endpoints_default_and_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KIMI_CODE_OAUTH_HOST", raising=False)
    monkeypatch.delenv("KIMI_CODE_BASE_URL", raising=False)
    assert kimi_module.token_url() == "https://auth.kimi.com/api/oauth/token"
    assert (
        kimi_module.device_authorization_url()
        == "https://auth.kimi.com/api/oauth/device_authorization"
    )
    assert kimi_module._base_url() == "https://api.kimi.com/coding/v1"

    # Overrides let a self-hosted or staging deployment be targeted, and a
    # trailing slash must not produce a double slash in the built URL.
    monkeypatch.setenv("KIMI_CODE_OAUTH_HOST", "https://auth.example.test/")
    monkeypatch.setenv("KIMI_CODE_BASE_URL", "https://api.example.test/v1/")
    assert kimi_module.token_url() == "https://auth.example.test/api/oauth/token"
    assert kimi_module._base_url() == "https://api.example.test/v1"


def test_device_headers_carry_a_stable_id() -> None:
    headers = kimi_module.device_headers("dev-123")
    assert headers["X-Msh-Device-Id"] == "dev-123"
    assert headers["X-Msh-Platform"] == "strix"
    # Every documented fingerprint header is present; a missing one is rejected
    # by the backend.
    for key in (
        "X-Msh-Version",
        "X-Msh-Device-Name",
        "X-Msh-Device-Model",
        "X-Msh-Os-Version",
    ):
        assert headers[key]


def test_start_device_authorization_binds_a_device_id(
    kimi: KimiProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def _fake_request(url: str, payload: dict[str, str], **kwargs: Any) -> dict[str, Any]:
        seen["url"] = url
        seen["payload"] = payload
        seen["headers"] = kwargs["headers"]
        return {
            "device_code": "dc",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://kimi.com/device",
            "interval": 5,
            "expires_in": 600,
        }

    monkeypatch.setattr(oauth, "request_device_code", _fake_request)
    authorization = kimi.start_device_authorization()

    assert authorization["user_code"] == "ABCD-EFGH"
    assert authorization["device_id"]
    assert seen["payload"]["client_id"] == kimi_module.CLIENT_ID
    # The device id used to request the code is the one sent on the wire, so the
    # approval and the later token exchange refer to the same device.
    assert seen["headers"]["X-Msh-Device-Id"] == authorization["device_id"]


def test_complete_device_authorization_persists_device_id(
    kimi: KimiProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _fake_poll(_url: str, payload: dict[str, str], **_kwargs: Any) -> dict[str, Any]:
        assert payload["grant_type"] == oauth.DEVICE_GRANT
        assert payload["device_code"] == "dc"
        return {"access_token": "at", "refresh_token": "rt", "expires_in": 3600}

    monkeypatch.setattr(oauth, "poll_device_token", _fake_poll)
    record = kimi.complete_device_authorization(
        {"device_code": "dc", "device_id": "dev-1", "interval": 1, "expires_in": 60}
    )

    assert record["access"] == "at"
    assert record["refresh"] == "rt"
    assert record["provider"] == "kimi"
    # The device id must survive into the record: refreshes reuse it.
    assert record["device_id"] == "dev-1"


def test_refresh_reuses_the_stored_device_id(
    kimi: KimiProvider, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def _fake_post(_url: str, payload: dict[str, str], **kwargs: Any) -> dict[str, Any]:
        seen["headers"] = kwargs["headers"]
        assert payload["refresh_token"] == "rt"
        return {"access_token": "at2", "refresh_token": "rt2", "expires_in": 3600}

    monkeypatch.setattr(oauth, "post_form", _fake_post)
    kimi.save_record(
        {
            "type": "oauth",
            "provider": "kimi",
            "access": "at",
            "refresh": "rt",
            "device_id": "dev-9",
            "expires_at": time.time() - 10,
        }
    )
    record = kimi.get_valid_record()

    assert record["access"] == "at2"
    assert record["device_id"] == "dev-9"
    assert seen["headers"]["X-Msh-Device-Id"] == "dev-9"


# --- device-code polling rules -------------------------------------------


def _poll(
    responses: list[tuple[int, dict[str, Any]]],
    monkeypatch: pytest.MonkeyPatch,
    **kwargs: Any,
) -> dict[str, Any]:
    calls = {"n": 0}

    def _fake_request(*_args: Any, **_kwargs: Any) -> tuple[int, dict[str, Any], str]:
        status, body = responses[min(calls["n"], len(responses) - 1)]
        calls["n"] += 1
        return status, body, ""

    monkeypatch.setattr(oauth, "_request", _fake_request)
    return oauth.poll_device_token(
        "https://auth.test/token",
        {"grant_type": oauth.DEVICE_GRANT},
        sleep=lambda _s: None,
        **kwargs,
    )


def test_poll_keeps_going_while_authorization_pending(monkeypatch: pytest.MonkeyPatch) -> None:
    data = _poll(
        [
            (400, {"error": "authorization_pending"}),
            (400, {"error": "authorization_pending"}),
            (200, {"access_token": "at", "refresh_token": "rt", "expires_in": 3600}),
        ],
        monkeypatch,
        interval=1,
        expires_in=60,
    )
    assert data["access_token"] == "at"


def test_poll_backs_off_on_slow_down(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    calls = {"n": 0}
    responses = [
        (400, {"error": "slow_down"}),
        (200, {"access_token": "at", "refresh_token": "rt"}),
    ]

    def _fake_request(*_args: Any, **_kwargs: Any) -> tuple[int, dict[str, Any], str]:
        status, body = responses[min(calls["n"], len(responses) - 1)]
        calls["n"] += 1
        return status, body, ""

    monkeypatch.setattr(oauth, "_request", _fake_request)
    oauth.poll_device_token(
        "https://auth.test/token",
        {"grant_type": oauth.DEVICE_GRANT},
        interval=5,
        expires_in=60,
        sleep=slept.append,
    )
    # RFC 8628 §3.5: slow_down raises the interval by 5 seconds.
    assert slept == [5.0, 10.0]


def test_poll_stops_on_access_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(subscription.SubscriptionAuthError) as exc:
        _poll([(400, {"error": "access_denied"})], monkeypatch, interval=1, expires_in=60)
    assert exc.value.code == "access_denied"


def test_poll_stops_on_expired_token(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(subscription.SubscriptionAuthError) as exc:
        _poll([(400, {"error": "expired_token"})], monkeypatch, interval=1, expires_in=60)
    assert exc.value.code == "device_code_expired"


def test_poll_gives_up_at_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    # The clock runs past expires_in while the user never approves.
    clock = {"t": 0.0}

    def _now() -> float:
        clock["t"] += 10.0
        return clock["t"]

    def _fake_request(*_args: Any, **_kwargs: Any) -> tuple[int, dict[str, Any], str]:
        return 400, {"error": "authorization_pending"}, ""

    monkeypatch.setattr(oauth, "_request", _fake_request)
    with pytest.raises(subscription.SubscriptionAuthError) as exc:
        oauth.poll_device_token(
            "https://auth.test/token",
            {"grant_type": oauth.DEVICE_GRANT},
            interval=1,
            expires_in=15,
            sleep=lambda _s: None,
            now=_now,
        )
    assert exc.value.code == "device_code_expired"


def test_request_device_code_rejects_incomplete_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(oauth, "post_form", lambda *_a, **_k: {"device_code": "dc"})
    with pytest.raises(subscription.SubscriptionAuthError) as exc:
        oauth.request_device_code("https://auth.test/device", {})
    assert exc.value.code == "bad_response"
