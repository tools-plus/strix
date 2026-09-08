"""Tests for the `strix-pentest auth` CLI: subcommand routing, provider resolution,
and the two sign-in flow drivers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from strix.config import subscription
from strix.config.subscription import store
from strix.interface import auth_cli


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        store, "AUTH_PATH", tmp_path / "home" / ".strix-pentest" / "subscription-auth.json"
    )


def _codex() -> Any:
    provider = subscription.get_provider("chatgpt")
    assert provider is not None
    return provider


def test_default_provider_is_chatgpt() -> None:
    # ChatGPT was the only provider before the registry, so a bare
    # `strix-pentest auth login` must keep signing in to it.
    assert auth_cli.DEFAULT_PROVIDER == "chatgpt"
    assert subscription.get_provider(auth_cli.DEFAULT_PROVIDER) is not None


def test_usage_lists_every_registered_provider() -> None:
    # Rendered, not raw: the "[chatgpt|kimi|grok]" placeholder is valid console
    # syntax that Rich parses as a style tag and silently drops unless markup
    # is disabled, so the raw string passing proves nothing.
    from rich.console import Console

    console = Console(record=True, width=100)
    auth_cli._print_usage(console)
    rendered = console.export_text()
    for name in subscription.provider_names():
        assert name in rendered


def test_unknown_subcommand_returns_usage_error() -> None:
    assert auth_cli.run_auth(["bogus"]) == 2


def test_help_returns_zero() -> None:
    assert auth_cli.run_auth(["--help"]) == 0


def test_status_not_signed_in() -> None:
    assert auth_cli.run_auth(["status"]) == 1


def test_login_rejects_unsupported_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    def _should_not_run(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        msg = "OAuth flow must not start for an unsupported provider"
        raise AssertionError(msg)

    monkeypatch.setattr(auth_cli, "_run_loopback_flow", _should_not_run)
    monkeypatch.setattr(auth_cli, "_run_device_code_flow", _should_not_run)
    assert auth_cli.run_auth(["login", "gemini"]) == 2


def test_logout_rejects_unsupported_provider() -> None:
    assert auth_cli.run_auth(["logout", "gemini"]) == 2


def test_finish_requires_state_on_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    codex = _codex()
    monkeypatch.setattr(codex, "exchange_code", lambda *_: {"ok": True})

    # Loopback (require_state=True): missing or mismatched state is rejected.
    with pytest.raises(subscription.SubscriptionAuthError) as missing:
        auth_cli._finish(codex, "code", None, "verifier", "expected", require_state=True)
    assert missing.value.code == "state_mismatch"
    with pytest.raises(subscription.SubscriptionAuthError) as mismatch:
        auth_cli._finish(codex, "code", "wrong", "verifier", "expected", require_state=True)
    assert mismatch.value.code == "state_mismatch"

    # Matching state proceeds to the exchange.
    assert auth_cli._finish(
        codex, "code", "expected", "verifier", "expected", require_state=True
    ) == {"ok": True}


def test_finish_manual_paste_allows_absent_state(monkeypatch: pytest.MonkeyPatch) -> None:
    codex = _codex()
    monkeypatch.setattr(codex, "exchange_code", lambda *_: {"ok": True})
    # Manual paste (require_state=False): a bare code with no state is accepted,
    # but a present-and-wrong state is still rejected.
    assert auth_cli._finish(codex, "code", None, "verifier", "expected", require_state=False) == {
        "ok": True
    }
    with pytest.raises(subscription.SubscriptionAuthError):
        auth_cli._finish(codex, "code", "wrong", "verifier", "expected", require_state=False)


def test_finish_rejects_missing_code() -> None:
    with pytest.raises(subscription.SubscriptionAuthError) as exc:
        auth_cli._finish(_codex(), None, "expected", "verifier", "expected", require_state=True)
    assert exc.value.code == "no_code"


def test_model_subcommand_removed() -> None:
    assert auth_cli.run_auth(["model", "gpt-5.5"]) == 2


@pytest.mark.parametrize("provider", ["chatgpt", "codex", "ChatGPT"])
def test_login_accepts_provider_aliases(provider: str, monkeypatch: pytest.MonkeyPatch) -> None:
    reached = {"flow": False}

    def _fake_flow(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        reached["flow"] = True
        return {
            "type": "oauth",
            "provider": "codex",
            "access": "a",
            "refresh": "r",
            "account_id": "acct",
            "expires_at": 0,
        }

    monkeypatch.setattr(auth_cli, "_run_loopback_flow", _fake_flow)
    monkeypatch.setattr(_codex(), "save_record", lambda _record: None)

    assert auth_cli.run_auth(["login", provider]) == 0
    assert reached["flow"] is True


@pytest.mark.parametrize("name", ["kimi", "kimi-code", "moonshot", "grok", "xai", "supergrok"])
def test_login_dispatches_device_code_flow(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # A device-code provider must not start a loopback listener: that flow is
    # what makes sign-in work where no browser redirect can reach the terminal.
    reached = {"device": False}

    def _no_loopback(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        msg = "a device-code provider must not run the loopback flow"
        raise AssertionError(msg)

    def _fake_device(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        reached["device"] = True
        return {
            "type": "oauth",
            "provider": "kimi",
            "access": "a",
            "refresh": "r",
            "expires_at": 0,
        }

    monkeypatch.setattr(auth_cli, "_run_loopback_flow", _no_loopback)
    monkeypatch.setattr(auth_cli, "_run_device_code_flow", _fake_device)
    provider = subscription.get_provider(name)
    assert provider is not None
    monkeypatch.setattr(provider, "save_record", lambda _record: None)

    assert auth_cli.run_auth(["login", name]) == 0
    assert reached["device"] is True


def test_device_code_flow_shows_the_user_code(monkeypatch: pytest.MonkeyPatch) -> None:
    from rich.console import Console

    kimi = subscription.get_provider("kimi")
    assert kimi is not None
    monkeypatch.setattr(
        kimi,
        "start_device_authorization",
        lambda: {
            "device_code": "dc",
            "user_code": "WXYZ-1234",
            "verification_uri": "https://kimi.example/device",
            "device_id": "dev-1",
        },
    )
    monkeypatch.setattr(kimi, "complete_device_authorization", lambda _a: {"access": "at"})
    monkeypatch.setattr(auth_cli.webbrowser, "open", lambda _url: True)

    console = Console(record=True, width=100)
    record = auth_cli._run_device_code_flow(console, kimi)

    output = console.export_text()
    assert "WXYZ-1234" in output  # the user cannot approve without seeing this
    assert "https://kimi.example/device" in output
    assert record == {"access": "at"}


def test_logout_without_provider_clears_all(monkeypatch: pytest.MonkeyPatch) -> None:
    cleared: list[str] = []
    for provider in subscription.all_providers():
        monkeypatch.setattr(provider, "logout", lambda name=provider.name: cleared.append(name))
    assert auth_cli.run_auth(["logout"]) == 0
    assert set(cleared) == {provider.name for provider in subscription.all_providers()}


def test_logout_with_provider_clears_only_that_one(monkeypatch: pytest.MonkeyPatch) -> None:
    cleared: list[str] = []
    for provider in subscription.all_providers():
        monkeypatch.setattr(provider, "logout", lambda name=provider.name: cleared.append(name))
    assert auth_cli.run_auth(["logout", "kimi"]) == 0
    assert cleared == ["kimi"]
