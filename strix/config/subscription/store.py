"""Shared, provider-keyed store for subscription OAuth tokens.

Kept separate from ``cli-config.json`` so OAuth tokens never land in the
env-var config. The file is a single JSON object keyed by provider name, so
signing in to one provider never disturbs another's credentials.
"""

from __future__ import annotations

import base64
import contextlib
import json
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from strix.utils.secret_files import write_secret_text


if TYPE_CHECKING:
    from collections.abc import Iterator


AUTH_PATH = Path.home() / ".strix" / "subscription-auth.json"

_refresh_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _read_store() -> dict[str, Any]:
    try:
        data = json.loads(AUTH_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_store(data: dict[str, Any]) -> None:
    write_secret_text(AUTH_PATH, json.dumps(data, indent=2))


def read_record(provider: str) -> dict[str, Any] | None:
    record = _read_store().get(provider)
    if not isinstance(record, dict) or record.get("type") != "oauth":
        return None
    return record


def save_record(provider: str, record: dict[str, Any]) -> None:
    data = _read_store()
    data[provider] = record
    _write_store(data)


def delete_record(provider: str) -> None:
    data = _read_store()
    if provider not in data:
        return
    del data[provider]
    if data:
        _write_store(data)
        return
    with contextlib.suppress(OSError):
        AUTH_PATH.unlink()


def _lock_for(provider: str) -> threading.Lock:
    with _locks_guard:
        lock = _refresh_locks.get(provider)
        if lock is None:
            lock = threading.Lock()
            _refresh_locks[provider] = lock
        return lock


@contextlib.contextmanager
def refresh_guard(provider: str) -> Iterator[None]:
    """Serialize token refresh within (lock) and across (flock) Strix processes,
    so concurrent runs can't both spend the single-use refresh token.

    The guard is per provider: refreshing ChatGPT must not block Kimi.
    """
    with _lock_for(provider):
        try:
            import fcntl

            lock_path = AUTH_PATH.with_name(f"{AUTH_PATH.stem}.{provider}.lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            handle = lock_path.open("w")
        except (ImportError, OSError):
            yield
            return
        try:
            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()


def jwt_claims(token: str | None) -> dict[str, Any] | None:
    """Read a JWT's payload without verifying it.

    The server enforces authenticity on use; Strix only needs a claim (an
    account id) to stamp on outbound requests.
    """
    if not token or token.count(".") != 2:
        return None
    payload_b64 = token.split(".")[1]
    padding = "=" * (-len(payload_b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    except (ValueError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None
