"""Derive release versions from a git tag.

Fork releases are tagged ``v<upstream-base>-TP-<YYYYMMDD>`` so they can never
collide with an upstream tag and state which upstream release they are built
from. That string is not a valid Python version, though -- PEP 440 has no place
for a ``-TP-`` segment -- so a build using it verbatim fails outright.

So two versions come out of one tag:

- the **display version** (``1.6.2-TP-20260908``) names the release, its
  binaries and its archives, which is what a human reads;
- the **package version** (``1.6.2+tp.20260908``) is the PEP 440 local-version
  form that goes into the wheel.

They sort identically and neither can collide with upstream. An upstream-shaped
tag (``v1.6.2``) passes through unchanged, so this is correct for upstream
releases too.

Usage::

    python scripts/release_version.py v1.6.2-TP-20260908
    python scripts/release_version.py v1.6.2-TP-20260908 --write pyproject.toml
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


#: ``<base>`` or ``<base>-<qualifier>``, with an optional leading ``v``.
_TAG_RE = re.compile(
    r"^v?(?P<base>\d+(?:\.\d+)*)"  # 1.6.2
    r"(?:-(?P<qualifier>[A-Za-z0-9][A-Za-z0-9.-]*))?$"  # -TP-20260908
)

_VERSION_LINE_RE = re.compile(r'^version\s*=\s*".*"$', re.MULTILINE)


class InvalidTagError(ValueError):
    """The tag is not a release tag this project knows how to version."""


def display_version(tag: str) -> str:
    """The human-facing version: the tag with any leading ``v`` removed."""
    return _parse(tag)[0]


def package_version(tag: str) -> str:
    """The PEP 440 version for the wheel.

    A qualifier becomes a local-version segment: ``-`` separators become ``.``
    and the whole thing is lower-cased, which is the normalization PEP 440
    would apply anyway. A tag with no qualifier is already valid and is
    returned unchanged.
    """
    _, base, qualifier = _parse(tag)
    if not qualifier:
        return base
    local = qualifier.replace("-", ".").lower()
    return f"{base}+{local}"


def _parse(tag: str) -> tuple[str, str, str]:
    """Return ``(display, base, qualifier)`` for *tag*."""
    cleaned = (tag or "").strip()
    match = _TAG_RE.match(cleaned)
    if not match:
        msg = (
            f"{cleaned!r} is not a release tag. Expected v<base> or "
            f"v<base>-<qualifier>, e.g. v1.6.2-TP-20260908"
        )
        raise InvalidTagError(msg)
    base = match.group("base")
    qualifier = match.group("qualifier") or ""
    display = cleaned[1:] if cleaned.startswith("v") else cleaned
    return display, base, qualifier


def stamp(pyproject: Path, version: str) -> None:
    """Rewrite the first ``version = "..."`` line of *pyproject* in place.

    The fork keeps ``pyproject.toml`` byte-identical to upstream so syncing
    never conflicts on the version line; the release build stamps it instead.
    """
    text = pyproject.read_text(encoding="utf-8")
    replaced, count = _VERSION_LINE_RE.subn(f'version = "{version}"', text, count=1)
    if count != 1:
        msg = f"no version line found in {pyproject}"
        raise InvalidTagError(msg)
    pyproject.write_text(replaced, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag", help="release tag, e.g. v1.6.2-TP-20260908")
    parser.add_argument(
        "--write",
        type=Path,
        default=None,
        help="stamp the package version into this pyproject.toml",
    )
    args = parser.parse_args(argv)

    try:
        display = display_version(args.tag)
        package = package_version(args.tag)
    except InvalidTagError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.write is not None:
        stamp(args.write, package)

    # Consumed by the release workflow via `>> "$GITHUB_OUTPUT"`.
    print(f"display_version={display}")
    print(f"package_version={package}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
