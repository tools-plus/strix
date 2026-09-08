"""Tests for release-tag version derivation.

Fork releases are tagged ``v<base>-TP-<YYYYMMDD>``, which PEP 440 rejects, so
the tag's spelling and the wheel's version deliberately differ. These tests pin
both, and pin that the derived package version is one Python accepts — getting
that wrong fails the release build rather than any test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from packaging.version import Version

from scripts.release_version import (
    InvalidTagError,
    display_version,
    main,
    package_version,
    stamp,
)


if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("tag", "display", "package"),
    [
        # The fork's own scheme.
        ("v1.6.2-TP-20260908", "1.6.2-TP-20260908", "1.6.2+tp.20260908"),
        ("1.6.2-TP-20260908", "1.6.2-TP-20260908", "1.6.2+tp.20260908"),
        ("v1.7.0-TP-20261101", "1.7.0-TP-20261101", "1.7.0+tp.20261101"),
        # An upstream-shaped tag passes straight through, so the workflow stays
        # correct for a plain upstream release too.
        ("v1.6.2", "1.6.2", "1.6.2"),
        ("v2.0", "2.0", "2.0"),
        # Any other qualifier is handled the same way, not special-cased to TP.
        ("v1.6.2-rc.1", "1.6.2-rc.1", "1.6.2+rc.1"),
    ],
)
def test_versions_derived_from_tag(tag: str, display: str, package: str) -> None:
    assert display_version(tag) == display
    assert package_version(tag) == package


@pytest.mark.parametrize(
    "tag",
    ["v1.6.2-TP-20260908", "v1.6.2", "v1.7.0-TP-20261101", "v1.6.2-rc.1"],
)
def test_package_version_is_valid_pep440(tag: str) -> None:
    # The whole point of the split: this must be a version Python accepts.
    Version(package_version(tag))


def test_fork_version_sorts_after_the_upstream_release_it_builds_on() -> None:
    # A fork build of 1.6.2 must not look older than upstream 1.6.2, and must
    # not look like 1.6.3 either.
    upstream = Version("1.6.2")
    fork = Version(package_version("v1.6.2-TP-20260908"))
    assert fork > upstream
    assert fork < Version("1.6.3")


def test_fork_versions_order_by_date() -> None:
    older = Version(package_version("v1.6.2-TP-20260908"))
    newer = Version(package_version("v1.6.2-TP-20261101"))
    assert newer > older


def test_display_version_never_collides_with_an_upstream_tag() -> None:
    assert display_version("v1.6.2-TP-20260908") != display_version("v1.6.2")


@pytest.mark.parametrize(
    "tag",
    ["", "not-a-tag", "v", "release-1.6.2", "vX.Y.Z", "v1.6.2-", "  "],
)
def test_invalid_tags_are_rejected(tag: str) -> None:
    with pytest.raises(InvalidTagError):
        package_version(tag)


def test_stamp_rewrites_only_the_project_version(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "strix-agent"\nversion = "1.6.2"\n\n[tool.other]\nversion = "9.9.9"\n',
        encoding="utf-8",
    )
    stamp(pyproject, "1.6.2+tp.20260908")
    text = pyproject.read_text(encoding="utf-8")
    assert 'version = "1.6.2+tp.20260908"' in text
    # Only the first version line is the project's; anything after it is not ours.
    assert 'version = "9.9.9"' in text


def test_stamp_fails_loudly_when_there_is_no_version_line(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[project]\nname = "strix-agent"\n', encoding="utf-8")
    with pytest.raises(InvalidTagError):
        stamp(pyproject, "1.6.2+tp.20260908")


def test_cli_emits_github_output_pairs(capsys: pytest.CaptureFixture[str]) -> None:
    # The workflow appends this straight to $GITHUB_OUTPUT, so the exact
    # key=value shape is load-bearing.
    assert main(["v1.6.2-TP-20260908"]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == [
        "display_version=1.6.2-TP-20260908",
        "package_version=1.6.2+tp.20260908",
    ]


def test_cli_rejects_a_bad_tag_with_a_nonzero_exit(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["not-a-tag"]) == 2
    assert "not a release tag" in capsys.readouterr().err
