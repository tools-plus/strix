"""Fork identity: the program name and the per-user config directory.

Both differ from upstream so this fork can be installed and run alongside
``usestrix/strix`` -- a different console script keeps the two off each other's
PATH entry, and a different config directory keeps their credentials, MCP
servers and caches apart.

Every module reads these constants rather than rebuilding the paths, so the
fork's divergence from upstream is one file instead of a literal scattered
through a dozen.
"""

from __future__ import annotations

from pathlib import Path


#: The installed console script, used in help text and error hints.
PROGRAM_NAME = "strix-pentest"

#: Per-user state: config, OAuth tokens, MCP servers, caches.
CONFIG_DIR_NAME = ".strix-pentest"


def config_dir() -> Path:
    """The per-user config directory (``~/.strix-pentest``)."""
    return Path.home() / CONFIG_DIR_NAME


def config_path(name: str) -> Path:
    """A file inside the per-user config directory."""
    return config_dir() / name
