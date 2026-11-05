"""Where the administrator's configuration lives, and how to show a location without giving away more than needed.

Standard library only, so it can be used whatever the state of the engine.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

APP_NAME = "Evidence Verification Portal"
CONFIG_NAME = "portal-config.json"
OUTSIDE_HOME = "(outside your home folder)"


def default_config_folder() -> Path:
    """The standard per-user folder for this computer. Nothing here creates it."""
    home = Path.home()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / APP_NAME
    return home / ".config" / "evidence-verification-portal"


def default_config_path() -> Path:
    return default_config_folder() / CONFIG_NAME


def display_path(path: Path | str) -> str:
    """``~/...`` for a place under the home folder. Anywhere else only the file's own name, never the full path."""
    place = Path(path)
    try:
        home = Path.home()
    except RuntimeError:
        return f"{OUTSIDE_HOME}/{place.name}"
    try:
        return "~" if place == home else f"~/{place.relative_to(home).as_posix()}"
    except ValueError:
        return f"{OUTSIDE_HOME}/{place.name}"


def hide_paths(text: str, *paths: Path) -> str:
    """Replace each of these places, wherever the text names it, by how ``display_path`` shows it."""
    shown = text
    for place in sorted({Path(p) for p in paths}, key=lambda p: -len(str(p))):
        shown = shown.replace(str(place), display_path(place))
    with contextlib.suppress(RuntimeError):  # no home folder to hide
        shown = shown.replace(str(Path.home()), "~")
    return shown
