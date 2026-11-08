"""Where the administrator's configuration lives, and how to show a location without giving away more than needed.

Standard library only, so it can be used whatever the state of the engine.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import contextlib
import shlex
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


def finder_steps(folder: Path | str) -> str:
    """How to open a folder in Finder that Finder does not show: on macOS, one inside ``~/Library``. Empty anywhere
    else. The folder is shown as ``~/...``, never by its full path. A sentence that starts with a space, to append."""
    if sys.platform != "darwin":
        return ""
    try:
        library = Path.home() / "Library"
    except RuntimeError:
        return ""
    place = Path(folder)
    if place != library and library not in place.parents:
        return ""
    return (
        " Finder hides that folder. To open it, click Finder in the Dock, choose Go > Go to Folder\u2026 in the menu "
        f"bar at the top of the screen, type {display_path(place)} and press Return."
    )


def hide_paths(text: str, *paths: Path) -> str:
    """Replace each of these places, wherever the text names it, by how ``display_path`` shows it."""
    shown = text
    for place in sorted({Path(p) for p in paths}, key=lambda p: -len(str(p))):
        shown = shown.replace(str(place), display_path(place))
    with contextlib.suppress(RuntimeError):  # no home folder to hide
        shown = shown.replace(str(Path.home()), "~")
    return shown


def bundled_command(name: str) -> Path | None:
    """The wrapper for a command, when this portal runs inside the macOS application. Otherwise ``None``.

    The application's Python is ``<app>/Contents/Resources/python/bin/python3``, and the wrappers that run the commands
    with it are in ``<app>/Contents/Resources/tools``. A normal install has no such folder next to its interpreter and
    its commands are on the search path under their plain names. Only the running interpreter's own place is looked at:
    nothing is read from the environment, and nothing is created.
    """
    if not sys.executable:
        return None
    try:
        wrapper = Path(sys.executable).resolve().parents[2] / "tools" / name
        return wrapper if wrapper.is_file() else None
    except (IndexError, OSError, RuntimeError):
        return None


def shell_path(place: Path) -> str:
    """A place as it can be typed into Terminal. ``~/...`` under the home folder, otherwise the full path.

    The part that has spaces or other special characters is quoted, and the leading ``~`` is not, so it still means the
    home folder.
    """
    with contextlib.suppress(ValueError, RuntimeError):
        return "~/" + shlex.quote(place.relative_to(Path.home()).as_posix())
    return shlex.quote(str(place))
