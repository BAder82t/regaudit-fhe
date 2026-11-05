"""Which verification engine this portal may use. Exactly one is recognised: the published regaudit-fhe 0.2.1.

The portal contains no verification logic. It calls ``regaudit_fhe.verify_report`` and gives a verdict only when the
installed engine is the recognised release: its version is 0.2.1 and its installed source files hash to the pinned
digest below. Anything else is refused. There is no option, flag or environment variable that changes this. Using
another engine needs a new, separately reviewed identity added to this file.

This module uses the standard library only and does not import the engine until the files have passed, so the
"verification unavailable" application can run when the engine is missing or damaged.

The check is of the installed source files. It does not show which code is actually running, and it is not a defence
against a tampered environment: an account that can change installed files can change this portal as well.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.metadata
import importlib.util
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

RELEASE = "0.2.1"
API = "regaudit_fhe.verify_report"

# How the digest below is made, so that anyone can reproduce it:
#   1. List every regular file under the ``regaudit_fhe`` package folder, leaving out anything inside a
#      ``__pycache__`` folder (46 files in 0.2.1). The check refuses, instead of skipping, a symbolic link anywhere in
#      the folder, anything that is not a regular file, and anything in a ``__pycache__`` folder that is not a regular
#      ``*.pyc`` file.
#   2. Name each file by its path inside the folder, written with "/" (for example ``fhe/backends.py``).
#   3. Sort the files by comparing those names part by part, splitting at "/" (so ``schemas/drift.input.schema.json``
#      comes before ``schemas.py``, which plain text order would not give).
#   4. Feed SHA-256, for each file in that order, the name as UTF-8, a zero byte, the file's own SHA-256 as 64
#      lowercase hex characters, and a newline.
# The result is the same for the 0.2.1 wheel on PyPI and for ``git archive v0.2.1:src/regaudit_fhe``. It covers the
# installed source files. Compiled ``.pyc`` files are not hashed, so the portal makes Python ignore the ones in the
# package folder (``regaudit_portal/__init__.py`` points the bytecode cache at a private folder), which means the
# code that loads is compiled from the files that were checked. The check still does not cover ``.pth`` files, the
# libraries the engine uses, or anything else around the files.
RELEASE_FILES_SHA256 = "84f9d593a2e3b325b091f5324dbec285ed64f10d174efce8c528ee8c1595d58e"

CHECK_SCOPE = (
    "This comparison covers the installed source files only. It does not show which code is actually running, and "
    "it is not a defence against a tampered environment."
)

# The approved text, word for word. The portal's security document, its README, the page that the warning
# links to and every saved result carry it unchanged. It must not be reworded here.
SECURITY_LIMITATION_TITLE = "Security limitation — published v0.2.1"
SECURITY_LIMITATION_PARAGRAPHS = (
    "Published regaudit-fhe v0.2.1 does not enforce the strict filesystem ownership and writable-permission "
    "protections for local trust-store and replay-state files introduced in the experimental code.",
    "Users with sufficient filesystem access may be able to modify those files. A valid report signature does not "
    "prove that the signing key was enrolled by an authenticated administrator.",
    "These protections are not included in the published v0.2.1 package. Do not rely on that version for security "
    "guarantees requiring them.",
)
SECURITY_LIMITATION = "\n\n".join((SECURITY_LIMITATION_TITLE, *SECURITY_LIMITATION_PARAGRAPHS))
# The shorter warning the interface shows beside a link to the full text.
SECURITY_LIMITATION_SHORT = (
    "Published v0.2.1 does not enforce strict ownership and permission protections for the local trust-store and "
    "replay-state files. A valid signature does not prove the key was enrolled by an authenticated administrator."
)

UNAVAILABLE_MESSAGE = (
    "The verification engine could not be loaded or its installation could not be validated. "
    "No verification was performed."
)

REINSTALL = 'pip install --force-reinstall "regaudit-fhe[server]==0.2.1"'


class UnsafeTree(Exception):
    """The engine folder holds something that is not a plain file: a link, or a stray entry in ``__pycache__``."""


def _name_order(name: str) -> tuple[str, ...]:
    return tuple(name.split("/"))


def _source_names(package_dir: Path) -> list[str]:
    """The files to hash. Refuses anything inside the tree that could make the hashed files differ from the loaded ones.

    No symbolic link is allowed anywhere inside the folder, whether to a file or to a folder, and nothing but a regular
    file. Inside a ``__pycache__`` folder only regular ``*.pyc`` files are allowed (they are not hashed, and are never
    loaded: see ``regaudit_portal/__init__.py``). A ``.py`` file, a link or a folder there is refused.
    """
    names = []
    for root, dirs, files in os.walk(package_dir, followlinks=False):
        here = Path(root)
        in_cache = "__pycache__" in here.relative_to(package_dir).parts
        for directory in dirs:
            path = here / directory
            if path.is_symlink():
                raise UnsafeTree(f"{path} is a symbolic link")
            if in_cache:
                raise UnsafeTree(f"{path} is a folder inside __pycache__")
        for file in files:
            path = here / file
            if path.is_symlink():
                raise UnsafeTree(f"{path} is a symbolic link")
            if not stat.S_ISREG(os.lstat(path).st_mode):
                raise UnsafeTree(f"{path} is not a regular file")
            if in_cache:
                if not file.endswith(".pyc"):
                    raise UnsafeTree(f"{path} is not a .pyc file but is inside __pycache__")
            else:
                names.append(path.relative_to(package_dir).as_posix())
    return sorted(names, key=_name_order)


def files_digest(package_dir: Path) -> str:
    """The digest that identifies the source files of a copy of the package (recipe above).

    Raises ``UnsafeTree`` for a link or a stray entry, and ``OSError`` if a file cannot be read or there are none.
    """
    names = _source_names(package_dir)
    if not names:
        raise OSError(
            f"no files found in {package_dir}"
        )  # the digest of nothing identifies nothing
    digest = hashlib.sha256()
    for name in names:
        content = hashlib.sha256((package_dir / name).read_bytes()).hexdigest()
        digest.update(name.encode("utf-8") + b"\0" + content.encode("ascii") + b"\n")
    return digest.hexdigest()


@dataclass(frozen=True)
class Identity:
    """The result of the check. ``detail`` is for the administrator's terminal only and never goes to a browser."""

    ok: bool
    reason: str
    detail: str
    engine: dict[str, Any] | None


def _refused(reason: str, detail: str) -> Identity:
    return Identity(False, reason, detail, None)


def _locate() -> Path | None:
    """Where the engine would be imported from, found without importing it."""
    try:
        spec = importlib.util.find_spec("regaudit_fhe")
    except (ImportError, ValueError, AttributeError):
        return None
    places = list(spec.submodule_search_locations or ()) if spec is not None else []
    return Path(places[0]) if len(places) == 1 else None


def _distribution_version() -> str | None:
    try:
        return importlib.metadata.version("regaudit-fhe")
    except importlib.metadata.PackageNotFoundError:
        return None


def check_engine(package_dir: Path | None = None) -> Identity:
    """Is the installed engine exactly the recognised release? Never raises: any doubt is a refusal.

    The files are hashed first. Only if they are the published ones is the engine imported, so a modified engine is
    never run by this check. Takes about 5 ms, so the portal repeats it before every verification.
    """
    try:
        folder = package_dir if package_dir is not None else _locate()
        if folder is None:
            return _refused(
                "ENGINE_MISSING",
                "regaudit_fhe is not installed, or is installed in more than one place",
            )
        try:
            found = files_digest(folder)
        except UnsafeTree as exc:
            return _refused(
                "ENGINE_TREE_UNSAFE",
                f"the engine folder {folder} is not made of plain files only: {exc}",
            )
        except OSError as exc:
            return _refused("ENGINE_UNREADABLE", f"cannot read the engine files in {folder}: {exc}")
        if found != RELEASE_FILES_SHA256:
            return _refused(
                "ENGINE_NOT_RECOGNISED",
                f"the engine files in {folder} hash to {found}, which is not the published {RELEASE} release "
                f"({RELEASE_FILES_SHA256})",
            )
        module = importlib.import_module("regaudit_fhe")
        loaded_from = Path(str(module.__file__)).resolve().parent
        if loaded_from != folder.resolve():
            return _refused(
                "ENGINE_LOCATION",
                f"the engine in use is {loaded_from}, not the files checked in {folder}",
            )
        version = getattr(module, "__version__", None)
        if version != RELEASE:
            return _refused(
                "ENGINE_VERSION", f"the engine reports version {version!r}, not {RELEASE!r}"
            )
        distribution = _distribution_version()
        if distribution not in (None, RELEASE):
            return _refused(
                "ENGINE_VERSION",
                f"the installed distribution is version {distribution!r}, not {RELEASE!r}",
            )
    except Exception as exc:  # the check itself failing is a refusal, never a pass
        return _refused(
            "ENGINE_CHECK_FAILED", f"the engine check failed: {type(exc).__name__}: {exc}"
        )
    return Identity(
        True,
        "OK",
        "",
        {
            "name": "regaudit-fhe",
            "version": version,
            "installed_distribution_version": distribution,
            "required_version": RELEASE,
            "api": API,
            "release_files": "IDENTICAL",
            "summary": (
                f"Verdicts are produced by regaudit-fhe {version}, using its published verification API ({API}). "
                f"Its installed source files are identical to the published {RELEASE} release, checked when the "
                "portal started and again before each verification."
            ),
            "check_scope": CHECK_SCOPE,
            "security_limitation": SECURITY_LIMITATION,
            "security_limitation_short": SECURITY_LIMITATION_SHORT,
        },
    )
