"""A local browser interface for checking signed regaudit-fhe reports.

It calls the published verifier and shows what it returns. It contains no cryptography of its own.

Copyright (C) 2026 VaultBytes Innovations Ltd
Licensed under AGPL-3.0-or-later.
"""

# This comes first, before any module of this package or of the engine is imported. The engine check hashes the
# engine's source files, but Python can run a compiled ``.pyc`` file next to them without looking at the source (an
# unchecked-hash file, or one whose recorded time and size match). Pointing the bytecode cache at a fresh private
# folder means no ``.pyc`` file inside the engine's folder, or anywhere else, is ever loaded: modules imported from now
# on are compiled from their source files, which are the files that were checked. The folder is created with mode
# 0700 when the package is first imported and removed, best effort, when the process exits. Modules that were
# already imported before this package was are not affected.
import atexit
import os
import shutil
import sys
import tempfile


def _use_a_private_bytecode_cache() -> str:
    folder = tempfile.mkdtemp(
        prefix="regaudit-portal-pyc-"
    )  # a new, empty folder, readable by this account only
    os.chmod(folder, 0o700)
    sys.pycache_prefix = folder
    atexit.register(shutil.rmtree, folder, ignore_errors=True)
    return folder


PRIVATE_BYTECODE_CACHE = _use_a_private_bytecode_cache()

__version__ = "0.0.1"
