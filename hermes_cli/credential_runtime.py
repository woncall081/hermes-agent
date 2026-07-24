"""Helpers for safe writes through managed volatile credential symlinks."""
from __future__ import annotations

import os
from pathlib import Path


def credential_write_path(path: Path) -> Path:
    """Return the runtime target when *path* resolves below the approved root.

    Atomic writers must create sibling temporary files on the volatile
    filesystem rather than beside the persistent symlink. Paths unrelated to
    the managed runtime are returned unchanged.
    """
    logical = path.expanduser().absolute()
    resolved = Path(os.path.realpath(logical))
    if resolved == logical:
        return path
    runtime = Path(os.environ.get("HERMES_CREDENTIAL_RUNTIME_ROOT", "/run/hermes-runtime"))
    runtime = Path(os.path.realpath(runtime.expanduser().absolute()))
    try:
        resolved.relative_to(runtime)
    except ValueError:
        return path
    return resolved
