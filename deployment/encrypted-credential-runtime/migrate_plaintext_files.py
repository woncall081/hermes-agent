#!/usr/bin/env python3
"""Replace allowlisted persistent credential files with volatile symlinks."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

RUNTIME = Path("/run/hermes-runtime")
STATIC = (
    (Path("/home/hermes/.hermes/.env"), RUNTIME / ".env"),
    (Path("/home/hermes/.hermes/profiles/agency/.env"), RUNTIME / "profiles/agency/.env"),
    (Path("/home/hermes/.hermes/auth.json"), RUNTIME / "auth.json"),
    (Path("/home/hermes/.hermes/profiles/be/auth.json"), RUNTIME / "profiles/be/auth.json"),
    (Path("/home/hermes/.hermes/profiles/fe/auth.json"), RUNTIME / "profiles/fe/auth.json"),
    (
        Path("/home/hermes/.hermes/profiles/agency/google_client_secret.json"),
        RUNTIME / "profiles/agency/google_client_secret.json",
    ),
    (
        Path("/home/hermes/.hermes/profiles/agency/google_token.json"),
        RUNTIME / "profiles/agency/google_token.json",
    ),
)
TREE_SOURCE = Path("/home/hermes/.hermes/mcp-tokens")
TREE_TARGET = RUNTIME / "mcp-tokens"
LEGACY_BOOTSTRAP = Path("/home/hermes/.hermes/.op.env")
OPTIONAL_VOLATILE = (
    (
        Path("/home/hermes/.hermes/profiles/agency/google_oauth_pending.json"),
        RUNTIME / "profiles/agency/google_oauth_pending.json",
    ),
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def erase_file(path: Path) -> None:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode):
        raise SystemExit(f"refusing to erase non-regular path: {path}")
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        remaining = st.st_size
        block = b"\0" * min(1024 * 1024, max(remaining, 1))
        while remaining:
            count = min(remaining, len(block))
            os.write(fd, block[:count])
            remaining -= count
        os.fsync(fd)
    finally:
        os.close(fd)
    path.unlink()


def install_symlink(path: Path, target: Path) -> None:
    temporary = path.with_name(f".{path.name}.runtime-link.{os.getpid()}")
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(target)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def verify_static() -> None:
    for source, target in STATIC:
        if source.is_symlink():
            if source.resolve(strict=True) != target.resolve(strict=True):
                raise SystemExit(f"unexpected credential symlink: {source}")
            continue
        if not source.is_file() or not target.is_file():
            raise SystemExit(f"missing source/runtime credential pair: {source}")
        if digest(source) != digest(target):
            raise SystemExit(f"runtime credential verification failed: {source}")


def verify_tree() -> None:
    if TREE_SOURCE.is_symlink():
        if TREE_SOURCE.resolve(strict=True) != TREE_TARGET.resolve(strict=True):
            raise SystemExit("unexpected MCP credential-tree symlink")
        return
    if not TREE_SOURCE.is_dir() or not TREE_TARGET.is_dir():
        raise SystemExit("missing MCP source/runtime credential tree")
    source_files = {
        path.relative_to(TREE_SOURCE).as_posix(): path
        for path in TREE_SOURCE.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    target_files = {
        path.relative_to(TREE_TARGET).as_posix(): path
        for path in TREE_TARGET.rglob("*")
        if path.is_file() and not path.is_symlink()
    }
    if not source_files or source_files.keys() != target_files.keys():
        raise SystemExit("MCP runtime credential-tree membership mismatch")
    for relative, source in source_files.items():
        if digest(source) != digest(target_files[relative]):
            raise SystemExit(f"MCP runtime credential verification failed: {relative}")


def migrate_static() -> int:
    migrated = 0
    for source, target in STATIC:
        if source.is_symlink():
            continue
        erase_file(source)
        install_symlink(source, target)
        migrated += 1
    return migrated


def migrate_tree() -> int:
    if TREE_SOURCE.is_symlink():
        return 0
    files = sorted(
        (path for path in TREE_SOURCE.rglob("*") if path.is_file() and not path.is_symlink()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for path in files:
        erase_file(path)
    directories = sorted(
        (path for path in TREE_SOURCE.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for directory in directories:
        directory.rmdir()
    TREE_SOURCE.rmdir()
    install_symlink(TREE_SOURCE, TREE_TARGET)
    return len(files)


def migrate_optional_volatile() -> int:
    migrated = 0
    for source, target in OPTIONAL_VOLATILE:
        if source.is_symlink():
            if Path(os.path.realpath(source)) != target:
                raise SystemExit(f"unexpected optional credential symlink: {source}")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.exists():
            if not source.is_file():
                raise SystemExit(f"invalid optional credential path: {source}")
            target.write_bytes(source.read_bytes())
            os.chmod(target, 0o600)
            os.chown(target, 1000, 1000)
            if digest(source) != digest(target):
                raise SystemExit(f"optional runtime credential verification failed: {source}")
            erase_file(source)
            migrated += 1
        install_symlink(source, target)
    return migrated


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    verify_static()
    verify_tree()

    migrated = migrate_static()
    migrated += migrate_tree()
    migrated += migrate_optional_volatile()
    if LEGACY_BOOTSTRAP.is_symlink():
        raise SystemExit("legacy bootstrap must never become a persistent symlink")
    if LEGACY_BOOTSTRAP.exists():
        erase_file(LEGACY_BOOTSTRAP)
        migrated += 1
    os.sync()

    verify_static()
    verify_tree()
    if LEGACY_BOOTSTRAP.exists() or LEGACY_BOOTSTRAP.is_symlink():
        raise SystemExit("legacy bootstrap removal failed")
    print(f"migrated_plaintext_paths={migrated} runtime_symlinks_verified=true")


if __name__ == "__main__":
    main()
