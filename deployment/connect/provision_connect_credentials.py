#!/usr/bin/env python3
"""Encrypt a 1Password Connect credential pair from a private RAM filesystem."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import secrets
import shutil
import stat
import subprocess
from typing import Iterable


DEFAULT_STORE = Path("/etc/credstore.encrypted")
DEFAULT_SCRATCH = Path("/run/hermes-connect-provision")
_TOKEN_RE = re.compile(r"[A-Za-z0-9._~-]+")


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _mount_fstype(path: Path, mountinfo: Path = Path("/proc/self/mountinfo")) -> str:
    resolved = path.resolve(strict=True)
    matches: list[tuple[int, str]] = []
    for line in mountinfo.read_text(encoding="utf-8").splitlines():
        left, separator, right = line.partition(" - ")
        if not separator:
            continue
        fields = left.split()
        rhs = right.split()
        if len(fields) < 5 or not rhs:
            continue
        mount_point = Path(
            fields[4]
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
        )
        try:
            resolved.relative_to(mount_point)
        except ValueError:
            continue
        matches.append((len(mount_point.parts), rhs[0]))
    if not matches:
        raise RuntimeError(f"cannot determine filesystem type for {resolved}")
    return max(matches)[1]


def _validate_source(path: Path, *, label: str, expected_uid: int, max_bytes: int) -> bytes:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or path.is_symlink():
        raise ValueError(f"{label} is not a regular non-symlink file")
    if st.st_uid != expected_uid or stat.S_IMODE(st.st_mode) & 0o077:
        raise ValueError(f"{label} ownership or mode is unsafe")
    if st.st_size <= 0 or st.st_size > max_bytes:
        raise ValueError(f"{label} size is invalid")
    return path.read_bytes()


def _run(command: Iterable[os.PathLike[str] | str]) -> None:
    subprocess.run([os.fspath(value) for value in command], check=True)


def provision(
    credentials: Path,
    token: Path,
    *,
    store: Path = DEFAULT_STORE,
    scratch: Path = DEFAULT_SCRATCH,
    systemd_creds: Path = Path("/usr/bin/systemd-creds"),
    expected_uid: int = 1000,
    require_ramfs: bool = True,
    require_root: bool = True,
) -> int:
    """Verify, encrypt, and atomically install both Connect credentials."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if require_root and os.geteuid() != 0:
        raise PermissionError("Connect credential provisioning must run as root")

    scratch_resolved = scratch.resolve(strict=True)
    scratch_stat = scratch_resolved.stat()
    if (
        not scratch_resolved.is_dir()
        or scratch_stat.st_uid not in {0, expected_uid}
        or stat.S_IMODE(scratch_stat.st_mode) & 0o077
    ):
        raise ValueError("Connect provisioning scratch directory is unsafe")
    if require_ramfs and _mount_fstype(scratch_resolved) != "ramfs":
        raise ValueError("Connect provisioning scratch directory is not ramfs")

    for source in (credentials, token):
        try:
            source.resolve(strict=True).relative_to(scratch_resolved)
        except ValueError as exc:
            raise ValueError("Connect source is outside the approved RAM filesystem") from exc

    credentials_bytes = _validate_source(
        credentials,
        label="Connect server credentials",
        expected_uid=expected_uid,
        max_bytes=1024 * 1024,
    )
    token_bytes = _validate_source(
        token,
        label="Connect token",
        expected_uid=expected_uid,
        max_bytes=16384,
    )
    try:
        parsed = json.loads(credentials_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Connect server credentials are not valid JSON") from exc
    if not isinstance(parsed, dict) or not parsed:
        raise ValueError("Connect server credentials JSON is empty or invalid")
    try:
        token_value = token_bytes.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("Connect token has an invalid format") from exc
    if not token_value or not _TOKEN_RE.fullmatch(token_value):
        raise ValueError("Connect token has an invalid format")

    store.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(store, 0o700)
    if store.stat().st_uid != 0 and require_root:
        raise ValueError("encrypted credential store is not root-owned")

    generation_name = f"hermes-connect-generation-{secrets.token_hex(12)}"
    staging_dir = store / f".{generation_name}.staged-{os.getpid()}"
    generation_dir = store / generation_name
    current = store / "hermes-connect-current"
    current_temporary = store / f".hermes-connect-current.tmp-{os.getpid()}"
    staging_dir.mkdir(mode=0o700)
    entries = (
        ("op-connect-credentials", credentials, staging_dir / "op-connect-credentials.cred"),
        ("op-connect-token", token, staging_dir / "op-connect-token.cred"),
    )
    verification_paths: list[Path] = []
    try:
        for name, source, staged_path in entries:
            verify_path = scratch_resolved / f"verify-{name}-{os.getpid()}"
            verify_path.unlink(missing_ok=True)
            _run(
                (
                    systemd_creds,
                    "encrypt",
                    "--quiet",
                    "--with-key=host",
                    f"--name={name}",
                    source,
                    staged_path,
                )
            )
            os.chmod(staged_path, 0o600)
            if require_root:
                os.chown(staged_path, 0, 0)
            _run(
                (
                    systemd_creds,
                    "decrypt",
                    "--quiet",
                    f"--name={name}",
                    staged_path,
                    verify_path,
                )
            )
            verification_paths.append(verify_path)
            if _digest(verify_path) != _digest(source):
                raise RuntimeError(f"encrypted verification failed for {name}")
            with staged_path.open("rb") as handle:
                os.fsync(handle.fileno())
        generation_fd = os.open(staging_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(generation_fd)
        finally:
            os.close(generation_fd)

        os.replace(staging_dir, generation_dir)
        current_temporary.unlink(missing_ok=True)
        os.symlink(generation_name, current_temporary)
        os.replace(current_temporary, current)
        directory_fd = os.open(store, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        credentials.unlink()
        token.unlink()
        return len(entries)
    finally:
        for path in verification_paths:
            path.unlink(missing_ok=True)
        current_temporary.unlink(missing_ok=True)
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
        is_current = current.is_symlink() and os.readlink(current) == generation_name
        if generation_dir.exists() and not is_current:
            shutil.rmtree(generation_dir)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Encrypt and install a RAM-only 1Password Connect credential pair"
    )
    parser.add_argument("credentials", type=Path)
    parser.add_argument("token", type=Path)
    args = parser.parse_args()
    count = provision(args.credentials, args.token)
    print(f"connect_credentials_encrypted={count} verified=true")


if __name__ == "__main__":
    main()
