#!/usr/bin/env python3
"""Encrypt the explicitly allowlisted Hermes credential files."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess

STORE = Path("/etc/credstore.encrypted")
RUN = Path("/run/hermes-credential-migration")
DROPIN = Path("/etc/systemd/system/hermes-credential-runtime.service.d/tree-credentials.conf")
ENTRIES = (
    ("default-env", Path("/home/hermes/.hermes/.env")),
    ("agency-env", Path("/home/hermes/.hermes/profiles/agency/.env")),
    ("default-auth", Path("/home/hermes/.hermes/auth.json")),
    ("be-auth", Path("/home/hermes/.hermes/profiles/be/auth.json")),
    ("fe-auth", Path("/home/hermes/.hermes/profiles/fe/auth.json")),
    ("agency-google-client-secret", Path("/home/hermes/.hermes/profiles/agency/google_client_secret.json")),
    ("agency-google-token", Path("/home/hermes/.hermes/profiles/agency/google_token.json")),
)
TREE_NAME = "mcp-tokens"
TREE = Path("/home/hermes/.hermes/mcp-tokens")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def encrypted_path(name: str) -> Path:
    return STORE / f"hermes-{name}.cred"


def encrypt(name: str, source: Path) -> None:
    if not source.is_file() or source.stat().st_size == 0:
        raise SystemExit(f"required credential source is missing or invalid: {source}")
    output = encrypted_path(name)
    temporary = STORE / f".{output.name}.tmp.{os.getpid()}"
    check = RUN / f"verify-{hashlib.sha256(name.encode()).hexdigest()}"
    try:
        subprocess.run(
            ["systemd-creds", "encrypt", "--quiet", "--with-key=host", f"--name={name}", str(source), str(temporary)],
            check=True,
        )
        os.chmod(temporary, 0o600)
        os.chown(temporary, 0, 0)
        subprocess.run(
            ["systemd-creds", "decrypt", "--quiet", f"--name={name}", str(temporary), str(check)],
            check=True,
        )
        if digest(check) != digest(source):
            raise SystemExit(f"encrypted credential verification failed: {name}")
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
        check.unlink(missing_ok=True)


def extract_op_token() -> Path:
    legacy = Path("/home/hermes/.hermes/.op.env")
    if not legacy.is_file():
        raise SystemExit("legacy .op.env is missing before initial migration")
    token = ""
    for line in legacy.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "OP_SERVICE_ACCOUNT_TOKEN":
            token = value.strip()
    if not re.fullmatch(r"ops_[A-Za-z0-9_]+", token):
        raise SystemExit("legacy .op.env does not contain one valid service-account token")
    path = RUN / "op-service-account-token"
    path.write_text(token, encoding="utf-8")
    os.chmod(path, 0o600)
    os.chown(path, 0, 0)
    return path


def tree_files() -> list[tuple[str, Path]]:
    root = TREE.resolve(strict=True)
    files: list[tuple[str, Path]] = []
    for source in sorted(root.rglob("*")):
        if source.is_symlink():
            raise SystemExit(f"credential tree contains a symlink: {source}")
        if not source.is_file():
            continue
        relative = source.relative_to(root).as_posix()
        if not relative or ".." in relative.split("/"):
            raise SystemExit("invalid credential-tree relative path")
        encoded = relative.encode("utf-8").hex()
        files.append((f"tree-{TREE_NAME}--{encoded}", source))
    if not files:
        raise SystemExit("credential tree is empty")
    return files


def write_dropin() -> None:
    blobs = sorted(STORE.glob(f"hermes-tree-{TREE_NAME}--*.cred"))
    lines = ["[Service]"]
    for blob in blobs:
        name = blob.name.removeprefix("hermes-").removesuffix(".cred")
        lines.append(f"LoadCredentialEncrypted={name}:{blob}")
    DROPIN.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = DROPIN.with_name(f".{DROPIN.name}.tmp.{os.getpid()}")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.replace(temporary, DROPIN)


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("must run as root")
    STORE.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STORE, 0o700)
    RUN.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(RUN, 0o700)

    op_blob = encrypted_path("op-service-account-token")
    legacy = Path("/home/hermes/.hermes/.op.env")
    if legacy.is_file():
        token_path = extract_op_token()
        try:
            encrypt("op-service-account-token", token_path)
        finally:
            token_path.unlink(missing_ok=True)
    elif not op_blob.is_file():
        raise SystemExit("neither legacy nor encrypted 1Password bootstrap exists")

    for name, source in ENTRIES:
        encrypt(name, source.resolve(strict=True))

    wanted_tree_blobs: set[Path] = set()
    for name, source in tree_files():
        encrypt(name, source)
        wanted_tree_blobs.add(encrypted_path(name))
    for stale in STORE.glob(f"hermes-tree-{TREE_NAME}--*.cred"):
        if stale not in wanted_tree_blobs:
            stale.unlink()
    write_dropin()
    print(f"encrypted_credentials={1 + len(ENTRIES) + len(wanted_tree_blobs)} verified=true")


if __name__ == "__main__":
    main()
