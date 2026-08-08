#!/usr/bin/env python3
"""Load the boot-time RAM snapshot directly into Hermes, then exec it."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path


GITHUB_TOKEN_FILE = Path(
    os.environ.get("HERMES_GITHUB_TOKEN_FILE", "/run/secrets/github-token")
)
DIGITALOCEAN_TOKEN_FILE = Path(
    os.environ.get(
        "HERMES_DIGITALOCEAN_TOKEN_FILE",
        "/run/secrets/digitalocean-token",
    )
)
SSH_PRIVATE_KEY_FILE = Path(
    os.environ.get(
        "HERMES_SSH_PRIVATE_KEY_SOURCE_FILE",
        "/run/secrets/ssh-private-key",
    )
)
DIRECT_SSH_PRIVATE_KEY_FILE = Path("/run/hermes-runtime/direct/ssh-private-key")
AGENCY_LOGINS_FILE = Path(
    os.environ.get("HERMES_AGENCY_LOGINS_FILE", "/run/secrets/agency-logins.json")
)
MAX_SECRET_BYTES = 256 * 1024


def fail(message: str) -> "NoReturn":
    print(f"hermes-direct-secrets: {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def read_private_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("RAM credential snapshot is unavailable")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("RAM credential snapshot is invalid")
        if metadata.st_uid not in {0, 1000} or stat.S_IMODE(metadata.st_mode) & 0o077:
            fail("RAM credential snapshot permissions are unsafe")
        payload = os.read(descriptor, MAX_SECRET_BYTES + 1)
    finally:
        os.close(descriptor)
    if not payload or len(payload) > MAX_SECRET_BYTES:
        fail("RAM credential snapshot payload is invalid")
    return payload


def read_token(path: Path) -> str:
    try:
        value = read_private_file(path).decode("utf-8")
    except UnicodeDecodeError:
        fail("RAM token encoding is invalid")
    if not value or any(ord(character) < 33 for character in value):
        fail("RAM token format is invalid")
    return value


def read_agency_logins(path: Path) -> dict[str, str]:
    try:
        payload = json.loads(read_private_file(path))
        secrets = payload["secrets"]
    except (json.JSONDecodeError, KeyError, TypeError):
        fail("agency RAM snapshot is invalid")
    expected = {
        "farmers_username": "FARMERS_AGENT_USERNAME",
        "farmers_password": "FARMERS_AGENT_PASSWORD",
        "agencyzoom_username": "AGENCYZOOM_USERNAME",
        "agencyzoom_password": "AGENCYZOOM_PASSWORD",
        "ricochet360_username": "RICOCHET360_USERNAME",
        "ricochet360_password": "RICOCHET360_PASSWORD",
    }
    environment: dict[str, str] = {}
    for field, variable in expected.items():
        value = secrets.get(field) if isinstance(secrets, dict) else None
        if not isinstance(value, str) or not value or "\x00" in value:
            fail("agency RAM snapshot is incomplete")
        environment[variable] = value
    return environment


def materialize_ssh_key(path: Path) -> None:
    payload = read_private_file(path)
    if not payload.startswith(b"-----BEGIN ") or b"PRIVATE KEY-----" not in payload[:128]:
        fail("SSH RAM snapshot is invalid")
    if not payload.endswith(b"\n"):
        payload += b"\n"
    DIRECT_SSH_PRIVATE_KEY_FILE.parent.mkdir(mode=0o700, exist_ok=True)
    temporary = DIRECT_SSH_PRIVATE_KEY_FILE.with_name(
        f".ssh-private-key.{os.getpid()}"
    )
    descriptor = os.open(
        temporary,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o400,
    )
    try:
        os.write(descriptor, payload)
        os.fchmod(descriptor, 0o400)
        os.fchown(descriptor, 1000, 1000)
    finally:
        os.close(descriptor)
    os.replace(temporary, DIRECT_SSH_PRIVATE_KEY_FILE)
    validation = subprocess.run(
        ["/usr/bin/ssh-keygen", "-y", "-f", str(DIRECT_SSH_PRIVATE_KEY_FILE)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    if validation.returncode != 0:
        fail("SSH RAM snapshot could not be loaded")


def build_environment() -> dict[str, str]:
    github_token = read_token(GITHUB_TOKEN_FILE)
    digitalocean_token = read_token(DIGITALOCEAN_TOKEN_FILE)
    materialize_ssh_key(SSH_PRIVATE_KEY_FILE)
    environment = os.environ.copy()
    environment.update(
        {
            "GITHUB_TOKEN": github_token,
            "GH_TOKEN": github_token,
            "DIGITALOCEAN_ACCESS_TOKEN": digitalocean_token,
            "DIGITALOCEAN_TOKEN": digitalocean_token,
            "HERMES_SSH_PRIVATE_KEY_FILE": str(DIRECT_SSH_PRIVATE_KEY_FILE),
            "HERMES_SSH_KNOWN_HOSTS_FILE": "/run/secrets/ssh-known-hosts",
            "HERMES_AGENCY_LOGINS_FILE": str(AGENCY_LOGINS_FILE),
            **read_agency_logins(AGENCY_LOGINS_FILE),
        }
    )
    for name in tuple(environment):
        if name.startswith("OP_") or name in {
            "SECRET_MANAGER_URL",
            "HERMES_WORKLOAD_IDENTITY_FILE",
        }:
            environment.pop(name, None)
    return environment


def main() -> None:
    environment = build_environment()
    if sys.argv[1:] == ["--check"]:
        print("hermes-direct-secrets: RAM bindings valid", flush=True)
        return
    print("hermes-direct-secrets: direct RAM bindings loaded", flush=True)
    os.execvpe(
        "/init",
        (
            "/init",
            "/opt/hermes/docker/main-wrapper.sh",
            *sys.argv[1:],
        ),
        environment,
    )


if __name__ == "__main__":
    main()
