#!/usr/bin/env python3
"""Load dashboard OAuth from the RAM snapshot, then start the normal runtime."""

from __future__ import annotations

import json
import os
import stat
import sys


OIDC_SNAPSHOT_FILE = os.environ.get(
    "HERMES_DASHBOARD_OIDC_FILE",
    "/run/secrets/dashboard-oidc.json",
)
GITHUB_TOKEN_FILE = os.environ.get(
    "HERMES_GITHUB_TOKEN_FILE",
    "/run/secrets/github-token",
)
MAX_SNAPSHOT_BYTES = 64 * 1024


def fail(message: str) -> None:
    print(f"dashboard-bootstrap: {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


def load_oidc_snapshot(path: str) -> tuple[str, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("dashboard OAuth snapshot is unavailable")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("dashboard OAuth snapshot is invalid")
        if metadata.st_uid not in {0, 1000} or stat.S_IMODE(metadata.st_mode) & 0o077:
            fail("dashboard OAuth snapshot permissions are unsafe")
        raw = os.read(descriptor, MAX_SNAPSHOT_BYTES + 1)
    finally:
        os.close(descriptor)
    if not raw or len(raw) > MAX_SNAPSHOT_BYTES:
        fail("dashboard OAuth snapshot payload is invalid")
    try:
        decoded = json.loads(raw)
        client_id = decoded["client_id"]
        client_secret = decoded["client_secret"]
    except (json.JSONDecodeError, KeyError, TypeError):
        fail("dashboard OAuth snapshot encoding is invalid")
    if not isinstance(client_id, str) or not isinstance(client_secret, str):
        fail("dashboard OAuth snapshot fields are invalid")
    if not client_id or not client_secret:
        fail("dashboard OAuth snapshot fields are empty")
    if any(ord(character) < 32 for character in client_id + client_secret):
        fail("dashboard OAuth snapshot contains control characters")
    return client_id, client_secret


def load_github_token(path: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("dashboard GitHub snapshot is unavailable")
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            fail("dashboard GitHub snapshot is invalid")
        if metadata.st_uid not in {0, 1000} or stat.S_IMODE(metadata.st_mode) & 0o077:
            fail("dashboard GitHub snapshot permissions are unsafe")
        raw = os.read(descriptor, MAX_SNAPSHOT_BYTES + 1)
    finally:
        os.close(descriptor)
    try:
        token = raw.decode("utf-8")
    except UnicodeDecodeError:
        fail("dashboard GitHub snapshot encoding is invalid")
    if (
        not token
        or len(raw) > MAX_SNAPSHOT_BYTES
        or any(ord(character) < 33 for character in token)
    ):
        fail("dashboard GitHub snapshot payload is invalid")
    return token


def main() -> None:
    client_id, client_secret = load_oidc_snapshot(OIDC_SNAPSHOT_FILE)
    github_token = load_github_token(GITHUB_TOKEN_FILE)

    environment = os.environ.copy()
    environment["HERMES_DASHBOARD_OIDC_CLIENT_ID"] = client_id
    environment["HERMES_DASHBOARD_OIDC_CLIENT_SECRET"] = client_secret
    environment["GITHUB_TOKEN"] = github_token
    environment["GH_TOKEN"] = github_token
    for name in (
        "OP_CONNECT_HOST",
        "OP_CONNECT_TOKEN",
        "HERMES_OP_CONNECT_TOKEN_FILE",
        "HERMES_SECRET_ENV_ALLOWLIST",
    ):
        environment.pop(name, None)
    client_id = ""
    client_secret = ""
    github_token = ""

    print("dashboard-bootstrap: scoped OAuth bindings loaded", flush=True)
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
