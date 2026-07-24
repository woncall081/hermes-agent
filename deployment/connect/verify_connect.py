#!/usr/bin/env python3
"""Verify a local 1Password Connect endpoint without exposing its bearer token."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import resource
import socket
import stat
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen


_TOKEN_RE = re.compile(r"[A-Za-z0-9._~-]+")


def _read_token(path: Path) -> str:
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or path.is_symlink():
        raise ValueError("Connect token file is not a regular non-symlink file")
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise ValueError("Connect token file permissions are unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        raw = os.read(fd, 16385)
    finally:
        os.close(fd)
    if len(raw) > 16384:
        raise ValueError("Connect token file is too large")
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("Connect token has an invalid format") from exc
    if not token or not _TOKEN_RE.fullmatch(token):
        raise ValueError("Connect token has an invalid format")
    return token


def _request(url: str, *, token: str = "") -> tuple[int, bytes]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers, method="GET")
    try:
        with urlopen(request, timeout=3) as response:
            return response.status, response.read(1024 * 1024)
    except HTTPError as exc:
        return exc.code, exc.read(4096)


def verify(
    base_url: str,
    token_file: Path,
    *,
    wait_seconds: float = 90,
    expected_vaults: int = 1,
) -> int:
    """Wait for Connect and verify health, denial, and authorized vault scope."""
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    parsed = urlparse(base_url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("Connect verification endpoint must be loopback HTTP")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Connect verification endpoint must not include a path")
    token = _read_token(token_file)
    deadline = time.monotonic() + max(0, wait_seconds)

    while True:
        try:
            health_status, _health = _request(urljoin(base_url.rstrip("/") + "/", "health"))
            denied_status, _denied = _request(
                urljoin(base_url.rstrip("/") + "/", "v1/vaults")
            )
            authorized_status, body = _request(
                urljoin(base_url.rstrip("/") + "/", "v1/vaults"), token=token
            )
            vaults = json.loads(body) if authorized_status == 200 else None
            if (
                health_status == 200
                and denied_status in {401, 403}
                and isinstance(vaults, list)
                and len(vaults) == expected_vaults
            ):
                return len(vaults)
        except (OSError, URLError, socket.timeout, json.JSONDecodeError, ValueError):
            pass
        if time.monotonic() >= deadline:
            raise TimeoutError(
                "Connect endpoint not ready or authorization policy mismatch"
            ) from None
        time.sleep(min(0.25, max(0.01, deadline - time.monotonic())))


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify local 1Password Connect")
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path("/run/hermes-runtime/bootstrap/op-connect-token"),
    )
    parser.add_argument("--wait-seconds", type=float, default=90)
    parser.add_argument("--expected-vaults", type=int, default=1)
    args = parser.parse_args()
    count = verify(
        args.base_url,
        args.token_file,
        wait_seconds=args.wait_seconds,
        expected_vaults=args.expected_vaults,
    )
    print(f"connect_health=true unauthenticated_denied=true authorized_vaults={count}")


if __name__ == "__main__":
    main()
