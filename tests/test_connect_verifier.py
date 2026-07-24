from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from pathlib import Path
import threading

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "deployment" / "connect" / "verify_connect.py"
TOKEN = "header.payload.signature"


def _load_module():
    spec = importlib.util.spec_from_file_location("connect_verify", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Handler(BaseHTTPRequestHandler):
    expected_token = TOKEN

    def log_message(self, format, *args):
        del format, args
        return

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"name":"1Password Connect API","version":"test"}')
            return
        if self.path == "/v1/vaults":
            if self.headers.get("Authorization") != f"Bearer {self.expected_token}":
                self.send_response(401)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'[{"id":"v1"}]')
            return
        self.send_response(404)
        self.end_headers()


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_verify_requires_denied_unauthenticated_and_exact_vault_count(tmp_path):
    module = _load_module()
    token = tmp_path / "token"
    token.write_text(TOKEN)
    token.chmod(0o400)
    server = _server()
    try:
        count = module.verify(
            f"http://127.0.0.1:{server.server_port}",
            token,
            wait_seconds=1,
            expected_vaults=1,
        )
    finally:
        server.shutdown()
    assert count == 1


def test_verify_failure_never_exposes_bearer(tmp_path):
    module = _load_module()
    token = tmp_path / "token"
    token.write_text("wrong.token.value")
    token.chmod(0o400)
    server = _server()
    try:
        with pytest.raises(TimeoutError) as excinfo:
            module.verify(
                f"http://127.0.0.1:{server.server_port}",
                token,
                wait_seconds=0.2,
                expected_vaults=1,
            )
    finally:
        server.shutdown()
    assert "wrong.token.value" not in str(excinfo.value)
