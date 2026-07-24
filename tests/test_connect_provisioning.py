from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = (
    ROOT
    / "deployment"
    / "connect"
    / "provision_connect_credentials.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("connect_provision", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fake_systemd_creds(path: Path, *, fail_name: str = "") -> Path:
    script = path / "systemd-creds"
    script.write_text(
        "#!/usr/bin/env python3\n"
        "import shutil, sys\n"
        f"fail={fail_name!r}\n"
        "name=next((x.split('=',1)[1] for x in sys.argv if x.startswith('--name=')), '')\n"
        "if fail and name == fail: raise SystemExit(23)\n"
        "shutil.copyfile(sys.argv[-2], sys.argv[-1])\n",
        encoding="utf-8",
    )
    script.chmod(0o700)
    return script


def _sources(scratch: Path) -> tuple[Path, Path]:
    credentials = scratch / "1password-credentials.json"
    token = scratch / "connect-token"
    credentials.write_text('{"verifier":"dummy","encCredentials":"dummy"}\n')
    token.write_text("header.payload.signature\n")
    credentials.chmod(0o600)
    token.chmod(0o600)
    return credentials, token


def test_provision_encrypts_verifies_installs_pair_and_removes_plaintext(tmp_path):
    module = _load_module()
    scratch = tmp_path / "scratch"
    store = tmp_path / "store"
    scratch.mkdir(mode=0o700)
    store.mkdir(mode=0o700)
    credentials, token = _sources(scratch)
    fake = _fake_systemd_creds(tmp_path)

    count = module.provision(
        credentials,
        token,
        store=store,
        scratch=scratch,
        systemd_creds=fake,
        expected_uid=os.getuid(),
        require_ramfs=False,
        require_root=False,
    )

    assert count == 2
    assert not credentials.exists()
    assert not token.exists()
    current = store / "hermes-connect-current"
    assert (current / "op-connect-credentials.cred").is_file()
    assert (current / "op-connect-token.cred").is_file()
    assert (current / "op-connect-credentials.cred").stat().st_mode & 0o777 == 0o600
    assert (current / "op-connect-token.cred").stat().st_mode & 0o777 == 0o600
    assert list(scratch.glob("verify-*")) == []


def test_provision_failure_keeps_previous_pair_and_plaintext_sources(tmp_path):
    module = _load_module()
    scratch = tmp_path / "scratch"
    store = tmp_path / "store"
    scratch.mkdir(mode=0o700)
    store.mkdir(mode=0o700)
    credentials, token = _sources(scratch)
    old_credentials = store / "hermes-op-connect-credentials.cred"
    old_token = store / "hermes-op-connect-token.cred"
    old_credentials.write_bytes(b"old-credentials")
    old_token.write_bytes(b"old-token")
    fake = _fake_systemd_creds(tmp_path, fail_name="op-connect-token")

    with pytest.raises(Exception):
        module.provision(
            credentials,
            token,
            store=store,
            scratch=scratch,
            systemd_creds=fake,
            expected_uid=os.getuid(),
            require_ramfs=False,
            require_root=False,
        )

    assert old_credentials.read_bytes() == b"old-credentials"
    assert old_token.read_bytes() == b"old-token"
    assert credentials.is_file()
    assert token.is_file()
    assert list(store.glob(".*.staged-*")) == []
    assert list(scratch.glob("verify-*")) == []


def test_provision_publishes_pair_through_one_atomic_generation_link(tmp_path):
    module = _load_module()
    scratch = tmp_path / "scratch"
    store = tmp_path / "store"
    scratch.mkdir(mode=0o700)
    store.mkdir(mode=0o700)
    credentials, token = _sources(scratch)
    fake = _fake_systemd_creds(tmp_path)

    module.provision(
        credentials,
        token,
        store=store,
        scratch=scratch,
        systemd_creds=fake,
        expected_uid=os.getuid(),
        require_ramfs=False,
        require_root=False,
    )

    current = store / "hermes-connect-current"
    assert current.is_symlink()
    generation = current.resolve(strict=True)
    assert generation.parent == store.resolve()
    assert (generation / "op-connect-credentials.cred").is_file()
    assert (generation / "op-connect-token.cred").is_file()
    assert not (store / "hermes-op-connect-credentials.cred").exists()
    assert not (store / "hermes-op-connect-token.cred").exists()


def test_provision_commit_failure_never_exposes_a_mixed_generation(tmp_path, monkeypatch):
    module = _load_module()
    scratch = tmp_path / "scratch"
    store = tmp_path / "store"
    scratch.mkdir(mode=0o700)
    store.mkdir(mode=0o700)
    old_generation = store / "hermes-connect-generation-old"
    old_generation.mkdir(mode=0o700)
    (old_generation / "op-connect-credentials.cred").write_bytes(b"old-credentials")
    (old_generation / "op-connect-token.cred").write_bytes(b"old-token")
    current = store / "hermes-connect-current"
    current.symlink_to(old_generation.name)
    credentials, token = _sources(scratch)
    fake = _fake_systemd_creds(tmp_path)

    real_replace = module.os.replace

    def fail_current_link(source, destination):
        if Path(destination) == current:
            raise OSError("injected atomic link switch failure")
        return real_replace(source, destination)

    monkeypatch.setattr(module.os, "replace", fail_current_link)

    with pytest.raises(OSError, match="atomic link switch failure"):
        module.provision(
            credentials,
            token,
            store=store,
            scratch=scratch,
            systemd_creds=fake,
            expected_uid=os.getuid(),
            require_ramfs=False,
            require_root=False,
        )

    assert current.resolve(strict=True) == old_generation.resolve()
    assert (current / "op-connect-credentials.cred").read_bytes() == b"old-credentials"
    assert (current / "op-connect-token.cred").read_bytes() == b"old-token"
    assert credentials.is_file()
    assert token.is_file()
    assert list(store.glob(".hermes-connect-current.tmp-*")) == []
    assert list(store.glob(".hermes-connect-generation-*.staged-*")) == []


def test_provision_rejects_invalid_connect_token_before_encryption(tmp_path):
    module = _load_module()
    scratch = tmp_path / "scratch"
    store = tmp_path / "store"
    scratch.mkdir(mode=0o700)
    store.mkdir(mode=0o700)
    credentials, token = _sources(scratch)
    token.write_text("not a token with spaces\n")
    token.chmod(0o600)
    fake = _fake_systemd_creds(tmp_path)

    with pytest.raises(ValueError, match="invalid format"):
        module.provision(
            credentials,
            token,
            store=store,
            scratch=scratch,
            systemd_creds=fake,
            expected_uid=os.getuid(),
            require_ramfs=False,
            require_root=False,
        )

    assert list(store.iterdir()) == []
