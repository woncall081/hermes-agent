from __future__ import annotations

import json
import os
from pathlib import Path


def _managed_symlink(tmp_path: Path, relative: str) -> tuple[Path, Path, Path]:
    runtime = tmp_path / "run" / "hermes-runtime"
    target = runtime / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    persistent = tmp_path / "home" / relative
    persistent.parent.mkdir(parents=True, exist_ok=True)
    persistent.symlink_to(target)
    return runtime, persistent, target


def test_credential_write_path_redirects_only_managed_runtime_symlink(monkeypatch, tmp_path):
    from hermes_cli.credential_runtime import credential_write_path

    runtime, persistent, target = _managed_symlink(tmp_path, "profiles/default/.env")
    monkeypatch.setenv("HERMES_CREDENTIAL_RUNTIME_ROOT", str(runtime))
    assert credential_write_path(persistent) == target

    unmanaged_target = tmp_path / "elsewhere" / "secret"
    unmanaged_target.parent.mkdir()
    unmanaged = tmp_path / "unmanaged-link"
    unmanaged.symlink_to(unmanaged_target)
    assert credential_write_path(unmanaged) == unmanaged


def test_env_atomic_writes_stay_in_runtime_and_preserve_symlink(monkeypatch, tmp_path):
    from hermes_cli import config

    runtime, persistent, target = _managed_symlink(tmp_path, ".env")
    target.write_text("EXISTING=1\n", encoding="utf-8")
    target.chmod(0o600)
    monkeypatch.setenv("HERMES_CREDENTIAL_RUNTIME_ROOT", str(runtime))
    monkeypatch.setattr(config, "get_env_path", lambda: persistent)
    monkeypatch.setattr(config, "ensure_hermes_home", lambda: None)
    monkeypatch.setattr(config, "is_managed", lambda: False)

    config.save_env_value("RUNTIME_TEST_KEY", "private-value")
    assert persistent.is_symlink()
    assert "RUNTIME_TEST_KEY=private-value" in target.read_text(encoding="utf-8")
    assert list(persistent.parent.glob(".env_*")) == []

    assert config.remove_env_value("RUNTIME_TEST_KEY") is True
    assert persistent.is_symlink()
    assert "private-value" not in target.read_text(encoding="utf-8")
    os.environ.pop("RUNTIME_TEST_KEY", None)


def test_auth_atomic_write_stays_in_runtime_and_preserves_symlink(monkeypatch, tmp_path):
    from hermes_cli import auth

    runtime, persistent, target = _managed_symlink(tmp_path, "auth.json")
    target.write_text("{}\n", encoding="utf-8")
    target.chmod(0o600)
    monkeypatch.setenv("HERMES_CREDENTIAL_RUNTIME_ROOT", str(runtime))

    result = auth._save_auth_store({"providers": {"demo": {"token": "private"}}}, persistent)
    assert result == persistent
    assert persistent.is_symlink()
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["providers"]["demo"]["token"] == "private"
    assert list(persistent.parent.glob("auth.json.tmp.*")) == []
