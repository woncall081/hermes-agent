"""Tests for the secret-source tracking in ``hermes_cli.env_loader``.

These cover the small public surface that lets `hermes model` / `hermes setup`
label detected credentials with their origin ("from Bitwarden") so users
don't see an unexplained "credentials ✓" line when their .env is empty.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hermes_cli import env_loader  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_sources():
    """Each test starts with a clean source map and applied-home guard."""
    env_loader._SECRET_SOURCES.clear()
    env_loader.reset_secret_source_cache()
    yield
    env_loader._SECRET_SOURCES.clear()
    env_loader.reset_secret_source_cache()


def test_get_secret_source_returns_none_for_untracked_var():
    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") is None


def test_get_secret_source_returns_label_for_tracked_var():
    env_loader._SECRET_SOURCES["ANTHROPIC_API_KEY"] = "bitwarden"
    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") == "bitwarden"


def test_format_secret_source_suffix_empty_for_untracked():
    # Credentials from .env or the shell shouldn't add noise — the
    # implicit case stays unlabeled.
    assert env_loader.format_secret_source_suffix("ANTHROPIC_API_KEY") == ""


def test_format_secret_source_suffix_bitwarden_uses_proper_name():
    env_loader._SECRET_SOURCES["ANTHROPIC_API_KEY"] = "bitwarden"
    assert (
        env_loader.format_secret_source_suffix("ANTHROPIC_API_KEY")
        == " (from Bitwarden)"
    )


def test_format_secret_source_suffix_generic_label_for_future_sources():
    # Future-proofing: a new secret source (e.g. "vault") should still
    # produce a sensible label without needing to edit every call site.
    env_loader._SECRET_SOURCES["OPENAI_API_KEY"] = "vault"
    assert env_loader.format_secret_source_suffix("OPENAI_API_KEY") == " (from vault)"


def test_format_secret_source_suffix_onepassword_uses_proper_name():
    env_loader._SECRET_SOURCES["OPENAI_API_KEY"] = "onepassword"
    assert (
        env_loader.format_secret_source_suffix("OPENAI_API_KEY") == " (from 1Password)"
    )


@pytest.mark.parametrize(
    "argv",
    [
        ["--help"],
        ["-V"],
        ["version"],
        ["config", "check"],
        ["profile", "list"],
        ["profile", "describe", "qa"],
        ["-p", "qa", "profile", "show", "qa"],
        ["sessions", "list"],
        ["completion", "bash"],
        ["skills", "list"],
        ["plugins", "list"],
        ["tools", "list"],
        ["mcp", "list"],
        ["gateway", "status"],
        ["cron", "list"],
        ["secrets", "onepassword", "set", "KEY", "op://Vault/Item/field"],
        ["secrets", "onepassword", "remove", "KEY"],
        ["secrets", "onepassword", "disable"],
        ["secrets", "onepassword", "sync", "--help"],
        ["-m", "config", "config", "check"],
        ["--provider=skills", "tools", "list"],
    ],
)
def test_local_cli_commands_skip_external_secret_loading(argv):
    assert not env_loader.cli_argv_needs_external_secrets(argv)


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["chat"],
        ["gateway", "run"],
        ["dashboard"],
        ["mcp", "test", "github"],
        ["cron", "run", "job-id"],
        ["-m", "config", "chat"],
        ["profile", "describe", "qa", "--auto"],
        ["profile", "describe", "--all", "--auto"],
        ["curator", "run", "--consolidate"],
        ["curator", "run", "--dry-run", "--consolidate"],
        ["skills", "publish", "./my-skill"],
        ["skills", "search", "react"],
        ["skills", "install", "official/example"],
        ["plugins", "install", "example"],
        ["secrets", "onepassword", "setup"],
        ["secrets", "onepassword", "status"],
        ["secrets", "onepassword", "sync"],
        ["secrets", "op", "sync"],
        ["secrets", "1password", "sync"],
        ["model"],
        ["setup"],
        ["doctor"],
        ["dump"],
        ["postinstall"],
        [
            "mcp",
            "add",
            "x",
            "--command",
            "node",
            "--args",
            "server.js",
            "--help",
        ],
    ],
)
def test_runtime_cli_commands_keep_external_secret_loading(argv):
    assert env_loader.cli_argv_needs_external_secrets(argv)


def test_credentialed_skills_publish_loads_mocked_onepassword_in_subprocess(tmp_path):
    marker = tmp_path / "op-calls"
    fake_op = tmp_path / "op"
    fake_op.write_text(
        f"#!/bin/sh\nprintf 'read\\n' >> {marker}\nprintf 'github-token-from-op\\n'\n"
    )
    fake_op.chmod(0o755)
    (tmp_path / "config.yaml").write_text(
        "secrets:\n"
        "  onepassword:\n"
        "    enabled: true\n"
        f"    binary_path: {fake_op}\n"
        "    cache_ttl_seconds: 0\n"
        "    env:\n"
        "      GITHUB_TOKEN: 'op://Private/GitHub/token'\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "HERMES_HOME": str(tmp_path),
        "OP_SERVICE_ACCOUNT_TOKEN": "ops_test_bootstrap",
        "PYTHONPATH": str(ROOT),
    }
    env.pop("GITHUB_TOKEN", None)
    cli = ROOT / ".venv" / "bin" / "hermes"

    local = subprocess.run(
        [str(cli), "skills", "list"],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert local.returncode == 0, local.stderr
    assert not marker.exists()

    subprocess.run(
        [str(cli), "skills", "publish", str(tmp_path / "missing-skill")],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert marker.read_text().splitlines() == ["read"]


def test_onepassword_sync_loads_only_bootstrap_before_fresh_read(tmp_path):
    marker = tmp_path / "op-bootstrap-seen"
    fake_op = tmp_path / "op"
    fake_op.write_text(
        "#!/bin/sh\n"
        "token=${OP_SERVICE_ACCOUNT_TOKEN:-missing}\n"
        f"printf '%s\\n' \"$token\" >> '{marker}'\n"
        '[ "$token" = ops_test_bootstrap ] || exit 7\n'
        "printf 'resolved-from-op\\n'\n",
        encoding="utf-8",
    )
    fake_op.chmod(0o755)
    (tmp_path / ".op.env").write_text(
        "OP_SERVICE_ACCOUNT_TOKEN=ops_test_bootstrap\n", encoding="utf-8"
    )
    (tmp_path / "config.yaml").write_text(
        "secrets:\n"
        "  onepassword:\n"
        "    enabled: true\n"
        f"    binary_path: {fake_op}\n"
        "    override_existing: false\n"
        "    cache_ttl_seconds: 0\n"
        "    env:\n"
        "      TEST_PROVIDER_API_KEY: 'op://Private/Provider/key'\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "HERMES_HOME": str(tmp_path),
        "PYTHONPATH": str(ROOT),
    }
    env.pop("OP_SERVICE_ACCOUNT_TOKEN", None)
    env.pop("TEST_PROVIDER_API_KEY", None)
    cli = ROOT / ".venv" / "bin" / "hermes"

    result = subprocess.run(
        [str(cli), "secrets", "onepassword", "sync"],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert marker.read_text().splitlines() == ["ops_test_bootstrap"]


@pytest.mark.parametrize("command", ["model", "setup", "doctor", "dump", "postinstall"])
def test_credential_aware_command_startup_loads_mocked_onepassword(command, tmp_path):
    """Credential-aware command families must resolve external-only keys.

    Importing ``hermes_cli.main`` executes the real startup classification and
    dotenv path without invoking the interactive command body.
    """
    marker = tmp_path / "op-calls"
    fake_op = tmp_path / "op"
    fake_op.write_text(
        f"#!/bin/sh\nprintf 'read\\n' >> {marker}\nprintf 'provider-key-from-op\\n'\n"
    )
    fake_op.chmod(0o755)
    (tmp_path / "config.yaml").write_text(
        "secrets:\n"
        "  onepassword:\n"
        "    enabled: true\n"
        f"    binary_path: {fake_op}\n"
        "    cache_ttl_seconds: 0\n"
        "    env:\n"
        "      TEST_PROVIDER_API_KEY: 'op://Private/Provider/key'\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "HERMES_HOME": str(tmp_path),
        "OP_SERVICE_ACCOUNT_TOKEN": "ops_test_bootstrap",
        "PYTHONPATH": str(ROOT),
    }
    env.pop("TEST_PROVIDER_API_KEY", None)

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; sys.argv=['hermes', sys.argv[1]]; import hermes_cli.main",
            command,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert marker.read_text().splitlines() == ["read"]


def test_load_hermes_dotenv_can_skip_external_secret_sources(tmp_path, monkeypatch):
    calls = {"n": 0}

    def _unexpected_external_load(_home_path):
        calls["n"] += 1

    monkeypatch.setattr(
        env_loader, "_apply_external_secret_sources", _unexpected_external_load
    )

    env_loader.load_hermes_dotenv(
        hermes_home=tmp_path,
        load_external_secrets=False,
    )

    assert calls["n"] == 0


def test_cli_deferral_blocks_later_default_loader_calls(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(env_loader, "_EXTERNAL_SECRET_SOURCES_DEFERRED", False)
    monkeypatch.setattr(
        env_loader,
        "_apply_external_secret_sources",
        lambda home_path: calls.append(home_path),
    )

    env_loader.defer_external_secret_sources()
    env_loader.load_hermes_dotenv(hermes_home=tmp_path)
    env_loader.load_hermes_dotenv(hermes_home=tmp_path)

    assert calls == []


def test_load_hermes_dotenv_loads_external_secret_sources_by_default(
    tmp_path, monkeypatch
):
    calls = []
    monkeypatch.setattr(
        env_loader,
        "_apply_external_secret_sources",
        lambda home_path: calls.append(home_path),
    )

    env_loader.load_hermes_dotenv(hermes_home=tmp_path)

    assert calls == [tmp_path]


def test_external_secret_resolution_consumes_onepassword_bootstrap_token(
    tmp_path, monkeypatch
):
    seen = []
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops_bootstrap_only")
    monkeypatch.setattr(
        env_loader,
        "_apply_external_secret_sources",
        lambda home_path: seen.append(os.environ.get("OP_SERVICE_ACCOUNT_TOKEN")),
    )

    env_loader.load_hermes_dotenv(hermes_home=tmp_path)

    assert seen == ["ops_bootstrap_only"]
    assert "OP_SERVICE_ACCOUNT_TOKEN" not in os.environ


def test_external_secret_failure_still_consumes_onepassword_bootstrap_token(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("OP_SERVICE_ACCOUNT_TOKEN", "ops_bootstrap_only")

    def fail(_home_path):
        raise RuntimeError("provider failed")

    monkeypatch.setattr(env_loader, "_apply_external_secret_sources", fail)

    with pytest.raises(RuntimeError, match="provider failed"):
        env_loader.load_hermes_dotenv(hermes_home=tmp_path)

    assert "OP_SERVICE_ACCOUNT_TOKEN" not in os.environ


def test_apply_external_secret_sources_records_bitwarden_origin(tmp_path, monkeypatch):
    """End-to-end: when the Bitwarden source fetches keys, applied vars
    end up in ``_SECRET_SOURCES`` so the UI can label them."""

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "0.test-token")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "secrets:\n"
        "  bitwarden:\n"
        "    enabled: true\n"
        "    project_id: test-project\n"
        "    access_token_env: BWS_ACCESS_TOKEN\n",
        encoding="utf-8",
    )

    # Stub the fetch layer under the SecretSource adapter.
    import agent.secret_sources.bitwarden as bw_module

    monkeypatch.setattr(bw_module, "find_bws", lambda **_kw: Path("/fake/bws"))
    monkeypatch.setattr(
        bw_module,
        "fetch_bitwarden_secrets",
        lambda **_kw: ({"ANTHROPIC_API_KEY": "sk-ant-test"}, []),
    )

    from agent.secret_sources import registry as reg_module

    reg_module._reset_registry_for_tests()

    env_loader._apply_external_secret_sources(tmp_path)

    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") == "bitwarden"
    assert (
        env_loader.format_secret_source_suffix("ANTHROPIC_API_KEY")
        == " (from Bitwarden)"
    )


def test_apply_external_secret_sources_noop_when_disabled(tmp_path, monkeypatch):
    """Disabled Bitwarden config must not touch the source map."""

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "secrets:\n  bitwarden:\n    enabled: false\n",
        encoding="utf-8",
    )

    env_loader._apply_external_secret_sources(tmp_path)

    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") is None


def test_apply_external_secret_sources_dedupes_within_process(tmp_path, monkeypatch):
    """``load_hermes_dotenv()`` is called at module-import time from several
    hot modules (cli.py, hermes_cli/main.py, run_agent.py, ...).  The
    Bitwarden status line previously printed once per call — 3-5x per
    startup.  The applied-home guard must short-circuit subsequent calls
    so the heavy work (config re-parse, Bitwarden lookup, status print)
    runs exactly once per HERMES_HOME per process.
    """

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.setenv("BWS_ACCESS_TOKEN", "0.test-token")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "secrets:\n"
        "  bitwarden:\n"
        "    enabled: true\n"
        "    project_id: test-project\n"
        "    access_token_env: BWS_ACCESS_TOKEN\n",
        encoding="utf-8",
    )

    call_count = {"n": 0}

    def _fake_fetch(**_kwargs):
        call_count["n"] += 1
        return {"ANTHROPIC_API_KEY": "sk-ant-test"}, []

    import agent.secret_sources.bitwarden as bw_module

    monkeypatch.setattr(bw_module, "find_bws", lambda **_kw: Path("/fake/bws"))
    monkeypatch.setattr(bw_module, "fetch_bitwarden_secrets", _fake_fetch)

    from agent.secret_sources import registry as reg_module

    reg_module._reset_registry_for_tests()

    # Five calls in a row, simulating module-import-time invocations from
    # cli.py, hermes_cli/main.py, run_agent.py, trajectory_compressor.py,
    # gateway/run.py.  Only the first should actually call the backend.
    for _ in range(5):
        env_loader._apply_external_secret_sources(tmp_path)

    assert call_count["n"] == 1, (
        "Bitwarden backend was called {} time(s); expected exactly 1 — "
        "the applied-home guard is broken.".format(call_count["n"])
    )

    # Source tracking still works after dedup.
    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") == "bitwarden"

    # reset_secret_source_cache() forces a fresh pull on the next call.
    env_loader.reset_secret_source_cache()
    env_loader._apply_external_secret_sources(tmp_path)
    assert call_count["n"] == 2


def test_apply_external_secret_sources_records_onepassword_origin(
    tmp_path, monkeypatch
):
    """When the 1Password source resolves refs, applied vars end up in
    ``_SECRET_SOURCES`` labeled ``onepassword``."""

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    (tmp_path / "config.yaml").write_text(
        "secrets:\n"
        "  onepassword:\n"
        "    enabled: true\n"
        "    env:\n"
        "      ANTHROPIC_API_KEY: 'op://Private/Anthropic/credential'\n",
        encoding="utf-8",
    )

    import agent.secret_sources.onepassword as op_module

    monkeypatch.setattr(op_module, "find_op", lambda *_a, **_kw: Path("/fake/op"))
    monkeypatch.setattr(
        op_module,
        "fetch_onepassword_secrets",
        lambda **_kw: ({"ANTHROPIC_API_KEY": "sk-ant-test"}, []),
    )

    from agent.secret_sources import registry as reg_module

    reg_module._reset_registry_for_tests()

    env_loader._apply_external_secret_sources(tmp_path)

    assert env_loader.get_secret_source("ANTHROPIC_API_KEY") == "onepassword"
    assert (
        env_loader.format_secret_source_suffix("ANTHROPIC_API_KEY")
        == " (from 1Password)"
    )


def test_apply_external_secret_sources_survives_non_dict_section(tmp_path, monkeypatch):
    """A malformed `secrets:` section must not abort startup (fail-open).

    Both `onepassword: true` (non-dict) and a bad bitwarden section must be
    coerced to empty config instead of raising AttributeError up through
    load_hermes_dotenv().
    """

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        "secrets:\n  bitwarden: true\n  onepassword: true\n",
        encoding="utf-8",
    )

    # Must not raise and must not record anything.
    env_loader._apply_external_secret_sources(tmp_path)
    assert env_loader.get_secret_source("ANYTHING") is None


def test_apply_external_secret_sources_bad_ttl_does_not_crash(tmp_path, monkeypatch):
    """A non-numeric cache_ttl_seconds must be coerced, not crash startup."""

    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    (tmp_path / "config.yaml").write_text(
        "secrets:\n"
        "  onepassword:\n"
        "    enabled: true\n"
        "    cache_ttl_seconds: not-a-number\n"
        "    env:\n"
        "      K: 'op://V/I/F'\n",
        encoding="utf-8",
    )

    captured = {}

    def _fake_fetch(**kwargs):
        captured.update(kwargs)
        return {}, []

    import agent.secret_sources.onepassword as op_module

    monkeypatch.setattr(op_module, "find_op", lambda *_a, **_kw: Path("/fake/op"))
    monkeypatch.setattr(op_module, "fetch_onepassword_secrets", _fake_fetch)

    from agent.secret_sources import registry as reg_module

    reg_module._reset_registry_for_tests()

    env_loader._apply_external_secret_sources(tmp_path)

    # Coerced to the 300s default rather than raising ValueError.
    assert captured["cache_ttl_seconds"] == 300
