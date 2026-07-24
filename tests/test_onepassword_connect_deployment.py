from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker-compose.yml"
DEPLOY = ROOT / "deployment" / "encrypted-credential-runtime"

API_IMAGE = (
    "1password/connect-api:1.8.2@"
    "sha256:e915c0c843972f02b0e7e2de502bda8bd4a092288b3f1866098a857bd715a281"
)
SYNC_IMAGE = (
    "1password/connect-sync:1.8.2@"
    "sha256:6297ca6136c0f0fb096bc64c49e1bc8df2aab35282ebff8c7bb60745ef176d0d"
)


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


def _mount(service: dict, target: str) -> dict:
    return next(
        volume
        for volume in service["volumes"]
        if isinstance(volume, dict) and volume.get("target") == target
    )


def test_connect_images_and_network_exposure_are_pinned_and_private():
    compose = _compose()
    services = compose["services"]
    api = services["op-connect-api"]
    sync = services["op-connect-sync"]

    assert api["image"] == API_IMAGE
    assert sync["image"] == SYNC_IMAGE
    assert api["ports"] == ["127.0.0.1:8080:8080"]
    assert "ports" not in sync
    assert api["networks"] == ["op-connect-bus"]
    assert set(sync["networks"]) == {"op-connect-bus", "op-connect-egress"}
    assert compose["networks"]["op-connect-bus"]["internal"] is True
    assert not compose["networks"]["op-connect-egress"].get("internal", False)


def test_connect_server_credentials_are_exact_read_only_bind_mounts():
    compose = _compose()
    for name in ("op-connect-api", "op-connect-sync"):
        service = compose["services"][name]
        credential = _mount(
            service, "/home/opuser/.op/1password-credentials.json"
        )
        assert credential == {
            "type": "bind",
            "source": "/run/hermes-runtime/bootstrap/op-connect-credentials",
            "target": "/home/opuser/.op/1password-credentials.json",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
        assert "OP_CONNECT_TOKEN" not in "\n".join(service.get("environment", []))


def test_connect_bus_is_explicit_and_data_volume_is_shared():
    compose = _compose()
    services = compose["services"]
    api_env = set(services["op-connect-api"]["environment"])
    sync_env = set(services["op-connect-sync"]["environment"])

    assert "OP_BUS_PORT=11223" in api_env
    assert "OP_BUS_PEERS=op-connect-sync:11223" in api_env
    assert "OP_BUS_PORT=11223" in sync_env
    assert "OP_BUS_PEERS=op-connect-api:11223" in sync_env
    assert "op_connect_data" in compose["volumes"]
    for name in ("op-connect-api", "op-connect-sync"):
        data = _mount(services[name], "/home/opuser/.op/data")
        assert data == {
            "type": "volume",
            "source": "op_connect_data",
            "target": "/home/opuser/.op/data",
        }


def test_hermes_services_receive_only_connect_endpoint_and_token_path():
    compose = _compose()
    for name in ("gateway", "dashboard"):
        service = compose["services"][name]
        env = set(service["environment"])
        assert "OP_CONNECT_HOST=http://127.0.0.1:8080" in env
        assert (
            "HERMES_OP_CONNECT_TOKEN_FILE=/run/secrets/hermes-op-connect-token"
            in env
        )
        assert not any(value.startswith("OP_CONNECT_TOKEN=") for value in env)
        token_mount = _mount(service, "/run/secrets/hermes-op-connect-token")
        assert token_mount == {
            "type": "bind",
            "source": "/run/hermes-runtime/bootstrap/op-connect-token",
            "target": "/run/secrets/hermes-op-connect-token",
            "read_only": True,
            "bind": {"create_host_path": False},
        }
        # Retain the encrypted Service Account file as rollback-only material.
        assert any(
            isinstance(volume, str)
            and "op-service-account-token:/run/secrets/hermes-op-service-account-token:ro"
            in volume
            for volume in service["volumes"]
        )


def test_systemd_materializes_both_connect_credentials_from_encrypted_store():
    service = (DEPLOY / "hermes-credential-runtime.service").read_text(
        encoding="utf-8"
    )
    manifest = (DEPLOY / "credential-manifest.sh").read_text(encoding="utf-8")
    runtime = (DEPLOY / "hermes-credential-runtime-start").read_text(
        encoding="utf-8"
    )

    assert (
        "LoadCredentialEncrypted=op-connect-credentials:"
        "/etc/credstore.encrypted/hermes-connect-current/op-connect-credentials.cred"
    ) in service
    assert (
        "LoadCredentialEncrypted=op-connect-token:"
        "/etc/credstore.encrypted/hermes-connect-current/op-connect-token.cred"
    ) in service
    assert "op-connect-credentials|" in manifest
    assert "|bootstrap/op-connect-credentials" in manifest
    assert "op-connect-token|" in manifest
    assert "|bootstrap/op-connect-token" in manifest
    assert '"$name" = op-connect-credentials' in runtime
    assert "install -m 0400 -o 999 -g 999" in runtime


def test_operator_workflow_is_least_privilege_and_two_phase():
    connect_dir = ROOT / "deployment" / "connect"
    prepare = (connect_dir / "prepare_connect_server.sh").read_text(encoding="utf-8")
    deploy_connect = (connect_dir / "deploy_connect.sh").read_text(encoding="utf-8")
    deploy_runtime = (DEPLOY / "deploy.sh").read_text(encoding="utf-8")

    assert "mount -t ramfs" in prepare
    assert "unset OP_SERVICE_ACCOUNT_TOKEN OP_CONNECT_HOST OP_CONNECT_TOKEN" in prepare
    assert 'connect server create "Hermes Connect" --vaults "Hermes"' in prepare
    assert 'connect token create "Hermes Agent read-only"' in prepare
    assert '--server "Hermes Connect" --vault "Hermes,r"' in prepare
    assert "1password-credentials.json" in prepare
    assert "connect-token" in prepare

    provision_position = deploy_connect.index("provision_connect_credentials.py")
    deploy_position = deploy_connect.index("encrypted-credential-runtime/deploy.sh")
    assert provision_position < deploy_position
    assert "umount /run/hermes-connect-provision" in deploy_connect

    connect_start = deploy_runtime.index("op-connect-sync op-connect-api")
    connect_verify = deploy_runtime.index("verify_connect.py")
    hermes_start = deploy_runtime.index("gateway dashboard")
    assert connect_start < connect_verify < hermes_start
    assert "hermes-op-connect-api hermes-op-connect-sync" in deploy_runtime
    assert "gateway dashboard caddy executive-assistant-browser" in deploy_runtime
    assert "agency-browser" not in deploy_runtime


def test_connect_pair_is_rotation_managed_and_not_mutable_sync_input():
    sync = (DEPLOY / "hermes-credential-sync").read_text(encoding="utf-8")
    deploy_runtime = (DEPLOY / "deploy.sh").read_text(encoding="utf-8")

    assert "op-connect-credentials|op-connect-token" in sync
    assert "continue" in sync
    final_sync = deploy_runtime.index("systemctl start hermes-credential-sync.service")
    rollback_disable = deploy_runtime.rindex("LIVE_CHANGED=0")
    assert final_sync < rollback_disable


def test_rollback_checks_every_restore_step_and_verifies_service_health():
    deploy_runtime = (DEPLOY / "deploy.sh").read_text(encoding="utf-8")
    rollback = deploy_runtime[
        deploy_runtime.index("rollback(){") : deploy_runtime.index("trap rollback ERR")
    ]

    assert "|| true" not in rollback
    assert "rollback_failed" in rollback
    assert "127.0.0.1:9119/health" in rollback
    assert "hermes-executive-assistant-browser" in rollback
