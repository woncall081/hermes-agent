# Encrypted credential runtime

This deployment removes persistent plaintext Hermes service credentials while preserving unattended reboot.

## Design

- `systemd-creds` encrypts the allowlisted credential files at `/etc/credstore.encrypted/` with the host key. The droplet has no TPM, so this protects against accidental plaintext exposure and backups, not a root/offline attacker who also obtains the host key.
- `hermes-credential-runtime.service` decrypts into systemd's root-only credential mount. systemd verified this mount as `tmpfs` with `noswap` on the target host.
- Mutable OAuth and `.env` files are copied into `/run/hermes-runtime`, a dedicated writable `tmpfs,noswap` mount, and the persistent paths become symlinks to the runtime copies.
- Codex `auth.json` and the generated app-server `config.toml` are encrypted as `codex-auth` and `codex-config`, materialized under `/run/hermes-runtime/codex`, and exposed to the gateway through `CODEX_HOME`. This keeps token refreshes and Codex's atomic file replacement inside tmpfs. The legacy persistent file references are runtime symlinks only.
- `hermes-credential-sync.path` re-encrypts mutable runtime files after changes and on service stop. It never writes plaintext outside `/run`.
- The 1Password service-account token is not copied into the writable runtime. It remains root-only in the systemd credential directory and is bind-mounted into only the gateway and dashboard containers.
- Root bootstrap wrappers inject the token only into credential-dependent service startup. After source application, `load_hermes_dotenv()` removes `OP_SERVICE_ACCOUNT_TOKEN` before the long-running agent or dashboard continues.
- Administrative CLI commands defer external source initialization, so status/config/tools/profile/Kanban/help/version operations perform no 1Password reads.
- `cache_ttl_seconds` remains zero; no `op_cache.json` is created.
- Plain swap is replaced by random-key dm-crypt swap so process-memory credentials cannot be written to plaintext swap.

## Rollback

The deployment records the previous image ID and creates a rollback compose file. If the new health gate fails, it recreates the prior image with an emergency `.op.env` generated only in the non-swappable runtime mount. No plaintext credential is restored to persistent storage.

## Rotation

1. Encrypt the replacement 1Password token with the same credential name (`op-service-account-token`) into `/etc/credstore.encrypted/hermes-op-service-account-token.cred` without placing it on argv.
2. Restart `hermes-credential-runtime.service`.
3. Recreate only `hermes-gateway` and `hermes-dashboard`.
4. Verify service health and scan for forbidden persistent plaintext/caches.

## Codex runtime enablement

Before first encryption, run the supported `/codex-runtime codex_app_server`
switch for an allowlisted profile while `CODEX_HOME` points at the existing
Codex home. This creates the managed `config.toml` (including the Hermes tool
callback) without copying OAuth material. Encrypt and verify `codex-auth` and
`codex-config`, restart the credential runtime, replace the two persistent
regular files with runtime symlinks, and recreate the gateway with
`CODEX_HOME=/run/hermes-runtime/codex`.

The writer-path audit must verify that the gateway and spawned Codex app-server
inherit that `CODEX_HOME`, that both files resolve to the `/run/hermes-runtime`
tmpfs device, and that no regular `auth.json` remains below the persistent
Codex home. A cold-boot test must stop the stack, clear the volatile mount via
the mount lifecycle, restart the credential runtime and Docker, then exercise
an allowlisted profile and its Kanban callback before the deployment is
accepted.

## Acceptance checks

- Targeted unit tests for lazy CLI loading, bootstrap loading, token cleanup, and s6 wrapper rendering pass.
- Image build and in-image smoke tests pass.
- systemd credential and runtime mounts report `noswap`; the token credential is root-owned mode `0400`.
- Docker inspect shows no `OP_SERVICE_ACCOUNT_TOKEN` value in container/image metadata.
- Harmless commands produce zero controlled 1Password reads.
- Gateway, dashboard, browser, Caddy, and public OIDC health checks pass.
- Exact-value scanning reports no known credential value outside approved encrypted or non-swappable runtime locations.
