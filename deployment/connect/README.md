# Shared 1Password Connect rollout

This rollout deploys one shared Connect API/Sync pair for every Hermes profile on the host.

## Security boundary

- The Connect server is limited to the single `Hermes` vault.
- The Hermes client token is explicitly `Hermes,r` (read-only).
- Server credentials and the client token are created in `/run/hermes-connect-provision`, a private `ramfs` mount.
- `systemd-creds` encrypts both artifacts with the host key before they leave RAM.
- Runtime plaintext is materialized only in the non-swappable `/run/hermes-runtime` mount.
- Docker receives only read-only file mounts and non-secret file-path environment variables. Neither bearer is stored in Compose, Docker `Config.Env`, command arguments, or logs.
- Connect API port 8080 binds only to `127.0.0.1`; Sync has outbound access but no published port.
- The existing Service Account token remains encrypted and available for rollback, but Hermes suppresses it whenever Connect is configured.

## Run on the Docker host

From the rollout checkout as the `hermes` user (UID/GID 1000):

```bash
cd /home/hermes/.hermes/hermes-connect-rollout-20260724
./deployment/connect/prepare_connect_server.sh [1password-account-shorthand]
```

The script verifies `/opt/data/bin/op` 2.35.0 by SHA-256, removes Service Account/Connect authentication variables from its own environment, and prompts for an authenticated 1Password user session if needed. It then creates:

- Connect server `Hermes Connect`, allowed vault: `Hermes`
- Connect token `Hermes Agent read-only`, grant: `Hermes,r`

Do not paste the token or credentials into chat, a shell command, an environment file, or Compose.

After creation succeeds:

```bash
sudo ./deployment/connect/deploy_connect.sh
```

The root-only deployment:

1. validates that both sources are private regular files owned by UID 1000 on `ramfs`;
2. encrypts and decrypt-verifies both with `systemd-creds`, then publishes the complete pair through one atomic generation-link switch;
3. removes the plaintext RAM sources;
4. installs the encrypted runtime boundary;
5. starts Connect Sync/API and verifies health, unauthenticated denial, and exactly one authorized vault;
6. recreates Hermes with file-based Connect authentication;
7. verifies all six containers and the local Connect endpoint;
8. unmounts the provisioning RAM filesystem.

## Rollback

The deployment takes a runtime backup and Compose snapshot before changing live services. Any failure restores the previous Hermes image and Compose configuration, removes the two new Connect containers, and verifies the restored Hermes container set and local health endpoint. A failed rollback exits with a distinct status and an operator-intervention warning rather than being suppressed. The encrypted Connect data volume is retained for diagnosis/retry. The encrypted Service Account credential remains available throughout the canary.

## Non-secret verification

```bash
sudo python3 deployment/connect/verify_connect.py --wait-seconds 10 --expected-vaults 1
docker inspect -f '{{json .NetworkSettings.Ports}}' hermes-op-connect-api
docker inspect -f '{{json .NetworkSettings.Ports}}' hermes-op-connect-sync
```

Expected results:

- verifier: `connect_health=true unauthorized_denied=true authorized_vaults=1`
- API: host binding only on `127.0.0.1:8080`
- Sync: no published ports

Never print or inspect the runtime credential files directly.
