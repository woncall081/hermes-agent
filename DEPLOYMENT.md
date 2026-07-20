# Joey Hermes Dashboard Deployment

This branch preserves the hardened deployment for `js.thesamudioagency.com`.

## Security contract

- Run the stack as the host `hermes` account, never with root's home.
- The launcher derives and exports the host account's UID/GID.
- Google OIDC authorization allows only `joey@samudioagency.com` and requires a verified email claim.
- Caddy is the only public dashboard entry point on TCP 80/443.
- TCP 9119 remains denied by the host firewall.
- Google OAuth credentials resolve from 1Password at runtime.
- Never commit `.op.env`, resolved credentials, tokens, or OAuth secrets.

## Start or redeploy

From a root shell:

```bash
cd /home/hermes/.hermes/hermes-agent
./start-dashboard.sh
```

The launcher safely drops to the `hermes` account, normalizes both operational
scripts to mode `0700`, validates 1Password and Compose, builds
`hermes-agent:js-dashboard-hardened`, and recreates the dashboard and Caddy.
Do not bypass the launcher with a bare `docker compose up`; Compose intentionally
requires `HERMES_UID` and `HERMES_GID`.

## Verify

```bash
sudo /home/hermes/.hermes/hermes-agent/audit-dashboard.sh
```

Then test in private browser sessions:

1. `joey@samudioagency.com` can sign in.
2. Every other Google identity is denied.

## Update from upstream

Before updating, create an encrypted off-host backup of the Hermes profile. Then:

```bash
cd /home/hermes/.hermes/hermes-agent
git switch deployment/js-dashboard-hardened
git fetch origin
git rebase origin/main
```

Resolve conflicts without dropping the self-hosted OIDC allowlist. Before deployment,
rerun the focused provider tests and shell/Compose checks. Rebuild through
`start-dashboard.sh`, rerun the audit, and repeat the two-account browser test.

## Roll back source

The known-good deployment tag is `deployment-js-dashboard-v1`. To inspect or rebuild
that exact source without moving the deployment branch:

```bash
cd /home/hermes/.hermes/hermes-agent
git switch --detach deployment-js-dashboard-v1
./start-dashboard.sh
```

Return to maintained deployment source with:

```bash
git switch deployment/js-dashboard-hardened
```

A source rollback does not restore profile data. Profile recovery requires a separate,
encrypted backup and restore procedure.
