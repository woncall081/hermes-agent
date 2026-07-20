#!/usr/bin/env bash
set -Eeuo pipefail

# The dashboard owns files in the Hermes profile and reads a narrowly scoped
# 1Password service-account token. Never run the stack with root's HOME.
if (( EUID == 0 )); then
  id hermes >/dev/null 2>&1 || {
    echo 'Required service user does not exist: hermes' >&2
    exit 1
  }
  hermes_uid=$(id -u hermes)
  hermes_gid=$(id -g hermes)
  drop_privileges=(
    env
    HOME=/home/hermes
    HERMES_HOME=/home/hermes/.hermes
    HERMES_UID="$hermes_uid"
    HERMES_GID="$hermes_gid"
    HERMES_OP_ENV=/home/hermes/.hermes/.op.env
    OP_BIN=/home/hermes/.hermes/bin/op
    OP_CONFIG_DIR=/home/hermes/.hermes/.op-cli
    "$0" "$@"
  )
  if command -v runuser >/dev/null; then
    exec runuser -u hermes -- "${drop_privileges[@]}"
  elif command -v sudo >/dev/null; then
    exec sudo -u hermes -H "${drop_privileges[@]}"
  else
    echo 'Run this launcher as the hermes user; runuser and sudo are unavailable.' >&2
    exit 1
  fi
fi

cd "$(dirname "$0")"
# Git records only the executable bit (typically checking these files out as
# 0755), while this deployment's local security contract requires 0700.
chmod 700 "$0" audit-dashboard.sh
HERMES_HOME=${HERMES_HOME:-$HOME/.hermes}
OP_ENV=${HERMES_OP_ENV:-$HERMES_HOME/.op.env}
OP_CONFIG_DIR=${OP_CONFIG_DIR:-$HERMES_HOME/.op-cli}
HERMES_UID=$(id -u)
HERMES_GID=$(id -g)
export HERMES_UID HERMES_GID
install -d -m 700 "$OP_CONFIG_DIR"
export OP_CONFIG_DIR

command -v docker >/dev/null || { echo 'Docker CLI not found.' >&2; exit 1; }
docker compose version >/dev/null || { echo 'Docker Compose plugin not found.' >&2; exit 1; }
docker info >/dev/null || { echo 'Cannot access the Docker daemon.' >&2; exit 1; }
[[ -r "$OP_ENV" ]] || { echo "Missing or unreadable $OP_ENV" >&2; exit 1; }
op_env_owner=$(stat -c '%u:%g' "$OP_ENV")
op_env_mode=$(stat -c '%a' "$OP_ENV")
expected_owner="$HERMES_UID:$HERMES_GID"
[[ "$op_env_owner" == "$expected_owner" ]] || {
  echo "$OP_ENV must be owned by the runtime account ($expected_owner); found $op_env_owner" >&2
  exit 1
}
[[ "$op_env_mode" == 600 ]] || {
  echo "$OP_ENV must have mode 0600; found $op_env_mode" >&2
  exit 1
}

# Load only the bootstrap variable, without printing its value or sourcing arbitrary shell code.
token=''
while IFS='=' read -r key value; do
  [[ "$key" == OP_SERVICE_ACCOUNT_TOKEN ]] && token=$value
done < "$OP_ENV"
[[ "$token" == ops_* ]] || { echo "No valid service-account token in $OP_ENV" >&2; exit 1; }
export OP_SERVICE_ACCOUNT_TOKEN=$token
unset token

OP_BIN=${OP_BIN:-$HERMES_HOME/bin/op}
[[ -x "$OP_BIN" ]] || { echo "1Password CLI not found: $OP_BIN" >&2; exit 1; }
"$OP_BIN" whoami >/dev/null || { echo '1Password service-account authentication failed.' >&2; exit 1; }

printf 'Validating Compose configuration...\n'
docker compose config --quiet
printf 'Building dashboard authorization code...\n'
docker compose build gateway
printf 'Pulling pinned Caddy image...\n'
docker compose pull caddy
printf 'Starting dashboard and Caddy...\n'
docker compose up -d --force-recreate dashboard caddy

url=https://js.thesamudioagency.com
for ((attempt=1; attempt<=60; attempt++)); do
  if curl -fsS --max-time 5 "$url" >/dev/null 2>&1; then
    printf 'Dashboard HTTPS endpoint is responding: %s\n' "$url"
    docker compose ps dashboard caddy
    exit 0
  fi
  sleep 2
done

echo "HTTPS did not become ready: $url" >&2
echo 'Check that inbound TCP 80 and 443 are allowed and TCP 9119 is blocked.' >&2
docker compose ps dashboard caddy >&2 || true
docker compose logs --tail=100 dashboard caddy >&2 || true
exit 1
