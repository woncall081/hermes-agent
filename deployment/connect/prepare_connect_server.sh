#!/usr/bin/env bash
# Create a least-privilege 1Password Connect server entirely in private RAM.
set -Eeuo pipefail
umask 077
ulimit -c 0

readonly SCRATCH=/run/hermes-connect-provision
readonly OP_BIN=/opt/data/bin/op
readonly OP_SHA256=eef619cb796d4ed75edec657f1c1d39c2e86020511e9c4df5e9b7c8de111e9cc
readonly ACCOUNT=${1:-}

if [[ $(id -u) -ne 1000 || $(id -g) -ne 1000 ]]; then
  echo "Run this script as the hermes user (UID/GID 1000), not root." >&2
  exit 1
fi
[[ -x "$OP_BIN" ]] || { echo "Missing pinned 1Password CLI: $OP_BIN" >&2; exit 1; }
printf '%s  %s\n' "$OP_SHA256" "$OP_BIN" | sha256sum -c - >/dev/null

sudo install -d -m 0700 -o 1000 -g 1000 "$SCRATCH"
if mountpoint -q "$SCRATCH"; then
  [[ $(findmnt -n -o FSTYPE --target "$SCRATCH") == ramfs ]] || {
    echo "$SCRATCH is mounted but is not ramfs" >&2
    exit 1
  }
else
  sudo mount -t ramfs -o nodev,nosuid,noexec ramfs "$SCRATCH"
  sudo chown 1000:1000 "$SCRATCH"
  sudo chmod 0700 "$SCRATCH"
fi

if [[ -e "$SCRATCH/1password-credentials.json" || -e "$SCRATCH/connect-token" ]]; then
  echo "Private provisioning RAM already contains a Connect credential pair; deploy or clear it first." >&2
  exit 1
fi

unset OP_SERVICE_ACCOUNT_TOKEN OP_CONNECT_HOST OP_CONNECT_TOKEN
unset HERMES_OP_SERVICE_ACCOUNT_TOKEN_FILE HERMES_OP_CONNECT_TOKEN_FILE

if ! "$OP_BIN" whoami --format=json >/dev/null 2>&1; then
  if [[ -n "$ACCOUNT" ]]; then
    signin_export=$("$OP_BIN" signin --account "$ACCOUNT")
  else
    signin_export=$("$OP_BIN" signin)
  fi
  eval "$signin_export"
  unset signin_export
fi

cd "$SCRATCH"
account_args=()
[[ -n "$ACCOUNT" ]] && account_args=(--account "$ACCOUNT")
"$OP_BIN" connect server create "Hermes Connect" --vaults "Hermes" "${account_args[@]}"
"$OP_BIN" connect token create "Hermes Agent read-only" \
  --server "Hermes Connect" --vault "Hermes,r" "${account_args[@]}" > .connect-token.tmp

[[ -f 1password-credentials.json && ! -L 1password-credentials.json ]] || {
  echo "1Password CLI did not create the expected server credentials file." >&2
  exit 1
}
chmod 0600 1password-credentials.json .connect-token.tmp

python3 - 1password-credentials.json .connect-token.tmp <<'PY'
import json
from pathlib import Path
import re
import sys
credentials, token_path = map(Path, sys.argv[1:])
parsed = json.loads(credentials.read_text(encoding="utf-8"))
if not isinstance(parsed, dict) or not parsed:
    raise SystemExit("Connect server credentials JSON is invalid")
token = token_path.read_text(encoding="ascii").strip()
if not re.fullmatch(r"[A-Za-z0-9._~-]+", token):
    raise SystemExit("Connect token output is invalid; nothing was persisted")
token_path.write_text(token + "\n", encoding="ascii")
PY
mv .connect-token.tmp connect-token
chmod 0600 connect-token

echo "Connect server created for vault Hermes; credential pair is held only in private ramfs."
echo "Next: sudo $(dirname "$0")/deploy_connect.sh"
