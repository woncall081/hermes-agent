#!/usr/bin/env bash
# Encrypt the RAM-only Connect credential pair and perform the staged rollout.
set -Eeuo pipefail
umask 077
ulimit -c 0

readonly SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly REPO=$(cd -- "$SCRIPT_DIR/../.." && pwd)
readonly SCRATCH=/run/hermes-connect-provision
readonly CREDENTIALS="$SCRATCH/1password-credentials.json"
readonly TOKEN="$SCRATCH/connect-token"

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo/root so systemd credentials and Docker can be updated." >&2
  exit 1
fi
exec 9>/run/lock/hermes-connect-deploy.lock
flock -n 9 || { echo "Another Connect deployment is already running." >&2; exit 1; }
mountpoint -q "$SCRATCH" || { echo "Missing private provisioning ramfs; run prepare_connect_server.sh first." >&2; exit 1; }
[[ $(findmnt -n -o FSTYPE --target "$SCRATCH") == ramfs ]] || {
  echo "$SCRATCH is not ramfs" >&2
  exit 1
}
[[ -f "$CREDENTIALS" && ! -L "$CREDENTIALS" && -f "$TOKEN" && ! -L "$TOKEN" ]] || {
  echo "Incomplete Connect credential pair in private ramfs." >&2
  exit 1
}

python3 "$SCRIPT_DIR/provision_connect_credentials.py" "$CREDENTIALS" "$TOKEN"
"$REPO/deployment/encrypted-credential-runtime/deploy.sh"
python3 "$SCRIPT_DIR/verify_connect.py" --wait-seconds 120 --expected-vaults 1

umount /run/hermes-connect-provision
rmdir /run/hermes-connect-provision
echo "Connect rollout complete: credentials encrypted, endpoint verified, plaintext ramfs removed."
