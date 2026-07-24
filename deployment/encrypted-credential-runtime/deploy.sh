#!/bin/bash
set -Eeuo pipefail
umask 077

REPO=$(cd "$(dirname "$0")/../.." && pwd)
DEPLOY="$REPO/deployment/encrypted-credential-runtime"
HERMES_HOME=/home/hermes/.hermes
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
STATE="$HERMES_HOME/deployments/encrypted-credential-runtime-$STAMP"
CANDIDATE="hermes-agent:encrypted-credential-runtime-$STAMP"
LIVE_IMAGE=hermes-agent:js-dashboard-hardened
PROJECT=hermes-agent
LIVE_CHANGED=0
HEALTHY=0
OLD_IMAGE=$(docker image inspect "$LIVE_IMAGE" --format '{{.Id}}')
mkdir -p "$STATE"
chmod 0700 "$STATE"

log(){ printf '[encrypted-credential-runtime] %s\n' "$*"; }

make_rollback_op_env(){
    python3 - <<'PY'
from pathlib import Path
import os
src=Path('/run/hermes-runtime/bootstrap/op-service-account-token')
dst=Path('/run/hermes-runtime/rollback.op.env')
token=src.read_text(encoding='utf-8').strip()
if not token.startswith('ops_'):
    raise SystemExit('invalid runtime bootstrap token')
dst.write_text('OP_SERVICE_ACCOUNT_TOKEN='+token+'\n', encoding='utf-8')
os.chmod(dst, 0o400); os.chown(dst, 0, 0)
PY
}

rollback(){
    rc=$?
    trap - ERR
    rollback_failed=0
    if [ "$LIVE_CHANGED" = 1 ]; then
        log "candidate failed; restoring previous image without restoring plaintext files"
        if ! make_rollback_op_env; then
            log "rollback error: could not build RAM-only bootstrap environment"
            rollback_failed=1
        fi
        if ! docker tag "$OLD_IMAGE" "$LIVE_IMAGE"; then
            log "rollback error: could not restore previous image tag"
            rollback_failed=1
        fi
        if ! HERMES_UID=1000 HERMES_GID=1000 docker compose -p "$PROJECT" \
            -f "$STATE/rollback-compose.yml" up -d --force-recreate; then
            log "rollback error: previous Compose stack did not start"
            rollback_failed=1
        fi
        for container in hermes-op-connect-api hermes-op-connect-sync; do
            if docker container inspect "$container" >/dev/null 2>&1 && \
               ! docker rm -f "$container" >/dev/null 2>&1; then
                log "rollback error: could not remove $container"
                rollback_failed=1
            fi
        done
        if ! curl -fsS --max-time 15 http://127.0.0.1:9119/health >/dev/null || \
           ! docker inspect -f '{{.State.Running}}' \
                hermes hermes-dashboard hermes-caddy hermes-executive-assistant-browser | \
                python3 -c 'import sys; raise SystemExit(0 if all(x.strip()=="true" for x in sys.stdin if x.strip()) else 1)'; then
            log "rollback error: restored service health verification failed"
            rollback_failed=1
        fi
    fi
    if [ "$rollback_failed" = 1 ]; then
        log "ROLLBACK FAILED; operator intervention required"
        exit 90
    fi
    exit "$rc"
}
trap rollback ERR

[ "$(id -u)" = 0 ] || { echo 'must run as root' >&2; exit 1; }
[ "$(stat -c %u:%g "$HERMES_HOME")" = 1000:1000 ] || { echo 'unexpected Hermes ownership' >&2; exit 1; }
curl -fsS --max-time 15 http://127.0.0.1:9119/health >/dev/null
curl -sS -o /dev/null --max-time 15 -w '%{http_code}' https://js.thesamudioagency.com/ | \
    python3 -c 'import sys; raise SystemExit(0 if sys.stdin.read().strip() in {"200","302","401"} else 1)'

log "preparing candidate image"
if [ -n "${PREBUILT_IMAGE:-}" ]; then
    docker image inspect "$PREBUILT_IMAGE" >/dev/null
    docker tag "$PREBUILT_IMAGE" "$CANDIDATE"
    printf 'reused preflight image %s\n' "$PREBUILT_IMAGE" >"$STATE/docker-build.log"
else
    for attempt in 1 2 3; do
        if DOCKER_BUILDKIT=1 docker build --pull=false -t "$CANDIDATE" "$REPO" >"$STATE/docker-build.log" 2>&1; then
            break
        fi
        [ "$attempt" -lt 3 ] || false
        sleep $((attempt * 5))
    done
fi

log "creating rollback compose bound only to RAM credentials"
cp "$HERMES_HOME/hermes-deploy-op-cache-20260724/docker-compose.yml" "$STATE/rollback-compose.yml"
python3 - "$STATE/rollback-compose.yml" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
text=p.read_text()
old_secret='/home/hermes/.hermes/.op.env:/run/secrets/hermes-op-bootstrap:ro'
old_home='- ~/.hermes:/opt/data'
assert old_secret in text, 'rollback compose bootstrap mount not found'
assert old_home in text, 'rollback compose home mount not found'
text=text.replace(old_secret,'/run/hermes-runtime/rollback.op.env:/run/secrets/hermes-op-bootstrap:ro')
text=text.replace(old_home,'- /home/hermes/.hermes:/opt/data\n      - /run/hermes-runtime:/run/hermes-runtime')
p.write_text(text)
PY
cp "$REPO/Caddyfile" "$STATE/Caddyfile"
cp "$HERMES_HOME/deployments/op-ram-cache-20260724T050604Z/rollback-entrypoint.sh" "$STATE/rollback-entrypoint.sh"
python3 - "$STATE/rollback-compose.yml" "$STATE/rollback-entrypoint.sh" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); entry=Path(sys.argv[2])
s=p.read_text().replace('/opt/data/deployments/op-ram-cache-20260724T050604Z/rollback-entrypoint.sh', str(entry))
p.write_text(s)
PY

log "migrating plaintext swap to random-key dm-crypt swap"
if ! swapon --show --noheadings --raw --output NAME | python3 -c 'import sys; raise SystemExit(0 if any("mapper" in x.split()[0] or "dm-" in x.split()[0] for x in sys.stdin if x.split()) else 1)'; then
    command -v cryptsetup >/dev/null
    [ -e /swapfile.encrypted ] || fallocate -l 2G /swapfile.encrypted
    chmod 0600 /swapfile.encrypted
    cp /etc/fstab "$STATE/fstab.before"
    [ ! -e /etc/crypttab ] || cp /etc/crypttab "$STATE/crypttab.before"
    python3 - <<'PY'
from pathlib import Path
fstab=Path('/etc/fstab')
lines=[x for x in fstab.read_text().splitlines() if not x.strip().startswith('/swapfile') and 'hermes-cryptswap' not in x]
lines.append('/dev/mapper/hermes-cryptswap none swap sw 0 0')
fstab.write_text('\n'.join(lines)+'\n')
crypt=Path('/etc/crypttab')
old=crypt.read_text().splitlines() if crypt.exists() else []
old=[x for x in old if not x.strip().startswith('hermes-cryptswap ')]
old.append('hermes-cryptswap /swapfile.encrypted /dev/urandom swap,cipher=aes-xts-plain64,size=256')
crypt.write_text('\n'.join(old)+'\n')
PY
    chmod 0600 /etc/crypttab
    systemctl daemon-reload
    systemctl start 'systemd-cryptsetup@hermes\x2dcryptswap.service'
    mkswap -f /dev/mapper/hermes-cryptswap >/dev/null
    swapon /dev/mapper/hermes-cryptswap
    if swapon --show --noheadings --raw --output NAME | python3 -c 'import sys; raise SystemExit(0 if any(x.split()[0]=="/swapfile" for x in sys.stdin if x.split()) else 1)'; then
        swapoff /swapfile
        # The legacy swapfile is exactly 2 GiB. Bound the overwrite: omitting
        # count would continue past EOF and fill the root filesystem.
        dd if=/dev/zero of=/swapfile bs=16M count=128 conv=fsync status=none
        rm -f /swapfile
    fi
fi

log "installing encrypted credential runtime"
install -d -m 0755 /usr/local/libexec /usr/local/lib/hermes-credential-runtime /etc/systemd/system/docker.service.d
install -m 0644 "$DEPLOY/credential-manifest.sh" /usr/local/lib/hermes-credential-runtime/credential-manifest.sh
install -m 0755 "$DEPLOY/hermes-credential-runtime-start" /usr/local/libexec/hermes-credential-runtime-start
install -m 0755 "$DEPLOY/hermes-credential-sync" /usr/local/libexec/hermes-credential-sync
install -m 0644 "$DEPLOY/run-hermes\\x2druntime.mount" '/etc/systemd/system/run-hermes\x2druntime.mount'
install -m 0644 "$DEPLOY/hermes-credential-runtime.service" /etc/systemd/system/
install -m 0644 "$DEPLOY/hermes-credential-sync.service" /etc/systemd/system/
install -m 0644 "$DEPLOY/hermes-credential-sync.path" /etc/systemd/system/
install -m 0644 "$DEPLOY/docker-hermes-credentials.conf" /etc/systemd/system/docker.service.d/hermes-credentials.conf

log "encrypting and verifying allowlisted credentials"
"$DEPLOY/prepare_credential_store.py"
systemctl daemon-reload
systemctl enable run-hermes\\x2druntime.mount hermes-credential-runtime.service hermes-credential-sync.path >/dev/null
systemctl start run-hermes\\x2druntime.mount
systemctl restart hermes-credential-runtime.service
systemctl start hermes-credential-sync.path
findmnt -n -o OPTIONS -T /run/hermes-runtime | python3 -c 'import sys; raise SystemExit(0 if "noswap" in sys.stdin.read() else 1)'

log "replacing plaintext files with runtime symlinks"
LIVE_CHANGED=1
"$DEPLOY/migrate_plaintext_files.py"

log "activating Connect candidate"
docker tag "$CANDIDATE" "$LIVE_IMAGE"
LIVE_CHANGED=1
HERMES_UID=1000 HERMES_GID=1000 docker compose -p "$PROJECT" -f "$REPO/docker-compose.yml" \
    up -d --force-recreate op-connect-sync op-connect-api
"$REPO/deployment/connect/verify_connect.py" --wait-seconds 120 --expected-vaults 1

log "activating Hermes candidate"
HERMES_UID=1000 HERMES_GID=1000 docker compose -p "$PROJECT" -f "$REPO/docker-compose.yml" \
    up -d --force-recreate gateway dashboard caddy executive-assistant-browser

log "verifying health"
for _ in $(seq 1 45); do
    if curl -fsS --max-time 5 http://127.0.0.1:9119/health >/dev/null && \
       curl -sS -o /dev/null --max-time 5 -w '%{http_code}' https://js.thesamudioagency.com/ | python3 -c 'import sys; raise SystemExit(0 if sys.stdin.read().strip() in {"200","302","401"} else 1)' && \
       docker inspect -f '{{.State.Running}}' hermes hermes-dashboard hermes-caddy hermes-executive-assistant-browser | python3 -c 'import sys; raise SystemExit(0 if all(x.strip()=="true" for x in sys.stdin if x.strip()) else 1)'; then
        HEALTHY=1
        break
    fi
    sleep 2
done
[ "$HEALTHY" = 1 ] || false

systemctl start hermes-credential-sync.service
rm -f /run/hermes-runtime/rollback.op.env
LIVE_CHANGED=0
log "deployment complete: $STAMP"
