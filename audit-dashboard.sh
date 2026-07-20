#!/usr/bin/env bash
set -uo pipefail

pass_count=0
warn_count=0
fail_count=0
pass() { printf 'PASS  %s\n' "$*"; ((pass_count++)) || true; }
warn() { printf 'WARN  %s\n' "$*"; ((warn_count++)) || true; }
fail() { printf 'FAIL  %s\n' "$*"; ((fail_count++)) || true; }

if (( EUID != 0 )); then
  echo 'Run this read-only audit with sudo so it can inspect /root and UFW.' >&2
  exit 2
fi

HERMES_USER=hermes
HERMES_HOME=/home/hermes/.hermes
PROJECT=$HERMES_HOME/hermes-agent
expected_uid=$(id -u "$HERMES_USER" 2>/dev/null) || { fail 'service user hermes is missing'; exit 1; }
expected_gid=$(id -g "$HERMES_USER")

printf 'Hermes dashboard security audit (read-only)\n'
printf 'Expected runtime identity: %s:%s\n\n' "$expected_uid" "$expected_gid"

# Root should not contain this deployment's profile or 1Password CLI state.
for path in /root/.hermes /root/.config/op; do
  if [[ -e "$path" ]]; then
    fail "unexpected root-owned deployment state exists: $path"
  else
    pass "absent from root: $path"
  fi
done

# Check the complete persistent profile without printing file contents.
ownership_report=$(python3 - "$HERMES_HOME" /home/hermes/.config/op "$expected_uid" "$expected_gid" <<'PY'
import os, sys
roots, uid, gid = sys.argv[1:-2], int(sys.argv[-2]), int(sys.argv[-1])
bad = []
try:
    entries = []
    for root in roots:
        if not os.path.lexists(root):
            continue
        entries.append(root)
        for base, dirs, files in os.walk(root, followlinks=False):
            entries.extend(os.path.join(base, x) for x in dirs)
            entries.extend(os.path.join(base, x) for x in files)
    for path in entries:
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            continue
        if st.st_uid != uid or st.st_gid != gid:
            bad.append((path, st.st_uid, st.st_gid))
except Exception as exc:
    print(f'ERROR\t{exc}')
    raise SystemExit(2)
print(f'COUNT\t{len(bad)}')
for path, actual_uid, actual_gid in bad[:20]:
    print(f'BAD\t{actual_uid}:{actual_gid}\t{path}')
PY
)
ownership_rc=$?
if (( ownership_rc != 0 )); then
  fail 'could not scan Hermes profile ownership'
else
  bad_count=$(printf '%s\n' "$ownership_report" | while IFS=$'\t' read -r kind value rest; do [[ $kind == COUNT ]] && printf '%s' "$value"; done)
  if [[ ${bad_count:-1} == 0 ]]; then
    pass "all Hermes and 1Password state under /home/hermes is owned by $HERMES_USER ($expected_uid:$expected_gid)"
  else
    fail "$bad_count Hermes/1Password paths under /home/hermes have incorrect ownership"
    printf '%s\n' "$ownership_report" | while IFS=$'\t' read -r kind owner path; do
      [[ $kind == BAD ]] && printf '      %s  %s\n' "$owner" "$path"
    done
  fi
fi

check_mode_owner() {
  local path=$1 expected_mode=$2
  if [[ ! -e "$path" ]]; then
    fail "missing required path: $path"
    return
  fi
  local mode uid gid
  mode=$(stat -c '%a' "$path")
  uid=$(stat -c '%u' "$path")
  gid=$(stat -c '%g' "$path")
  if [[ $mode == "$expected_mode" && $uid == "$expected_uid" && $gid == "$expected_gid" ]]; then
    pass "$path mode=$mode owner=$uid:$gid"
  else
    fail "$path expected mode=$expected_mode owner=$expected_uid:$expected_gid; found mode=$mode owner=$uid:$gid"
  fi
}

check_mode_owner "$HERMES_HOME/.op.env" 600
check_mode_owner "$HERMES_HOME/.op-cli" 700
check_mode_owner "$PROJECT/start-dashboard.sh" 700
check_mode_owner "$PROJECT/audit-dashboard.sh" 700

if ! command -v docker >/dev/null; then
  fail 'Docker CLI is unavailable'
elif ! docker info >/dev/null 2>&1; then
  fail 'Docker daemon is unavailable'
else
  pass 'Docker daemon is available'
  for container in hermes hermes-dashboard hermes-caddy; do
    if ! docker inspect "$container" >/dev/null 2>&1; then
      fail "container is missing: $container"
      continue
    fi
    running=$(docker inspect -f '{{.State.Running}}' "$container")
    restart_policy=$(docker inspect -f '{{.HostConfig.RestartPolicy.Name}}' "$container")
    log_driver=$(docker inspect -f '{{.HostConfig.LogConfig.Type}}' "$container")
    log_max_size=$(docker inspect -f '{{index .HostConfig.LogConfig.Config "max-size"}}' "$container")
    log_max_file=$(docker inspect -f '{{index .HostConfig.LogConfig.Config "max-file"}}' "$container")
    [[ $running == true ]] && pass "$container is running" || fail "$container is not running"
    [[ $restart_policy == unless-stopped ]] && pass "$container restart policy is unless-stopped" || warn "$container restart policy is $restart_policy"
    if [[ $log_driver == json-file && $log_max_size == 10m && $log_max_file == 3 ]]; then
      pass "$container logs rotate at 10m with 3 files"
    else
      fail "$container log rotation is driver=$log_driver max-size=${log_max_size:-unset} max-file=${log_max_file:-unset}"
    fi

    if [[ $container == hermes || $container == hermes-dashboard ]]; then
      image_ref=$(docker inspect -f '{{.Config.Image}}' "$container")
      [[ $image_ref == hermes-agent:js-dashboard-hardened ]] && pass "$container uses hardened image tag" || fail "$container image is $image_ref; expected hermes-agent:js-dashboard-hardened"
      uid_env=''
      gid_env=''
      while IFS= read -r entry; do
        case "$entry" in
          HERMES_UID=*) uid_env=${entry#*=} ;;
          HERMES_GID=*) gid_env=${entry#*=} ;;
        esac
      done < <(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$container")
      [[ $uid_env == "$expected_uid" ]] && pass "$container HERMES_UID=$uid_env" || fail "$container HERMES_UID is ${uid_env:-unset}; expected $expected_uid"
      [[ $gid_env == "$expected_gid" ]] && pass "$container HERMES_GID=$gid_env" || fail "$container HERMES_GID is ${gid_env:-unset}; expected $expected_gid"
      profile_mount=$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/opt/data"}}{{.Source}}{{end}}{{end}}' "$container")
      [[ $profile_mount == "$HERMES_HOME" ]] && pass "$container mounts $HERMES_HOME at /opt/data" || fail "$container /opt/data mount is ${profile_mount:-missing}"
    fi
  done

  # Validate only the authorization value and its type inside the Hermes image;
  # do not dump config.yaml or any credential-bearing environment variables.
  if docker exec hermes-dashboard python -c '
import yaml
with open("/opt/data/config.yaml", encoding="utf-8") as f:
    cfg = yaml.safe_load(f) or {}
value = cfg.get("dashboard", {}).get("oauth", {}).get("self_hosted", {}).get("allowed_emails")
assert isinstance(value, list), f"allowed_emails must be a list, got {type(value).__name__}"
assert value == ["joey@samudioagency.com"], f"unexpected allowed_emails: {value!r}"
'; then
    pass 'Google OIDC allowlist is exactly [joey@samudioagency.com] and is a YAML list'
  else
    fail 'Google OIDC allowlist is missing, malformed, or contains another account'
  fi

  if sudo -u "$HERMES_USER" -H env \
      HOME=/home/hermes \
      HERMES_HOME="$HERMES_HOME" \
      HERMES_UID="$expected_uid" \
      HERMES_GID="$expected_gid" \
      OP_SERVICE_ACCOUNT_TOKEN=audit-placeholder \
      bash -lc "cd '$PROJECT' && docker compose config --quiet"; then
    pass 'Docker Compose configuration validates'
  else
    fail 'Docker Compose configuration does not validate'
  fi
fi

if command -v ufw >/dev/null; then
  ufw_output=$(ufw status 2>&1)
  if [[ $ufw_output =~ 9119/tcp[[:space:]]+DENY ]]; then
    pass 'UFW denies public TCP 9119'
  else
    fail 'UFW does not show a DENY rule for TCP 9119'
  fi
  [[ $ufw_output =~ 80/tcp[[:space:]]+ALLOW ]] && pass 'UFW allows TCP 80' || fail 'UFW does not allow TCP 80'
  [[ $ufw_output =~ 443/tcp[[:space:]]+ALLOW ]] && pass 'UFW allows TCP 443' || fail 'UFW does not allow TCP 443'
else
  warn 'UFW is unavailable; host firewall rules were not checked'
fi

local_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:9119/ 2>/dev/null || true)
[[ $local_code == 302 ]] && pass 'local dashboard redirects unauthenticated requests (HTTP 302)' || fail "local dashboard returned HTTP ${local_code:-unreachable}; expected 302"

public_code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 15 https://js.thesamudioagency.com/ 2>/dev/null || true)
[[ $public_code == 302 ]] && pass 'public HTTPS dashboard redirects unauthenticated requests (HTTP 302)' || fail "public dashboard returned HTTP ${public_code:-unreachable}; expected 302"

printf '\nSummary: %d passed, %d warnings, %d failures\n' "$pass_count" "$warn_count" "$fail_count"
if (( fail_count > 0 )); then
  exit 1
fi
exit 0
