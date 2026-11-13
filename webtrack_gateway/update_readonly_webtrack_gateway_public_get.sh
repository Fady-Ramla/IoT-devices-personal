#!/usr/bin/env bash
set -Eeuo pipefail

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_USER="${SUDO_USER:-$(id -un)}"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
RUN_GROUP="$(id -gn "$RUN_USER")"
PROXY_SOURCE="$BUNDLE_DIR/webtrack_readonly_proxy.py"
API_TOKEN_FILE="$RUN_HOME/.secureiot_api_token"
CONFIG_DIR="$RUN_HOME/.config/secureiot"
ENV_FILE="$CONFIG_DIR/webtrack-readonly.env"
INSTALL_DIR="/opt/secureiot/webtrack-readonly"
INSTALLED_PROXY="$INSTALL_DIR/webtrack_readonly_proxy.py"
PROXY_UNIT="/etc/systemd/system/secureiot-webtrack-readonly.service"
SERVICE="secureiot-webtrack-readonly.service"

if [[ "$EUID" -ne 0 ]]; then
  echo "STOP: run this updater with sudo." >&2
  exit 2
fi
for file in "$PROXY_SOURCE" "$API_TOKEN_FILE" "$ENV_FILE" "$INSTALLED_PROXY" "$PROXY_UNIT"; do
  if [[ ! -f "$file" ]]; then
    echo "STOP: required existing gateway file missing: $file" >&2
    exit 3
  fi
done
if ! grep -Fq "EnvironmentFile=$ENV_FILE" "$PROXY_UNIT" \
  || ! grep -Fq "ExecStart=/usr/bin/python3 $INSTALLED_PROXY" "$PROXY_UNIT"; then
  echo "STOP: gateway unit differs from the expected installed service; no changes made." >&2
  exit 4
fi

API_TOKEN="$(runuser -u "$RUN_USER" -- env HOME="$RUN_HOME" bash -c 'source "$HOME/.secureiot_api_token"; printf "%s" "${SECUREIOT_API_TOKEN:-}"')"
if [[ ${#API_TOKEN} -lt 32 ]]; then
  echo "STOP: SECUREIOT_API_TOKEN is missing or too short; no changes made." >&2
  exit 5
fi
/usr/bin/python3 -m py_compile "$PROXY_SOURCE"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
PROXY_BACKUP="$INSTALLED_PROXY.before_public_get_$STAMP"
ENV_BACKUP="$ENV_FILE.before_public_get_$STAMP"
cp -a "$INSTALLED_PROXY" "$PROXY_BACKUP"
cp -a "$ENV_FILE" "$ENV_BACKUP"

rollback() {
  install -o root -g root -m 0755 "$PROXY_BACKUP" "$INSTALLED_PROXY"
  install -o "$RUN_USER" -g "$RUN_GROUP" -m 0600 "$ENV_BACKUP" "$ENV_FILE"
  systemctl restart "$SERVICE" || true
}

umask 077
printf 'SECUREIOT_API_TOKEN=%s\n' "$API_TOKEN" > "$ENV_FILE"
chown "$RUN_USER:$RUN_GROUP" "$ENV_FILE"
chmod 0600 "$ENV_FILE"
unset API_TOKEN
install -o root -g root -m 0755 "$PROXY_SOURCE" "$INSTALLED_PROXY"

if ! systemctl restart "$SERVICE"; then
  echo "Gateway restart failed; restoring backups." >&2
  rollback
  exit 6
fi

sleep 1
SNAPSHOT_CODE="$(curl -sS -o /tmp/webtrack-public-get-snapshot.json -w '%{http_code}' \
  --max-time 10 http://127.0.0.1:8090/dashboard/snapshot || true)"
POST_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
  -X POST http://127.0.0.1:8090/dashboard/snapshot || true)"
CONTROL_CODE="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
  http://127.0.0.1:8090/network/action || true)"

if [[ "$SNAPSHOT_CODE" != "200" && "$SNAPSHOT_CODE" != "502" ]] \
  || [[ "$POST_CODE" != "405" ]] || [[ "$CONTROL_CODE" != "404" ]]; then
  echo "Gateway contract check failed (snapshot=$SNAPSHOT_CODE POST=$POST_CODE control_GET=$CONTROL_CODE); rolling back." >&2
  rollback
  exit 7
fi

printf 'Public GET gateway update applied. No client bearer token is required.\n'
printf 'Checks: GET /dashboard/snapshot HTTP %s; POST snapshot HTTP %s; GET /network/action HTTP %s.\n' \
  "$SNAPSHOT_CODE" "$POST_CODE" "$CONTROL_CODE"
printf 'Internal Ryu API token remains private in the mode-0600 gateway environment file.\n'
printf 'Backups: %s and %s\n' "$PROXY_BACKUP" "$ENV_BACKUP"
printf 'Only %s was restarted; Ryu, Mininet, ngrok, SQLite, and datasets were not changed.\n' "$SERVICE"
printf 'If snapshot returned 502, Ryu may be stopped; start Ryu and rerun the GET verification.\n'
