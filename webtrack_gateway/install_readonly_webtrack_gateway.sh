#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="${1:-$HOME/Graduation_Project/IoT-devices}"
BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_USER="${SUDO_USER:-$(id -un)}"
RUN_HOME="$(getent passwd "$RUN_USER" | cut -d: -f6)"
RUN_GROUP="$(id -gn "$RUN_USER")"
PROXY_SOURCE="$BUNDLE_DIR/webtrack_readonly_proxy.py"
API_TOKEN_FILE="$RUN_HOME/.secureiot_api_token"
CONFIG_DIR="$RUN_HOME/.config/secureiot"
ENV_FILE="$CONFIG_DIR/webtrack-readonly.env"
INSTALL_DIR="/opt/secureiot/webtrack-readonly"
PROXY_UNIT="/etc/systemd/system/secureiot-webtrack-readonly.service"
NGROK_UNIT="/etc/systemd/system/ngrok-webtrack-readonly.service"

if [[ "$EUID" -ne 0 ]]; then
  echo "STOP: run this installer with sudo." >&2
  exit 2
fi
if [[ ! -f "$PROXY_SOURCE" || ! -f "$API_TOKEN_FILE" ]]; then
  echo "STOP: bundle or existing private Ryu-token file is missing." >&2
  exit 3
fi
if [[ ! -d "$ROOT" || ! -f "$ROOT/runtime_network_api.py" ]]; then
  echo "STOP: project root or runtime_network_api.py is missing." >&2
  exit 4
fi
if [[ ! -f "$RUN_HOME/.config/ngrok/ngrok.yml" ]]; then
  echo "STOP: ngrok config not found at $RUN_HOME/.config/ngrok/ngrok.yml." >&2
  exit 5
fi
if ! command -v systemctl >/dev/null || [[ ! -d /run/systemd/system ]]; then
  echo "STOP: systemd is not active on this VM; no service was installed." >&2
  exit 6
fi
for path in "$ENV_FILE" "$INSTALL_DIR" "$PROXY_UNIT" "$NGROK_UNIT"; do
  if [[ -e "$path" ]]; then
    echo "STOP: gateway path already exists: $path (not overwriting)." >&2
    exit 7
  fi
done

NGROK_BIN="$(runuser -u "$RUN_USER" -- env HOME="$RUN_HOME" bash -c 'command -v ngrok' 2>/dev/null || true)"
if [[ -z "$NGROK_BIN" || ! -x "$NGROK_BIN" ]]; then
  echo "STOP: ngrok executable is not available to $RUN_USER." >&2
  exit 8
fi
if ! runuser -u "$RUN_USER" -- env HOME="$RUN_HOME" "$NGROK_BIN" config check >/dev/null 2>&1; then
  echo "STOP: ngrok config is invalid or unreadable by $RUN_USER." >&2
  exit 9
fi
if pgrep -af '[n]grok http' >/dev/null; then
  echo "STOP: an ngrok HTTP tunnel is already running; stop it before installing this dedicated service." >&2
  exit 10
fi
if ss -ltn 2>/dev/null | grep -qE '127\.0\.0\.1:8090|0\.0\.0\.0:8090|\[::\]:8090'; then
  echo "STOP: port 8090 is already in use." >&2
  exit 11
fi
if [[ -e "$PROXY_UNIT" || -e "$NGROK_UNIT" ]]; then
  echo "STOP: a service with this name already exists." >&2
  exit 12
fi

API_TOKEN="$(runuser -u "$RUN_USER" -- env HOME="$RUN_HOME" bash -c 'source "$HOME/.secureiot_api_token"; printf "%s" "${SECUREIOT_API_TOKEN:-}"')"
if [[ ${#API_TOKEN} -lt 32 ]]; then
  echo "STOP: SECUREIOT_API_TOKEN is missing or too short in $API_TOKEN_FILE." >&2
  exit 13
fi
install -d -o "$RUN_USER" -g "$RUN_GROUP" -m 0700 "$CONFIG_DIR"
umask 077
printf 'SECUREIOT_API_TOKEN=%s\n' "$API_TOKEN" > "$ENV_FILE"
chown "$RUN_USER:$RUN_GROUP" "$ENV_FILE"
chmod 0600 "$ENV_FILE"
unset API_TOKEN

install -d -o root -g root -m 0755 "$INSTALL_DIR"
install -o root -g root -m 0755 "$PROXY_SOURCE" "$INSTALL_DIR/webtrack_readonly_proxy.py"
/usr/bin/python3 -m py_compile "$INSTALL_DIR/webtrack_readonly_proxy.py"

cat > "$PROXY_UNIT" <<EOF
[Unit]
Description=SecureIoT WebTrack read-only API gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_GROUP
EnvironmentFile=$ENV_FILE
Environment=PYTHONDONTWRITEBYTECODE=1
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/webtrack_readonly_proxy.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_UNIX

[Install]
WantedBy=multi-user.target
EOF

cat > "$NGROK_UNIT" <<EOF
[Unit]
Description=ngrok HTTPS tunnel for SecureIoT WebTrack read-only gateway
After=network-online.target secureiot-webtrack-readonly.service
Wants=network-online.target
Requires=secureiot-webtrack-readonly.service

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_GROUP
Environment=HOME=$RUN_HOME
WorkingDirectory=$RUN_HOME
ExecStart=$NGROK_BIN http 8090
Restart=always
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$PROXY_UNIT" "$NGROK_UNIT"
systemctl daemon-reload
systemctl enable --now secureiot-webtrack-readonly.service
systemctl enable --now ngrok-webtrack-readonly.service

PUBLIC_URL=""
for _ in $(seq 1 30); do
  PUBLIC_URL="$(python3 - <<'PY'
import json
import urllib.request
try:
    with urllib.request.urlopen('http://127.0.0.1:4040/api/tunnels', timeout=1) as r:
        data=json.loads(r.read().decode('utf-8'))
    for tunnel in data.get('tunnels', []):
        url=tunnel.get('public_url', '')
        if url.startswith('https://') and '8090' in str(tunnel.get('config', {}).get('addr', '')):
            print(url)
            break
except Exception:
    pass
PY
)"
  if [[ -n "$PUBLIC_URL" ]]; then break; fi
  sleep 1
done

printf '\nRead-only gateway and ngrok services installed and enabled.\n'
printf 'Base URL: %s\n' "${PUBLIC_URL:-NOT YET REPORTED; check systemctl status and journalctl}"
printf 'Public: unauthenticated GET routes in the explicit read-only allowlist.\n'
printf 'Blocked: all non-GET methods, control/action routes, and dataset lifecycle routes.\n'
printf 'Private upstream Ryu token remains in %s and is not sent to WebTrack clients.\n' "$ENV_FILE"
printf 'Anyone with the ngrok URL can read the allowlisted status/telemetry.\n'
printf 'Ryu/Mininet remain independently managed; the gateway returns 502 while local Ryu is stopped.\n'
printf 'Free-plan limits still apply: 20,000 HTTP requests and 1 GB transfer per month.\n'
