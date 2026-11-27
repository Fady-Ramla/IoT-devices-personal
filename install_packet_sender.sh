#!/usr/bin/env bash
# Install the OVS-mirror packet sender. start_secureiot.sh configures and enables
# it automatically after all six OVS mirrors have been created.
set -Eeuo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$PROJECT_DIR/vpn-packet-sender"
CONF_DIR="/etc/secureiot"
CONF="$CONF_DIR/security_sender_config.json"

echo "Installing sender script and systemd unit (requires sudo)."
sudo install -m 0755 -o root -g root "$SRC/security_packet_sender.py" /usr/local/bin/security_packet_sender.py
sudo install -d -m 0750 -o root -g root "$CONF_DIR"
if sudo test -f "$CONF"; then
    echo "Keeping existing $CONF (not overwritten)."
else
    sudo install -m 0640 -o root -g root "$SRC/security_sender_config.json" "$CONF"
    echo "Created $CONF (disabled template, receiver_ip placeholder)."
fi
sudo install -m 0644 -o root -g root "$PROJECT_DIR/security-packet-sender.service" /etc/systemd/system/security-packet-sender.service
sudo systemctl daemon-reload
sudo python3 /usr/local/bin/security_packet_sender.py --config "$CONF" --check

cat <<MSG

The sender starts automatically from ./start_secureiot.sh after the six
sec-mirror-s* interfaces exist. Set these values in .env first:
  SECUREIOT_SECURITY_TAILSCALE_IP=<Security receiver Tailscale IPv4>
  SECUREIOT_SECURITY_RECEIVER_PORT=9000
  SECUREIOT_PACKET_SENDER_ENABLED=1

To inspect it:
  sudo systemctl status security-packet-sender.service
  journalctl -u security-packet-sender.service -f
MSG
