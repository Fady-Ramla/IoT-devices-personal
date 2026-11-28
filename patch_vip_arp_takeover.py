#!/usr/bin/env python3
"""Add takeover-safe proxy ARP for the SecureIoT VIP.

This script modifies topology_monitor.py only. It keeps the h38 MAC drop and
SSH policy unchanged. During an active VIP takeover, ARP replies for
10.10.20.100 use a stable virtual MAC instead of h38's blocked MAC.
"""
from pathlib import Path
import re
import shutil
import sys

TARGET = Path("topology_monitor.py")
BACKUP = TARGET.with_suffix(TARGET.suffix + ".before_vip_arp_takeover")
VIP = "10.10.20.100"
VIRTUAL_MAC = "02:00:00:20:00:64"


def fail(message: str) -> None:
    print(f"ERROR: {message}")
    sys.exit(1)


if not TARGET.is_file():
    fail(f"{TARGET} not found; run this from the project directory")

text = TARGET.read_text()

# Add one module-level constant beside the existing SSH frontend constant.
constant = f'VIP_TAKEOVER_MAC = "{VIRTUAL_MAC}"'
if constant not in text:
    marker = 'SSH_FRONTEND_IP = "10.10.20.100"'
    occurrences = text.count(marker)
    if occurrences != 1:
        fail(f"expected one SSH_FRONTEND_IP marker, found {occurrences}")
    text = text.replace(marker, marker + "\n" + constant, 1)

# Replace only _try_proxy_arp, up to the next method definition.
pattern = re.compile(
    r"(?ms)^    def _try_proxy_arp\(self, datapath, in_port, arp_pkt, vlan_id\):\n"
    r".*?(?=^    def _send_arp_reply\()"
)
match = pattern.search(text)
if not match:
    fail("could not locate _try_proxy_arp()")

new_method = f'''    def _try_proxy_arp(self, datapath, in_port, arp_pkt, vlan_id):
        """Answer ARP requests, including the takeover-safe VIP identity."""

        if arp_pkt.dst_ip == arp_pkt.src_ip:
            return False

        # When h38 is blocked, its learned MAC must not remain the ARP owner
        # of the VIP.  Use a stable virtual MAC that is not subject to the
        # h38 source-MAC drop.  The normal VIP PacketIn path consumes this MAC
        # as the frontend identity and rewrites traffic toward the backend.
        if (
            arp_pkt.opcode == arp.ARP_REQUEST
            and arp_pkt.dst_ip == "{VIP}"
            and getattr(self, "vip_takeover_active", False)
            and int(vlan_id) == 20
        ):
            target_mac = VIP_TAKEOVER_MAC
            self._send_arp_reply(
                datapath, in_port,
                arp_pkt.src_mac, arp_pkt.src_ip,
                target_mac, arp_pkt.dst_ip, vlan_id)
            self.logger.info(
                "VIP takeover proxy ARP reply: vip=%s mac=%s switch=s%d in_port=%s",
                arp_pkt.dst_ip, target_mac, int(datapath.id), in_port,
            )
            return True

        target_mac = self.ip_to_mac.get(arp_pkt.dst_ip)

        if (target_mac is None or target_mac not in self.host_location
                or self.ip_vlan.get(arp_pkt.dst_ip) != vlan_id
                or self.mac_vlan.get(target_mac) != vlan_id):
            return False

        self._send_arp_reply(
            datapath, in_port,
            arp_pkt.src_mac, arp_pkt.src_ip,
            target_mac, arp_pkt.dst_ip, vlan_id)

        return True

'''

text = text[:match.start()] + new_method + text[match.end():]

if BACKUP.exists():
    print(f"Backup already exists: {BACKUP}")
else:
    shutil.copy2(TARGET, BACKUP)

TARGET.write_text(text)
print(f"Updated: {TARGET}")
print(f"Backup:  {BACKUP}")
print(f"VIP takeover ARP MAC: {VIRTUAL_MAC}")
print("Next: restart Ryu via ./run_ryu.sh, then run BLOCK once and test ARP/HTTP.")
