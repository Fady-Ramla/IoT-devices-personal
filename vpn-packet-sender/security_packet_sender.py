#!/usr/bin/env python3
"""Capture raw Ethernet frames from OVS mirror interfaces.

TCP framing is unchanged: each frame is sent as a 4-byte unsigned network-order
length followed by the raw Ethernet frame. UDP sends one raw Ethernet frame per
datagram. Multiple capture interfaces share one receiver connection; the frame
payload does not include source-interface metadata.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import select
import signal
import socket
import struct
import time
from pathlib import Path
from typing import Any

LOG = logging.getLogger("secureiot-packet-sender")
STOP = False
MAX_FRAME = 65535
MAX_CAPTURE_INTERFACES = 64
INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def stop_handler(_signum: int, _frame: Any) -> None:
    global STOP
    STOP = True


def parse_capture_interfaces(value: Any) -> list[str]:
    """Parse a comma-separated interface list and reject duplicates/invalid names."""
    if not isinstance(value, str):
        raise ValueError("capture_interface must be a comma-separated string")

    interfaces = [item.strip() for item in value.split(",") if item.strip()]
    if not interfaces:
        raise ValueError("capture_interface must contain at least one interface")
    if len(interfaces) > MAX_CAPTURE_INTERFACES:
        raise ValueError(
            f"capture_interface supports at most {MAX_CAPTURE_INTERFACES} interfaces"
        )
    if len(set(interfaces)) != len(interfaces):
        raise ValueError("capture_interface contains duplicate interface names")

    invalid = [name for name in interfaces if not INTERFACE_RE.fullmatch(name)]
    if invalid:
        raise ValueError("invalid capture interface name(s): " + ", ".join(invalid))

    return interfaces


def load_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        cfg = json.load(fh)

    required = ["enabled", "capture_interface", "receiver_ip", "receiver_port", "transport"]
    missing = [key for key in required if key not in cfg]
    if missing:
        raise ValueError(f"missing config keys: {', '.join(missing)}")

    if not isinstance(cfg["enabled"], bool):
        raise ValueError("enabled must be a JSON boolean (true or false)")

    interfaces = parse_capture_interfaces(cfg["capture_interface"])
    cfg["transport"] = str(cfg["transport"]).strip().lower()
    if cfg["transport"] not in {"tcp", "udp"}:
        raise ValueError("transport must be 'tcp' or 'udp'")

    if not isinstance(cfg["receiver_ip"], str) or not cfg["receiver_ip"].strip():
        raise ValueError("receiver_ip must be a non-empty IP address or hostname")
    cfg["receiver_ip"] = cfg["receiver_ip"].strip()
    if cfg["enabled"]:
        if cfg["receiver_ip"].upper().startswith("REPLACE"):
            raise ValueError(
                "receiver_ip is still the placeholder; set the Security "
                "receiver's Tailscale IP before enabling the sender"
            )
        try:
            receiver_addr = ipaddress.ip_address(cfg["receiver_ip"])
        except ValueError:
            pass  # hostname (e.g. MagicDNS name): resolved at connect time
        else:
            if receiver_addr not in ipaddress.ip_network("100.64.0.0/10"):
                raise ValueError(
                    "receiver_ip must be a Tailscale IPv4 address in 100.64.0.0/10; "
                    "mirrored frames must travel over the VPN"
                )
        if cfg["transport"] == "udp":
            LOG.warning(
                "UDP carries one frame per datagram; frames larger than the "
                "Tailscale MTU (1280) will fail. Prefer transport=tcp."
            )

    if isinstance(cfg["receiver_port"], bool):
        raise ValueError("receiver_port must be an integer between 1 and 65535")
    try:
        port = int(cfg["receiver_port"])
    except (TypeError, ValueError) as exc:
        raise ValueError("receiver_port must be an integer between 1 and 65535") from exc
    if not 1 <= port <= 65535:
        raise ValueError("receiver_port must be between 1 and 65535")
    cfg["receiver_port"] = port

    cfg["_capture_interfaces"] = interfaces
    return cfg


def open_capture(interface: str) -> socket.socket:
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    try:
        sock.bind((interface, 0))
        sock.setblocking(False)
    except Exception:
        sock.close()
        raise
    LOG.info("capturing raw Ethernet frames from %s", interface)
    return sock


def connect_tcp(host: str, port: int, timeout: float, send_timeout: float = 10.0) -> socket.socket:
    LOG.info("connecting TCP receiver %s:%d", host, port)
    sock = socket.create_connection((host, port), timeout=timeout)
    # A stalled receiver must not block the sender forever: sendall() raises
    # on timeout and the reconnect path takes over.
    sock.settimeout(send_timeout)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    LOG.info("TCP receiver connected")
    return sock


def close_capture_sockets(captures: dict[str, socket.socket]) -> None:
    for sock in captures.values():
        try:
            sock.close()
        except OSError:
            pass
    captures.clear()


def close_output_socket(sock: socket.socket | None) -> None:
    if sock is not None:
        try:
            sock.close()
        except OSError:
            pass


def run(cfg: dict[str, Any]) -> None:
    interfaces = cfg.get("_capture_interfaces") or parse_capture_interfaces(cfg["capture_interface"])
    receiver = str(cfg["receiver_ip"])
    port = int(cfg["receiver_port"])
    transport = str(cfg["transport"]).lower()
    reconnect_delay = max(1.0, float(cfg.get("reconnect_delay_seconds", 5)))
    connect_timeout = max(1.0, float(cfg.get("connect_timeout_seconds", 10)))
    send_timeout = max(1.0, float(cfg.get("send_timeout_seconds", 10)))
    stats_every = max(0, int(cfg.get("log_stats_every_seconds", 30)))

    captures: dict[str, socket.socket] = {}
    output: socket.socket | None = None
    frames = 0
    bytes_sent = 0
    last_stats = time.monotonic()

    try:
        while not STOP:
            try:
                for interface in interfaces:
                    if interface not in captures:
                        captures[interface] = open_capture(interface)
            except OSError as exc:
                LOG.warning("capture interface unavailable: %s; retrying in %.1fs", exc, reconnect_delay)
                time.sleep(reconnect_delay)
                continue

            if len(captures) != len(interfaces):
                time.sleep(reconnect_delay)
                continue

            if output is None:
                try:
                    if transport == "tcp":
                        output = connect_tcp(receiver, port, connect_timeout, send_timeout)
                    else:
                        output = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        output.settimeout(connect_timeout)
                        LOG.info("UDP receiver configured as %s:%d", receiver, port)
                except OSError as exc:
                    LOG.warning("receiver connection failed: %s; retrying in %.1fs", exc, reconnect_delay)
                    close_output_socket(output)
                    output = None
                    time.sleep(reconnect_delay)
                    continue

            socket_to_interface = {sock: name for name, sock in captures.items()}
            try:
                readable, _, _ = select.select(list(socket_to_interface), [], [], 1.0)
            except (OSError, ValueError) as exc:
                LOG.warning("capture select failed: %s; reopening capture sockets", exc)
                close_capture_sockets(captures)
                time.sleep(reconnect_delay)
                continue

            for capture_sock in readable:
                interface = socket_to_interface[capture_sock]
                try:
                    frame = capture_sock.recv(MAX_FRAME)
                except BlockingIOError:
                    continue
                except OSError as exc:
                    LOG.warning("capture failed on %s: %s; reopening that interface", interface, exc)
                    try:
                        capture_sock.close()
                    except OSError:
                        pass
                    captures.pop(interface, None)
                    continue

                if not frame:
                    continue

                try:
                    if transport == "tcp":
                        assert output is not None
                        output.sendall(struct.pack("!I", len(frame)) + frame)
                    else:
                        assert output is not None
                        output.sendto(frame, (receiver, port))
                except (BrokenPipeError, ConnectionError, OSError) as exc:
                    LOG.warning(
                        "receiver send failed for frame from %s: %s; reconnecting in %.1fs",
                        interface, exc, reconnect_delay,
                    )
                    close_output_socket(output)
                    output = None
                    time.sleep(reconnect_delay)
                    break

                frames += 1
                bytes_sent += len(frame)
                now = time.monotonic()
                if stats_every and now - last_stats >= stats_every:
                    LOG.info(
                        "forwarded frames=%d bytes=%d capture_interfaces=%d",
                        frames, bytes_sent, len(interfaces),
                    )
                    last_stats = now
    except Exception:
        LOG.exception("unexpected sender error")
        raise
    finally:
        close_output_socket(output)
        close_capture_sockets(captures)
        LOG.info("sender stopped; forwarded frames=%d bytes=%d", frames, bytes_sent)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-c", "--config", default="/etc/secureiot/security_sender_config.json")
    parser.add_argument("--check", action="store_true", help="validate configuration without capturing")
    args = parser.parse_args()

    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        cfg = load_config(Path(args.config))
    except Exception as exc:
        LOG.error("invalid configuration: %s", exc)
        return 2

    if args.check:
        LOG.info(
            "configuration is valid (enabled=%s, capture_interfaces=%d, transport=%s)",
            cfg["enabled"], len(cfg["_capture_interfaces"]), cfg["transport"],
        )
        return 0

    if not cfg["enabled"]:
        LOG.warning("sender is disabled in configuration")
        return 0

    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    run(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
