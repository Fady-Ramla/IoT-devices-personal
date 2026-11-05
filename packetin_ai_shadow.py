#!/usr/bin/env python3
"""Ryu PacketIn observer for non-enforcing AI shadow inference.

This app is additive: it does not modify forwarding state, emit PacketOut,
write dataset/label files, or call security enforcement APIs. It aggregates an
independent 10-second packetin_window and queues records for a loopback-only
inference service.
"""
import ipaddress
import json
import os
import queue
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet, ipv4, tcp, udp

WINDOW_SECONDS = 10.0
QUEUE_MAXSIZE = 1024
INFERENCE_TIMEOUT_SECONDS = 0.5
INFERENCE_URL = os.environ.get(
    "PACKETIN_AI_URL", "http://127.0.0.1:8765/predict"
)
PROTOCOL_NAMES = {1: "icmp", 6: "tcp", 17: "udp"}


def _validate_loopback_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost")
            or parsed.port != 8765 or parsed.path != "/predict"
            or parsed.query or parsed.fragment or parsed.username or parsed.password):
        raise ValueError("PACKETIN_AI_URL must be http://127.0.0.1:8765/predict")
    return value


class PacketInAIShadow(app_manager.RyuApp):
    """Collect live Ryu PacketIn windows and log prediction-only results."""

    def __init__(self, *args, **kwargs):
        super(PacketInAIShadow, self).__init__(*args, **kwargs)
        self.inference_url = _validate_loopback_url(INFERENCE_URL)
        self._windows = {}
        self._lock = hub.Semaphore()
        self._queue = queue.Queue(maxsize=QUEUE_MAXSIZE)
        self._last_warning = 0.0
        self._dropped = 0
        self._flush_thread = hub.spawn(self._flush_loop)
        self._inference_thread = hub.spawn(self._inference_loop)
        self.logger.info(
            "AI_SHADOW_STARTED url=%s window_seconds=%.1f queue_max=%d actions=disabled",
            self.inference_url, WINDOW_SECONDS, QUEUE_MAXSIZE
        )

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _observe_packet_in(self, ev):
        """Collect counters only; do not alter or consume the packet."""
        try:
            msg = ev.msg
            parsed = packet.Packet(msg.data)
            ip = parsed.get_protocol(ipv4.ipv4)
            if ip is None or ip.proto not in PROTOCOL_NAMES:
                return
            src_addr = ipaddress.ip_address(ip.src)
            dst_addr = ipaddress.ip_address(ip.dst)
            if (src_addr.version != 4 or dst_addr.version != 4
                    or src_addr.is_multicast or dst_addr.is_multicast):
                return
            proto_name = PROTOCOL_NAMES[ip.proto]
            src_port = ""
            dst_port = ""
            flags = 0
            if ip.proto == 6:
                segment = parsed.get_protocol(tcp.tcp)
                if segment is not None:
                    src_port = str(segment.src_port)
                    dst_port = str(segment.dst_port)
                    flags = int(getattr(segment, "bits", 0) or 0)
            elif ip.proto == 17:
                segment = parsed.get_protocol(udp.udp)
                if segment is not None:
                    src_port = str(segment.src_port)
                    dst_port = str(segment.dst_port)

            now = time.time()
            dpid = int(msg.datapath.id)
            key = (dpid, str(src_addr), str(dst_addr), int(ip.proto))
            packet_length = len(msg.data)
            expired_record = None
            with self._lock:
                state = self._windows.get(key)
                if state is not None and now - state["start_time"] >= WINDOW_SECONDS:
                    expired_record = self._record_from_state(state)
                    self._windows.pop(key, None)
                    state = None
                if state is None:
                    state = {
                        "start_time": now,
                        "last_time": now,
                        "dpid": dpid,
                        "src_ip": str(src_addr),
                        "dst_ip": str(dst_addr),
                        "protocol": proto_name,
                        "protocol_number": int(ip.proto),
                        "packet_count": 0,
                        "byte_count": 0,
                        "syn_count": 0,
                        "ack_count": 0,
                        "rst_count": 0,
                        "fin_count": 0,
                        "src_ports": set(),
                        "dst_ports": set(),
                    }
                    self._windows[key] = state
                state["last_time"] = now
                state["packet_count"] += 1
                state["byte_count"] += packet_length
                if src_port:
                    state["src_ports"].add(src_port)
                if dst_port:
                    state["dst_ports"].add(dst_port)
                state["syn_count"] += int(bool(flags & 0x02))
                state["ack_count"] += int(bool(flags & 0x10))
                state["rst_count"] += int(bool(flags & 0x04))
                state["fin_count"] += int(bool(flags & 0x01))
            if expired_record is not None:
                self._enqueue(expired_record)
        except Exception:
            # Malformed/unexpected packets must not affect the controller.
            self.logger.debug("AI_SHADOW_PACKET_PARSE_SKIPPED", exc_info=True)

    def _record_from_state(self, state):
        duration = max(float(state["last_time"] - state["start_time"]), 0.001)
        packets = int(state["packet_count"])
        byte_count = int(state["byte_count"])
        protocol = int(state["protocol_number"])
        syn = int(state["syn_count"])
        ack = int(state["ack_count"])
        rst = int(state["rst_count"])
        ports_src = state["src_ports"]
        ports_dst = state["dst_ports"]
        return {
            "protocol": state["protocol"],
            "src_port": next(iter(ports_src)) if len(ports_src) == 1 else "",
            "dst_port": next(iter(ports_dst)) if len(ports_dst) == 1 else "",
            "priority": 0,
            "packet_count": packets,
            "byte_count": byte_count,
            "packet_rate": packets / duration,
            "byte_rate": byte_count / duration,
            "duration_sec": duration,
            "avg_packet_size": byte_count / max(packets, 1),
            "syn_count": syn,
            "ack_count": ack,
            "rst_count": rst,
            "fin_count": int(state["fin_count"]),
            "syn_ack_ratio": syn / max(ack, 1),
            "rst_ratio": rst / max(packets, 1),
            "unique_dst_ports": len(ports_dst),
            "failed_connection_count": max(syn - ack, 0),
            "tcp_fraction": float(protocol == 6),
            "udp_fraction": float(protocol == 17),
            "icmp_fraction": float(protocol == 1),
            "source": "packetin_window",
        }

    def _flush_loop(self):
        while True:
            now = time.time()
            ready = []
            with self._lock:
                for key, state in list(self._windows.items()):
                    if now - state["start_time"] >= WINDOW_SECONDS:
                        self._windows.pop(key, None)
                        ready.append(self._record_from_state(state))
            for record in ready:
                self._enqueue(record)
            hub.sleep(0.25)

    def _enqueue(self, record):
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            self._dropped += 1
            now = time.time()
            if now - self._last_warning >= 30.0:
                self._last_warning = now
                self.logger.warning(
                    "AI_SHADOW_QUEUE_FULL dropped_since_start=%d; forwarding remains unchanged",
                    self._dropped
                )

    def _inference_loop(self):
        while True:
            try:
                record = self._queue.get_nowait()
            except queue.Empty:
                hub.sleep(0.05)
                continue
            try:
                body = json.dumps(record, separators=(",", ":")).encode("utf-8")
                request = Request(
                    self.inference_url,
                    data=body,
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    method="POST",
                )
                with urlopen(request, timeout=INFERENCE_TIMEOUT_SECONDS) as response:
                    result = json.loads(response.read(8192).decode("utf-8"))
                self.logger.info(
                    "AI_SHADOW_PREDICTION label=%s confidence=%.4f source=%s feature_count=%d model=%s actions=disabled",
                    result.get("predicted_label", "unknown"),
                    float(result.get("confidence", 0.0)),
                    result.get("source", "unknown"),
                    int(result.get("model_feature_count", 0)),
                    result.get("model_version", "unknown"),
                )
            except (HTTPError, URLError, ValueError, TypeError, OSError) as exc:
                now = time.time()
                if now - self._last_warning >= 30.0:
                    self._last_warning = now
                    self.logger.warning(
                        "AI_SHADOW_INFERENCE_UNAVAILABLE error=%s; forwarding remains unchanged",
                        type(exc).__name__,
                    )
            except Exception as exc:
                now = time.time()
                if now - self._last_warning >= 30.0:
                    self._last_warning = now
                    self.logger.warning(
                        "AI_SHADOW_INFERENCE_ERROR error=%s; forwarding remains unchanged",
                        type(exc).__name__,
                    )
            finally:
                self._queue.task_done()
