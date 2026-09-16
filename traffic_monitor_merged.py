# traffic_monitor.py
# =============================================================
# Ryu Traffic Monitor + OpenFlow Quarantine + REST API
#
# PacketIn  -> packet_features.csv
# FlowStats -> traffic_features.csv
#
# PacketIn : first/unmatched packets + packet-level features
# FlowStats: OVS flow counters + interval-based rates
#
# Priority architecture:
#   200 -> QUARANTINE / DROP
#   100 -> SELF-HEALING / REROUTING (TopologyMonitor)
#    10 -> NORMAL FORWARDING
#     0 -> TABLE-MISS
#
# Notes:
#   - First FlowStats observation = baseline only
#   - Later observations = deltas
#   - CSV buffering for performance
#   - Stale flow cleanup
#   - Graceful shutdown flushes buffers
#   - Host IP/MAC tracking
#   - OpenFlow quarantine + REST API
#   - Normal IPv4 flows include:
#       IP / protocol / TCP-UDP ports
#     so FlowStats can collect them correctly
#
# Online Feature Engineering:
#   syn_ack_ratio = syn_flag / (ack_flag + 1)
#
#   This is calculated directly inside Ryu from the same
#   syn_flag_number and ack_flag_number features used during
#   offline feature engineering.
# =============================================================

import csv
import os
import time
import json

from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER,
    MAIN_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.lib import hub

from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import WSGIApplication
from ryu.app.wsgi import route


class TrafficMonitor(app_manager.RyuApp):

    OFP_VERSIONS = [
        ofproto_v1_3.OFP_VERSION
    ]

    _CONTEXTS = {
        "wsgi": WSGIApplication
    }

    # =========================================================
    # CONFIG
    # =========================================================

    FLOW_POLL_INTERVAL = 2.0
    FLOW_IDLE_TIMEOUT = 15
    STALE_FLOW_MAX_AGE = 60
    CSV_FLUSH_EVERY = 50

    # ---------------------------------------------------------
    # OpenFlow priorities
    #
    # 200 -> Quarantine / DROP
    # 100 -> Rerouting (TopologyMonitor)
    #  10 -> Normal forwarding
    #   0 -> Table miss
    # ---------------------------------------------------------

    QUARANTINE_PRIORITY = 200
    NORMAL_PRIORITY = 10

    RESTORE_SAFE_TIME = 30

    # =========================================================
    # INITIALIZATION
    # =========================================================

    def __init__(self, *args, **kwargs):

        super(
            TrafficMonitor,
            self
        ).__init__(*args, **kwargs)

        # ---------------- MAC / datapath ----------------

        self.mac_to_port = {}
        self.datapaths = {}

        # ---------------- Host tracking ----------------

        self.host_locations = {}
        self.ip_to_mac = {}
        self.ip_locations = {}

        # ---------------- Quarantine ----------------

        self.quarantined_hosts = {}
        self.restore_candidates = {}

        # ---------------- FlowStats deltas ----------------

        self.previous_flow_stats = {}

        # ---------------- CSV ----------------

        self.packet_csv_file = (
            "packet_features.csv"
        )

        self.flow_csv_file = (
            "traffic_features.csv"
        )

        self._packet_buffer = []
        self._flow_buffer = []

        self._initialize_csv_files()

        # ---------------- REST API ----------------

        wsgi = kwargs["wsgi"]

        wsgi.register(
            RestIsolationController,
            {
                "traffic_monitor_api_app": self
            },
        )

        # ---------------- Monitor thread ----------------

        self.monitor_thread = hub.spawn(
            self._monitor
        )

    # =========================================================
    # CSV INIT
    # =========================================================

    def _initialize_csv_files(self):

        if not os.path.exists(
            self.packet_csv_file
        ):

            with open(
                self.packet_csv_file,
                "w",
                newline=""
            ) as f:

                csv.writer(f).writerow([

                    "timestamp",
                    "switch",

                    "src_mac",
                    "dst_mac",

                    "src_ip",
                    "dst_ip",

                    "src_port",
                    "dst_port",

                    "ip_proto",
                    "ttl",

                    "tcp",
                    "udp",
                    "icmp",
                    "arp",

                    "http",
                    "https",
                    "dns",
                    "ssh",
                    "telnet",
                    "smtp",

                    "syn_flag_number",
                    "ack_flag_number",
                    "fin_flag_number",
                    "rst_flag_number",
                    "psh_flag_number",

                    "packet_length",
                    "payload_length",

                    # NEW:
                    # Online engineered feature
                    "syn_ack_ratio",
                ])

        if not os.path.exists(
            self.flow_csv_file
        ):

            with open(
                self.flow_csv_file,
                "w",
                newline=""
            ) as f:

                csv.writer(f).writerow([

                    "timestamp",
                    "switch",

                    "src_ip",
                    "dst_ip",

                    "src_port",
                    "dst_port",

                    "ip_proto",

                    "tcp",
                    "udp",
                    "icmp",

                    "http",
                    "https",
                    "dns",
                    "ssh",
                    "telnet",
                    "smtp",

                    "flow_duration",

                    "total_pkts",
                    "total_bytes",

                    "packet_rate",
                    "byte_rate",

                    "avg_packet_size",
                ])

    # =========================================================
    # DATAPATH REGISTRATION
    # =========================================================

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER],
    )
    def _state_change_handler(self, ev):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:

            if datapath.id not in self.datapaths:

                self.datapaths[
                    datapath.id
                ] = datapath

                self.logger.info(
                    "REGISTERED SWITCH: %016x",
                    datapath.id,
                )

        elif ev.state == DEAD_DISPATCHER:

            if datapath.id in self.datapaths:

                del self.datapaths[
                    datapath.id
                ]

                self.logger.info(
                    "UNREGISTERED SWITCH: %016x",
                    datapath.id,
                )

    # =========================================================
    # SWITCH FEATURES
    # Table-miss -> controller
    # =========================================================

    @set_ev_cls(
        ofp_event.EventOFPSwitchFeatures,
        CONFIG_DISPATCHER,
    )
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath

        self.datapaths[
            datapath.id
        ] = datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()

        actions = [

            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER,
            )

        ]

        self.add_flow(
            datapath,
            0,
            match,
            actions,
        )

        self.logger.info(
            "SWITCH FEATURES INSTALLED: %016x",
            datapath.id,
        )

    # =========================================================
    # FLOW HELPERS
    # =========================================================

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions,
        idle_timeout=0,
        hard_timeout=0,
    ):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [

            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions,
            )

        ]

        mod = parser.OFPFlowMod(

            datapath=datapath,

            priority=priority,

            match=match,

            instructions=inst,

            idle_timeout=idle_timeout,

            hard_timeout=hard_timeout,
        )

        datapath.send_msg(mod)

    def delete_flow(
        self,
        datapath,
        match,
        priority,
    ):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod(

            datapath=datapath,

            command=ofproto.OFPFC_DELETE,

            out_port=ofproto.OFPP_ANY,

            out_group=ofproto.OFPG_ANY,

            priority=priority,

            match=match,
        )

        datapath.send_msg(mod)

    # =========================================================
    # MONITOR LOOP
    # =========================================================

    def _monitor(self):

        while True:

            for datapath in list(
                self.datapaths.values()
            ):

                try:

                    self._request_stats(
                        datapath
                    )

                except Exception as e:

                    self.logger.error(
                        "STATS ERROR on switch %s: %s",
                        datapath.id,
                        e,
                    )

            self._check_restore_candidates()

            hub.sleep(
                self.FLOW_POLL_INTERVAL
            )

    def _request_stats(self, datapath):

        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(
            datapath
        )

        datapath.send_msg(req)

    # =========================================================
    # PACKET FEATURE EXTRACTION
    # =========================================================

    def extract_packet_features(self, pkt):

        pkt_ipv4 = pkt.get_protocol(
            ipv4.ipv4
        )

        pkt_tcp = pkt.get_protocol(
            tcp.tcp
        )

        pkt_udp = pkt.get_protocol(
            udp.udp
        )

        pkt_icmp = pkt.get_protocol(
            icmp.icmp
        )

        pkt_arp = pkt.get_protocol(
            arp.arp
        )

        features = {

            "src_ip": "",
            "dst_ip": "",

            "src_port": 0,
            "dst_port": 0,

            "ip_proto": 0,
            "ttl": 0,

            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "arp": 0,

            "http": 0,
            "https": 0,
            "dns": 0,
            "ssh": 0,
            "telnet": 0,
            "smtp": 0,

            "syn_flag": 0,
            "ack_flag": 0,
            "fin_flag": 0,
            "rst_flag": 0,
            "psh_flag": 0,

            "packet_length": 0,
            "payload_length": 0,

            # NEW:
            # Will be calculated after TCP flags are known.
            "syn_ack_ratio": 0.0,
        }

        # ---------------- IPv4 ----------------

        if pkt_ipv4:

            features["src_ip"] = (
                pkt_ipv4.src
            )

            features["dst_ip"] = (
                pkt_ipv4.dst
            )

            features["ip_proto"] = (
                pkt_ipv4.proto
            )

            features["ttl"] = (
                pkt_ipv4.ttl
            )

            ip_header_len = (
                pkt_ipv4.header_length * 4
            )

            transport_header_len = 0

            # -------- TCP --------

            if pkt_tcp:

                features["src_port"] = (
                    pkt_tcp.src_port
                )

                features["dst_port"] = (
                    pkt_tcp.dst_port
                )

                features["tcp"] = 1

                sp = pkt_tcp.src_port
                dp = pkt_tcp.dst_port

                if (
                    sp in (80, 8080)
                    or dp in (80, 8080)
                ):

                    features["http"] = 1

                if (
                    sp == 443
                    or dp == 443
                ):

                    features["https"] = 1

                if (
                    sp == 22
                    or dp == 22
                ):

                    features["ssh"] = 1

                if (
                    sp == 23
                    or dp == 23
                ):

                    features["telnet"] = 1

                if (
                    sp == 25
                    or dp == 25
                ):

                    features["smtp"] = 1

                bits = pkt_tcp.bits

                features["syn_flag"] = (
                    1
                    if bits & tcp.TCP_SYN
                    else 0
                )

                features["ack_flag"] = (
                    1
                    if bits & tcp.TCP_ACK
                    else 0
                )

                features["fin_flag"] = (
                    1
                    if bits & tcp.TCP_FIN
                    else 0
                )

                features["rst_flag"] = (
                    1
                    if bits & tcp.TCP_RST
                    else 0
                )

                features["psh_flag"] = (
                    1
                    if bits & tcp.TCP_PSH
                    else 0
                )

                # =================================================
                # ONLINE FEATURE ENGINEERING
                # =================================================
                #
                # Same formula used offline:
                #
                # syn_ack_ratio =
                #     syn_flag_number /
                #     (ack_flag_number + 1)
                #
                # The +1 prevents division by zero.
                # =================================================

                features["syn_ack_ratio"] = (
                    features["syn_flag"]
                    / (
                        features["ack_flag"]
                        + 1
                    )
                )

                transport_header_len = (
                    pkt_tcp.offset * 4
                )

            # -------- UDP --------

            elif pkt_udp:

                features["src_port"] = (
                    pkt_udp.src_port
                )

                features["dst_port"] = (
                    pkt_udp.dst_port
                )

                features["udp"] = 1

                sp = pkt_udp.src_port
                dp = pkt_udp.dst_port

                if (
                    sp == 53
                    or dp == 53
                ):

                    features["dns"] = 1

                transport_header_len = 8

            # -------- ICMP --------

            elif pkt_icmp:

                features["icmp"] = 1

                transport_header_len = 8

            # -------- Payload --------

            ip_payload_length = (
                pkt_ipv4.total_length
                - ip_header_len
            )

            features["payload_length"] = max(

                0,

                ip_payload_length
                - transport_header_len,
            )

        # ---------------- ARP ----------------

        elif pkt_arp:

            features["arp"] = 1

            features["src_ip"] = str(
                pkt_arp.src_ip
            )

            features["dst_ip"] = str(
                pkt_arp.dst_ip
            )

            features["ip_proto"] = 0

        return features

    # =========================================================
    # PACKET IN HANDLER
    # =========================================================

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER,
    )
    def _packet_in_handler(self, ev):

        msg = ev.msg

        datapath = msg.datapath

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match[
            "in_port"
        ]

        dpid = datapath.id

        pkt = packet.Packet(
            msg.data
        )

        eth = pkt.get_protocol(
            ethernet.ethernet
        )

        # ---------------- Ignore LLDP ----------------

        if (
            eth is None
            or eth.ethertype
                == ether_types.ETH_TYPE_LLDP
            or eth.dst
                == "01:80:c2:00:00:00"
        ):

            return

        src = eth.src
        dst = eth.dst

        # =====================================================
        # MAC LEARNING
        # =====================================================

        self.mac_to_port.setdefault(
            dpid,
            {},
        )

        self.mac_to_port[
            dpid
        ][src] = in_port

        self.host_locations[
            src
        ] = (
            dpid,
            in_port,
        )

        # =====================================================
        # IP / MAC TRACKING
        # =====================================================

        pkt_ipv4 = pkt.get_protocol(
            ipv4.ipv4
        )

        pkt_arp = pkt.get_protocol(
            arp.arp
        )

        if pkt_ipv4:

            self.ip_to_mac[
                pkt_ipv4.src
            ] = src

            self.ip_locations[
                pkt_ipv4.src
            ] = (
                dpid,
                in_port,
            )

        elif (
            pkt_arp
            and pkt_arp.src_ip
        ):

            self.ip_to_mac[
                str(pkt_arp.src_ip)
            ] = src

            self.ip_locations[
                str(pkt_arp.src_ip)
            ] = (
                dpid,
                in_port,
            )

        # =====================================================
        # QUARANTINE CHECK
        # =====================================================

        check_src_ip = (

            pkt_ipv4.src

            if pkt_ipv4

            else (

                str(pkt_arp.src_ip)

                if pkt_arp

                else None
            )
        )

        check_dst_ip = (

            pkt_ipv4.dst

            if pkt_ipv4

            else (

                str(pkt_arp.dst_ip)

                if pkt_arp

                else None
            )
        )

        if (

            self._is_quarantined_ip(
                check_src_ip
            )

            or

            self._is_quarantined_ip(
                check_dst_ip
            )
        ):

            return

        # =====================================================
        # OUTPUT PORT
        # =====================================================

        if (
            dst
            in self.mac_to_port[dpid]
        ):

            out_port = (
                self.mac_to_port[
                    dpid
                ][dst]
            )

        else:

            out_port = (
                ofproto.OFPP_FLOOD
            )

        actions = [

            parser.OFPActionOutput(
                out_port
            )

        ]

        # =====================================================
        # INSTALL NORMAL FLOW
        # =====================================================

        if (
            out_port
            != ofproto.OFPP_FLOOD
        ):

            pkt_tcp = pkt.get_protocol(
                tcp.tcp
            )

            pkt_udp = pkt.get_protocol(
                udp.udp
            )

            pkt_icmp = pkt.get_protocol(
                icmp.icmp
            )

            # -------------------------------------------------
            # IPv4 + TCP
            # -------------------------------------------------

            if (
                pkt_ipv4
                and pkt_tcp
            ):

                match = parser.OFPMatch(

                    eth_type=(
                        ether_types.ETH_TYPE_IP
                    ),

                    eth_dst=dst,

                    ipv4_src=(
                        pkt_ipv4.src
                    ),

                    ipv4_dst=(
                        pkt_ipv4.dst
                    ),

                    ip_proto=6,

                    tcp_src=(
                        pkt_tcp.src_port
                    ),

                    tcp_dst=(
                        pkt_tcp.dst_port
                    ),
                )

            # -------------------------------------------------
            # IPv4 + UDP
            # -------------------------------------------------

            elif (
                pkt_ipv4
                and pkt_udp
            ):

                match = parser.OFPMatch(

                    eth_type=(
                        ether_types.ETH_TYPE_IP
                    ),

                    eth_dst=dst,

                    ipv4_src=(
                        pkt_ipv4.src
                    ),

                    ipv4_dst=(
                        pkt_ipv4.dst
                    ),

                    ip_proto=17,

                    udp_src=(
                        pkt_udp.src_port
                    ),

                    udp_dst=(
                        pkt_udp.dst_port
                    ),
                )

            # -------------------------------------------------
            # IPv4 + ICMP
            # -------------------------------------------------

            elif (
                pkt_ipv4
                and pkt_icmp
            ):

                match = parser.OFPMatch(

                    eth_type=(
                        ether_types.ETH_TYPE_IP
                    ),

                    eth_dst=dst,

                    ipv4_src=(
                        pkt_ipv4.src
                    ),

                    ipv4_dst=(
                        pkt_ipv4.dst
                    ),

                    ip_proto=1,
                )

            # -------------------------------------------------
            # Other IPv4
            # -------------------------------------------------

            elif pkt_ipv4:

                match = parser.OFPMatch(

                    eth_type=(
                        ether_types.ETH_TYPE_IP
                    ),

                    eth_dst=dst,

                    ipv4_src=(
                        pkt_ipv4.src
                    ),

                    ipv4_dst=(
                        pkt_ipv4.dst
                    ),

                    ip_proto=(
                        pkt_ipv4.proto
                    ),
                )

            # -------------------------------------------------
            # Non-IPv4 traffic
            # -------------------------------------------------

            else:

                match = parser.OFPMatch(
                    eth_dst=dst
                )

            self.add_flow(

                datapath,

                self.NORMAL_PRIORITY,

                match,

                actions,

                idle_timeout=(
                    self.FLOW_IDLE_TIMEOUT
                ),
            )

        # =====================================================
        # EXTRACT FEATURES
        # =====================================================

        features = (
            self.extract_packet_features(
                pkt
            )
        )

        features["src_mac"] = src
        features["dst_mac"] = dst

        features["switch"] = dpid

        features["packet_length"] = (
            len(msg.data)
        )

        features["timestamp"] = (
            time.time()
        )

        self._buffer_packet_row(
            dpid,
            features,
        )

        # =====================================================
        # FORWARD PACKET
        # =====================================================

        data = None

        if (
            msg.buffer_id
            == ofproto.OFP_NO_BUFFER
        ):

            data = msg.data

        out = parser.OFPPacketOut(

            datapath=datapath,

            buffer_id=msg.buffer_id,

            in_port=in_port,

            actions=actions,

            data=data,
        )

        datapath.send_msg(out)

    # =========================================================
    # CSV BUFFERING
    # =========================================================

    def _buffer_packet_row(
        self,
        dpid,
        f,
    ):

        self._packet_buffer.append([

            f["timestamp"],

            format(
                dpid,
                "016x",
            ),

            f["src_mac"],
            f["dst_mac"],

            f["src_ip"],
            f["dst_ip"],

            f["src_port"],
            f["dst_port"],

            f["ip_proto"],
            f["ttl"],

            f["tcp"],
            f["udp"],
            f["icmp"],
            f["arp"],

            f["http"],
            f["https"],
            f["dns"],

            f["ssh"],
            f["telnet"],
            f["smtp"],

            f["syn_flag"],
            f["ack_flag"],
            f["fin_flag"],
            f["rst_flag"],
            f["psh_flag"],

            f["packet_length"],
            f["payload_length"],

            # NEW:
            f["syn_ack_ratio"],
        ])

        if (
            len(self._packet_buffer)
            >= self.CSV_FLUSH_EVERY
        ):

            self._flush_packet_buffer()

    def _flush_packet_buffer(self):

        if not self._packet_buffer:

            return

        with open(
            self.packet_csv_file,
            "a",
            newline="",
        ) as file:

            csv.writer(
                file
            ).writerows(
                self._packet_buffer
            )

        self._packet_buffer.clear()

    def _buffer_flow_row(
        self,
        row,
    ):

        self._flow_buffer.append(
            row
        )

        if (
            len(self._flow_buffer)
            >= self.CSV_FLUSH_EVERY
        ):

            self._flush_flow_buffer()

    def _flush_flow_buffer(self):

        if not self._flow_buffer:

            return

        with open(
            self.flow_csv_file,
            "a",
            newline="",
        ) as file:

            csv.writer(
                file
            ).writerows(
                self._flow_buffer
            )

        self._flow_buffer.clear()

    # =========================================================
    # QUARANTINE / RESTORE
    # =========================================================

    def _is_quarantined_ip(
        self,
        host_ip,
    ):

        if not host_ip:

            return False

        return (
            host_ip
            in self.quarantined_hosts
        )

    def quarantine_host(
        self,
        host_ip,
        host_mac=None,
    ):

        if (
            not host_ip
            or host_ip
                in self.quarantined_hosts
        ):

            return False

        if host_mac is None:

            host_mac = (
                self.ip_to_mac.get(
                    host_ip
                )
            )

        self.quarantined_hosts[
            host_ip
        ] = {

            "mac": host_mac,

            "timestamp":
                time.time(),
        }

        self.restore_candidates.pop(
            host_ip,
            None,
        )

        self.logger.warning(

            ">>> [OPENFLOW] "
            "AUTOMATIC QUARANTINE "
            "FOR IP: %s <<<",

            host_ip,
        )

        # =====================================================
        # INSTALL QUARANTINE RULES
        #
        # Priority = 200
        #
        # This is intentionally higher than:
        # Rerouting = 100
        # Normal    = 10
        # =====================================================

        for datapath in list(
            self.datapaths.values()
        ):

            parser = (
                datapath.ofproto_parser
            )

            # -------------------------------------------------
            # IPv4 source
            # -------------------------------------------------

            match_src = parser.OFPMatch(

                eth_type=0x0800,

                ipv4_src=host_ip,
            )

            self.add_flow(

                datapath,

                self.QUARANTINE_PRIORITY,

                match_src,

                [],
            )

            # -------------------------------------------------
            # IPv4 destination
            # -------------------------------------------------

            match_dst = parser.OFPMatch(

                eth_type=0x0800,

                ipv4_dst=host_ip,
            )

            self.add_flow(

                datapath,

                self.QUARANTINE_PRIORITY,

                match_dst,

                [],
            )

            # -------------------------------------------------
            # ARP source
            # -------------------------------------------------

            match_arp_src = parser.OFPMatch(

                eth_type=0x0806,

                arp_spa=host_ip,
            )

            self.add_flow(

                datapath,

                self.QUARANTINE_PRIORITY,

                match_arp_src,

                [],
            )

            # -------------------------------------------------
            # ARP destination
            # -------------------------------------------------

            match_arp_dst = parser.OFPMatch(

                eth_type=0x0806,

                arp_tpa=host_ip,
            )

            self.add_flow(

                datapath,

                self.QUARANTINE_PRIORITY,

                match_arp_dst,

                [],
            )

        return True

    def restore_host(
        self,
        host_ip,
    ):

        if (
            host_ip
            not in self.quarantined_hosts
        ):

            return False

        self.logger.info(

            ">>> [OPENFLOW] "
            "RESTORING HOST IP: %s <<<",

            host_ip,
        )

        # =====================================================
        # DELETE QUARANTINE RULES
        # =====================================================

        for datapath in list(
            self.datapaths.values()
        ):

            parser = (
                datapath.ofproto_parser
            )

            matches = (

                parser.OFPMatch(

                    eth_type=0x0800,

                    ipv4_src=host_ip,
                ),

                parser.OFPMatch(

                    eth_type=0x0800,

                    ipv4_dst=host_ip,
                ),

                parser.OFPMatch(

                    eth_type=0x0806,

                    arp_spa=host_ip,
                ),

                parser.OFPMatch(

                    eth_type=0x0806,

                    arp_tpa=host_ip,
                ),
            )

            for match in matches:

                self.delete_flow(

                    datapath,

                    match,

                    self.QUARANTINE_PRIORITY,
                )

        del self.quarantined_hosts[
            host_ip
        ]

        self.restore_candidates.pop(
            host_ip,
            None,
        )

        return True

    # =========================================================
    # OPTIONAL SAFE RESTORE
    # =========================================================

    def mark_host_safe(
        self,
        host_ip,
    ):

        if (

            host_ip
            in self.quarantined_hosts

            and

            host_ip
            not in self.restore_candidates

        ):

            self.restore_candidates[
                host_ip
            ] = time.time()

    def _check_restore_candidates(
        self,
    ):

        now = time.time()

        for host_ip in list(
            self.restore_candidates.keys()
        ):

            safe_since = (
                self.restore_candidates[
                    host_ip
                ]
            )

            if (
                now - safe_since
                >= self.RESTORE_SAFE_TIME
            ):

                self.restore_host(
                    host_ip
                )

    # =========================================================
    # FLOW STATS REPLY
    # =========================================================

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER,
    )
    def _flow_stats_reply_handler(
        self,
        ev,
    ):

        body = ev.msg.body

        datapath = ev.msg.datapath

        dpid = datapath.id

        current_time = time.time()

        active_keys = set()

        for stat in body:

            # =================================================
            # Skip:
            #   0   = table miss
            #   200 = quarantine
            # =================================================

            if stat.priority in (

                0,

                self.QUARANTINE_PRIORITY,

            ):

                continue

            # =================================================
            # Only IPv4 flows
            # =================================================

            if (
                "ipv4_src"
                not in stat.match
            ):

                continue

            # =================================================
            # Stable flow key
            # =================================================

            flow_key = (

                dpid,

                stat.match.get(
                    "ipv4_src",
                    "",
                ),

                stat.match.get(
                    "ipv4_dst",
                    "",
                ),

                stat.match.get(
                    "ip_proto",
                    0,
                ),

                stat.match.get(

                    "tcp_src",

                    stat.match.get(
                        "udp_src",
                        0,
                    ),
                ),

                stat.match.get(

                    "tcp_dst",

                    stat.match.get(
                        "udp_dst",
                        0,
                    ),
                ),
            )

            active_keys.add(
                flow_key
            )

            current_packets = (
                stat.packet_count
            )

            current_bytes = (
                stat.byte_count
            )

            previous = (
                self.previous_flow_stats.get(
                    flow_key
                )
            )

            # =================================================
            # First observation = baseline
            # =================================================

            if previous is None:

                self.previous_flow_stats[
                    flow_key
                ] = {

                    "packets":
                        current_packets,

                    "bytes":
                        current_bytes,

                    "timestamp":
                        current_time,
                }

                self.logger.debug(

                    "FLOW BASELINE | "
                    "switch=%016x "
                    "pkts=%s "
                    "bytes=%s",

                    dpid,

                    current_packets,

                    current_bytes,
                )

                continue

            # =================================================
            # Delta time
            # =================================================

            delta_time = (

                current_time
                - previous["timestamp"]
            )

            if delta_time <= 0:

                continue

            # =================================================
            # Delta counters
            # =================================================

            delta_packets = max(

                0,

                current_packets
                - previous["packets"],
            )

            delta_bytes = max(

                0,

                current_bytes
                - previous["bytes"],
            )

            # =================================================
            # Update previous
            # =================================================

            self.previous_flow_stats[
                flow_key
            ] = {

                "packets":
                    current_packets,

                "bytes":
                    current_bytes,

                "timestamp":
                    current_time,
            }

            # =================================================
            # Skip idle flow
            # =================================================

            if (

                delta_packets == 0

                and

                delta_bytes == 0

            ):

                continue

            self.logger.debug(

                "FLOW DELTA | "
                "switch=%016x "
                "d_pkts=%s "
                "d_bytes=%s "
                "d_t=%.4f",

                dpid,

                delta_packets,

                delta_bytes,

                delta_time,
            )

            # =================================================
            # Match fields
            # =================================================

            src_ip = stat.match.get(
                "ipv4_src",
                "",
            )

            dst_ip = stat.match.get(
                "ipv4_dst",
                "",
            )

            ip_proto = stat.match.get(
                "ip_proto",
                0,
            )

            src_port = 0
            dst_port = 0

            tcp_flow = 0
            udp_flow = 0
            icmp_flow = 0

            http = 0
            https = 0
            dns = 0
            ssh = 0
            telnet = 0
            smtp = 0

            # =================================================
            # ICMP
            # =================================================

            if ip_proto == 1:

                icmp_flow = 1

            # =================================================
            # TCP
            # =================================================

            if (
                "tcp_src"
                in stat.match
            ):

                src_port = (
                    stat.match.get(
                        "tcp_src",
                        0,
                    )
                )

                dst_port = (
                    stat.match.get(
                        "tcp_dst",
                        0,
                    )
                )

                tcp_flow = 1

                if (

                    src_port
                    in (80, 8080)

                    or

                    dst_port
                    in (80, 8080)

                ):

                    http = 1

                if (

                    src_port == 443

                    or

                    dst_port == 443

                ):

                    https = 1

                if (

                    src_port == 22

                    or

                    dst_port == 22

                ):

                    ssh = 1

                if (

                    src_port == 23

                    or

                    dst_port == 23

                ):

                    telnet = 1

                if (

                    src_port == 25

                    or

                    dst_port == 25

                ):

                    smtp = 1

            # =================================================
            # UDP
            # =================================================

            elif (
                "udp_src"
                in stat.match
            ):

                src_port = (
                    stat.match.get(
                        "udp_src",
                        0,
                    )
                )

                dst_port = (
                    stat.match.get(
                        "udp_dst",
                        0,
                    )
                )

                udp_flow = 1

                if (

                    src_port == 53

                    or

                    dst_port == 53

                ):

                    dns = 1

            # =================================================
            # Duration
            # =================================================

            flow_duration = (

                stat.duration_sec

                +

                (
                    stat.duration_nsec
                    / 1e9
                )
            )

            # =================================================
            # Rates
            # =================================================

            packet_rate = (

                delta_packets
                / delta_time
            )

            byte_rate = (

                delta_bytes
                / delta_time
            )

            avg_packet_size = (

                delta_bytes
                / delta_packets

                if delta_packets > 0

                else 0
            )

            # =================================================
            # Buffer Flow Row
            # =================================================

            self._buffer_flow_row([

                current_time,

                format(
                    dpid,
                    "016x",
                ),

                src_ip,
                dst_ip,

                src_port,
                dst_port,

                ip_proto,

                tcp_flow,
                udp_flow,
                icmp_flow,

                http,
                https,
                dns,

                ssh,
                telnet,
                smtp,

                flow_duration,

                current_packets,
                current_bytes,

                packet_rate,
                byte_rate,

                avg_packet_size,
            ])

        # =====================================================
        # Cleanup stale flows
        # =====================================================

        self._cleanup_stale_flows(

            active_keys,

            current_time,
        )

    # =========================================================
    # CLEANUP STALE FLOWS
    # =========================================================

    def _cleanup_stale_flows(
        self,
        active_keys,
        now,
    ):

        stale = [

            k

            for k, v
            in self.previous_flow_stats.items()

            if (

                k not in active_keys

                and

                (
                    now - v["timestamp"]
                )
                > self.STALE_FLOW_MAX_AGE
            )
        ]

        for k in stale:

            del self.previous_flow_stats[
                k
            ]

        if stale:

            self.logger.debug(

                "Cleaned up %d "
                "stale flow entries",

                len(stale),
            )

    # =========================================================
    # GRACEFUL SHUTDOWN
    # =========================================================

    def close(self):

        try:

            self._flush_packet_buffer()

            self._flush_flow_buffer()

        except Exception as e:

            self.logger.error(

                "Error flushing buffers "
                "on close: %s",

                e,
            )

        if hasattr(
            self,
            "monitor_thread",
        ):

            self.monitor_thread.kill()

        super(
            TrafficMonitor,
            self,
        ).close()


# =============================================================
# REST API CONTROLLER
# =============================================================

class RestIsolationController(
    ControllerBase
):

    def __init__(
        self,
        req,
        link,
        data,
        **config,
    ):

        super(
            RestIsolationController,
            self,
        ).__init__(
            req,
            link,
            data,
            **config,
        )

        self.app = data[
            "traffic_monitor_api_app"
        ]

    # =========================================================
    # POST /quarantine/{ip}
    # =========================================================

    @route(
        "quarantine",
        "/quarantine/{ip}",
        methods=["POST"],
    )
    def quarantine(
        self,
        req,
        **kwargs,
    ):

        host_ip = kwargs.get(
            "ip"
        )

        if not host_ip:

            return Response(

                content_type=(
                    "application/json"
                ),

                charset="utf-8",

                body=json.dumps({

                    "status":
                        "error",

                    "message":
                        "IP address is required",
                }),
            )

        try:

            result = (
                self.app.quarantine_host(
                    host_ip
                )
            )

            if result:

                body = {

                    "status":
                        "success",

                    "action":
                        "quarantine",

                    "ip":
                        host_ip,

                    "message":
                        "Host quarantined successfully",
                }

            else:

                body = {

                    "status":
                        "info",

                    "action":
                        "quarantine",

                    "ip":
                        host_ip,

                    "message":
                        "Host is already quarantined "
                        "or invalid IP",
                }

            return Response(

                content_type=(
                    "application/json"
                ),

                charset="utf-8",

                body=json.dumps(
                    body
                ),
            )

        except Exception as e:

            self.app.logger.exception(
                "QUARANTINE API ERROR"
            )

            return Response(

                status=500,

                content_type=(
                    "application/json"
                ),

                charset="utf-8",

                body=json.dumps({

                    "status":
                        "error",

                    "message":
                        str(e),
                }),
            )

    # =========================================================
    # POST /restore/{ip}
    # =========================================================

    @route(
        "restore",
        "/restore/{ip}",
        methods=["POST"],
    )
    def restore(
        self,
        req,
        **kwargs,
    ):

        host_ip = kwargs.get(
            "ip"
        )

        if not host_ip:

            return Response(

                content_type=(
                    "application/json"
                ),

                charset="utf-8",

                body=json.dumps({

                    "status":
                        "error",

                    "message":
                        "IP address is required",
                }),
            )

        try:

            result = (
                self.app.restore_host(
                    host_ip
                )
            )

            if result:

                body = {

                    "status":
                        "success",

                    "action":
                        "restore",

                    "ip":
                        host_ip,

                    "message":
                        "Host restored successfully",
                }

            else:

                body = {

                    "status":
                        "info",

                    "action":
                        "restore",

                    "ip":
                        host_ip,

                    "message":
                        "Host is not quarantined",
                }

            return Response(

                content_type=(
                    "application/json"
                ),

                charset="utf-8",

                body=json.dumps(
                    body
                ),
            )

        except Exception as e:

            self.app.logger.exception(
                "RESTORE API ERROR"
            )

            return Response(

                status=500,

                content_type=(
                    "application/json"
                ),

                charset="utf-8",

                body=json.dumps({

                    "status":
                        "error",

                    "message":
                        str(e),
                }),
            )
