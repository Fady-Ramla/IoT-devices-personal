from operator import attrgetter
import time
import csv
import os

from ryu.app import simple_switch_13

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.ofproto import ofproto_v1_3

from packet_parser import extract_packet_features


class TrafficMonitor(simple_switch_13.SimpleSwitch13):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):

        super(TrafficMonitor, self).__init__(*args, **kwargs)

        self.datapaths = {}
        self.previous_stats = {}

        self.monitor_thread = hub.spawn(self._monitor)

        self.csv_file = "traffic_features.csv"

        if not os.path.exists(self.csv_file):

            with open(self.csv_file, "w", newline="") as f:

                writer = csv.writer(f)

                writer.writerow([

                    "timestamp",

                    "switch",

                    "src_mac",
                    "dst_mac",

                    "src_ip",
                    "dst_ip",

                    "src_port",
                    "dst_port",

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

                    "flow_duration",
                    "total_pkts",
                    "total_bytes",

                    "packet_rate",
                    "byte_rate",

                    "avg_packet_size"
                ])

        # =============================================
        # NEW: Initialize packet features CSV
        # =============================================
        self.packet_csv_file = "packet_features.csv"
        
        if not os.path.exists(self.packet_csv_file):
            with open(self.packet_csv_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "timestamp",
                    "src_ip", "dst_ip",
                    "src_port", "dst_port",
                    "ttl",
                    "tcp", "udp", "icmp", "arp",
                    "http", "https", "dns", "ssh", "telnet", "smtp",
                    "syn_flag", "ack_flag", "fin_flag", "rst_flag", "psh_flag",
                    "packet_length", "payload_length"
                ])

    # =====================================================
    # SWITCH REGISTRATION
    # =====================================================

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER]
    )
    def _state_change_handler(self, ev):

        datapath = ev.datapath

        if ev.state == MAIN_DISPATCHER:

            if datapath.id not in self.datapaths:

                self.logger.info(
                    "Register switch %016x",
                    datapath.id
                )

                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:

            if datapath.id in self.datapaths:

                self.logger.info(
                    "Unregister switch %016x",
                    datapath.id
                )

                del self.datapaths[datapath.id]

    # =====================================================
    # MONITOR THREAD
    # =====================================================

    def _monitor(self):

        while True:

            for dp in self.datapaths.values():

                self._request_stats(dp)

            hub.sleep(5)

    # =====================================================
    # REQUEST STATS
    # =====================================================

    def _request_stats(self, datapath):

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        req = parser.OFPFlowStatsRequest(datapath)

        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(
            datapath,
            0,
            ofproto.OFPP_ANY
        )

        datapath.send_msg(req)

    # =====================================================
    # PACKET IN
    # =====================================================

    @set_ev_cls(
        ofp_event.EventOFPPacketIn,
        MAIN_DISPATCHER
    )
    def _packet_in_handler(self, ev):

        msg = ev.msg

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(
            ethernet.ethernet
        )[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.mac_to_port.setdefault(
            dpid,
            {}
        )

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:

            out_port = self.mac_to_port[dpid][dst]

        else:

            out_port = ofproto.OFPP_FLOOD

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        if out_port != ofproto.OFPP_FLOOD:

            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst,
                eth_src=src
            )

            self.add_flow(
                datapath,
                1,
                match,
                actions
            )

        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

        # ==============================
        # FEATURE EXTRACTION FROM packet_parser.py
        # ==============================

        try:

            features = extract_packet_features(msg)

            self.logger.info(
                "Packet Features -> %s",
                features
            )

            # ==============================
            # SAVE PACKET FEATURES TO CSV
            # ==============================
            
            with open(self.packet_csv_file, "a", newline="") as f:
                writer = csv.writer(f)
                
                writer.writerow([
                    time.time(),
                    features.get("src_ip", ""),
                    features.get("dst_ip", ""),
                    features.get("src_port", 0),
                    features.get("dst_port", 0),
                    features.get("ttl", 0),
                    features.get("tcp", 0),
                    features.get("udp", 0),
                    features.get("icmp", 0),
                    features.get("arp", 0),
                    features.get("http", 0),
                    features.get("https", 0),
                    features.get("dns", 0),
                    features.get("ssh", 0),
                    features.get("telnet", 0),
                    features.get("smtp", 0),
                    features.get("syn_flag_number", 0),
                    features.get("ack_flag_number", 0),
                    features.get("fin_flag_number", 0),
                    features.get("rst_flag_number", 0),
                    features.get("psh_flag_number", 0),
                    features.get("packet_length", 0),
                    features.get("payload_length", 0)
                ])

        except Exception as e:

            self.logger.error(
                "Packet Parsing Error: %s",
                str(e)
            )

    # =====================================================
    # FLOW STATS REPLY
    # =====================================================

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER
    )
    def _flow_stats_reply_handler(self, ev):

        body = ev.msg.body

        datapath = ev.msg.datapath

        dpid = datapath.id

        current_time = time.time()

        with open(
            self.csv_file,
            "a",
            newline=""
        ) as f:

            writer = csv.writer(f)

            for stat in body:

                if stat.priority == 0:
                    continue

                src_mac = stat.match.get(
                    "eth_src",
                    "Unknown"
                )

                dst_mac = stat.match.get(
                    "eth_dst",
                    "Unknown"
                )

                in_port = stat.match.get(
                    "in_port",
                    0
                )

                total_pkts = stat.packet_count
                total_bytes = stat.byte_count

                flow_duration = stat.duration_sec

                flow_id = (
                    dpid,
                    src_mac,
                    dst_mac,
                    in_port
                )

                packet_rate = 0
                byte_rate = 0

                if flow_id in self.previous_stats:

                    old_pkts, old_bytes, old_time = \
                        self.previous_stats[flow_id]

                    elapsed = current_time - old_time

                    if elapsed > 0:

                        packet_rate = (
                            total_pkts - old_pkts
                        ) / elapsed

                        byte_rate = (
                            total_bytes - old_bytes
                        ) / elapsed

                self.previous_stats[flow_id] = (
                    total_pkts,
                    total_bytes,
                    current_time
                )

                avg_packet_size = 0

                if total_pkts > 0:

                    avg_packet_size = (
                        total_bytes /
                        total_pkts
                    )

                # Note: IP and port fields are left empty in flow stats
                # They are captured in packet_features.csv instead
                writer.writerow([

                    current_time,

                    dpid,

                    src_mac,
                    dst_mac,

                    "", "",  # src_ip, dst_ip
                    0, 0,    # src_port, dst_port
                    0,       # ttl

                    0, 0, 0, 0,  # tcp, udp, icmp, arp

                    0, 0, 0, 0, 0, 0,  # app protocols

                    0, 0, 0, 0, 0,  # tcp flags

                    0,  # packet_length
                    0,  # payload_length

                    flow_duration,
                    total_pkts,
                    total_bytes,

                    packet_rate,
                    byte_rate,

                    avg_packet_size
                ])

    # =====================================================
    # PORT STATS
    # =====================================================

    @set_ev_cls(
        ofp_event.EventOFPPortStatsReply,
        MAIN_DISPATCHER
    )
    def _port_stats_reply_handler(self, ev):

        body = ev.msg.body

        for stat in sorted(
            body,
            key=attrgetter("port_no")
        ):

            self.logger.info(
                "DPID=%016x PORT=%d RX=%d TX=%d",
                ev.msg.datapath.id,
                stat.port_no,
                stat.rx_packets,
                stat.tx_packets
            )
