import csv
import os
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
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

class TrafficMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(TrafficMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.previous_flow_stats = {}

        # Define the CSV files
        self.packet_csv_file = "packet_features.csv"
        self.flow_csv_file = "traffic_features.csv"

        # Initialize Packet CSV File with all features + ip_proto
        if not os.path.exists(self.packet_csv_file):
            with open(self.packet_csv_file, mode='w', newline='') as f:
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
                    "payload_length"
                ])

        # Initialize Flow CSV File with timestamp, switch, and ip_proto
        if not os.path.exists(self.flow_csv_file):
            with open(self.flow_csv_file, mode='w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
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
                    "avg_packet_size"
                ])

        # Monitor Thread
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info('Registering datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info('Unregistering datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(2)

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def extract_packet_features(self, pkt):
        """Extract features from a single packet"""
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_arp = pkt.get_protocol(arp.arp)

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
            "payload_length": 0
        }

        if pkt_ipv4:
            features["src_ip"] = pkt_ipv4.src
            features["dst_ip"] = pkt_ipv4.dst
            features["ip_proto"] = pkt_ipv4.proto
            features["ttl"] = pkt_ipv4.ttl

            ip_header_len = pkt_ipv4.header_length * 4
            transport_header_len = 0

            if pkt_tcp:
                features["src_port"] = pkt_tcp.src_port
                features["dst_port"] = pkt_tcp.dst_port
                features["tcp"] = 1

                if pkt_tcp.src_port == 80 or pkt_tcp.dst_port == 80:
                    features["http"] = 1
                if pkt_tcp.src_port == 443 or pkt_tcp.dst_port == 443:
                    features["https"] = 1
                if pkt_tcp.src_port == 22 or pkt_tcp.dst_port == 22:
                    features["ssh"] = 1
                if pkt_tcp.src_port == 23 or pkt_tcp.dst_port == 23:
                    features["telnet"] = 1
                if pkt_tcp.src_port == 25 or pkt_tcp.dst_port == 25:
                    features["smtp"] = 1

                features["syn_flag"] = 1 if pkt_tcp.bits & tcp.TCP_SYN else 0
                features["ack_flag"] = 1 if pkt_tcp.bits & tcp.TCP_ACK else 0
                features["fin_flag"] = 1 if pkt_tcp.bits & tcp.TCP_FIN else 0
                features["rst_flag"] = 1 if pkt_tcp.bits & tcp.TCP_RST else 0
                features["psh_flag"] = 1 if pkt_tcp.bits & tcp.TCP_PSH else 0

                transport_header_len = pkt_tcp.offset * 4

            elif pkt_udp:
                features["src_port"] = pkt_udp.src_port
                features["dst_port"] = pkt_udp.dst_port
                features["udp"] = 1

                if pkt_udp.src_port == 53 or pkt_udp.dst_port == 53:
                    features["dns"] = 1

                transport_header_len = 8

            elif pkt_icmp:
                features["icmp"] = 1
                transport_header_len = 8

            # Calculate payload length
            ip_payload_length = pkt_ipv4.total_length - ip_header_len
            features["payload_length"] = max(
                0,
                ip_payload_length - transport_header_len
            )

        elif pkt_arp:
            features["arp"] = 1
            features["src_ip"] = str(pkt_arp.src_ip)
            features["dst_ip"] = str(pkt_arp.dst_ip)
            features["ip_proto"] = 0
            features["packet_length"] = 28  # ARP packet length
            features["payload_length"] = 0   # ARP has no payload

        return features

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        # Get actual packet length once
        actual_packet_length = len(msg.data)

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)

            if ip_pkt and tcp_pkt:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    ip_proto=6,
                    tcp_src=tcp_pkt.src_port,
                    tcp_dst=tcp_pkt.dst_port
                )
            elif ip_pkt and udp_pkt:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    ip_proto=17,
                    udp_src=udp_pkt.src_port,
                    udp_dst=udp_pkt.dst_port
                )
            elif ip_pkt:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst,
                    ip_proto=ip_pkt.proto
                )
            else:
                match = None

            if match is not None:
                self.add_flow(datapath, 1, match, actions)

        # Extract features and save Packet CSV
        features = self.extract_packet_features(pkt)

        # Debug: Print packet features to terminal
        self.logger.info("PACKET FEATURES = %s", features)

        # Add MAC addresses, switch ID, and actual packet length
        features["src_mac"] = src
        features["dst_mac"] = dst
        features["switch"] = dpid
        features["packet_length"] = actual_packet_length
        features["timestamp"] = time.time()

        with open(self.packet_csv_file, mode='a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                features["timestamp"],
                features["switch"],
                features["src_mac"],
                features["dst_mac"],
                features["src_ip"],
                features["dst_ip"],
                features["src_port"],
                features["dst_port"],
                features["ip_proto"],
                features["ttl"],
                features["tcp"],
                features["udp"],
                features["icmp"],
                features["arp"],
                features["http"],
                features["https"],
                features["dns"],
                features["ssh"],
                features["telnet"],
                features["smtp"],
                features["syn_flag"],
                features["ack_flag"],
                features["fin_flag"],
                features["rst_flag"],
                features["psh_flag"],
                features["packet_length"],
                features["payload_length"]
            ])

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id

        for stat in body:
            if stat.priority == 0:
                continue

            if "ipv4_src" not in stat.match:
                continue

            # Prevent duplicate flow logging using (dpid, match) tuple
            flow_key = (dpid, str(stat.match))
            prev = self.previous_flow_stats.get(flow_key)

            if prev and prev["packets"] == stat.packet_count and prev["bytes"] == stat.byte_count:
                continue

            self.previous_flow_stats[flow_key] = {
                "packets": stat.packet_count,
                "bytes": stat.byte_count
            }

            self.logger.info("FLOW MATCH = %s", stat.match)

            src_ip = stat.match.get("ipv4_src", "")
            dst_ip = stat.match.get("ipv4_dst", "")
            ip_proto = stat.match.get("ip_proto", 0)

            src_port = 0
            dst_port = 0

            tcp = 0
            udp = 0
            icmp_flow = 0
            http = 0
            https = 0
            dns = 0
            ssh = 0
            telnet = 0
            smtp = 0

            if ip_proto == 1:
                icmp_flow = 1

            if "tcp_src" in stat.match:
                src_port = stat.match.get("tcp_src", 0)
                dst_port = stat.match.get("tcp_dst", 0)
                tcp = 1

                if src_port == 80 or dst_port == 80:
                    http = 1
                if src_port == 443 or dst_port == 443:
                    https = 1
                if src_port == 22 or dst_port == 22:
                    ssh = 1
                if src_port == 23 or dst_port == 23:
                    telnet = 1
                if src_port == 25 or dst_port == 25:
                    smtp = 1

            elif "udp_src" in stat.match:
                src_port = stat.match.get("udp_src", 0)
                dst_port = stat.match.get("udp_dst", 0)
                udp = 1

                if src_port == 53 or dst_port == 53:
                    dns = 1

            total_pkts = stat.packet_count
            total_bytes = stat.byte_count
            duration_sec = stat.duration_sec
            duration_nsec = stat.duration_nsec

            flow_duration = duration_sec + (duration_nsec / 1e9)

            packet_rate = 0
            byte_rate = 0
            avg_packet_size = 0

            if flow_duration > 0:
                packet_rate = total_pkts / flow_duration
                byte_rate = total_bytes / flow_duration

            if total_pkts > 0:
                avg_packet_size = total_bytes / total_pkts

            with open(self.flow_csv_file, mode='a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    time.time(),
                    dpid,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    ip_proto,
                    tcp,
                    udp,
                    icmp_flow,
                    http,
                    https,
                    dns,
                    ssh,
                    telnet,
                    smtp,
                    flow_duration,
                    total_pkts,
                    total_bytes,
                    packet_rate,
                    byte_rate,
                    avg_packet_size
                ])
