from operator import attrgetter
import time
import csv
import os

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.ofproto import ofproto_v1_3

from ryu.app import simple_switch_13


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
                    "time",
                    "switch",
                    "src_mac",
                    "dst_mac",
                    "in_port",
                    "out_port",
                    "flow_duration",
                    "total_pkts",
                    "total_bytes",
                    "packet_rate",
                    "byte_rate",
                    "avg_packet_size"
                ])

    @set_ev_cls(
        ofp_event.EventOFPStateChange,
        [MAIN_DISPATCHER, DEAD_DISPATCHER]
    )
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("Register Switch %016x", datapath.id)
                self.datapaths[datapath.id] = datapath

        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info("Unregister Switch %016x", datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        self.logger.info("Send Stats Request: %016x", datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        flow_req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(flow_req)

        port_req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(port_req)

    @set_ev_cls(
        ofp_event.EventOFPFlowStatsReply,
        MAIN_DISPATCHER
    )
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        datapath = ev.msg.datapath
        dpid = datapath.id
        current_time = time.time()

        with open(self.csv_file, "a", newline="") as f:
            writer = csv.writer(f)

            for stat in sorted(
                    body,
                    key=lambda flow: (
                        flow.match.get('in_port', 0),
                        flow.match.get('eth_dst', '')
                    )):

                if stat.priority == 0:
                    continue

                src_mac = stat.match.get('eth_src', "Unknown")
                dst_mac = stat.match.get('eth_dst', "Unknown")
                in_port = stat.match.get('in_port', 0)

                out_port = "Unknown"
                if len(stat.instructions) > 0:
                    actions = stat.instructions[0].actions
                    for action in actions:
                        if hasattr(action, 'port'):
                            out_port = action.port
                            break

                total_pkts = stat.packet_count
                total_bytes = stat.byte_count
                flow_duration = stat.duration_sec + (stat.duration_nsec / 1000000000)

                flow_id = (dpid, src_mac, dst_mac, in_port, out_port)

                packet_rate = 0
                byte_rate = 0

                if flow_id in self.previous_stats:
                    prev_pkts, prev_bytes, prev_time = self.previous_stats[flow_id]
                    elapsed = current_time - prev_time

                    if elapsed > 0:
                        packet_rate = (total_pkts - prev_pkts) / elapsed
                        byte_rate = (total_bytes - prev_bytes) / elapsed

                self.previous_stats[flow_id] = (total_pkts, total_bytes, current_time)

                avg_packet_size = 0
                if total_pkts > 0:
                    avg_packet_size = total_bytes / total_pkts

                self.logger.info("===================================")
                self.logger.info("Switch: %016x", dpid)
                self.logger.info("Source: %s | Destination: %s", src_mac, dst_mac)
                self.logger.info("In Port: %s | Out Port: %s", in_port, out_port)
                self.logger.info("Flow Duration: %.2f sec", flow_duration)
                self.logger.info("Total Packets: %d | Total Bytes: %d", total_pkts, total_bytes)
                self.logger.info("Packet Rate: %.2f Pkts/s | Byte Rate: %.2f Bytes/s", packet_rate, byte_rate)
                self.logger.info("Average Packet Size: %.2f Bytes", avg_packet_size)
                self.logger.info("===================================")

                writer.writerow([
                    current_time,
                    dpid,
                    src_mac,
                    dst_mac,
                    in_port,
                    out_port,
                    flow_duration,
                    total_pkts,
                    total_bytes,
                    packet_rate,
                    byte_rate,
                    avg_packet_size
                ])

    @set_ev_cls(
        ofp_event.EventOFPPortStatsReply,
        MAIN_DISPATCHER
    )
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info("DPID\t\t\tPORT\tRX_PKTS\tTX_PKTS\tRX_BYTES\tTX_BYTES")

        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info(
                "%016x\t%d\t%d\t%d\t%d\t%d",
                ev.msg.datapath.id,
                stat.port_no,
                stat.rx_packets,
                stat.tx_packets,
                stat.rx_bytes,
                stat.tx_bytes
            )



