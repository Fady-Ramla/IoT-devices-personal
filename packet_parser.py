# packet_parser.py
# Ryu 4.34
# Python 3.8
# ============================================================

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp


def extract_packet_features(msg):

    pkt = packet.Packet(msg.data)

    features = {

        # IP
        "src_ip": None,
        "dst_ip": None,

        # Ports
        "src_port": 0,
        "dst_port": 0,

        # TTL
        "ttl": 0,

        # Protocols
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "arp": 0,

        # Application protocols
        "http": 0,
        "https": 0,
        "dns": 0,
        "ssh": 0,
        "telnet": 0,
        "smtp": 0,

        # TCP flags
        "syn_flag_number": 0,
        "ack_flag_number": 0,
        "fin_flag_number": 0,
        "rst_flag_number": 0,
        "psh_flag_number": 0,

        # Packet size
        "packet_length": len(msg.data),
        "payload_length": 0
    }

    # ======================================================
    # Ethernet Header
    # ======================================================

    eth = pkt.get_protocol(ethernet.ethernet)
    
    if not eth:
        return features

    # ======================================================
    # ARP
    # ======================================================

    arp_pkt = pkt.get_protocol(arp.arp)

    if arp_pkt:

        features["arp"] = 1
        features["src_ip"] = str(arp_pkt.src_ip)
        features["dst_ip"] = str(arp_pkt.dst_ip)
        return features

    # ======================================================
    # IPv4 Header
    # ======================================================

    ip_pkt = pkt.get_protocol(ipv4.ipv4)

    if ip_pkt:

        features["src_ip"] = str(ip_pkt.src)
        features["dst_ip"] = str(ip_pkt.dst)
        features["ttl"] = ip_pkt.ttl

        # ======================================================
        # TCP
        # ======================================================

        tcp_pkt = pkt.get_protocol(tcp.tcp)

        if tcp_pkt:

            features["tcp"] = 1
            features["src_port"] = tcp_pkt.src_port
            features["dst_port"] = tcp_pkt.dst_port

            # TCP Flags
            flags = tcp_pkt.bits

            if flags & tcp.TCP_SYN:
                features["syn_flag_number"] = 1

            if flags & tcp.TCP_ACK:
                features["ack_flag_number"] = 1

            if flags & tcp.TCP_FIN:
                features["fin_flag_number"] = 1

            if flags & tcp.TCP_RST:
                features["rst_flag_number"] = 1

            if flags & tcp.TCP_PSH:
                features["psh_flag_number"] = 1

            # Application Detection (Port Based)
            ports = [tcp_pkt.src_port, tcp_pkt.dst_port]

            if 80 in ports:
                features["http"] = 1
            if 443 in ports:
                features["https"] = 1
            if 53 in ports:
                features["dns"] = 1
            if 22 in ports:
                features["ssh"] = 1
            if 23 in ports:
                features["telnet"] = 1
            if 25 in ports:
                features["smtp"] = 1

        # ======================================================
        # UDP
        # ======================================================

        udp_pkt = pkt.get_protocol(udp.udp)

        if udp_pkt:

            features["udp"] = 1
            features["src_port"] = udp_pkt.src_port
            features["dst_port"] = udp_pkt.dst_port

            # Application Detection
            ports = [udp_pkt.src_port, udp_pkt.dst_port]

            if 53 in ports:
                features["dns"] = 1
            if 80 in ports:
                features["http"] = 1
            if 443 in ports:
                features["https"] = 1

        # ======================================================
        # ICMP
        # ======================================================

        icmp_pkt = pkt.get_protocol(icmp.icmp)

        if icmp_pkt:
            features["icmp"] = 1

    # ======================================================
    # Payload Length Calculation
    # ======================================================

    try:
        total_length = len(msg.data)
        header_length = 0

        # Ethernet Header
        if eth:
            header_length += 14

        # IPv4 Header
        if ip_pkt:
            header_length += ip_pkt.header_length * 4

        # TCP Header
        if tcp_pkt:
            header_length += tcp_pkt.offset * 4

        # UDP Header
        if udp_pkt:
            header_length += 8

        payload = total_length - header_length

        if payload > 0:
            features["payload_length"] = payload
        else:
            features["payload_length"] = 0

    except Exception:
        features["payload_length"] = 0

    # ======================================================
    # Return Features
    # ======================================================

    return features
