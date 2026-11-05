#!/usr/bin/env python3

from scapy.all import PcapReader, IP, TCP, UDP, ICMP, ARP, Ether
import csv
import os
import sys


# ============================================================
# Convert one packet into feature dictionary
# ============================================================

def packet_to_features(pkt, run_id=""):

    features = {
        "run_id": run_id,
        "timestamp": float(pkt.time),

        "switch": "",

        "src_mac": "",
        "dst_mac": "",

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

        "syn_flag_number": 0,
        "ack_flag_number": 0,
        "fin_flag_number": 0,
        "rst_flag_number": 0,
        "psh_flag_number": 0,

        "packet_length": len(pkt),
        "payload_length": 0
    }

    # ========================================================
    # Ethernet / MAC
    # ========================================================

    if Ether in pkt:

        eth = pkt[Ether]

        features["src_mac"] = eth.src
        features["dst_mac"] = eth.dst

    # ========================================================
    # IPv4
    # ========================================================

    if IP in pkt:

        ip = pkt[IP]

        features["src_ip"] = ip.src
        features["dst_ip"] = ip.dst

        features["ip_proto"] = int(ip.proto)
        features["ttl"] = int(ip.ttl)

        # ====================================================
        # TCP
        # ====================================================

        if TCP in pkt:

            tcp = pkt[TCP]

            features["tcp"] = 1

            features["src_port"] = int(tcp.sport)
            features["dst_port"] = int(tcp.dport)

            # ------------------------------------------------
            # Application protocol indicators
            # ------------------------------------------------

            # HTTP
            # Project Web/API server uses port 5000
            if (
                tcp.sport in (80, 5000)
                or tcp.dport in (80, 5000)
            ):
                features["http"] = 1

            # HTTPS
            if (
                tcp.sport == 443
                or tcp.dport == 443
            ):
                features["https"] = 1

            # SSH
            if (
                tcp.sport == 22
                or tcp.dport == 22
            ):
                features["ssh"] = 1

            # Telnet
            if (
                tcp.sport == 23
                or tcp.dport == 23
            ):
                features["telnet"] = 1

            # SMTP
            if (
                tcp.sport == 25
                or tcp.dport == 25
            ):
                features["smtp"] = 1

            # ------------------------------------------------
            # TCP Flags
            # ------------------------------------------------

            flags = int(tcp.flags)

            # SYN
            features["syn_flag_number"] = int(
                bool(flags & 0x02)
            )

            # ACK
            features["ack_flag_number"] = int(
                bool(flags & 0x10)
            )

            # FIN
            features["fin_flag_number"] = int(
                bool(flags & 0x01)
            )

            # RST
            features["rst_flag_number"] = int(
                bool(flags & 0x04)
            )

            # PSH
            features["psh_flag_number"] = int(
                bool(flags & 0x08)
            )

            # ------------------------------------------------
            # TCP payload
            # ------------------------------------------------

            if tcp.payload:

                features["payload_length"] = len(
                    bytes(tcp.payload)
                )

        # ====================================================
        # UDP
        # ====================================================

        elif UDP in pkt:

            udp = pkt[UDP]

            features["udp"] = 1

            features["src_port"] = int(udp.sport)
            features["dst_port"] = int(udp.dport)

            # ------------------------------------------------
            # DNS
            # ------------------------------------------------

            if (
                udp.sport == 53
                or udp.dport == 53
            ):
                features["dns"] = 1

            # ------------------------------------------------
            # UDP payload
            # ------------------------------------------------

            if udp.payload:

                features["payload_length"] = len(
                    bytes(udp.payload)
                )

        # ====================================================
        # ICMP
        # ====================================================

        elif ICMP in pkt:

            features["icmp"] = 1

            if pkt[ICMP].payload:

                features["payload_length"] = len(
                    bytes(pkt[ICMP].payload)
                )

    # ========================================================
    # ARP
    # ========================================================

    elif ARP in pkt:

        arp = pkt[ARP]

        features["arp"] = 1

        # ARP uses protocol addresses instead of IP layer
        features["src_ip"] = arp.psrc
        features["dst_ip"] = arp.pdst

        # ARP is not TCP/UDP/ICMP
        features["ip_proto"] = 0

    # ========================================================
    # Return extracted features
    # ========================================================

    return features


# ============================================================
# Convert PCAP to CSV
# ============================================================

def convert_pcap(pcap_file, output_csv, run_id=""):

    print()
    print("==============================================")
    print("           PCAP TO CSV CONVERSION")
    print("==============================================")

    print("PCAP file :", pcap_file)
    print("Output CSV:", output_csv)

    if run_id:

        print("Run ID    :", run_id)

    print("----------------------------------------------")

    # --------------------------------------------------------
    # Check PCAP
    # --------------------------------------------------------

    if not os.path.isfile(pcap_file):

        print("ERROR: PCAP file does not exist.")

        sys.exit(1)

    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    output_dir = os.path.dirname(output_csv)

    if output_dir:

        os.makedirs(
            output_dir,
            exist_ok=True
        )

    # --------------------------------------------------------
    # CSV columns
    # --------------------------------------------------------

    columns = [

        "run_id",

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
    ]

    # --------------------------------------------------------
    # Open PCAP as streaming reader
    # --------------------------------------------------------

    packet_count = 0

    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    arp_count = 0

    syn_count = 0

    # PcapReader reads packets one by one.
    # This is better for large PCAP files.

    try:

        with PcapReader(pcap_file) as packets:

            with open(
                output_csv,
                "w",
                newline=""
            ) as csv_file:

                writer = csv.DictWriter(
                    csv_file,
                    fieldnames=columns
                )

                writer.writeheader()

                # --------------------------------------------
                # Process packets one by one
                # --------------------------------------------

                for pkt in packets:

                    try:

                        features = packet_to_features(
                            pkt,
                            run_id
                        )

                        writer.writerow(features)

                        packet_count += 1

                        # ------------------------------------
                        # Statistics
                        # ------------------------------------

                        if features["tcp"] == 1:

                            tcp_count += 1

                        if features["udp"] == 1:

                            udp_count += 1

                        if features["icmp"] == 1:

                            icmp_count += 1

                        if features["arp"] == 1:

                            arp_count += 1

                        if features["syn_flag_number"] == 1:

                            syn_count += 1

                    except Exception as packet_error:

                        print(
                            "WARNING: Failed to parse packet:",
                            packet_error
                        )

                        continue

    except Exception as error:

        print()
        print("ERROR while reading PCAP:")
        print(error)

        sys.exit(1)

    # ========================================================
    # Final statistics
    # ========================================================

    print()
    print("==============================================")
    print("              CONVERSION COMPLETE")
    print("==============================================")

    print("Total packets :", packet_count)
    print("TCP packets   :", tcp_count)
    print("UDP packets   :", udp_count)
    print("ICMP packets  :", icmp_count)
    print("ARP packets   :", arp_count)
    print("SYN packets   :", syn_count)

    print("----------------------------------------------")

    print("Output CSV    :", output_csv)

    print("==============================================")
    print()


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    # --------------------------------------------------------
    # Usage:
    #
    # python3 pcap_to_csv.py input.pcap output.csv
    #
    # OR
    #
    # python3 pcap_to_csv.py input.pcap output.csv run_id
    # --------------------------------------------------------

    if len(sys.argv) not in (3, 4):

        print()
        print(
            "Usage:"
        )

        print(
            "python3 pcap_to_csv.py "
            "<input.pcap> "
            "<output.csv> "
            "[run_id]"
        )

        print()

        sys.exit(1)

    pcap_file = sys.argv[1]

    output_csv = sys.argv[2]

    run_id = ""

    if len(sys.argv) == 4:

        run_id = sys.argv[3]

    convert_pcap(
        pcap_file,
        output_csv,
        run_id
    )
