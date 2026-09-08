#!/usr/bin/env python3

import csv
from collections import Counter, defaultdict

PACKET_FILE = "labeled_packet_features.csv"
FLOW_FILE = "labeled_traffic_features.csv"
METADATA_FILE = "datasets/metadata/attack_metadata.csv"

def load_csv(file_path):
    data = []
    with open(file_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            data.append(row)
    return data

def main():
    print("\n" + "="*60)
    print("        DATASET STATISTICS")
    print("="*60)

    packets = load_csv(PACKET_FILE)
    flows = load_csv(FLOW_FILE)
    metadata = load_csv(METADATA_FILE)

    # 1. Packets per label (using 'label' column)
    print("\n1. Packets per label:")
    packet_counts = Counter(row.get("label", "unknown") for row in packets)
    for label, count in packet_counts.most_common():
        print(f"   {label}: {count}")

    # 2. Flows per label
    print("\n2. Flows per label:")
    flow_counts = Counter(row.get("label", "unknown") for row in flows)
    for label, count in flow_counts.most_common():
        print(f"   {label}: {count}")

    # 3. Packets/Flows per attack run
    print("\n3. Packets/Flows per attack run:")
    run_packets = defaultdict(int)
    run_flows = defaultdict(int)
    for p in packets:
        run_id = p.get("run_id", "")
        if run_id and run_id not in ("unmatched", "ambiguous"):
            run_packets[run_id] += 1
    for f in flows:
        run_id = f.get("run_id", "")
        if run_id and run_id not in ("unmatched", "ambiguous"):
            run_flows[run_id] += 1
    for run_id in list(run_packets.keys())[:20]:
        print(f"   {run_id}: Packets={run_packets[run_id]}, Flows={run_flows.get(run_id, 0)}")

    # 4. Normal traffic diversity (Top protocols)
    print("\n4. Normal traffic diversity (Top protocols):")
    normal_packets = [p for p in packets if p.get("label") == "normal"]
    proto_counts = Counter()
    for p in normal_packets[:10000]:
        proto = p.get("ip_proto", "unknown")
        proto_counts[proto] += 1
    for proto, count in proto_counts.most_common(10):
        print(f"   IP_PROTO={proto}: {count}")

    # 5. Missing IP in attack vs normal
    print("\n5. Missing IP in attacks vs normal:")
    attack_missing = 0
    normal_missing = 0
    for p in packets:
        src = p.get("src_ip", "")
        dst = p.get("dst_ip", "")
        missing = (src == "" or dst == "")
        if p.get("label") != "normal":
            if missing:
                attack_missing += 1
        else:
            if missing:
                normal_missing += 1
    print(f"   Attack missing IP: {attack_missing}")
    print(f"   Normal missing IP: {normal_missing}")

    print("\n" + "="*60)
    print("        STATISTICS COMPLETE")
    print("="*60)

if __name__ == "__main__":
    main()
