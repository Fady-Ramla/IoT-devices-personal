import pandas as pd
import os

# ============================================================
# TRAINING / SERVING AUDIT
# ============================================================

BASE_DIR = os.path.expanduser("~/IoT-devices")

PACKET_FILE = os.path.join(
    BASE_DIR,
    "feature_engineering",
    "packet_features_engineered.csv"
)

FLOW_FILE = os.path.join(
    BASE_DIR,
    "ML_FINAL",
    "labeled_traffic_features_ML.csv"
)

print("=" * 75)
print("                 TRAINING / SERVING AUDIT")
print("=" * 75)

# ============================================================
# ONLINE FEATURES AVAILABLE IN CURRENT TRAFFIC MONITOR
# ============================================================

ONLINE_PACKET = {
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
}

ONLINE_FLOW = {
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
}

# ============================================================
# LOAD DATASETS
# ============================================================

packet_df = pd.read_csv(PACKET_FILE)
flow_df = pd.read_csv(FLOW_FILE)

packet_features = [
    c for c in packet_df.columns
    if c not in {"timestamp", "run_id", "label"}
]

flow_features = [
    c for c in flow_df.columns
    if c not in {"timestamp", "run_id", "label"}
]

# ============================================================
# PACKET AUDIT
# ============================================================

print("\n" + "=" * 75)
print("PACKET DATASET")
print("=" * 75)

for feature in packet_features:

    if feature == "syn_ack_ratio":
        status = "SAFE - ENGINEERED FROM ONLINE FEATURES"

    elif feature in ONLINE_PACKET:
        status = "SAFE - AVAILABLE ONLINE"

    elif feature in {
        "src_mac",
        "dst_mac",
        "src_ip",
        "dst_ip",
        "switch"
    }:
        status = "REVIEW - OPERATIONAL CONTEXT / NOT ML INPUT"

    else:
        status = "NOT AVAILABLE ONLINE"

    print(f"{feature:25s} -> {status}")

# ============================================================
# FLOW AUDIT
# ============================================================

print("\n" + "=" * 75)
print("FLOW DATASET")
print("=" * 75)

for feature in flow_features:

    if feature in ONLINE_FLOW:
        status = "SAFE - AVAILABLE ONLINE"

    elif feature in {
        "src_ip",
        "dst_ip",
        "switch"
    }:
        status = "REVIEW - OPERATIONAL CONTEXT / NOT ML INPUT"

    else:
        status = "NOT AVAILABLE ONLINE"

    print(f"{feature:25s} -> {status}")

# ============================================================
# SUMMARY
# ============================================================

packet_safe = [
    f for f in packet_features
    if f in ONLINE_PACKET or f == "syn_ack_ratio"
]

flow_safe = [
    f for f in flow_features
    if f in ONLINE_FLOW
]

print("\n" + "=" * 75)
print("SUMMARY")
print("=" * 75)

print("\nPACKET SAFE FEATURES:")
for f in packet_safe:
    print(f"  - {f}")

print("\nFLOW SAFE FEATURES:")
for f in flow_safe:
    print(f"  - {f}")

print("\n" + "=" * 75)
print("IMPORTANT")
print("=" * 75)

print("""
1. ML_FINAL was NOT modified.
2. syn_ack_ratio is derived only from existing Packet features.
3. syn_pkt_ratio is NOT being added to Flow.
4. IP/MAC/switch identifiers are kept as operational context,
   but are not automatically selected as ML input.
5. Final feature selection will be decided after this audit.
""")

print("=" * 75)
