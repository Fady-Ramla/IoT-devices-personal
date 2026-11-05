import pandas as pd
import os

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

PACKET_FEATURES = [
    "src_port",
    "dst_port",
    "ip_proto",
    "ttl",
    "http",
    "syn_flag_number",
    "ack_flag_number",
    "fin_flag_number",
    "rst_flag_number",
    "psh_flag_number",
    "packet_length",
    "payload_length",
    "syn_ack_ratio",
]

FLOW_FEATURES = [
    "src_port",
    "dst_port",
    "ip_proto",
    "flow_duration",
    "total_pkts",
    "total_bytes",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
]

print("=" * 70)
print("              FINAL FEATURE CHECK")
print("=" * 70)

packet_df = pd.read_csv(PACKET_FILE)
flow_df = pd.read_csv(FLOW_FILE, low_memory=False)

# ------------------------------------------------------------
# Check existence
# ------------------------------------------------------------

print("\nPACKET FEATURES:")
for f in PACKET_FEATURES:
    print(f"  {'OK' if f in packet_df.columns else 'MISSING'}  {f}")

print("\nFLOW FEATURES:")
for f in FLOW_FEATURES:
    print(f"  {'OK' if f in flow_df.columns else 'MISSING'}  {f}")

# ------------------------------------------------------------
# Correlation check
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("PACKET REDUNDANCY CHECK | |r| >= 0.90")
print("=" * 70)

packet_corr = packet_df[PACKET_FEATURES].corr()

found = False

for i in range(len(PACKET_FEATURES)):
    for j in range(i + 1, len(PACKET_FEATURES)):
        a = PACKET_FEATURES[i]
        b = PACKET_FEATURES[j]

        r = packet_corr.loc[a, b]

        if abs(r) >= 0.90:
            print(f"{a:25s} <-> {b:25s} : {r:.4f}")
            found = True

if not found:
    print("No high redundancy pairs found.")

# ------------------------------------------------------------
# Flow redundancy
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("FLOW REDUNDANCY CHECK | |r| >= 0.90")
print("=" * 70)

flow_corr = flow_df[FLOW_FEATURES].corr()

found = False

for i in range(len(FLOW_FEATURES)):
    for j in range(i + 1, len(FLOW_FEATURES)):
        a = FLOW_FEATURES[i]
        b = FLOW_FEATURES[j]

        r = flow_corr.loc[a, b]

        if abs(r) >= 0.90:
            print(f"{a:25s} <-> {b:25s} : {r:.4f}")
            found = True

if not found:
    print("No high redundancy pairs found.")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)

