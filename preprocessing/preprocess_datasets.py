import pandas as pd
import os

BASE_DIR = os.path.expanduser("~/IoT-devices")

PACKET_INPUT = os.path.join(
    BASE_DIR,
    "feature_engineering",
    "packet_features_engineered.csv"
)

FLOW_INPUT = os.path.join(
    BASE_DIR,
    "ML_FINAL",
    "labeled_traffic_features_ML.csv"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "preprocessing"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)

# ============================================================
# FINAL FEATURES
# ============================================================

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
    "syn_ack_ratio",
]

FLOW_FEATURES = [
    "src_port",
    "dst_port",
    "ip_proto",
    "flow_duration",
    "total_pkts",
    "packet_rate",
    "avg_packet_size",
]

# ============================================================
# LOAD
# ============================================================

print("=" * 70)
print("                    PREPROCESSING")
print("=" * 70)

print("\nLoading Packet dataset...")
packet = pd.read_csv(PACKET_INPUT, low_memory=False)

print("Loading Flow dataset...")
flow = pd.read_csv(FLOW_INPUT, low_memory=False)

# ============================================================
# BUILD PACKET ML DATASET
# ============================================================

packet_cols = PACKET_FEATURES + ["label", "run_id"]

packet_ml = packet[packet_cols].copy()

# Numeric conversion
for col in PACKET_FEATURES:
    packet_ml[col] = pd.to_numeric(
        packet_ml[col],
        errors="coerce"
    )

# Remove rows with invalid ML feature values
before = len(packet_ml)

packet_ml = packet_ml.dropna(
    subset=PACKET_FEATURES
).copy()

after = len(packet_ml)

print("\nPacket:")
print(f"  Original rows : {before:,}")
print(f"  Final rows    : {after:,}")
print(f"  Removed rows  : {before - after:,}")

# ============================================================
# BUILD FLOW ML DATASET
# ============================================================

flow_cols = FLOW_FEATURES + ["label", "run_id"]

flow_ml = flow[flow_cols].copy()

for col in FLOW_FEATURES:
    flow_ml[col] = pd.to_numeric(
        flow_ml[col],
        errors="coerce"
    )

before = len(flow_ml)

flow_ml = flow_ml.dropna(
    subset=FLOW_FEATURES
).copy()

after = len(flow_ml)

print("\nFlow:")
print(f"  Original rows : {before:,}")
print(f"  Final rows    : {after:,}")
print(f"  Removed rows  : {before - after:,}")

# ============================================================
# CHECK INFINITE VALUES
# ============================================================

print("\nChecking infinite values...")

packet_inf = packet_ml[PACKET_FEATURES].isin(
    [float("inf"), float("-inf")]
).sum().sum()

flow_inf = flow_ml[FLOW_FEATURES].isin(
    [float("inf"), float("-inf")]
).sum().sum()

print(f"  Packet infinite values: {packet_inf}")
print(f"  Flow infinite values  : {flow_inf}")

# ============================================================
# LABEL DISTRIBUTION
# ============================================================

print("\nPacket labels:")
print(packet_ml["label"].value_counts())

print("\nFlow labels:")
print(flow_ml["label"].value_counts())

# ============================================================
# SAVE
# ============================================================

packet_output = os.path.join(
    OUTPUT_DIR,
    "packet_preprocessed.csv"
)

flow_output = os.path.join(
    OUTPUT_DIR,
    "flow_preprocessed.csv"
)

packet_ml.to_csv(
    packet_output,
    index=False
)

flow_ml.to_csv(
    flow_output,
    index=False
)

# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("                    SAVED")
print("=" * 70)

print(f"\nPacket:")
print(f"  {packet_output}")

print(f"\nFlow:")
print(f"  {flow_output}")

print("\nML_FINAL was NOT modified.")
print("=" * 70)
