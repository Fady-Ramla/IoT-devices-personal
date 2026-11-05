import os
import pandas as pd
import numpy as np

BASE_DIR = os.path.expanduser("~/IoT-devices")

PACKET_SOURCE = os.path.join(
    BASE_DIR,
    "feature_engineering",
    "packet_features_engineered.csv"
)

FLOW_SOURCE = os.path.join(
    BASE_DIR,
    "ML_FINAL",
    "labeled_traffic_features_ML.csv"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "AI_DATASET"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ============================================================
# FINAL FEATURES FOR AI
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

COMMON_META = [
    "run_id",
    "label",
]


def check_dataset(df, features, name):

    print("\n" + "=" * 60)
    print(f"{name} FINAL CHECK")
    print("=" * 60)

    required = features + COMMON_META

    missing = [
        col for col in required
        if col not in df.columns
    ]

    if missing:
        raise ValueError(
            f"{name}: Missing columns: {missing}"
        )

    # Numeric conversion check
    for col in features:
        df[col] = pd.to_numeric(
            df[col],
            errors="coerce"
        )

    # NaN
    nan_count = df[features].isna().sum().sum()

    # Inf
    inf_count = np.isinf(
        df[features].to_numpy()
    ).sum()

    # Labels
    labels = df["label"].value_counts()

    # Attack rows without run_id
    attack_missing_run = df.loc[
        df["label"] != "normal",
        "run_id"
    ].isna().sum()

    print(f"Rows: {len(df):,}")
    print(f"Features: {len(features)}")
    print(f"NaN in features: {nan_count}")
    print(f"Inf in features: {inf_count}")
    print(
        f"Attack rows without run_id: "
        f"{attack_missing_run}"
    )

    print("\nLabels:")
    print(labels.to_string())

    if nan_count != 0:
        raise ValueError(
            f"{name}: NaN found in ML features."
        )

    if inf_count != 0:
        raise ValueError(
            f"{name}: Inf found in ML features."
        )

    if attack_missing_run != 0:
        raise ValueError(
            f"{name}: Attack rows missing run_id."
        )

    print("\nPASS")


def main():

    print("=" * 60)
    print("        PREPARING AI DATASET")
    print("=" * 60)

    # ========================================================
    # PACKET
    # ========================================================

    print("\nLoading Packet dataset...")

    packet = pd.read_csv(
        PACKET_SOURCE,
        low_memory=False
    )

    check_dataset(
        packet,
        PACKET_FEATURES,
        "PACKET"
    )

    packet_final = packet[
        PACKET_FEATURES + COMMON_META
    ].copy()

    packet_output = os.path.join(
        OUTPUT_DIR,
        "packet_final.csv"
    )

    packet_final.to_csv(
        packet_output,
        index=False
    )

    # ========================================================
    # FLOW
    # ========================================================

    print("\nLoading Flow dataset...")

    flow = pd.read_csv(
        FLOW_SOURCE,
        low_memory=False
    )

    check_dataset(
        flow,
        FLOW_FEATURES,
        "FLOW"
    )

    flow_final = flow[
        FLOW_FEATURES + COMMON_META
    ].copy()

    flow_output = os.path.join(
        OUTPUT_DIR,
        "flow_final.csv"
    )

    flow_final.to_csv(
        flow_output,
        index=False
    )

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    print("\n")
    print("=" * 60)
    print("        AI DATASET READY")
    print("=" * 60)

    print(
        f"\nPacket file:\n{packet_output}"
    )

    print(
        f"\nFlow file:\n{flow_output}"
    )

    print("\nPacket shape:")
    print(packet_final.shape)

    print("\nFlow shape:")
    print(flow_final.shape)

    print("\nPacket columns:")
    print(packet_final.columns.tolist())

    print("\nFlow columns:")
    print(flow_final.columns.tolist())

    print("\nIMPORTANT:")
    print("ML_FINAL was NOT modified.")
    print("These are copies prepared for the AI team.")


if __name__ == "__main__":
    main()
