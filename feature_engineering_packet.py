import pandas as pd
import os

# ============================================================
# PACKET FEATURE ENGINEERING
# Read-only from ML_FINAL
# ============================================================

BASE_DIR = os.path.expanduser("~/IoT-devices")

INPUT_FILE = os.path.join(
    BASE_DIR,
    "ML_FINAL",
    "labeled_packet_features_ML.csv"
)

OUTPUT_DIR = os.path.join(
    BASE_DIR,
    "feature_engineering"
)

OUTPUT_FILE = os.path.join(
    OUTPUT_DIR,
    "packet_features_engineered.csv"
)

os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 60)
print("        PACKET FEATURE ENGINEERING")
print("=" * 60)

# ------------------------------------------------------------
# 1. Load frozen dataset
# ------------------------------------------------------------

print("\nLoading frozen dataset...")

df = pd.read_csv(INPUT_FILE)

print(f"Loaded: {len(df):,} packets")
print(f"Columns: {len(df.columns)}")

# ------------------------------------------------------------
# 2. Check required columns
# ------------------------------------------------------------

required_columns = [
    "syn_flag_number",
    "ack_flag_number"
]

missing = [
    col for col in required_columns
    if col not in df.columns
]

if missing:
    print("\nERROR: Missing required columns:")
    for col in missing:
        print(f"  - {col}")
    raise SystemExit(1)

# ------------------------------------------------------------
# 3. Feature Engineering
# ------------------------------------------------------------

print("\nCreating feature:")

# SYN / (ACK + 1)
df["syn_ack_ratio"] = (
    df["syn_flag_number"] /
    (df["ack_flag_number"] + 1)
)

print("  syn_ack_ratio = syn_flag_number / (ack_flag_number + 1)")

# ------------------------------------------------------------
# 4. Basic validation
# ------------------------------------------------------------

print("\nValidation:")

print(f"  New column exists: {'syn_ack_ratio' in df.columns}")

print(
    f"  NaN values: "
    f"{df['syn_ack_ratio'].isna().sum():,}"
)

print(
    f"  Infinite values: "
    f"{df['syn_ack_ratio'].isin([float('inf'), float('-inf')]).sum():,}"
)

print(
    f"  Min: {df['syn_ack_ratio'].min():.4f}"
)

print(
    f"  Max: {df['syn_ack_ratio'].max():.4f}"
)

print(
    f"  Mean: {df['syn_ack_ratio'].mean():.4f}"
)

# ------------------------------------------------------------
# 5. Check labels
# ------------------------------------------------------------

print("\nFeature by label:")

summary = (
    df.groupby("label")["syn_ack_ratio"]
    .agg(["count", "mean", "min", "max"])
)

print(summary.to_string())

# ------------------------------------------------------------
# 6. Save engineered dataset
# ------------------------------------------------------------

df.to_csv(
    OUTPUT_FILE,
    index=False
)

print("\nSaved:")
print(f"  {OUTPUT_FILE}")

print("\nOriginal frozen dataset was NOT modified.")

print("\n" + "=" * 60)
print("                    DONE")
print("=" * 60)
