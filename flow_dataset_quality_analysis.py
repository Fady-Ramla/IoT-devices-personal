import pandas as pd
import os

FILE = "labeled_traffic_features.csv"

print("=" * 60)
print("        FLOW DATASET QUALITY ANALYSIS")
print("=" * 60)

if not os.path.exists(FILE):
    print(f"\nERROR: File not found: {FILE}")
    exit(1)

df = pd.read_csv(FILE)

print(f"\nFile: {FILE}")
print(f"Loaded: {len(df)} flows")

# ============================================================
# 1. LABEL DISTRIBUTION
# ============================================================

print("\n" + "=" * 60)
print("1. LABEL DISTRIBUTION")
print("=" * 60)

labels = df["label"].fillna("").astype(str).str.strip()

print(labels.value_counts().to_string())
print(f"\nTotal: {len(df)}")

# ============================================================
# 2. UNKNOWN / EMPTY LABELS
# ============================================================

print("\n" + "=" * 60)
print("2. LABEL VALIDITY")
print("=" * 60)

valid_labels = {
    "normal",
    "syn_flood",
    "port_scan",
    "malicious_post"
}

unknown_mask = ~labels.isin(valid_labels)

print(f"Unknown labels : {unknown_mask.sum()}")
print(f"Empty labels   : {(labels == '').sum()}")

if unknown_mask.any():
    print("\nUnknown label values:")
    print(labels[unknown_mask].value_counts())

# ============================================================
# 3. COLUMN CHECK
# ============================================================

print("\n" + "=" * 60)
print("3. COLUMN CHECK")
print("=" * 60)

print(f"Columns: {len(df.columns)}")

print("\nColumns:")
for col in df.columns:
    print(f"  - {col}")

# ============================================================
# 4. MISSING VALUES
# ============================================================

print("\n" + "=" * 60)
print("4. MISSING VALUES")
print("=" * 60)

missing = df.isnull().sum()

missing = missing[missing > 0]

if len(missing) == 0:
    print("No missing values.")
else:
    print(missing.to_string())

# ============================================================
# 5. TOTAL_PKTS CHECK
# ============================================================

print("\n" + "=" * 60)
print("5. TOTAL_PKTS CHECK")
print("=" * 60)

if "total_pkts" in df.columns:

    total_pkts = pd.to_numeric(
        df["total_pkts"],
        errors="coerce"
    )

    zero_pkts = (total_pkts == 0).sum()
    negative_pkts = (total_pkts < 0).sum()
    invalid_pkts = total_pkts.isna().sum()

    print(f"total_pkts = 0      : {zero_pkts}")
    print(f"total_pkts < 0      : {negative_pkts}")
    print(f"Invalid total_pkts  : {invalid_pkts}")

    print("\nStatistics:")
    print(total_pkts.describe())

else:
    print("WARNING: total_pkts column not found.")

# ============================================================
# 6. ATTACK BREAKDOWN
# ============================================================

print("\n" + "=" * 60)
print("6. ATTACK BREAKDOWN")
print("=" * 60)

for attack in ["syn_flood", "port_scan", "malicious_post"]:

    count = (labels == attack).sum()

    print(f"{attack:<20}: {count}")

# ============================================================
# 7. FLOW DURATION CHECK
# ============================================================

print("\n" + "=" * 60)
print("7. FLOW DURATION CHECK")
print("=" * 60)

if "flow_duration" in df.columns:

    duration = pd.to_numeric(
        df["flow_duration"],
        errors="coerce"
    )

    print(f"Negative durations : {(duration < 0).sum()}")
    print(f"Zero durations     : {(duration == 0).sum()}")
    print(f"Invalid durations  : {duration.isna().sum()}")

    print("\nStatistics:")
    print(duration.describe())

# ============================================================
# 8. PACKET / BYTE RATE CHECK
# ============================================================

print("\n" + "=" * 60)
print("8. RATE CHECK")
print("=" * 60)

for col in ["packet_rate", "byte_rate"]:

    if col in df.columns:

        values = pd.to_numeric(
            df[col],
            errors="coerce"
        )

        print(f"\n{col}")
        print(f"  Negative : {(values < 0).sum()}")
        print(f"  Invalid  : {values.isna().sum()}")
        print(f"  Zero     : {(values == 0).sum()}")

# ============================================================
# 9. DUPLICATE ROWS
# ============================================================

print("\n" + "=" * 60)
print("9. DUPLICATE ROWS")
print("=" * 60)

duplicates = df.duplicated().sum()

print(f"Exact duplicate rows: {duplicates}")

# ============================================================
# FINAL SUMMARY
# ============================================================

print("\n" + "=" * 60)
print("        FLOW DATASET ANALYSIS COMPLETE")
print("=" * 60)
