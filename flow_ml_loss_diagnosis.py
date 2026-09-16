import pandas as pd
from pathlib import Path

BASE_DIR = Path.home() / "IoT-devices"

MASTER_FILE = BASE_DIR / "labeled_traffic_features.csv"
ML_FILE = BASE_DIR / "labeled_traffic_features_ML.csv"

LOST_RUNS = [
    "run_20260902_180607_729072",
    "run_20260902_180622_364696",
    "run_20260902_180631_569404",
    "run_20260902_184130_251133",
    "run_20260910_141007_210777",
]

print("=" * 78)
print("             FLOW MASTER -> ML LOSS DIAGNOSIS")
print("=" * 78)

print("\nLoading datasets...")

master = pd.read_csv(MASTER_FILE, low_memory=False)
ml = pd.read_csv(ML_FILE, low_memory=False)

master["run_id"] = master["run_id"].fillna("").astype(str).str.strip()
ml["run_id"] = ml["run_id"].fillna("").astype(str).str.strip()

master["label"] = master["label"].fillna("").astype(str).str.strip()
ml["label"] = ml["label"].fillna("").astype(str).str.strip()

print(f"Master rows : {len(master):,}")
print(f"ML rows     : {len(ml):,}")

# ============================================================
# 1. Exact run comparison
# ============================================================

print("\n" + "-" * 78)
print("1. LOST RUNS")
print("-" * 78)

for run_id in LOST_RUNS:

    m = master[master["run_id"] == run_id]
    x = ml[ml["run_id"] == run_id]

    print(f"\nRUN: {run_id}")

    print(f"  Master rows : {len(m):,}")
    print(f"  ML rows     : {len(x):,}")

    if len(m) > 0:
        print(
            f"  Master label: "
            f"{m['label'].value_counts().to_dict()}"
        )

    if len(x) > 0:
        print(
            f"  ML label    : "
            f"{x['label'].value_counts().to_dict()}"
        )

# ============================================================
# 2. Check missing values
# ============================================================

print("\n" + "-" * 78)
print("2. MISSING VALUES IN LOST RUNS")
print("-" * 78)

for run_id in LOST_RUNS:

    m = master[master["run_id"] == run_id]

    print(f"\nRUN: {run_id}")

    if len(m) == 0:
        print("  NOT FOUND IN MASTER")
        continue

    missing = m.isna().sum()
    missing = missing[missing > 0]

    if len(missing) == 0:
        print("  No NaN values.")
    else:
        print(missing.to_string())

# ============================================================
# 3. Empty strings
# ============================================================

print("\n" + "-" * 78)
print("3. EMPTY STRING CHECK")
print("-" * 78)

for run_id in LOST_RUNS:

    m = master[master["run_id"] == run_id]

    print(f"\nRUN: {run_id}")

    found = False

    for col in m.columns:

        if m[col].dtype == "object":

            empty_count = (
                m[col]
                .fillna("")
                .astype(str)
                .str.strip()
                .eq("")
                .sum()
            )

            if empty_count > 0:

                print(
                    f"  {col:25s}: "
                    f"{empty_count:,} empty"
                )

                found = True

    if not found:
        print("  No empty strings.")

# ============================================================
# 4. Infinite values
# ============================================================

print("\n" + "-" * 78)
print("4. INFINITE VALUES")
print("-" * 78)

for run_id in LOST_RUNS:

    m = master[master["run_id"] == run_id]

    print(f"\nRUN: {run_id}")

    numeric = m.select_dtypes(include="number")

    if len(numeric.columns) == 0:
        print("  No numeric columns.")
        continue

    inf_count = numeric.isin([float("inf"), float("-inf")]).sum()
    inf_count = inf_count[inf_count > 0]

    if len(inf_count) == 0:
        print("  No Inf values.")
    else:
        print(inf_count.to_string())

# ============================================================
# 5. Compare schema
# ============================================================

print("\n" + "-" * 78)
print("5. COLUMN COMPARISON")
print("-" * 78)

master_cols = list(master.columns)
ml_cols = list(ml.columns)

print("\nMaster columns:")
print(master_cols)

print("\nML columns:")
print(ml_cols)

print("\nColumns in Master but NOT ML:")
print([c for c in master_cols if c not in ml_cols])

print("\nColumns in ML but NOT Master:")
print([c for c in ml_cols if c not in master_cols])

# ============================================================
# 6. Row-level difference
# ============================================================

print("\n" + "-" * 78)
print("6. ROW COUNTS BY LOST RUN")
print("-" * 78)

for run_id in LOST_RUNS:

    master_count = (
        master["run_id"] == run_id
    ).sum()

    ml_count = (
        ml["run_id"] == run_id
    ).sum()

    print(
        f"{run_id} | "
        f"Master={master_count:,} | "
        f"ML={ml_count:,} | "
        f"Lost={master_count - ml_count:,}"
    )

# ============================================================
# 7. Special check for SYN flood run
# ============================================================

special_run = "run_20260910_141007_210777"

print("\n" + "-" * 78)
print("7. SPECIAL SYN_FLOOD RUN INSPECTION")
print("-" * 78)

m = master[master["run_id"] == special_run]

if len(m) > 0:

    print(f"Rows: {len(m):,}")

    print("\nLabels:")
    print(m["label"].value_counts())

    print("\nProtocol distribution:")
    if "ip_proto" in m.columns:
        print(m["ip_proto"].value_counts(dropna=False))

    print("\nSource ports:")
    if "src_port" in m.columns:
        print(
            m["src_port"]
            .value_counts(dropna=False)
            .head(15)
        )

    print("\nDestination ports:")
    if "dst_port" in m.columns:
        print(
            m["dst_port"]
            .value_counts(dropna=False)
            .head(15)
        )

# ============================================================
# Final
# ============================================================

print("\n" + "=" * 78)
print("DIAGNOSIS COMPLETE")
print("=" * 78)

print("\nREAD-ONLY:")
print("No dataset was modified.")
print("No rows were deleted.")
print("No labels were changed.")

print("=" * 78)
