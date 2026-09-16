"""
flow_final_quality_check.py
---------------------------
Read-only quality check for the Flow ML dataset.

Works on any machine — no hard-coded username / hostname.
Uses IOT_BASE_DIR env var if set, otherwise ~/IoT-devices.

This script DOES NOT modify the dataset.
"""

import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd


# ============================================================
# PORTABLE PATHS
# ============================================================

BASE_DIR = Path(
    os.environ.get("IOT_BASE_DIR", Path.home() / "IoT-devices")
)

FILE = BASE_DIR / "labeled_traffic_features_ML.csv"


# ============================================================
# CONFIG
# ============================================================

EXPECTED_LABELS = {
    "normal",
    "syn_flood",
    "malicious_post",
    "port_scan",
}

ATTACK_LABELS = {
    "syn_flood",
    "malicious_post",
    "port_scan",
}

REQUIRED_COLUMNS = [
    "run_id",
    "label",
    "flow_duration",
    "total_pkts",
    "total_bytes",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
]

NUMERIC_COLUMNS = [
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
]


# ============================================================
# HEADER
# ============================================================

print()
print("=" * 70)
print("        FLOW FINAL QUALITY CHECK")
print("=" * 70)
print(f"BASE_DIR : {BASE_DIR}")
print(f"File     : {FILE}")
print()

if not FILE.exists():
    print(f"[ERROR] File not found: {FILE}")
    print()
    print("Hint: set IOT_BASE_DIR if your project is elsewhere:")
    print("  export IOT_BASE_DIR=/path/to/IoT-devices")
    sys.exit(1)

df = pd.read_csv(FILE)

print(f"Rows    : {len(df):,}")
print(f"Columns : {len(df.columns)}")
print()


# ============================================================
# problems tracker
# ============================================================

problems = []


# ============================================================
# 1. REQUIRED COLUMNS
# ============================================================

print("-" * 70)
print("1. REQUIRED COLUMNS")
print("-" * 70)

missing_columns = [c for c in REQUIRED_COLUMNS if c not in df.columns]

if missing_columns:
    print("[FAIL] Missing required columns:")
    for c in missing_columns:
        print(f"  - {c}")
    problems.append("Missing required columns")
else:
    print("[PASS] All required columns exist.")

print()


# ============================================================
# 2. LABEL CHECK
# ============================================================

print("-" * 70)
print("2. LABEL CHECK")
print("-" * 70)

unexpected_labels = set()

if "label" not in df.columns:
    print("[FAIL] label column is missing.")
    problems.append("Missing label column")
else:
    labels = df["label"].value_counts(dropna=False)

    print("Labels found:")
    for label, count in labels.items():
        pct = count / len(df) * 100 if len(df) else 0
        print(f"  {str(label):<22}{count:>10,} ({pct:6.2f}%)")

    actual_labels = set(df["label"].dropna().unique())
    unexpected_labels = actual_labels - EXPECTED_LABELS

    print()
    if unexpected_labels:
        print("[FAIL] Unexpected labels:")
        for label in sorted(unexpected_labels):
            print(f"  - {label}")
        problems.append("Unexpected labels")
    else:
        print("[PASS] Only the expected 4 labels exist.")

print()


# ============================================================
# 3. LABEL MISSING VALUES
# ============================================================

print("-" * 70)
print("3. LABEL MISSING VALUES")
print("-" * 70)

missing_labels = 0
empty_labels = 0

if "label" in df.columns:
    missing_labels = int(df["label"].isna().sum())
    empty_labels = int(
        df["label"].astype("string").str.strip().eq("").sum()
    )

    print(f"Missing label values: {missing_labels:,}")
    print(f"Empty label values:   {empty_labels:,}")

    if missing_labels == 0 and empty_labels == 0:
        print("[PASS] No missing/empty labels.")
    else:
        print("[FAIL] Missing/empty labels detected.")
        problems.append("Missing/empty labels")

print()


# ============================================================
# 4. RUN_ID INTEGRITY
# ============================================================

print("-" * 70)
print("4. RUN_ID INTEGRITY")
print("-" * 70)

missing_attack_run_id = 0

if "run_id" not in df.columns or "label" not in df.columns:
    print("[FAIL] run_id or label column is missing.")
    problems.append("Missing run_id or label")
else:
    attack_mask = df["label"].isin(ATTACK_LABELS)
    attack_rows = int(attack_mask.sum())

    attack_run_id = (
        df.loc[attack_mask, "run_id"].astype("string").str.strip()
    )

    missing_attack_run_id = int(
        attack_run_id.isna().sum()
        + attack_run_id.eq("").sum()
    )

    print(f"Attack rows: {attack_rows:,}")
    print(f"Attack rows with missing run_id: {missing_attack_run_id:,}")

    if missing_attack_run_id == 0:
        print("[PASS] Every attack flow has a valid run_id.")
    else:
        print("[FAIL] Some attack flows are missing run_id.")
        problems.append("Attack flows missing run_id")

    print()
    print("Run-level inventory:")

    for label in sorted(ATTACK_LABELS):
        subset = df[df["label"] == label]
        runs = (
            subset["run_id"].dropna().astype("string").str.strip()
        )
        runs = runs[runs != ""]
        print(f"  {label:<22}{runs.nunique():>5} unique runs")

print()


# ============================================================
# 5. NORMAL RUN_ID CHECK
# ============================================================

print("-" * 70)
print("5. NORMAL RUN_ID CHECK")
print("-" * 70)

if "run_id" in df.columns and "label" in df.columns:
    normal_mask = df["label"] == "normal"
    normal_rows = int(normal_mask.sum())

    normal_run_id = (
        df.loc[normal_mask, "run_id"].astype("string").str.strip()
    )

    empty_normal_run_id = int(
        normal_run_id.isna().sum()
        + normal_run_id.eq("").sum()
    )

    unique_normal_runs = normal_run_id[
        normal_run_id.notna() & (normal_run_id != "")
    ].nunique()

    print(f"Normal rows: {normal_rows:,}")
    print(f"Normal rows with empty run_id: {empty_normal_run_id:,}")
    print(f"Normal unique run_ids: {unique_normal_runs:,}")

    if empty_normal_run_id > 0:
        print("[INFO] Normal run_id is empty for some/all normal flows.")
        print("       NOT treated as a flow-quality failure here.")
        print("       Will be handled later in the grouped-split strategy.")
    else:
        print("[PASS] Normal flows have run_id information.")

print()


# ============================================================
# 6. DUPLICATE ROW CHECK
# ============================================================

print("-" * 70)
print("6. DUPLICATE ROW CHECK")
print("-" * 70)

duplicate_rows = int(df.duplicated().sum())
print(f"Exact duplicate rows: {duplicate_rows:,}")

if duplicate_rows == 0:
    print("[PASS] No exact duplicate rows.")
else:
    print("[INFO] Exact duplicate rows detected.")
    print("       Reported only; dataset will NOT be modified.")

print()


# ============================================================
# 7. NaN / INF CHECK
# ============================================================

print("-" * 70)
print("7. NaN / INF CHECK")
print("-" * 70)

total_nan = int(df.isna().sum().sum())

numeric_df = df.select_dtypes(include=[np.number])
total_inf = (
    int(np.isinf(numeric_df.to_numpy()).sum())
    if numeric_df.shape[1] > 0
    else 0
)

print(f"Total NaN / missing cells: {total_nan:,}")
print(f"Total numeric Inf cells:   {total_inf:,}")

if total_nan == 0 and total_inf == 0:
    print("[PASS] No NaN / Inf values detected.")
else:
    print("[INFO] NaN and/or Inf values detected.")

    if total_nan > 0:
        print()
        print("NaN per column:")
        nan_counts = df.isna().sum()
        nan_counts = nan_counts[nan_counts > 0]
        for col, count in nan_counts.items():
            print(f"  {col:<25}{count:>10,}")

print()


# ============================================================
# 8. NUMERIC COLUMN CHECK
# ============================================================

print("-" * 70)
print("8. NUMERIC COLUMN CHECK")
print("-" * 70)

missing_numeric = [c for c in NUMERIC_COLUMNS if c not in df.columns]
non_numeric = []

if missing_numeric:
    print("[FAIL] Missing expected numeric columns:")
    for col in missing_numeric:
        print(f"  - {col}")
    problems.append("Missing numeric columns")
else:
    for col in NUMERIC_COLUMNS:
        if not pd.api.types.is_numeric_dtype(df[col]):
            non_numeric.append(col)

    if non_numeric:
        print("[FAIL] Non-numeric columns detected:")
        for col in non_numeric:
            print(f"  - {col}")
        problems.append("Non-numeric columns")
    else:
        print("[PASS] All expected numeric columns exist and are numeric.")

print()


# ============================================================
# 9. ZERO-PACKET FLOW CHECK
# ============================================================

print("-" * 70)
print("9. ZERO-PACKET FLOW CHECK")
print("-" * 70)

if "total_pkts" in df.columns:
    total_pkts = pd.to_numeric(df["total_pkts"], errors="coerce")
    zero_pkts = int((total_pkts == 0).sum())
    neg_pkts = int((total_pkts < 0).sum())

    print(f"Flows with total_pkts == 0: {zero_pkts:,}")
    print(f"Flows with total_pkts <  0: {neg_pkts:,}")

    if zero_pkts == 0 and neg_pkts == 0:
        print("[PASS] No zero/negative total_pkts.")
    else:
        print("[FAIL] Zero/negative total_pkts found.")
        if zero_pkts > 0:
            problems.append("Zero-packet flows detected")
        if neg_pkts > 0:
            problems.append("Negative total_pkts")
else:
    print("[INFO] total_pkts column not found.")

print()


# ============================================================
# 10. BYTE / RATE SANITY CHECK
# ============================================================

print("-" * 70)
print("10. BYTE / RATE SANITY CHECK")
print("-" * 70)

for col in [
    "total_bytes",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
    "flow_duration",
]:
    if col not in df.columns:
        print(f"[INFO] {col} not present.")
        continue

    values = pd.to_numeric(df[col], errors="coerce")
    neg = int((values < 0).sum())
    nan = int(values.isna().sum())

    print(f"{col:20s} negative={neg:>8,}  NaN={nan:>8,}")

print()


# ============================================================
# 11. PORT / PROTOCOL VALIDATION
# ============================================================

print("-" * 70)
print("11. PORT / PROTOCOL VALIDATION")
print("-" * 70)

for col in ["src_port", "dst_port"]:
    if col not in df.columns:
        print(f"[INFO] {col} not present.")
        continue
    values = pd.to_numeric(df[col], errors="coerce")
    invalid = int(((values < 0) | (values > 65535)).sum())
    print(f"{col:20s} invalid={invalid:,}")

if "ip_proto" in df.columns:
    proto = pd.to_numeric(df["ip_proto"], errors="coerce")
    invalid = int(((proto < 0) | (proto > 255)).sum())
    print(f"{'ip_proto':20s} invalid={invalid:,}")

print()


# ============================================================
# 12. BASIC FLOW STATISTICS
# ============================================================

print("-" * 70)
print("12. BASIC FLOW STATISTICS")
print("-" * 70)

for col in [
    "flow_duration",
    "total_pkts",
    "total_bytes",
    "packet_rate",
    "byte_rate",
    "avg_packet_size",
]:
    if col not in df.columns:
        continue
    print(f"{col}:")
    print(f"  min  = {df[col].min()}")
    print(f"  max  = {df[col].max()}")
    print(f"  mean = {df[col].mean():.4f}")
    print()

print()


# ============================================================
# 13. FINAL VERDICT
# ============================================================

print("=" * 70)
print("        FINAL FLOW QUALITY VERDICT")
print("=" * 70)

if problems:
    print()
    print("[NOT READY]")
    print()
    print("Problems detected:")
    for problem in problems:
        print(f"  - {problem}")
    print()
    print("Do NOT freeze the dataset yet.")
else:
    print()
    print("[PASS]")
    print()
    print("No blocking flow-quality problems detected.")
    print()
    print("The file was NOT modified.")
    print("Next step can be Packet<->Flow Consistency Check.")

print()
print("=" * 70)
