"""
nan_diagnosis.py
----------------
Read-only diagnosis of NaN values in the Packet ML dataset.

Answers:
  - Which columns have NaN?
  - How many NaN per column?
  - Which labels are affected?
  - Is the NaN expected (protocol-dependent) or suspicious?
"""

import os
import sys
from pathlib import Path

import pandas as pd
import numpy as np


# ============================================================
# PORTABLE PATH
# ============================================================

BASE_DIR = Path(
    os.environ.get("IOT_BASE_DIR", Path.home() / "IoT-devices")
)
FILE = BASE_DIR / "labeled_packet_features_ML.csv"


# ============================================================
# HEADER
# ============================================================

print()
print("=" * 70)
print("        NaN DIAGNOSIS — PACKET ML DATASET")
print("=" * 70)
print(f"File: {FILE}")
print()

if not FILE.exists():
    print(f"[ERROR] File not found: {FILE}")
    sys.exit(1)

df = pd.read_csv(FILE)

print(f"Rows    : {len(df):,}")
print(f"Columns : {len(df.columns)}")
print()


# ============================================================
# 1. NaN PER COLUMN
# ============================================================

print("-" * 70)
print("1. NaN PER COLUMN")
print("-" * 70)

nan_per_col = df.isna().sum()
nan_per_col = nan_per_col[nan_per_col > 0].sort_values(ascending=False)

if len(nan_per_col) == 0:
    print("[PASS] No NaN in any column.")
else:
    print(f"{'Column':<25}{'NaN Count':>12}{'%':>10}")
    print("-" * 47)
    for col, cnt in nan_per_col.items():
        pct = cnt / len(df) * 100
        print(f"{col:<25}{cnt:>12,}{pct:>9.2f}%")

print()


# ============================================================
# 2. NaN PER LABEL
# ============================================================

print("-" * 70)
print("2. NaN PER LABEL")
print("-" * 70)

if "label" in df.columns:
    # rows with at least one NaN
    rows_with_nan = df.isna().any(axis=1)

    print(f"{'Label':<20}{'Total Rows':>12}{'Rows w/ NaN':>14}{'%':>10}")
    print("-" * 56)

    for label in sorted(df["label"].dropna().unique()):
        mask = df["label"] == label
        total = mask.sum()
        with_nan = (mask & rows_with_nan).sum()
        pct = with_nan / total * 100 if total > 0 else 0
        print(f"{label:<20}{total:>12,}{with_nan:>14,}{pct:>9.2f}%")

print()


# ============================================================
# 3. NaN PATTERNS — CO-OCCURRENCE
# ============================================================

print("-" * 70)
print("3. NaN CO-OCCURRENCE (top patterns)")
print("-" * 70)

if len(nan_per_col) > 0:
    nan_cols = list(nan_per_col.index)
    pattern = df[nan_cols].isna().astype(int).astype(str).agg("".join, axis=1)

    top_patterns = pattern.value_counts().head(10)

    print(f"{'Pattern':<30}{'Rows':>12}{'%':>10}")
    print("-" * 52)

    for pat, cnt in top_patterns.items():
        pct = cnt / len(df) * 100
        # show which columns are NaN
        cols_nan = [c for c, b in zip(nan_cols, pat) if b == "1"]
        short = ",".join(cols_nan[:3])
        if len(cols_nan) > 3:
            short += f" (+{len(cols_nan)-3})"
        print(f"{short:<30}{cnt:>12,}{pct:>9.2f}%")

print()


# ============================================================
# 4. SUSPICIOUS NaN — IN NON-NULLABLE COLUMNS
# ============================================================

print("-" * 70)
print("4. SUSPICIOUS NaN (columns that should never be NaN)")
print("-" * 70)

# Columns that logically should NEVER be NaN
critical_cols = [
    "src_port",
    "dst_port",
    "ip_proto",
    "ttl",
    "packet_length",
    "payload_length",
    "syn_flag_number",
    "ack_flag_number",
    "fin_flag_number",
    "rst_flag_number",
    "psh_flag_number",
]

suspicious = {}
for col in critical_cols:
    if col in df.columns:
        cnt = int(df[col].isna().sum())
        if cnt > 0:
            suspicious[col] = cnt

if suspicious:
    print("[WARNING] These columns have NaN — needs review:")
    for col, cnt in suspicious.items():
        print(f"  - {col:<25} {cnt:,} NaN")
else:
    print("[PASS] No NaN in critical columns.")

print()


# ============================================================
# 5. SUMMARY
# ============================================================

print("=" * 70)
print("        SUMMARY")
print("=" * 70)

total_nan = int(df.isna().sum().sum())
cols_with_nan = len(nan_per_col)

print(f"Total NaN cells      : {total_nan:,}")
print(f"Columns with NaN     : {cols_with_nan} / {len(df.columns)}")
print()

if suspicious:
    print("VERDICT: [INVESTIGATE]")
    print()
    print("NaN exists in critical columns.")
    print("Review the columns above before freezing.")
else:
    print("VERDICT: [LIKELY OK]")
    print()
    print("NaN only in protocol-dependent columns.")
    print("This is expected (e.g., UDP has no SYN flag).")

print()
print("=" * 70)
