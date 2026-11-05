"""
packet_flow_consistency_check.py
--------------------------------
Read-only consistency check between Packet and Flow ML datasets.

Compares run_ids and labels across:
  - labeled_packet_features_ML.csv
  - labeled_traffic_features_ML.csv

Produces a report.
DOES NOT modify any dataset.
"""

import os
import sys
from pathlib import Path

import pandas as pd


# ============================================================
# PORTABLE PATHS
# ============================================================

BASE_DIR = Path(
    os.environ.get("IOT_BASE_DIR", Path.home() / "IoT-devices")
)

PACKET_FILE = BASE_DIR / "labeled_packet_features_ML.csv"
FLOW_FILE   = BASE_DIR / "labeled_traffic_features_ML.csv"


# ============================================================
# HEADER
# ============================================================

print()
print("=" * 70)
print("     PACKET <-> FLOW CONSISTENCY CHECK")
print("=" * 70)
print(f"BASE_DIR    : {BASE_DIR}")
print(f"Packet file : {PACKET_FILE}")
print(f"Flow file   : {FLOW_FILE}")
print()


# ============================================================
# FILE CHECK
# ============================================================

if not PACKET_FILE.exists():
    print(f"[ERROR] Packet file not found: {PACKET_FILE}")
    sys.exit(1)

if not FLOW_FILE.exists():
    print(f"[ERROR] Flow file not found: {FLOW_FILE}")
    sys.exit(1)


# ============================================================
# LOAD
# ============================================================

print("Loading datasets...")
packet_df = pd.read_csv(PACKET_FILE, low_memory=False)
flow_df   = pd.read_csv(FLOW_FILE,   low_memory=False)

print(f"  Packet rows: {len(packet_df):,}")
print(f"  Flow rows  : {len(flow_df):,}")
print()


# ============================================================
# CLEAN
# ============================================================

def clean_run_ids(df):
    return (
        df["run_id"]
        .fillna("")
        .astype(str)
        .str.strip()
    )

packet_run = clean_run_ids(packet_df)
flow_run   = clean_run_ids(flow_df)

packet_lbl = packet_df["label"].fillna("").astype(str).str.strip()
flow_lbl   = flow_df["label"].fillna("").astype(str).str.strip()


# ============================================================
# RUN SETS (only non-empty)
# ============================================================

packet_runs = set(packet_run[packet_run != ""].unique())
flow_runs   = set(flow_run[flow_run != ""].unique())

common_runs       = packet_runs & flow_runs
packet_only_runs  = packet_runs - flow_runs
flow_only_runs    = flow_runs - packet_runs


# ============================================================
# 1. SUMMARY
# ============================================================

print("-" * 70)
print("1. RUN-LEVEL SUMMARY")
print("-" * 70)
print(f"Packet unique runs : {len(packet_runs):,}")
print(f"Flow unique runs   : {len(flow_runs):,}")
print(f"Common runs        : {len(common_runs):,}")
print(f"Packet-only runs   : {len(packet_only_runs):,}")
print(f"Flow-only runs     : {len(flow_only_runs):,}")
print()


# ============================================================
# 2. LABEL MAPPING PER RUN
# ============================================================

# For each run_id, get the set of labels in packet & flow
packet_run_labels = (
    pd.DataFrame({"run_id": packet_run, "label": packet_lbl})
    .query("run_id != ''")
    .groupby("run_id")["label"]
    .apply(lambda s: sorted(set(s)))
)

flow_run_labels = (
    pd.DataFrame({"run_id": flow_run, "label": flow_lbl})
    .query("run_id != ''")
    .groupby("run_id")["label"]
    .apply(lambda s: sorted(set(s)))
)


# ============================================================
# 3. LABEL MISMATCHES
# ============================================================

print("-" * 70)
print("2. LABEL MISMATCHES (on common runs)")
print("-" * 70)

mismatches = []

for run_id in sorted(common_runs):
    p_labels = packet_run_labels.get(run_id, [])
    f_labels = flow_run_labels.get(run_id, [])

    # A run should map to exactly 1 label in each dataset
    p_set = set(p_labels)
    f_set = set(f_labels)

    if p_set != f_set:
        mismatches.append(
            (run_id, p_labels, f_labels)
        )

print(f"Total mismatches: {len(mismatches):,}")

if mismatches:
    print()
    print(f"{'run_id':<40}{'packet':<20}{'flow':<20}")
    print("-" * 80)
    for run_id, p, f in mismatches[:50]:
        print(f"{str(run_id):<40}{str(p):<20}{str(f):<20}")
    if len(mismatches) > 50:
        print(f"... ({len(mismatches) - 50} more)")
else:
    print("[PASS] No label mismatches on common runs.")

print()


# ============================================================
# 4. PACKET-ONLY RUNS
# ============================================================

print("-" * 70)
print("3. PACKET-ONLY RUNS")
print("-" * 70)

if not packet_only_runs:
    print("[PASS] No packet-only runs.")
else:
    print(f"Total packet-only runs: {len(packet_only_runs)}")
    print()

    # Group by label
    packet_only_df = (
        pd.DataFrame({"run_id": packet_run, "label": packet_lbl})
        .query("run_id != ''")
        .drop_duplicates()
    )
    packet_only_df = packet_only_df[
        packet_only_df["run_id"].isin(packet_only_runs)
    ]

    for label in sorted(packet_only_df["label"].unique()):
        runs = sorted(
            packet_only_df[packet_only_df["label"] == label]["run_id"]
        )
        print(f"  {label:<20}{len(runs):>5} runs")
        for r in runs[:10]:
            print(f"     - {r}")
        if len(runs) > 10:
            print(f"     ... ({len(runs) - 10} more)")

print()


# ============================================================
# 5. FLOW-ONLY RUNS
# ============================================================

print("-" * 70)
print("4. FLOW-ONLY RUNS")
print("-" * 70)

if not flow_only_runs:
    print("[PASS] No flow-only runs.")
else:
    print(f"Total flow-only runs: {len(flow_only_runs)}")
    print()

    flow_only_df = (
        pd.DataFrame({"run_id": flow_run, "label": flow_lbl})
        .query("run_id != ''")
        .drop_duplicates()
    )
    flow_only_df = flow_only_df[
        flow_only_df["run_id"].isin(flow_only_runs)
    ]

    for label in sorted(flow_only_df["label"].unique()):
        runs = sorted(
            flow_only_df[flow_only_df["label"] == label]["run_id"]
        )
        print(f"  {label:<20}{len(runs):>5} runs")
        for r in runs[:10]:
            print(f"     - {r}")
        if len(runs) > 10:
            print(f"     ... ({len(runs) - 10} more)")

print()


# ============================================================
# 6. RUNS PER LABEL (each dataset)
# ============================================================

print("-" * 70)
print("5. RUNS PER LABEL (each dataset)")
print("-" * 70)

for label in ["normal", "syn_flood", "port_scan", "malicious_post"]:
    p_runs = sorted(
        pd.DataFrame({"run_id": packet_run, "label": packet_lbl})
        .query("run_id != '' and label == @label")["run_id"]
        .unique()
    )
    f_runs = sorted(
        pd.DataFrame({"run_id": flow_run, "label": flow_lbl})
        .query("run_id != '' and label == @label")["run_id"]
        .unique()
    )

    print(f"{label:<20} packet={len(p_runs):>4}  flow={len(f_runs):>4}")

print()


# ============================================================
# 7. FINAL VERDICT
# ============================================================

print("=" * 70)
print("     CONSISTENCY VERDICT")
print("=" * 70)

if mismatches:
    print()
    print("[INCONSISTENT]")
    print()
    print(f"Label mismatches on common runs: {len(mismatches)}")
    print()
    print("Do NOT freeze yet.")
    print("Review mismatches above.")
else:
    print()
    print("[CONSISTENT]")
    print()
    print("No label mismatches on common runs.")
    print()

    if packet_only_runs or flow_only_runs:
        print("NOTE:")
        if packet_only_runs:
            print(f"  - {len(packet_only_runs)} packet-only runs")
        if flow_only_runs:
            print(f"  - {len(flow_only_runs)} flow-only runs")
        print()
        print("This may be normal due to the different nature of")
        print("packet-level vs flow-level collection.")
        print("Document as a KNOWN OPEN ITEM if needed.")
    else:
        print("Perfect match on common runs.")

print()
print("=" * 70)
