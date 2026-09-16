"""
run_level_analysis.py
---------------------
Run-level analysis between Packet and Flow datasets.

READ-ONLY: does NOT modify any dataset.

Compares FOUR datasets:
  - labeled_packet_features_FINAL.csv   (Packet Master)
  - labeled_packet_features_ML.csv      (Packet ML)
  - labeled_traffic_features.csv        (Flow Master)
  - labeled_traffic_features_ML.csv     (Flow ML)

Answers:
  - Which runs exist in each dataset?
  - Which runs disappeared between Master -> ML?
  - Where do Flow-only runs come from?
  - Where does the Packet-only run go?
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

PACKET_MASTER = BASE_DIR / "labeled_packet_features_FINAL.csv"
PACKET_ML     = BASE_DIR / "labeled_packet_features_ML.csv"
FLOW_MASTER   = BASE_DIR / "labeled_traffic_features.csv"
FLOW_ML       = BASE_DIR / "labeled_traffic_features_ML.csv"

OUTPUT_FILE   = BASE_DIR / "run_level_analysis.csv"


# ============================================================
# HEADER
# ============================================================

print()
print("=" * 78)
print("              RUN-LEVEL DATASET ANALYSIS")
print("=" * 78)
print(f"BASE_DIR      : {BASE_DIR}")
print(f"Packet Master : {PACKET_MASTER}")
print(f"Packet ML     : {PACKET_ML}")
print(f"Flow Master   : {FLOW_MASTER}")
print(f"Flow ML       : {FLOW_ML}")
print()


# ============================================================
# FILE CHECK
# ============================================================

required_files = {
    "packet_master": PACKET_MASTER,
    "packet_ml":     PACKET_ML,
    "flow_master":   FLOW_MASTER,
    "flow_ml":       FLOW_ML,
}

for name, path in required_files.items():
    if not path.exists():
        print(f"[WARNING] {name} not found: {path}")


# ============================================================
# LOAD
# ============================================================

def load(path):
    if not path.exists():
        return None
    print(f"Loading {path.name}...")
    return pd.read_csv(path, low_memory=False)


packet_master_df = load(PACKET_MASTER)
packet_ml_df     = load(PACKET_ML)
flow_master_df   = load(FLOW_MASTER)
flow_ml_df       = load(FLOW_ML)

print()


# ============================================================
# HELPERS
# ============================================================

def clean_series(s):
    return s.fillna("").astype(str).str.strip()


def run_set(df):
    if df is None or "run_id" not in df.columns:
        return set()
    s = clean_series(df["run_id"])
    return set(s[s != ""].unique())


def run_label_map(df):
    if df is None or "run_id" not in df.columns or "label" not in df.columns:
        return {}
    sub = df.copy()
    sub["run_id"] = clean_series(sub["run_id"])
    sub["label"]  = clean_series(sub["label"])
    sub = sub[sub["run_id"] != ""]
    return (
        sub.groupby("run_id")["label"]
        .apply(lambda x: "|".join(sorted(set(x))))
        .to_dict()
    )


def run_count_map(df):
    if df is None or "run_id" not in df.columns:
        return {}
    s = clean_series(df["run_id"])
    s = s[s != ""]
    return s.value_counts().to_dict()


# ============================================================
# BUILD RUN SETS
# ============================================================

pm_runs = run_set(packet_master_df)
pml_runs = run_set(packet_ml_df)
fm_runs = run_set(flow_master_df)
fml_runs = run_set(flow_ml_df)

pm_labels = run_label_map(packet_master_df)
pml_labels = run_label_map(packet_ml_df)
fm_labels = run_label_map(flow_master_df)
fml_labels = run_label_map(flow_ml_df)

pm_counts = run_count_map(packet_master_df)
pml_counts = run_count_map(packet_ml_df)
fm_counts = run_count_map(flow_master_df)
fml_counts = run_count_map(flow_ml_df)

all_runs = sorted(pm_runs | pml_runs | fm_runs | fml_runs)


# ============================================================
# 1. SUMMARY
# ============================================================

print("-" * 78)
print("1. RUN-LEVEL SUMMARY")
print("-" * 78)

print(f"Packet Master runs : {len(pm_runs):>5}")
print(f"Packet ML runs     : {len(pml_runs):>5}")
print(f"Flow Master runs   : {len(fm_runs):>5}")
print(f"Flow ML runs       : {len(fml_runs):>5}")
print()


# ============================================================
# 2. WHERE DID FLOW-ONLY RUNS COME FROM?
# ============================================================

print("-" * 78)
print("2. FLOW-ONLY ANALYSIS (in Flow ML but not in Packet ML)")
print("-" * 78)

flow_only_in_ml = fml_runs - pml_runs
print(f"Flow-only runs (ML vs ML): {len(flow_only_in_ml)}")
print()

# Split by source
from_master = flow_only_in_ml & fm_runs
not_in_master = flow_only_in_ml - fm_runs

print(f"  Present in Flow Master : {len(from_master)}")
print(f"  NOT in Flow Master     : {len(not_in_master)}")
print()

# Do they exist in Packet Master?
in_packet_master = flow_only_in_ml & pm_runs
not_in_packet_master = flow_only_in_ml - pm_runs

print(f"  Present in Packet Master : {len(in_packet_master)}")
print(f"  NOT in Packet Master     : {len(not_in_packet_master)}")
print()

print("Interpretation:")
print()
if in_packet_master:
    print(f"  ⚠️  {len(in_packet_master)} flow-only runs EXIST in Packet Master")
    print("     → they were dropped during Packet ML preparation")
    print()
    for r in sorted(in_packet_master)[:10]:
        print(f"       - {r}")
    if len(in_packet_master) > 10:
        print(f"       ... ({len(in_packet_master) - 10} more)")

if not_in_packet_master:
    print()
    print(f"  ⚠️  {len(not_in_packet_master)} flow-only runs NOT in Packet Master")
    print("     → packet capture likely missing for those runs")
    print()
    for r in sorted(not_in_packet_master)[:10]:
        print(f"       - {r}")
    if len(not_in_packet_master) > 10:
        print(f"       ... ({len(not_in_packet_master) - 10} more)")

print()


# ============================================================
# 3. PACKET-ONLY ANALYSIS
# ============================================================

print("-" * 78)
print("3. PACKET-ONLY ANALYSIS (in Packet ML but not in Flow ML)")
print("-" * 78)

packet_only_in_ml = pml_runs - fml_runs
print(f"Packet-only runs (ML vs ML): {len(packet_only_in_ml)}")
print()

in_flow_master = packet_only_in_ml & fm_runs
not_in_flow_master = packet_only_in_ml - fm_runs

print(f"  Present in Flow Master : {len(in_flow_master)}")
print(f"  NOT in Flow Master     : {len(not_in_flow_master)}")
print()

print("Interpretation:")
print()
if in_flow_master:
    print(f"  ⚠️  {len(in_flow_master)} packet-only runs EXIST in Flow Master")
    print("     → they were dropped during Flow ML preparation")
    print()
    for r in sorted(in_flow_master):
        print(f"       - {r}")

if not_in_flow_master:
    print()
    print(f"  ⚠️  {len(not_in_flow_master)} packet-only runs NOT in Flow Master")
    print("     → flow capture likely missing for those runs")
    print()
    for r in sorted(not_in_flow_master):
        print(f"       - {r}")

print()


# ============================================================
# 4. RUNS LOST: MASTER -> ML
# ============================================================

print("-" * 78)
print("4. RUNS LOST BETWEEN MASTER AND ML")
print("-" * 78)

packet_lost = pm_runs - pml_runs
flow_lost = fm_runs - fml_runs

print(f"Packet runs lost (Master → ML): {len(packet_lost)}")
for r in sorted(packet_lost):
    lbl = pm_labels.get(r, "?")
    cnt = pm_counts.get(r, 0)
    print(f"  - {r}  [{lbl}]  ({cnt} packets)")

print()
print(f"Flow runs lost (Master → ML): {len(flow_lost)}")
for r in sorted(flow_lost):
    lbl = fm_labels.get(r, "?")
    cnt = fm_counts.get(r, 0)
    print(f"  - {r}  [{lbl}]  ({cnt} flows)")

print()


# ============================================================
# 5. RUNS ADDED: MASTER -> ML
# ============================================================

print("-" * 78)
print("5. RUNS ADDED BETWEEN MASTER AND ML (should be 0)")
print("-" * 78)

packet_added = pml_runs - pm_runs
flow_added = fml_runs - fm_runs

print(f"Packet runs added: {len(packet_added)}")
for r in sorted(packet_added):
    print(f"  - {r}")

print()
print(f"Flow runs added: {len(flow_added)}")
for r in sorted(flow_added):
    print(f"  - {r}")

print()


# ============================================================
# 6. PER-LABEL BREAKDOWN
# ============================================================

print("-" * 78)
print("6. RUNS PER LABEL (across all 4 datasets)")
print("-" * 78)

labels = ["normal", "syn_flood", "port_scan", "malicious_post"]

print(
    f"{'Label':<18}"
    f"{'PM':>6}{'PML':>6}"
    f"{'FM':>6}{'FML':>6}"
)
print("-" * 48)

for label in labels:
    pm_c = sum(1 for r in pm_runs if pm_labels.get(r) == label)
    pml_c = sum(1 for r in pml_runs if pml_labels.get(r) == label)
    fm_c = sum(1 for r in fm_runs if fm_labels.get(r) == label)
    fml_c = sum(1 for r in fml_runs if fml_labels.get(r) == label)
    print(
        f"{label:<18}"
        f"{pm_c:>6}{pml_c:>6}"
        f"{fm_c:>6}{fml_c:>6}"
    )

print()
print("Legend:")
print("  PM  = Packet Master")
print("  PML = Packet ML")
print("  FM  = Flow Master")
print("  FML = Flow ML")
print()


# ============================================================
# 7. BUILD OUTPUT CSV
# ============================================================

rows = []
for r in all_runs:
    rows.append({
        "run_id":        r,
        "label_pm":      pm_labels.get(r, ""),
        "label_pml":     pml_labels.get(r, ""),
        "label_fm":      fm_labels.get(r, ""),
        "label_fml":     fml_labels.get(r, ""),
        "packet_master": pm_counts.get(r, 0),
        "packet_ml":     pml_counts.get(r, 0),
        "flow_master":   fm_counts.get(r, 0),
        "flow_ml":       fml_counts.get(r, 0),
        "in_packet_master": r in pm_runs,
        "in_packet_ml":     r in pml_runs,
        "in_flow_master":   r in fm_runs,
        "in_flow_ml":       r in fml_runs,
    })

out_df = pd.DataFrame(rows)

# Sort by label then run_id
out_df["_label_sort"] = (
    out_df["label_pml"]
    .replace("", pd.NA)
    .fillna(out_df["label_pm"])
    .replace("", pd.NA)
    .fillna(out_df["label_fml"])
    .replace("", pd.NA)
    .fillna(out_df["label_fm"])
    .fillna("unknown")
)

label_order = {
    "normal": 0,
    "syn_flood": 1,
    "port_scan": 2,
    "malicious_post": 3,
    "unknown": 99,
}
out_df["_label_order"] = out_df["_label_sort"].map(label_order).fillna(99)
out_df = out_df.sort_values(["_label_order", "run_id"]).drop(
    columns=["_label_sort", "_label_order"]
)

out_df.to_csv(OUTPUT_FILE, index=False)


# ============================================================
# FINAL SUMMARY
# ============================================================

print("=" * 78)
print("              RUN-LEVEL ANALYSIS SUMMARY")
print("=" * 78)

print()
print(f"Total unique runs found : {len(all_runs)}")
print()
print(f"Packet Master : {len(pm_runs):>5} runs")
print(f"Packet ML     : {len(pml_runs):>5} runs  (lost: {len(packet_lost)})")
print(f"Flow Master   : {len(fm_runs):>5} runs")
print(f"Flow ML       : {len(fml_runs):>5} runs  (lost: {len(flow_lost)})")
print()

if in_packet_master:
    print(f"⚠️  {len(in_packet_master)} Flow-only runs are in Packet Master")
    print("   → dropped during Packet ML prep")
print()

print(f"Output saved to: {OUTPUT_FILE}")
print()
print("READ-ONLY: no dataset was modified.")
print("=" * 78)
