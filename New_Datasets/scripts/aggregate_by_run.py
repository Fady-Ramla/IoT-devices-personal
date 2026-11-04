#!/usr/bin/env python3
"""Aggregate split-level SDN observations into one row per run.

The script keeps train/validation/test boundaries intact and never aggregates
across splits. Packet source/destination ports are intentionally excluded as
numeric features to reduce port-shortcut leakage (for example, dst_port=5000).
"""

import argparse
from pathlib import Path

import pandas as pd

IDENTITY = {"run_id", "observation_id", "label", "label_status"}
PACKET_PORTS = {"src_port", "dst_port"}


def aggregate_file(input_path, output_path, level):
    df = pd.read_csv(input_path)

    required = {"run_id", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError("{} missing columns: {}".format(input_path, sorted(missing)))

    labels_per_run = df.groupby("run_id")["label"].nunique(dropna=False)
    bad = labels_per_run[labels_per_run != 1]
    if not bad.empty:
        raise ValueError("Multiple labels found for runs: {}".format(list(bad.index)))

    group = df.groupby("run_id", sort=True)
    result = pd.DataFrame(index=group.size().index)
    result.index.name = "run_id"

    # Run size is useful context and is available for both packet and flow data.
    result["observation_count"] = group.size().astype("int64")

    # Numeric aggregation. Ports are intentionally excluded for packet data.
    numeric_columns = [
        column for column in df.select_dtypes(include="number").columns
        if column not in IDENTITY
        and not (level == "packet" and column in PACKET_PORTS)
    ]

    for column in numeric_columns:
        series = group[column]
        result[column + "__mean"] = series.mean()
        result[column + "__std"] = series.std(ddof=0).fillna(0.0)
        result[column + "__min"] = series.min()
        result[column + "__max"] = series.max()
        result[column + "__median"] = series.median()

    # Protocol composition is represented as proportions, not arbitrary IDs.
    if "protocol" in df.columns:
        protocol = pd.crosstab(df["run_id"], df["protocol"], normalize="index")
        protocol.columns = ["protocol__{}__fraction".format(str(c).lower())
                            for c in protocol.columns]
        result = result.join(protocol, how="left")

    # Keep exactly one run-level label and status.
    result["label"] = group["label"].first()
    if "label_status" in df.columns:
        result["label_status"] = group["label_status"].first()

    result = result.reset_index()
    result["observation_id"] = result["run_id"].map(lambda value: value + "::run")

    ordered = ["run_id", "observation_id"]
    ordered += [c for c in result.columns if c not in ordered + ["label", "label_status"]]
    ordered += ["label"]
    if "label_status" in result.columns:
        ordered += ["label_status"]
    result = result[ordered]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(output_path, index=False)
    print("{} -> {} rows, {} columns".format(output_path, len(result), len(result.columns)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--level", choices=("flow", "packet"), required=True)
    args = parser.parse_args()

    for split in ("train", "validation", "test"):
        input_path = args.input_dir / (split + ".csv")
        output_path = args.output_dir / (split + ".csv")
        if not input_path.exists():
            raise SystemExit("Missing input: {}".format(input_path))
        aggregate_file(input_path, output_path, args.level)


if __name__ == "__main__":
    main()
