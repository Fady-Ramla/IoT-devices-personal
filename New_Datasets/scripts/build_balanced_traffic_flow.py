#!/usr/bin/env python3
"""Build a 100k balanced traffic-flow training view.

This script deliberately splits first, then oversamples only the training
partition. The held-out test partition remains untouched. Reused source rows
are reported in the manifest; the output must not be described as 100k unique
observations unless the manifest confirms that.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

LABEL_MAP = {
    "normal": "Normal",
    "port_scan": "Port_Scan",
    "syn_flood": "SYN_Flood",
    "malicious_post": "Malicious_POST",
}
LABELS = ["Normal", "Port_Scan", "SYN_Flood", "Malicious_POST"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--output-train", type=Path, required=True)
    ap.add_argument("--output-test", type=Path, required=True)
    ap.add_argument("--output-report", type=Path, required=True)
    ap.add_argument("--rows-per-class", type=int, default=25_000)
    ap.add_argument("--test-size", type=float, default=0.20)
    ap.add_argument("--seed", type=int, default=20261117)
    args = ap.parse_args()
    if args.rows_per_class <= 0 or not 0 < args.test_size < 1:
        raise SystemExit("rows-per-class must be positive and test-size must be in (0,1)")

    df = pd.read_csv(args.input, low_memory=False)
    if "label" not in df.columns:
        raise SystemExit("input is missing label column")
    df["label"] = df["label"].astype(str).map(LABEL_MAP).fillna(df["label"])
    unknown = sorted(set(df["label"]) - set(LABELS))
    if unknown:
        raise SystemExit(f"unknown labels: {unknown}")
    df["__source_row"] = np.arange(len(df), dtype=np.int64)

    # Split before any resampling. Test rows can never be copied into training.
    train_parts, test_parts = [], []
    for label in LABELS:
        group = df[df["label"] == label]
        tr, te = train_test_split(
            group, test_size=args.test_size, random_state=args.seed, shuffle=True
        )
        train_parts.append(tr)
        test_parts.append(te)
    train = pd.concat(train_parts, ignore_index=True)
    test = pd.concat(test_parts, ignore_index=True)
    train_ids = set(train["__source_row"])
    test_ids = set(test["__source_row"])
    if train_ids & test_ids:
        raise SystemExit("internal error: source-row overlap between train and test")

    rng = np.random.default_rng(args.seed)
    balanced_parts = []
    per_class = {}
    for label in LABELS:
        group = train[train["label"] == label]
        replace = len(group) < args.rows_per_class
        choices = rng.choice(len(group), size=args.rows_per_class, replace=replace)
        balanced_parts.append(group.iloc[choices])
        source_unique = int(group["__source_row"].nunique())
        output_unique = int(group.iloc[choices]["__source_row"].nunique())
        per_class[label] = {
            "available_train_rows": int(len(group)),
            "requested_output_rows": args.rows_per_class,
            "output_rows": int(len(choices)),
            "replacement_used": bool(replace),
            "unique_source_rows_in_output": output_unique,
            "reused_rows_in_output": int(len(choices) - output_unique),
            "available_unique_train_rows": source_unique,
        }
    balanced = pd.concat(balanced_parts, ignore_index=True)
    balanced = balanced.sample(frac=1.0, random_state=args.seed).reset_index(drop=True)

    out_columns = [c for c in df.columns if c != "__source_row"]
    args.output_train.parent.mkdir(parents=True, exist_ok=True)
    args.output_test.parent.mkdir(parents=True, exist_ok=True)
    args.output_report.parent.mkdir(parents=True, exist_ok=True)
    balanced[out_columns].to_csv(args.output_train, index=False)
    test[out_columns].to_csv(args.output_test, index=False)

    report = {
        "input": str(args.input),
        "seed": args.seed,
        "rows_per_class": args.rows_per_class,
        "total_output_train_rows": int(len(balanced)),
        "total_test_rows_untouched": int(len(test)),
        "source_total_rows": int(len(df)),
        "source_unique_rows": int(len(df.drop_duplicates())),
        "train_source_rows": int(len(train)),
        "test_source_rows": int(len(test)),
        "train_test_source_row_overlap": int(len(train_ids & test_ids)),
        "output_duplicate_rows": int(balanced.duplicated().sum()),
        "labels_output": balanced["label"].value_counts().to_dict(),
        "labels_test": test["label"].value_counts().to_dict(),
        "per_class": per_class,
        "warning": "The 100k training view uses replacement for minority classes; it contains 100k rows but not 100k unique observations.",
    }
    args.output_report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
