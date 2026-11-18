#!/usr/bin/env python3
"""Build a balanced Packet-In dataset from real Ryu collection runs.

Only rows whose flow source is ``packetin_window`` are eligible. The script
never synthesizes or duplicates rows, rejects duplicate observation IDs, and
keeps all rows from one run in one split to prevent run leakage.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

LABEL_ALIASES = {
    "normal": "Normal",
    "normal_baseline": "Normal",
    "port_scan": "Port_Scan",
    "portscan": "Port_Scan",
    "syn_flood": "SYN_Flood",
    "synflood": "SYN_Flood",
    "malicious_post": "Malicious_POST",
    "malicious-post": "Malicious_POST",
    "maliciouspost": "Malicious_POST",
}
REQUIRED_CLASSES = ("Normal", "Port_Scan", "SYN_Flood", "Malicious_POST")


def norm(value):
    return str(value or "").strip().lower().replace(" ", "_")


def manifest_label(row):
    for key in ("label", "manifest_label", "expected_label", "attack_type", "scenario", "mode"):
        value = norm(row.get(key))
        if value in LABEL_ALIASES:
            return LABEL_ALIASES[value]
    for value in row.values():
        value = norm(value)
        if value in LABEL_ALIASES:
            return LABEL_ALIASES[value]
    return None


def load_manifest(path):
    result = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("manifest has no header")
        for row in reader:
            run_id = (row.get("run_id") or "").strip()
            label = manifest_label(row)
            if run_id and label:
                result[run_id] = label
    return result


def collect_rows(flow_dir, labels, allow_mixed=False):
    rows = []
    seen_obs = set()
    duplicate_obs = []
    rejected_source = 0
    unknown_runs = []
    for path in sorted(flow_dir.glob("*.csv")):
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                if row.get("source", "").strip() != "packetin_window":
                    rejected_source += 1
                    continue
                run_id = row.get("run_id", "").strip()
                obs = row.get("observation_id", "").strip()
                label = labels.get(run_id)
                if not label:
                    unknown_runs.append(run_id)
                    continue
                if obs in seen_obs:
                    duplicate_obs.append(obs)
                    continue
                seen_obs.add(obs)
                row["label"] = label
                rows.append(row)
    if duplicate_obs:
        raise ValueError(f"duplicate observation_id values: {len(duplicate_obs)}")
    if unknown_runs and not allow_mixed:
        sample = sorted(set(unknown_runs))[:5]
        raise ValueError(f"packetin rows have no manifest label; sample runs={sample}")
    return rows, rejected_source, sorted(set(unknown_runs))


def split_runs(rows, seed):
    by_label_run = defaultdict(lambda: defaultdict(list))
    for row in rows:
        by_label_run[row["label"]][row["run_id"]].append(row)
    rng = random.Random(seed)
    train, validation, test = [], [], []
    for label in REQUIRED_CLASSES:
        run_ids = list(by_label_run.get(label, {}))
        rng.shuffle(run_ids)
        n = len(run_ids)
        n_test = max(1, round(n * 0.20)) if n >= 3 else 0
        n_val = max(1, round(n * 0.10)) if n >= 5 else 0
        test_ids = set(run_ids[:n_test])
        val_ids = set(run_ids[n_test:n_test + n_val])
        for run_id, run_rows in by_label_run.get(label, {}).items():
            if run_id in test_ids:
                test.extend(run_rows)
            elif run_id in val_ids:
                validation.extend(run_rows)
            else:
                train.extend(run_rows)
    return train, validation, test


def write_csv(path, rows, header):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=header, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path("New_Datasets"))
    ap.add_argument("--manifest", type=Path, default=None)
    ap.add_argument("--output", type=Path, default=Path("New_Datasets/derived/packetin_balanced"))
    ap.add_argument("--seed", type=int, default=20261118)
    ap.add_argument("--allow-unlabeled", action="store_true")
    args = ap.parse_args()

    manifest_path = args.manifest or (args.root / "experiments" / "run_manifest.csv")
    flow_dir = args.root / "raw" / "flow"
    if not manifest_path.exists():
        raise SystemExit(f"manifest not found: {manifest_path}")
    if not flow_dir.exists():
        raise SystemExit(f"flow directory not found: {flow_dir}")

    labels = load_manifest(manifest_path)
    rows, rejected_source, unknown_runs = collect_rows(
        flow_dir, labels, allow_mixed=args.allow_unlabeled
    )
    available = Counter(row["label"] for row in rows)
    missing = [label for label in REQUIRED_CLASSES if not available[label]]
    if missing:
        raise SystemExit(f"missing required classes: {missing}; available={dict(available)}")

    # No oversampling: balance to the smallest real class count.
    target = min(available[label] for label in REQUIRED_CLASSES)
    by_class = {label: [] for label in REQUIRED_CLASSES}
    for row in rows:
        if len(by_class[row["label"]]) < target:
            by_class[row["label"]].append(row)
    balanced = [row for label in REQUIRED_CLASSES for row in by_class[label]]
    train, validation, test = split_runs(balanced, args.seed)

    header = [key for key in rows[0].keys() if key != "label"] + ["label"]
    args.output.mkdir(parents=True, exist_ok=True)
    write_csv(args.output / "packetin_balanced_all.csv", balanced, header)
    write_csv(args.output / "packetin_train.csv", train, header)
    write_csv(args.output / "packetin_validation.csv", validation, header)
    write_csv(args.output / "packetin_test.csv", test, header)

    report = {
        "source_policy": "only source == packetin_window",
        "oversampling": False,
        "duplicate_observation_ids": 0,
        "rejected_switch_flow_stats_rows": rejected_source,
        "unlabeled_run_count": len(unknown_runs),
        "available_rows_by_class": dict(available),
        "balanced_rows_by_class": dict(Counter(row["label"] for row in balanced)),
        "balanced_rows": len(balanced),
        "target_rows_per_class": target,
        "run_counts": {
            split: len({row["run_id"] for row in data})
            for split, data in (("train", train), ("validation", validation), ("test", test))
        },
        "row_counts": {split: len(data) for split, data in (("train", train), ("validation", validation), ("test", test))},
        "seed": args.seed,
    }
    (args.output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    print("PACKET-IN BALANCED DATASET: PASS")


if __name__ == "__main__":
    main()
