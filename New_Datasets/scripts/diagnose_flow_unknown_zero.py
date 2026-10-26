#!/usr/bin/env python3
"""Read-only diagnosis of Flow protocol=unknown and dst_port=0 values.
Compares final packaged splits with original raw collector CSVs by split and label.
Does not modify any files.
"""
from __future__ import annotations
import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

SPLITS = ("train", "validation", "test")
LABELS = ("Malicious_POST", "Normal", "Port_Scan", "SYN_Flood")


def load(path: Path):
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError(f"No header: {path}")
        return reader.fieldnames, list(reader)


def norm(v):
    return (v or "").strip().lower()


def pct(n, d):
    return f"{100*n/d:.1f}%" if d else "n/a"


def report(title, rows):
    print("\n" + title)
    for label in LABELS:
        subset = [r for r in rows if r.get("label") == label]
        if not subset:
            continue
        protocols = Counter(norm(r.get("protocol")) or "<blank>" for r in subset)
        ports = Counter(norm(r.get("dst_port")) or "<blank>" for r in subset)
        n = len(subset)
        p_blank = protocols.get("<blank>", 0)
        p_unknown = protocols.get("unknown", 0)
        p_zero = ports.get("0", 0)
        p_blank_port = ports.get("<blank>", 0)
        print(f"  {label}: rows={n}; protocol blank={p_blank} ({pct(p_blank,n)}), unknown={p_unknown} ({pct(p_unknown,n)}); dst_port 0={p_zero} ({pct(p_zero,n)}), blank={p_blank_port} ({pct(p_blank_port,n)})")
        print(f"    protocol values: {protocols.most_common(8)}")
        print(f"    dst_port values: {ports.most_common(8)}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root", type=Path, default=Path.cwd())
    args = ap.parse_args()
    root = args.project_root.resolve()
    package = root / "New_Datasets/AI_OFFLINE_LEARNING_FINAL_V3_20261025"
    rawdir = root / "New_Datasets/raw/flow"
    assignment_path = package / "run_split_manifest.csv"
    if not assignment_path.is_file():
        raise SystemExit(f"STOP: missing {assignment_path}")
    if not rawdir.is_dir():
        raise SystemExit(f"STOP: missing {rawdir}")
    with assignment_path.open("r", newline="", encoding="utf-8") as f:
        assignments = list(csv.DictReader(f))
    by_run = {r["run_id"]: r for r in assignments}
    if len(by_run) != 160:
        raise SystemExit(f"STOP: expected 160 unique successful run assignments, found {len(by_run)}")

    print("=== FINAL PACKAGED FLOW DATA ===")
    for split in SPLITS:
        p = package / "flow_splits" / f"{split}.csv"
        if not p.is_file():
            raise SystemExit(f"STOP: missing {p}")
        _, rows = load(p)
        report(f"Packaged split: {split} ({len(rows)} rows)", rows)

    print("\n=== RAW COLLECTOR FLOW VALUES ===")
    for split in ("train", "validation", "final_test"):
        raw_rows = []
        missing_files = []
        for run_id, assignment in by_run.items():
            if assignment.get("planned_split") != split:
                continue
            p = rawdir / f"{run_id}.csv"
            if not p.is_file():
                missing_files.append(str(p))
                continue
            _, rows = load(p)
            label = assignment["label"]
            for r in rows:
                r["label"] = label
                raw_rows.append(r)
        if missing_files:
            raise SystemExit(f"STOP: missing {len(missing_files)} raw flow files; first: {missing_files[0]}")
        print(f"Raw split: {split} ({len(raw_rows)} rows; {len([x for x in by_run.values() if x.get('planned_split') == split])} runs)")
        report("Raw values grouped by label", raw_rows)

    print("\nInterpretation guide:")
    print("- Raw blank/unknown protocol and blank dst_port indicate missing or unmapped source telemetry; inspect exporter/collector handling before modeling.")
    print("- Raw literal dst_port=0 may be a placeholder, a non-port protocol record, or a genuine value; decide from collector schema/protocol semantics, do not blindly replace it.")
    print("- If raw values are populated but packaged values become blank/unknown/0, inspect the packager transformation.")
    print("- A similar missing-value rate across labels is not by itself proof of no bias; compare split/class patterns and feature meaning.")


if __name__ == "__main__":
    main()
