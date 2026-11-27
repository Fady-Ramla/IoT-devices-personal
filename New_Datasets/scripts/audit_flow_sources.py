#!/usr/bin/env python3
"""Read-only breakdown of raw Flow telemetry sources and missing tuple fields."""
from __future__ import annotations
import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

LABELS = ("Malicious_POST", "Normal", "Port_Scan", "SYN_Flood")
SPLITS = ("train", "validation", "final_test")


def read_csv(path):
    with path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def blank(v):
    return not (v or "").strip()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root", type=Path, default=Path.cwd())
    args = ap.parse_args()
    root = args.project_root.resolve()
    package = root / "New_Datasets/AI_OFFLINE_LEARNING_FINAL_V3_20261025"
    rawdir = root / "New_Datasets/raw/flow"
    split_manifest = package / "run_split_manifest.csv"
    assignments = {r["run_id"]: r for r in read_csv(split_manifest)}
    if len(assignments) != 160:
        raise SystemExit(f"STOP: expected 160 run assignments, got {len(assignments)}")

    groups = defaultdict(list)
    missing = []
    for rid, info in assignments.items():
        path = rawdir / f"{rid}.csv"
        if not path.is_file():
            missing.append(str(path)); continue
        for row in read_csv(path):
            row["_label"] = info["label"]
            row["_split"] = info["planned_split"]
            row["_run_id"] = rid
            groups[(info["planned_split"], info["label"], row.get("source") or "<blank-source>")].append(row)
    if missing:
        raise SystemExit(f"STOP: {len(missing)} raw flow files missing; first: {missing[0]}")

    print("Raw flow rows grouped by split / label / source.")
    print("Rows with blank protocol or ports are not deleted by this audit.")
    for split in SPLITS:
        print(f"\n=== {split} ===")
        for label in LABELS:
            sources = sorted({src for sp, lab, src in groups if sp == split and lab == label})
            if not sources:
                print(label, "NO ROWS")
                continue
            for source in sources:
                rows = groups[(split, label, source)]
                n = len(rows)
                bproto = sum(blank(r.get("protocol")) for r in rows)
                bsrc = sum(blank(r.get("src_port")) for r in rows)
                bdst = sum(blank(r.get("dst_port")) for r in rows)
                zero_packets = sum((r.get("packet_count") or "").strip() in ("0", "0.0") for r in rows)
                zero_bytes = sum((r.get("byte_count") or "").strip() in ("0", "0.0") for r in rows)
                runs = len({r["_run_id"] for r in rows})
                packet_counts = []
                for r in rows:
                    try: packet_counts.append(float(r.get("packet_count") or 0))
                    except ValueError: pass
                mean_packets = sum(packet_counts) / len(packet_counts) if packet_counts else 0.0
                print(f"{label:15s} source={source:20s} rows={n:5d} runs={runs:2d} blank(protocol/src_port/dst_port)={bproto}/{bsrc}/{bdst} zero(packet_count/byte_count)={zero_packets}/{zero_bytes} mean_packet_count={mean_packets:.3f}")

    print("\nSource semantics from raw collector rows:")
    for source in sorted({src for _, _, src in groups}):
        rows = [r for (sp, lab, s), vals in groups.items() if s == source for r in vals]
        print(f"{source}: rows={len(rows)}; examples:")
        for r in rows[:2]:
            print({k: r.get(k) for k in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol", "priority", "packet_count", "byte_count", "packet_rate", "source", "src_mac", "dst_mac")})

    print("\nNote: this is descriptive only. Do not filter rows or change feature values until source semantics are confirmed.")


if __name__ == "__main__":
    main()
