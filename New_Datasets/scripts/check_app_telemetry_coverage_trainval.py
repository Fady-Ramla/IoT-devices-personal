#!/usr/bin/env python3
"""Read-only availability check for application telemetry on train/validation runs only."""
from __future__ import annotations
import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

LABELS=("Malicious_POST","Normal","Port_Scan","SYN_Flood")
SPLITS=("train","validation")


def read_csv(path):
    with path.open("r",newline="",encoding="utf-8") as f:
        reader=csv.DictReader(f)
        return reader.fieldnames or [], list(reader)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root",type=Path,default=Path.cwd())
    args=ap.parse_args()
    root=args.project_root.resolve()
    package=root/"New_Datasets/AI_OFFLINE_LEARNING_FINAL_V3_20261025"
    assignments_path=package/"run_split_manifest.csv"
    raw=root/"New_Datasets/raw"
    if not assignments_path.is_file(): raise SystemExit(f"STOP: missing {assignments_path}")
    assignments={r["run_id"]:r for r in read_csv(assignments_path)[1]
                 if r.get("planned_split") in SPLITS}
    dirs=sorted(p for p in raw.glob("application*") if p.is_dir())
    if not dirs:
        print("No New_Datasets/raw/application* directories found.")
        return
    matched=defaultdict(list)
    unknown_files=[]
    for d in dirs:
        for p in d.rglob("*.csv"):
            if p.stem in assignments:
                fields,rows=read_csv(p)
                rid_values={r.get("run_id") for r in rows if r.get("run_id")}
                matched[p.stem].append({"path":p,"fields":fields,"rows":rows,"run_ids":rid_values})
    print("TRAIN/VALIDATION ONLY; final_test run IDs and raw files were not inspected.")
    print("Application directories:",", ".join(str(p.relative_to(root)) for p in dirs))
    print("\nCoverage by split and class:")
    for split in SPLITS:
        for label in LABELS:
            runids=[rid for rid,a in assignments.items() if a.get("planned_split")==split and a.get("label")==label]
            found=[rid for rid in runids if rid in matched]
            events=sum(len(item["rows"]) for rid in found for item in matched[rid])
            print(f"{split:10s} {label:15s} files_for_runs={len(found)}/{len(runids)} events={events}")
    print("\nMatched files and fields:")
    for rid in sorted(matched):
        a=assignments[rid]
        for item in matched[rid]:
            bad = bool(item["run_ids"] and item["run_ids"] != {rid})
            print(f"{a['planned_split']:10s} {a['label']:15s} profile={a.get('profile_id')} run={rid} rows={len(item['rows'])} run_id_mismatch={bad} file={item['path'].relative_to(root)}")
            print("  columns:",item["fields"])
    if not matched:
        print("No application telemetry file stems match any train/validation run_id.")
    print("\nNo files were edited; this check does not assess or use test-set telemetry.")

if __name__=="__main__": main()
