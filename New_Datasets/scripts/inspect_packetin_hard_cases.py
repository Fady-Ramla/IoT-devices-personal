#!/usr/bin/env python3
"""Read-only train/validation summary for packetin_window hard cases.
Never opens test runs or modifies files.
"""
from __future__ import annotations
import argparse
import csv
from collections import defaultdict
from pathlib import Path
import statistics

TARGETS = {"Malicious_POST", "SYN_Flood", "Normal"}
NUMERIC = ["packet_count", "byte_count", "packet_rate", "byte_rate", "duration_sec",
           "avg_packet_size", "syn_count", "ack_count", "rst_count", "fin_count",
           "syn_ack_ratio", "rst_ratio", "unique_dst_ports", "tcp_fraction",
           "udp_fraction", "icmp_fraction"]


def read_csv(path):
    with path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def mean(rows, col):
    vals=[]
    for r in rows:
        try: vals.append(float(r.get(col) or 0))
        except (TypeError, ValueError): pass
    return statistics.mean(vals) if vals else 0.0


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root", type=Path, default=Path.cwd())
    args=ap.parse_args()
    root=args.project_root.resolve()
    pkg=root/"New_Datasets/AI_OFFLINE_LEARNING_FINAL_V3_20261025"
    raw=root/"New_Datasets/raw/flow"
    assignment={r["run_id"]:r for r in read_csv(pkg/"run_split_manifest.csv")}
    manifest={r["run_id"]:r for r in read_csv(root/"New_Datasets/experiments/run_manifest.csv")}
    predpath=root/"New_Datasets/reports/flow_source_ablation_trainval_20261025.json"
    import json
    report=json.loads(predpath.read_text(encoding="utf-8"))
    predlist=report["variants"]["packetin_window_only"]["xgboost"]["validation"]["run_level"]["predictions"]
    preds={r["run_id"]:r for r in predlist}

    grouped=defaultdict(list)
    for rid,a in assignment.items():
        split=a["planned_split"]
        if split not in ("train","validation") or a["label"] not in TARGETS:
            continue
        path=raw/f"{rid}.csv"
        if not path.is_file(): raise SystemExit(f"STOP: missing {path}")
        rows=[r for r in read_csv(path) if r.get("source")=="packetin_window"]
        grouped[(split,a["label"])].append((rid,a,manifest.get(rid,{}),rows))

    print("TRAIN/VALIDATION ONLY; test was not read.")
    print("Per-run feature means are descriptive, not statistical tests.")
    print("\n=== Group summaries by label/split ===")
    cols=["packet_count","packet_rate","byte_rate","avg_packet_size","syn_count","ack_count","unique_dst_ports"]
    for split in ("train","validation"):
        for label in ("Malicious_POST","SYN_Flood","Normal"):
            runs=grouped[(split,label)]
            total_windows=sum(len(x[3]) for x in runs)
            if not runs: continue
            print(f"{split:10s} {label:15s} runs={len(runs):2d} windows={total_windows:4d}")
            for col in cols:
                per_run=[mean(x[3],col) for x in runs if x[3]]
                print(f"  {col:18s} mean-of-run-means={statistics.mean(per_run):.3f}" if per_run else f"  {col:18s} no windows")

    print("\n=== Malicious_POST training and validation profiles ===")
    print("split profile actual predicted rate duration windows mean_packet_rate mean_byte_rate mean_syn mean_ack mean_unique_dst_ports")
    for split in ("train","validation"):
        for rid,a,m,rows in grouped[(split,"Malicious_POST")]:
            p=preds.get(rid,{})
            print(split,a.get("profile_id"),"Malicious_POST",p.get("predicted","(not predicted)"),
                  m.get("rate_value"),m.get("duration_sec"),len(rows),
                  f"{mean(rows,'packet_rate'):.3f}",f"{mean(rows,'byte_rate'):.3f}",
                  f"{mean(rows,'syn_count'):.3f}",f"{mean(rows,'ack_count'):.3f}",
                  f"{mean(rows,'unique_dst_ports'):.3f}")

    print("\n=== SYN_Flood training and validation profiles ===")
    print("split profile actual predicted rate duration windows mean_packet_rate mean_byte_rate mean_syn mean_ack mean_unique_dst_ports")
    for split in ("train","validation"):
        for rid,a,m,rows in grouped[(split,"SYN_Flood")]:
            p=preds.get(rid,{})
            print(split,a.get("profile_id"),"SYN_Flood",p.get("predicted","(not predicted)"),
                  m.get("rate_value"),m.get("duration_sec"),len(rows),
                  f"{mean(rows,'packet_rate'):.3f}",f"{mean(rows,'byte_rate'):.3f}",
                  f"{mean(rows,'syn_count'):.3f}",f"{mean(rows,'ack_count'):.3f}",
                  f"{mean(rows,'unique_dst_ports'):.3f}")

    print("\nNote: model features have no HTTP method/route/response/auth-outcome field. Network-only telemetry cannot directly encode application intent.")

if __name__=="__main__": main()
