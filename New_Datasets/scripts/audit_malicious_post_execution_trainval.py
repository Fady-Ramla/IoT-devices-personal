#!/usr/bin/env python3
"""Audit execution validity for train/validation Malicious_POST runs only."""
from __future__ import annotations
import argparse
import csv
import json
from collections import Counter
from pathlib import Path


def read_csv(path):
    with path.open("r",newline="",encoding="utf-8") as f:
        return list(csv.DictReader(f))


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root",type=Path,default=Path.cwd())
    args=ap.parse_args()
    root=args.project_root.resolve()
    base=root/"New_Datasets"
    package=base/"AI_OFFLINE_LEARNING_FINAL_V3_20261025"
    assignments=[r for r in read_csv(package/"run_split_manifest.csv")
                 if r.get("planned_split") in ("train","validation") and r.get("label")=="Malicious_POST"]
    manifest={r["run_id"]:r for r in read_csv(base/"experiments/run_manifest.csv")}
    plans={r["profile_id"]:r for r in read_csv(base/"scripts/collection_plan_packet_flow_final_v3_160runs.csv")}
    app_dirs=[p for p in (base/"raw").glob("application*") if p.is_dir()]
    files_by_id={}
    for d in app_dirs:
        for p in d.rglob("*.csv"):
            files_by_id.setdefault(p.stem,[]).append(p)

    print("TRAIN/VALIDATION ONLY; no final_test run or app file is opened.")
    print("Per-run check: planned attack attempt vs observed HTTP POSTs.")
    valid_files=0; total_events=0; total_posts=0; missing=0
    for a in sorted(assignments,key=lambda x:(x["planned_split"],x.get("profile_id",""))):
        rid=a["run_id"]; m=manifest.get(rid,{}); plan=plans.get(a.get("profile_id",""),{})
        paths=files_by_id.get(rid,[])
        events=[]
        for p in paths:
            events.extend(read_csv(p))
        methods=Counter((r.get("http_method") or "<blank>").upper() for r in events)
        statuses=Counter(r.get("response_status") or "<blank>" for r in events)
        routes=Counter(r.get("route_category") or "<blank>" for r in events)
        post_count=methods.get("POST",0)
        valid_files += bool(events); total_events+=len(events); total_posts+=post_count
        if not events: missing+=1
        notes=m.get("notes","")
        try:
            notes=json.loads(notes) if notes else {}
            if isinstance(notes.get("operator_notes"),str):
                try: notes["operator_notes"]=json.loads(notes["operator_notes"])
                except json.JSONDecodeError: pass
        except (json.JSONDecodeError,TypeError,AttributeError):
            notes={"raw_notes":str(notes)[:300]}
        output=str(notes.get("output_tail", "")) if isinstance(notes,dict) else ""
        errors=notes.get("errors",[]) if isinstance(notes,dict) else []
        print({
            "split":a["planned_split"],"profile":a.get("profile_id"),"run_id":rid,
            "manifest_status":m.get("status"),"requested_command":plan.get("command"),
            "application_files":len(paths),"application_events":len(events),
            "observed_methods":dict(methods),"POST_events":post_count,
            "response_statuses":dict(statuses),"route_categories":dict(routes),
            "errors":errors,"client_output_tail":output[-220:] if output else "",
        })
    print("SUMMARY:",{"runs":len(assignments),"runs_with_app_events":valid_files,
                       "runs_without_app_events":missing,"events":total_events,
                       "observed_POST_events":total_posts})
    print("Interpretation: completed manifest status only means the capture lifecycle completed; it does not prove the POST request reached the app.")
    print("Do not change labels or manifest status based on this output alone; use a separate QC/eligibility decision.")

if __name__=="__main__": main()
