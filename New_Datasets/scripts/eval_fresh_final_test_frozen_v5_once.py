#!/usr/bin/env python3
"""One-shot evaluation of frozen expanded-development Packet/Flow models.

Reads the 160-run fresh final-test plan and matching manifest/application QC,
then opens test Packet/Flow captures only after pre-score checks pass. It loads
frozen v5 models from the 240-run development package and never fits or retunes.
"""
from __future__ import annotations
import csv, importlib.util, json, sys, hashlib
from collections import Counter
from pathlib import Path
import pandas as pd

LABELS={"Malicious_POST","Normal","Port_Scan","SYN_Flood"}

def read_csv(path):
    with path.open(newline="",encoding="utf-8-sig") as f:
        reader=csv.DictReader(f)
        if not reader.fieldnames:raise ValueError(f"CSV has no header: {path}")
        return reader.fieldnames,list(reader)

def file_sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""):h.update(block)
    return h.hexdigest()

def main():
    root=Path.cwd();base=root/"New_Datasets"
    dev=base/"AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026"
    plan_path=base/"scripts/collection_plan_fresh_test_160_20261025.csv"
    builder_path=base/"scripts/build_train_expanded_dev_once_v5.py"
    out=base/"AI_OFFLINE_LEARNING_EXPANDED_FINAL_TEST_V1_20261026"
    model_root=dev/"models/final_trainval_20261026"
    if out.exists():raise SystemExit(f"STOP: one-shot final-test output already exists: {out}")
    if not dev.is_dir() or not plan_path.is_file() or not builder_path.is_file():raise SystemExit("STOP: development package, test plan, or builder helper missing")
    spec=importlib.util.spec_from_file_location("builder",builder_path);b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
    b.verify_package_checksums(dev)
    with plan_path.open(newline="",encoding="utf-8-sig") as f:plan=list(csv.DictReader(f))
    if len(plan)!=160 or len({p["profile_id"] for p in plan})!=160 or len({p["command"] for p in plan})!=160:
        raise ValueError("STOP: final-test plan must have 160 unique profiles and commands")
    if {p["planned_split"] for p in plan}!={"final_test"} or {p["expected_label"] for p in plan}!=LABELS:
        raise ValueError("STOP: final-test plan has wrong split or class set")
    if any(sum(p["expected_label"]==lab for p in plan)!=40 for lab in LABELS):
        raise ValueError("STOP: final-test plan must have 40 runs per class")
    _,manifest=read_csv(base/"experiments/run_manifest.csv")
    dev_manifest=pd.read_csv(dev/"run_split_manifest.csv",dtype={"run_id":str})
    dev_ids=set(dev_manifest.run_id.astype(str))
    test_assignments=[];test_ids=set();generations=[];issues=[]
    # Pre-score audit: command/label identity, statuses, run leakage, app evidence,
    # and file existence only; packet/flow contents are not opened here.
    for p in plan:
        candidates=[r for r in manifest if b.exact_manifest_match(r,p)]
        if len(candidates)!=1:
            issues.append(f"{p['profile_id']}: manifest command match count={len(candidates)}");continue
        r=candidates[0];rid=str(r.get("run_id") or "")
        if r.get("status")!="completed":issues.append(f"{p['profile_id']}: status={r.get('status')}");continue
        if rid in test_ids or rid in dev_ids:issues.append(f"{p['profile_id']}: duplicate or development-leaked run_id {rid}");continue
        test_ids.add(rid)
        try:generations.append(int(r.get("generation") or 0))
        except ValueError:issues.append(f"{p['profile_id']}: invalid generation")
        for level in ("packet","flow"):
            raw=base/"raw"/level/(rid+".csv")
            if not raw.is_file() or raw.stat().st_size==0:issues.append(f"{p['profile_id']}: missing/empty {level} capture")
        if p["expected_label"]=="Malicious_POST":
            events=b.app_events(base,rid);valid=[]
            for e in events:
                if (b.event_value(e,"http_method","method").upper()=="POST" and
                    b.event_value(e,"route_category","route").lower()=="auth" and
                    b.event_value(e,"response_status","status")=="401"):
                    valid.append(e)
            if not valid:issues.append(f"{p['profile_id']}: missing POST/auth/401 telemetry")
        test_assignments.append({"generation":r.get("generation"),"run_id":rid,"label":p["expected_label"],"profile_id":p["profile_id"],"planned_split":"final_test"})
    if len(test_ids)!=160:issues.append(f"valid distinct test runs={len(test_ids)}, expected=160")
    if len(generations)!=160 or set(generations)!=set(range(550,710)):
        issues.append(f"expected unique test generations 550-709; found {len(generations)} matched")
    if issues:raise SystemExit("STOP: final-test pre-score QC failed; no Packet/Flow test features were opened and no metrics computed:\n  "+"\n  ".join(issues[:40]))
    print("PASS: pre-score QC; 160 completed, 40/class, app evidence verified, no run leakage. Feature CSVs remain unopened until marker.",flush=True)

    # Freeze invariant: hash all four trained models and stop if anything changes.
    model_paths={}
    for level in ("packet","flow"):
        for name in ("random_forest","xgboost"):
            path=model_root/level/f"{name}.joblib"
            if not path.is_file():raise SystemExit(f"STOP: frozen model missing: {path}")
            model_paths[level,name]=path
    hashes={f"{level}/{name}":file_sha(path) for (level,name),path in model_paths.items()}
    cfg=json.loads((dev/"config/model_features.json").read_text(encoding="utf-8"))
    _,dev_records=read_csv(dev/"run_split_manifest.csv")
    counts=Counter((r["label"],r["planned_split"]) for r in dev_records)
    for lab in LABELS:
        if counts[lab,"train"]!=48 or counts[lab,"validation"]!=12:
            raise ValueError(f"Frozen development split is not 48/12 for {lab}")
    out.mkdir(parents=True,exist_ok=False)
    (out/"RUN_ONCE_IN_PROGRESS.txt").write_text(
        "Final-test feature access begins below; do not rerun or retune after this marker.\n"
        f"Development package: {dev}\nTest plan: {plan_path}\nFrozen model hashes: {json.dumps(hashes,sort_keys=True)}\n",encoding="utf-8")

    import joblib
    from collections import defaultdict
    metrics={"purpose":"One-shot final evaluation of frozen development-trained Packet/Flow models; no test fitting or retuning.",
             "development_package":str(dev),"test_plan":str(plan_path),"test_policy":"All four models scored once; no model selection or tuning after viewing test results.",
             "test_runs":160,"runs_per_class":40,"frozen_model_sha256":hashes,"levels":{}}
    assignments_by_id={r["run_id"]:r for r in test_assignments}
    for level,features in (("packet",list(cfg["packet_features"])),("flow",list(cfg["flow_features"]))):
        records=[];seen=set();exact=set()
        for p in plan:
            found=[x for x in test_assignments if x["profile_id"]==p["profile_id"]]
            if len(found)!=1:raise ValueError(f"Internal mapping error for {p['profile_id']}")
            a=found[0];rid=a["run_id"];raw_path=base/"raw"/level/(rid+".csv")
            _,raw_rows=read_csv(raw_path)
            for row in raw_rows:
                obs=str(row.get("observation_id") or "").strip()
                if not obs:raise ValueError(f"{level} raw capture has missing observation_id: {rid}")
                if obs in seen:raise ValueError(f"{level} duplicate observation_id across final-test runs: {obs}")
                seen.add(obs)
                values=b.packet_values(row,features) if level=="packet" else b.flow_values(row,features)
                rec={"run_id":rid,"observation_id":obs,**values,"label":p["expected_label"],"label_status":"verified_final_test"}
                sig=tuple(str(rec[k]) for k in ["run_id","observation_id",*features,"label","label_status"])
                if sig in exact:raise ValueError(f"{level} exact duplicate observation row: {obs}")
                exact.add(sig);records.append(rec)
        frame=pd.DataFrame(records,columns=["run_id","observation_id",*features,"label","label_status"])
        if frame.empty:raise ValueError(f"{level} final-test rows are empty")
        if frame.groupby("run_id").label.nunique().gt(1).any():raise ValueError(f"{level}: conflicting labels in a run")
        if set(frame.run_id.astype(str))!=test_ids:raise ValueError(f"{level}: feature rows do not match all 160 test runs")
        splitdir=out/f"{level}_splits";splitdir.mkdir()
        frame.to_csv(splitdir/"test.csv",index=False)
        x=b.encode(frame,features)
        level_metrics={"features":features,"rows":int(len(frame)),"runs":int(frame.run_id.nunique()),"models":{}}
        for name in ("random_forest","xgboost"):
            model=joblib.load(model_paths[level,name])
            encoder=joblib.load(model_root/level/"label_encoder.joblib")
            if set(map(str,encoder.classes_))!=LABELS:raise ValueError(f"{level}/{name}: class encoder mismatch")
            level_metrics["models"][name]={"test":b.evaluate(model,x,frame,encoder)}
            run=level_metrics["models"][name]["test"]["run_level"]
            print(f"{level}/{name}: final-test run accuracy={run['accuracy']:.4f}; macro-F1={run['f1_macro']:.4f}",flush=True)
        metrics["levels"][level]=level_metrics
        (out/"final_test_metrics.partial.json").write_text(json.dumps(metrics,indent=2)+"\n",encoding="utf-8")
    after={f"{level}/{name}":file_sha(path) for (level,name),path in model_paths.items()}
    if after!=hashes:raise ValueError("A frozen model artifact changed during evaluation")
    with (out/"run_split_manifest.csv").open("w",newline="",encoding="utf-8") as f:
        cols=["generation","run_id","label","profile_id","planned_split"];w=csv.DictWriter(f,fieldnames=cols);w.writeheader();w.writerows(test_assignments)
    qc={"test_runs":160,"runs_per_class":dict(Counter(x["label"] for x in test_assignments)),"development_test_run_leakage":False,"test_features_opened_once":True,"model_retraining_or_retuning":False,"final_test_telemetry_verified":True,"packet_flow_observation_ids_unique":True,"frozen_model_sha256_unchanged":True}
    (out/"qc_report.json").write_text(json.dumps(qc,indent=2)+"\n",encoding="utf-8")
    (out/"final_test_metrics.json").write_text(json.dumps(metrics,indent=2)+"\n",encoding="utf-8")
    partial=out/"final_test_metrics.partial.json"
    if partial.exists():partial.unlink()
    (out/"RUN_ONCE_IN_PROGRESS.txt").rename(out/"RUN_ONCE_COMPLETE.txt")
    files=sorted(p for p in out.rglob("*") if p.is_file() and p.name!="SHA256SUMS.txt")
    (out/"SHA256SUMS.txt").write_text("".join(f"{file_sha(p)}  {p.relative_to(out).as_posix()}\n" for p in files),encoding="utf-8")
    print("FINAL-TEST EVALUATION COMPLETE. Do not retrain/tune against these results.",flush=True)
    print("Saved metrics:",out/"final_test_metrics.json",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print(f"FINAL TEST STOP: {type(exc).__name__}: {exc}",file=sys.stderr);raise
