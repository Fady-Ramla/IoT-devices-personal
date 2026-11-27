#!/usr/bin/env python3
"""One-shot evaluation using 154 verified original holdout runs + 6 replacements."""
import csv, hashlib, importlib.util, json, sys
from collections import Counter
from pathlib import Path
import pandas as pd

BAD_POST={"MPNEW064","MPNEW072","MPNEW020","MPNEW004","MPNEW068","MPNEW001"}
LABELS={"Malicious_POST","Normal","Port_Scan","SYN_Flood"}

def read_csv(path):
    with path.open(newline="",encoding="utf-8-sig") as f:
        r=csv.DictReader(f)
        if not r.fieldnames:raise ValueError(f"CSV missing header: {path}")
        return list(r)
def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
    return h.hexdigest()
def valid_post_events(b,base,rid):
    events=b.app_events(base,rid)
    return [e for e in events if b.event_value(e,"http_method","method").upper()=="POST" and b.event_value(e,"route_category","route").lower()=="auth" and b.event_value(e,"response_status","status")=="401"]
def main():
    root=Path.cwd();base=root/"New_Datasets";dev=base/"AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026"
    plan_path=base/"scripts/collection_plan_fresh_test_160_20261025.csv"
    repl_path=base/"scripts/collection_plan_final_test_post_replacements_6_20261026.csv"
    helper=base/"scripts/build_train_expanded_dev_once_v5.py"
    out=base/"AI_OFFLINE_LEARNING_EXPANDED_FINAL_TEST_V1_20261026"
    if out.exists():raise SystemExit(f"STOP: output exists; never rerun final evaluation: {out}")
    if not dev.is_dir() or not plan_path.is_file() or not repl_path.is_file() or not helper.is_file():raise SystemExit("STOP: required development/test/replacement inputs missing")
    spec=importlib.util.spec_from_file_location("builder",helper);b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b);b.verify_package_checksums(dev)
    plan=read_csv(plan_path);repls=read_csv(repl_path);manifest=read_csv(base/"experiments/run_manifest.csv")
    if len(plan)!=160 or len(repls)!=6 or {r["profile_id"] for r in plan if r["profile_id"] in BAD_POST}!=BAD_POST:raise ValueError("Test/replacement plan size or excluded profile set mismatch")
    if any(r["expected_label"]!="Malicious_POST" or r["planned_split"]!="final_test" for r in repls):raise ValueError("All six replacements must be Malicious_POST/final_test")
    dev_ids={str(x) for x in pd.read_csv(dev/"run_split_manifest.csv",dtype={"run_id":str}).run_id}
    bygen={}
    for r in manifest:
        try:g=int(r.get("generation") or 0)
        except ValueError:continue
        bygen.setdefault(g,[]).append(r)
    assignments=[];excluded=[];issues=[]
    # The original 160 are mapped by immutable batch sequence, not ambiguous global signatures.
    for i,p in enumerate(plan):
        gen=550+i;records=bygen.get(gen,[])
        if len(records)!=1:issues.append(f"{p['profile_id']}: expected one manifest record at gen {gen}, found {len(records)}");continue
        r=records[0]
        if r.get("status")!="completed" or r.get("label")!=p["expected_label"] or not b.exact_manifest_match(r,p):
            issues.append(f"{p['profile_id']}: gen {gen} manifest/plan mismatch or incomplete");continue
        rid=str(r.get("run_id") or "")
        if p["profile_id"] in BAD_POST:
            if valid_post_events(b,base,rid):issues.append(f"{p['profile_id']}: excluded run unexpectedly has POST/auth/401 evidence; review identity")
            excluded.append(p["profile_id"]);continue
        if p["expected_label"]=="Malicious_POST" and not valid_post_events(b,base,rid):issues.append(f"{p['profile_id']}: missing POST/auth/401")
        assignments.append({"generation":gen,"run_id":rid,"label":p["expected_label"],"profile_id":p["profile_id"],"planned_split":"final_test"})
    if set(excluded)!=BAD_POST:issues.append(f"Excluded invalid profiles mismatch: {excluded}")
    # New replacement batch begins at generation 710; restrict match scope to avoid old command signatures.
    for j,p in enumerate(repls):
        gen=710+j;records=bygen.get(gen,[])
        if len(records)!=1:issues.append(f"{p['profile_id']}: expected one manifest record at gen {gen}, found {len(records)}");continue
        r=records[0]
        if r.get("status")!="completed" or r.get("label")!="Malicious_POST" or not b.exact_manifest_match(r,p):
            issues.append(f"{p['profile_id']}: gen {gen} manifest/plan mismatch or incomplete");continue
        rid=str(r.get("run_id") or "")
        if not valid_post_events(b,base,rid):issues.append(f"{p['profile_id']}: replacement lacks POST/auth/401 app evidence")
        assignments.append({"generation":gen,"run_id":rid,"label":"Malicious_POST","profile_id":p["profile_id"],"planned_split":"final_test"})
    counts=Counter(x["label"] for x in assignments)
    if len(assignments)!=160 or counts!={x:40 for x in LABELS}:issues.append(f"Final selection runs/counts invalid: {len(assignments)}, {dict(counts)}")
    ids=[x["run_id"] for x in assignments]
    if len(set(ids))!=160 or set(ids)&dev_ids:issues.append("run ID duplicate or development/test leakage")
    for a in assignments:
        for level in ("packet","flow"):
            p=base/"raw"/level/(a["run_id"]+".csv")
            if not p.is_file() or p.stat().st_size==0:issues.append(f"{a['profile_id']}: missing/empty {level} capture")
    if issues:raise SystemExit("STOP: no test features opened and no scores computed:\n  " + "\n  ".join(issues[:50]))
    print("PASS: 160 balanced final-test runs; 154 original valid + 6 verified replacements; no leakage; app telemetry checked.",flush=True)
    modeldir=dev/"models/final_trainval_20261026";paths={};hashes={}
    for level in ("packet","flow"):
        for name in ("random_forest","xgboost"):
            p=modeldir/level/f"{name}.joblib"
            if not p.is_file():raise SystemExit(f"STOP: missing frozen model {p}")
            paths[level,name]=p;hashes[f"{level}/{name}"]=sha(p)
    out.mkdir(parents=True,exist_ok=False)
    (out/"RUN_ONCE_IN_PROGRESS.txt").write_text("Final test feature access starts below. Do not rerun or retune.\n"+json.dumps(hashes,sort_keys=True)+"\n",encoding="utf-8")
    import joblib
    cfg=json.loads((dev/"config/model_features.json").read_text(encoding="utf-8"))
    metrics={"purpose":"One-shot evaluation of frozen v5 models on 160 independent final-test runs; no fitting or tuning.","test_policy":"154 telemetry-valid original runs plus six verified POST replacements; all 160 scored once.","runs":160,"runs_per_class":dict(counts),"frozen_model_sha256":hashes,"levels":{}}
    for level,features in (("packet",cfg["packet_features"]),("flow",cfg["flow_features"])):
        rows=[];obs_seen=set()
        for a in assignments:
            raw=base/"raw"/level/(a["run_id"]+".csv")
            _,raw_rows=b.read_csv(raw)
            for rr in raw_rows:
                obs=str(rr.get("observation_id") or "").strip()
                if not obs or obs in obs_seen:raise ValueError(f"{level} missing/duplicate observation_id {obs!r}")
                obs_seen.add(obs)
                vals=b.packet_values(rr,features) if level=="packet" else b.flow_values(rr,features)
                rows.append({"run_id":a["run_id"],"observation_id":obs,**vals,"label":a["label"],"label_status":"verified_final_test"})
        frame=pd.DataFrame(rows,columns=["run_id","observation_id",*features,"label","label_status"])
        if set(frame.run_id.astype(str))!=set(ids):raise ValueError(f"{level}: feature table does not cover exact test run set")
        d=out/f"{level}_splits";d.mkdir();frame.to_csv(d/"test.csv",index=False)
        x=b.encode(frame,features);lvl={"rows":len(frame),"runs":int(frame.run_id.nunique()),"features":features,"models":{}}
        for name in ("random_forest","xgboost"):
            model=joblib.load(paths[level,name]);enc=joblib.load(modeldir/level/"label_encoder.joblib")
            lvl["models"][name]={"test":b.evaluate(model,x,frame,enc)}
            r=lvl["models"][name]["test"]["run_level"]
            print(f"{level}/{name}: run accuracy={r['accuracy']:.4f}; macro-F1={r['f1_macro']:.4f}",flush=True)
        metrics["levels"][level]=lvl
        (out/"final_test_metrics.partial.json").write_text(json.dumps(metrics,indent=2)+"\n",encoding="utf-8")
    if any(sha(p)!=hashes[f"{level}/{name}"] for (level,name),p in paths.items()):raise ValueError("Frozen model changed during test")
    with (out/"run_split_manifest.csv").open("w",newline="",encoding="utf-8") as f:
        cols=["generation","run_id","label","profile_id","planned_split"];w=csv.DictWriter(f,fieldnames=cols);w.writeheader();w.writerows(assignments)
    (out/"qc_report.json").write_text(json.dumps({"runs":160,"runs_per_class":dict(counts),"excluded_original_bad_post_profiles":sorted(BAD_POST),"replacement_count":6,"run_leakage":False,"models_retrained":False,"final_test_features_opened_once":True},indent=2)+"\n",encoding="utf-8")
    (out/"final_test_metrics.json").write_text(json.dumps(metrics,indent=2)+"\n",encoding="utf-8")
    (out/"final_test_metrics.partial.json").unlink(missing_ok=True)
    (out/"RUN_ONCE_IN_PROGRESS.txt").rename(out/"RUN_ONCE_COMPLETE.txt")
    files=sorted(p for p in out.rglob("*") if p.is_file() and p.name!="SHA256SUMS.txt")
    (out/"SHA256SUMS.txt").write_text("".join(f"{sha(p)}  {p.relative_to(out).as_posix()}\n" for p in files),encoding="utf-8")
    print("FINAL-TEST ONE-SHOT COMPLETE. Do not retrain or retune on this holdout.",flush=True)
    print("Metrics:",out/"final_test_metrics.json",flush=True)
if __name__=="__main__":
    try:main()
    except Exception as e:print(f"STOP: {type(e).__name__}: {e}",file=sys.stderr);raise
