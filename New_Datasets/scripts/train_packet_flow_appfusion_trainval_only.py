#!/usr/bin/env python3
"""Exploratory Packet/Flow + application telemetry fusion (TRAIN+VALIDATION only).

Broadcasts run-level aggregates from verified application events onto each
packet/flow observation, then uses the project's exact encoding, equal-run
weights, RF/XGBoost settings, and mean-probability run aggregation. It opens
only train.csv, validation.csv, the run split manifest, and application logs
for those selected run IDs; never opens final_test data.
"""
from __future__ import annotations
import argparse, csv, json, sys
from collections import Counter, defaultdict
from pathlib import Path
import numpy as np
import pandas as pd

LABELS={"Normal","Malicious_POST","Port_Scan","SYN_Flood"}
FLOW_FEATURES=["protocol","src_port","dst_port","packet_count","byte_count","packet_rate","byte_rate","duration_sec","avg_packet_size","syn_count","ack_count","rst_count","fin_count","syn_ack_ratio","rst_ratio","unique_dst_ports","failed_connection_count","tcp_fraction","udp_fraction","icmp_fraction"]
PACKET_FEATURES=["protocol","src_port","dst_port","packet_length","tcp_syn","tcp_ack","tcp_rst","tcp_fin","icmp_type","arp_operation"]
APP_FEATURES=["app_event_count","app_post_count","app_get_count","app_auth_count","app_iot_api_count","app_health_count","app_status_200_count","app_status_202_count","app_status_401_count","app_other_status_count","app_post_ratio","app_auth_ratio","app_401_ratio"]


def read_csv(path):
    with path.open(newline="",encoding="utf-8") as f:return list(csv.DictReader(f))

def app_aggregate(run_ids, raw_root):
    selected=set(map(str,run_ids)); events=defaultdict(list); paths_seen=Counter(); ids_seen=defaultdict(set)
    for directory in (raw_root/"New_Datasets"/"raw").glob("application*"):
        if not directory.is_dir():continue
        for path in directory.rglob("*.csv"):
            if path.stem not in selected:continue
            paths_seen[path.stem]+=1
            for e in read_csv(path):
                rid=str(e.get("run_id",path.stem))
                if rid!=path.stem:raise ValueError(f"run_id mismatch in application telemetry {path}")
                oid=e.get("application_observation_id","")
                if oid and oid in ids_seen[rid]:raise ValueError(f"duplicate application_observation_id {oid} in {rid}")
                if oid:ids_seen[rid].add(oid)
                events[rid].append(e)
    if any(n>1 for n in paths_seen.values()):
        # Multiple raw app dirs per run could be accidental duplicate capture; fail closed.
        raise ValueError("More than one application telemetry file found for a selected run")
    features={}
    for rid in selected:
        es=events[rid];n=len(es)
        methods=Counter((e.get("http_method") or "").strip().upper() for e in es)
        routes=Counter((e.get("route_category") or "").strip().lower() for e in es)
        statuses=Counter((e.get("response_status") or "").strip() for e in es)
        values={
          "app_event_count":n,
          "app_post_count":methods["POST"],
          "app_get_count":methods["GET"],
          "app_auth_count":routes["auth"],
          "app_iot_api_count":routes["iot_api"],
          "app_health_count":routes["health"],
          "app_status_200_count":statuses["200"],
          "app_status_202_count":statuses["202"],
          "app_status_401_count":statuses["401"],
          "app_other_status_count":sum(c for s,c in statuses.items() if s not in {"200","202","401"}),
        }
        denom=max(n,1)
        values.update({"app_post_ratio":values["app_post_count"]/denom,"app_auth_ratio":values["app_auth_count"]/denom,"app_401_ratio":values["app_status_401_count"]/denom})
        features[rid]=values
    return features,events

def encode(df, columns):
    missing=sorted(set(columns)-set(df.columns))
    if missing:raise ValueError(f"Missing model features: {missing}")
    x=df.loc[:,columns].copy()
    if "protocol" in x.columns:
        x["protocol"]=(x["protocol"].astype(str).str.strip().str.lower().map({"tcp":6,"udp":17,"icmp":1,"icmpv6":58,"igmp":2,"other":0,"unknown":0}).fillna(0))
    for c in x.columns:x[c]=pd.to_numeric(x[c],errors="coerce").fillna(0)
    return x

def weights(frame):
    ids=frame.run_id.astype(str);counts=ids.value_counts();w=ids.map(lambda r:1.0/counts[r]).to_numpy(dtype=float);w*=len(w)/w.sum();return w

def evaluate(model,x,frame,encoder):
    from sklearn.metrics import accuracy_score,classification_report,confusion_matrix,f1_score,precision_score,recall_score
    y=encoder.transform(frame.label.astype(str));pred=model.predict(x);order=list(range(len(encoder.classes_)))
    row={"rows":int(len(frame)),"accuracy":float(accuracy_score(y,pred)),"precision_macro":float(precision_score(y,pred,average="macro",zero_division=0)),"recall_macro":float(recall_score(y,pred,average="macro",zero_division=0)),"f1_macro":float(f1_score(y,pred,average="macro",zero_division=0)),"confusion_matrix":confusion_matrix(y,pred,labels=order).tolist(),"classification_report":classification_report(y,pred,labels=order,target_names=encoder.classes_.tolist(),output_dict=True,zero_division=0)}
    probs=pd.DataFrame(model.predict_proba(x),index=frame.index,columns=model.classes_);probs["run_id"]=frame.run_id.astype(str).to_numpy();mean=probs.groupby("run_id",sort=True).mean()
    actual=frame.assign(_rid=frame.run_id.astype(str)).groupby("_rid",sort=True).label.first().loc[mean.index]
    pred_run=encoder.inverse_transform(mean.to_numpy().argmax(axis=1));true_run=actual.to_numpy()
    run={"runs":int(len(true_run)),"accuracy":float(accuracy_score(true_run,pred_run)),"precision_macro":float(precision_score(true_run,pred_run,average="macro",zero_division=0)),"recall_macro":float(recall_score(true_run,pred_run,average="macro",zero_division=0)),"f1_macro":float(f1_score(true_run,pred_run,average="macro",zero_division=0)),"confusion_matrix":confusion_matrix(true_run,pred_run,labels=encoder.classes_.tolist()).tolist(),"classification_report":classification_report(true_run,pred_run,labels=encoder.classes_.tolist(),target_names=encoder.classes_.tolist(),output_dict=True,zero_division=0),"predictions":[{"run_id":str(r),"actual":str(a),"predicted":str(p)} for r,a,p in zip(mean.index,true_run,pred_run)]}
    return {"row_level":row,"run_level":run}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset-dir",type=Path,required=True)
    ap.add_argument("--project-root",type=Path,default=Path.cwd())
    ap.add_argument("--output-dir",type=Path,required=True)
    ap.add_argument("--level",choices=("packet","flow"),required=True)
    ap.add_argument("--seed",type=int,default=42)
    a=ap.parse_args();ds=a.dataset_dir.resolve();root=a.project_root.resolve();out=a.output_dir.resolve()
    if out.exists() and any(out.iterdir()):raise SystemExit(f"STOP: output directory is nonempty: {out}")
    split_manifest=ds/"run_split_manifest.csv"
    if not split_manifest.is_file():raise SystemExit(f"STOP: missing {split_manifest}")
    assignments=read_csv(split_manifest)
    if any(r.get("planned_split") not in {"train","validation"} for r in assignments):raise SystemExit("STOP: split manifest contains a non-development split")
    ids=[r["run_id"] for r in assignments]
    if len(ids)!=80 or len(set(ids))!=80:raise SystemExit(f"STOP: expected 80 unique train/validation run IDs, got {len(ids)}/{len(set(ids))}")
    by_id={r["run_id"]:r for r in assignments}
    for label in LABELS:
        for split,n in (("train",16),("validation",4)):
            count=sum(r["label"]==label and r["planned_split"]==split for r in assignments)
            if count!=n:raise SystemExit(f"STOP: {label}/{split} has {count} runs; expected {n}")
    app,events=app_aggregate(ids,root)
    # All app-generating Normal and Malicious_POST runs in the repaired development set must have observed telemetry.
    for r in assignments:
        if r["label"] in {"Normal","Malicious_POST"} and not events.get(r["run_id"]):
            raise SystemExit(f"STOP: expected verified application events missing for {r['profile_id']} ({r['run_id']})")
    level_dir=ds/f"{a.level}_splits";tr=pd.read_csv(level_dir/"train.csv");va=pd.read_csv(level_dir/"validation.csv")
    for name,frame in (("train",tr),("validation",va)):
        if set(frame.label.astype(str))!=LABELS:raise SystemExit(f"STOP: {name} labels differ from expected classes")
        allowed={r["run_id"] for r in assignments if r["planned_split"]==name}
        if set(frame.run_id.astype(str))!=allowed:raise SystemExit(f"STOP: {name} rows do not match run_split_manifest")
        if frame.groupby("run_id").label.nunique().gt(1).any():raise SystemExit(f"STOP: conflicting labels in {name}")
        frame[APP_FEATURES]=frame.run_id.astype(str).map(app).apply(pd.Series)[APP_FEATURES]
    # Assignment matrix and feature order are fixed before evaluation; no test files are opened.
    net=FLOW_FEATURES if a.level=="flow" else PACKET_FEATURES
    cols=net+APP_FEATURES
    xtr=encode(tr,cols);xva=encode(va,cols)
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    from xgboost import XGBClassifier
    import joblib
    enc=LabelEncoder().fit(tr.label.astype(str));ytr=enc.transform(tr.label.astype(str));yva=enc.transform(va.label.astype(str));w=weights(tr)
    print(f"APP-FUSION TRAIN/VAL ONLY level={a.level}; network features={len(net)}; app features={len(APP_FEATURES)}; train rows/runs={len(tr)}/{tr.run_id.nunique()}; val={len(va)}/{va.run_id.nunique()}",flush=True)
    print("Telemetry coverage:", {label:sum(1 for r in assignments if r['label']==label and events.get(r['run_id'])) for label in sorted(LABELS)},flush=True)
    rf=RandomForestClassifier(n_estimators=400,random_state=a.seed,n_jobs=-1)
    rf.fit(xtr,ytr,sample_weight=w)
    xgb=XGBClassifier(n_estimators=300,max_depth=3,learning_rate=0.05,subsample=0.9,colsample_bytree=0.9,min_child_weight=2,reg_lambda=1.0,objective="multi:softprob",eval_metric="mlogloss",random_state=a.seed,n_jobs=-1,tree_method="hist")
    xgb.fit(xtr,ytr,sample_weight=w,eval_set=[(xva,yva)],verbose=False)
    out.mkdir(parents=True,exist_ok=True)
    res={"purpose":"Exploratory Packet/Flow+application telemetry fusion; train+validation only; no test data opened.","level":a.level,"network_features":net,"application_features":APP_FEATURES,"classes":enc.classes_.tolist(),"seed":a.seed,"weighting":"equal total sample weight per run_id","telemetry_coverage_by_label":{lab:sum(1 for r in assignments if r["label"]==lab and events.get(r["run_id"])) for lab in sorted(LABELS)},"models":{}}
    for name,model in (("random_forest",rf),("xgboost",xgb)):
        res["models"][name]={"train":evaluate(model,xtr,tr,enc),"validation":evaluate(model,xva,va,enc)}
        joblib.dump(model,out/f"{name}.joblib")
    joblib.dump(enc,out/"label_encoder.joblib")
    (out/"training_metrics_appfusion_trainval_only.json").write_text(json.dumps(res,indent=2)+"\n",encoding="utf-8")
    (out/"feature_columns.json").write_text(json.dumps({"level":a.level,"network_features":net,"application_features":APP_FEATURES},indent=2)+"\n",encoding="utf-8")
    for name,m in res["models"].items():
        tv=m["train"]["run_level"];vv=m["validation"]["run_level"]
        print(f"{name}: train run acc/F1={tv['accuracy']:.4f}/{tv['f1_macro']:.4f}; validation run acc/F1={vv['accuracy']:.4f}/{vv['f1_macro']:.4f}",flush=True)
    print("Exploratory only: validation has four runs/class; keep final_test sealed until model and protocol are frozen.")

if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"APP-FUSION STOP: {type(e).__name__}: {e}",file=sys.stderr);raise
