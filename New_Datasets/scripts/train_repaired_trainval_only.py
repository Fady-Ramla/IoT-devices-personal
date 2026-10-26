#!/usr/bin/env python3
"""Train/evaluate repaired Packet or Flow models using TRAIN+VALIDATION only.

Matches the project's train_models.py encoding, equal-run sample weights, model
hyperparameters, and mean-probability run aggregation. Never opens test.csv.
Validation is for model selection only, not final performance claims.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
import numpy as np
import pandas as pd

FLOW_FEATURES=["protocol","src_port","dst_port","packet_count","byte_count","packet_rate","byte_rate","duration_sec","avg_packet_size","syn_count","ack_count","rst_count","fin_count","syn_ack_ratio","rst_ratio","unique_dst_ports","failed_connection_count","tcp_fraction","udp_fraction","icmp_fraction"]
PACKET_FEATURES=["protocol","src_port","dst_port","packet_length","tcp_syn","tcp_ack","tcp_rst","tcp_fin","icmp_type","arp_operation"]
LABELS={"Normal","Malicious_POST","Port_Scan","SYN_Flood"}


def encode(frame,columns):
    missing=sorted(set(columns)-set(frame.columns))
    if missing:raise ValueError(f"Missing model features: {missing}")
    x=frame.loc[:,columns].copy()
    if "protocol" in x.columns:
        x["protocol"]=(x["protocol"].astype(str).str.strip().str.lower().map({"tcp":6,"udp":17,"icmp":1,"icmpv6":58,"igmp":2,"other":0,"unknown":0}).fillna(0))
    for col in x.columns:x[col]=pd.to_numeric(x[col],errors="coerce").fillna(0)
    return x


def equal_run_weights(frame):
    ids=frame["run_id"].astype(str);counts=ids.value_counts()
    w=ids.map(lambda rid:1.0/counts[rid]).to_numpy(dtype=float,copy=True)
    w*=len(w)/w.sum()
    return w


def evaluate(model,x,frame,encoder):
    from sklearn.metrics import accuracy_score,classification_report,confusion_matrix,f1_score,precision_score,recall_score
    y=encoder.transform(frame["label"].astype(str));pred=model.predict(x);ids=list(range(len(encoder.classes_)))
    row={"rows":int(len(frame)),"runs":int(frame.run_id.nunique()),"accuracy":float(accuracy_score(y,pred)),"precision_macro":float(precision_score(y,pred,average="macro",zero_division=0)),"recall_macro":float(recall_score(y,pred,average="macro",zero_division=0)),"f1_macro":float(f1_score(y,pred,average="macro",zero_division=0)),"confusion_matrix":confusion_matrix(y,pred,labels=ids).tolist(),"classification_report":classification_report(y,pred,labels=ids,target_names=encoder.classes_.tolist(),output_dict=True,zero_division=0)}
    probs=pd.DataFrame(model.predict_proba(x),index=frame.index,columns=model.classes_)
    probs["run_id"]=frame["run_id"].astype(str).to_numpy()
    mean=probs.groupby("run_id",sort=True).mean()
    actual=frame.assign(_rid=frame["run_id"].astype(str)).groupby("_rid",sort=True)["label"].first().loc[mean.index]
    run_pred=encoder.inverse_transform(mean.to_numpy().argmax(axis=1));run_true=actual.to_numpy()
    run={"runs":int(len(run_true)),"aggregation":"mean class probability across observations in each run","accuracy":float(accuracy_score(run_true,run_pred)),"precision_macro":float(precision_score(run_true,run_pred,average="macro",zero_division=0)),"recall_macro":float(recall_score(run_true,run_pred,average="macro",zero_division=0)),"f1_macro":float(f1_score(run_true,run_pred,average="macro",zero_division=0)),"confusion_matrix":confusion_matrix(run_true,run_pred,labels=encoder.classes_.tolist()).tolist(),"classification_report":classification_report(run_true,run_pred,labels=encoder.classes_.tolist(),target_names=encoder.classes_.tolist(),output_dict=True,zero_division=0),"predictions":[{"run_id":str(rid),"actual":str(a),"predicted":str(p)} for rid,a,p in zip(mean.index,run_true,run_pred)]}
    return {"row_level":row,"run_level":run}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--split-dir",type=Path,required=True)
    ap.add_argument("--run-split-manifest",type=Path,required=True)
    ap.add_argument("--output-dir",type=Path,required=True)
    ap.add_argument("--level",choices=("packet","flow"),required=True)
    ap.add_argument("--seed",type=int,default=42)
    args=ap.parse_args()
    for p in (args.split_dir/"train.csv",args.split_dir/"validation.csv",args.run_split_manifest):
        if not p.is_file():raise SystemExit(f"STOP: required input missing: {p}")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):raise SystemExit(f"STOP: output exists and is nonempty: {args.output_dir}")
    train=pd.read_csv(args.split_dir/"train.csv");val=pd.read_csv(args.split_dir/"validation.csv")
    required={"run_id","label"}
    for name,frame in (("train",train),("validation",val)):
        if frame.empty or not required.issubset(frame.columns):raise SystemExit(f"STOP: invalid/empty {name} split")
        if frame[list(required)].isna().any().any():raise SystemExit(f"STOP: missing run_id/label in {name}")
        if set(frame.label.astype(str))!=LABELS:raise SystemExit(f"STOP: {name} labels differ from expected classes")
        if frame.groupby("run_id").label.nunique().gt(1).any():raise SystemExit(f"STOP: conflicting labels in {name}")
    train_ids=set(train.run_id.astype(str));val_ids=set(val.run_id.astype(str))
    if train_ids&val_ids:raise SystemExit("STOP: run_id leakage across train and validation")
    sm=pd.read_csv(args.run_split_manifest,dtype={"run_id":str})
    if not {"run_id","label","planned_split","profile_id"}.issubset(sm.columns):raise SystemExit("STOP: malformed run split manifest")
    if sm.run_id.duplicated().any() or sm.profile_id.duplicated().any():raise SystemExit("STOP: duplicate run/profile in split manifest")
    for name,frame in (("train",train),("validation",val)):
        want="train" if name=="train" else "validation"
        assigns=sm[sm.planned_split==want]
        observed=set(frame.run_id.astype(str));expected=set(assigns.run_id.astype(str))
        if observed!=expected:raise SystemExit(f"STOP: {name} CSV run IDs do not match split manifest; missing={len(expected-observed)}, extra={len(observed-expected)}")
        pair=set(zip(frame.run_id.astype(str),frame.label.astype(str)))
        manifest_pairs=set(zip(assigns.run_id.astype(str),assigns.label.astype(str)))
        if pair!=manifest_pairs:raise SystemExit(f"STOP: {name} labels disagree with run split manifest")
        runs=assigns[["run_id","label"]].drop_duplicates().groupby("label").run_id.nunique().to_dict()
        expected_n=16 if name=="train" else 4
        if any(int(runs.get(label,0))!=expected_n for label in LABELS):raise SystemExit(f"STOP: {name} does not have {expected_n} runs/class: {runs}")
    columns=FLOW_FEATURES if args.level=="flow" else PACKET_FEATURES
    xtr=encode(train,columns);xva=encode(val,columns)
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    from xgboost import XGBClassifier
    import joblib
    enc=LabelEncoder().fit(train.label.astype(str));ytr=enc.transform(train.label.astype(str));yva=enc.transform(val.label.astype(str));weights=equal_run_weights(train)
    print(f"Training level={args.level}; features={len(columns)}; train rows/runs={len(train)}/{train.run_id.nunique()}; validation rows/runs={len(val)}/{val.run_id.nunique()}",flush=True)
    print("Train/validation runs per class:",train[["run_id","label"]].drop_duplicates().groupby("label").run_id.nunique().to_dict(),val[["run_id","label"]].drop_duplicates().groupby("label").run_id.nunique().to_dict(),flush=True)
    print("Weights: equal total contribution per run; no test split loaded.",flush=True)
    rf=RandomForestClassifier(n_estimators=400,random_state=args.seed,n_jobs=-1)
    rf.fit(xtr,ytr,sample_weight=weights)
    xgb=XGBClassifier(n_estimators=300,max_depth=3,learning_rate=0.05,subsample=0.9,colsample_bytree=0.9,min_child_weight=2,reg_lambda=1.0,objective="multi:softprob",eval_metric="mlogloss",random_state=args.seed,n_jobs=-1,tree_method="hist")
    xgb.fit(xtr,ytr,sample_weight=weights,eval_set=[(xva,yva)],verbose=False)
    args.output_dir.mkdir(parents=True,exist_ok=True)
    results={"purpose":"Train/validation model development only. No test data loaded, evaluated, or used.","level":args.level,"features":columns,"classes":enc.classes_.tolist(),"seed":args.seed,"training_weighting":"equal total sample weight per run_id","hyperparameters":{"random_forest":{"n_estimators":400,"random_state":args.seed,"n_jobs":-1},"xgboost":{"n_estimators":300,"max_depth":3,"learning_rate":0.05,"subsample":0.9,"colsample_bytree":0.9,"min_child_weight":2,"reg_lambda":1.0,"random_state":args.seed,"tree_method":"hist"}},"split_summary":{n:{"rows":int(len(f)),"runs":int(f.run_id.nunique()),"runs_per_label":f[["run_id","label"]].drop_duplicates().groupby("label").run_id.nunique().to_dict(),"rows_per_label":f.label.value_counts().to_dict()} for n,f in (("train",train),("validation",val))},"models":{}}
    for name,model in (("random_forest",rf),("xgboost",xgb)):
        results["models"][name]={"train":evaluate(model,xtr,train,enc),"validation":evaluate(model,xva,val,enc)}
        joblib.dump(model,args.output_dir/f"{name}.joblib")
    joblib.dump(enc,args.output_dir/"label_encoder.joblib")
    (args.output_dir/"feature_columns.json").write_text(json.dumps({"level":args.level,"features":columns},indent=2)+"\n",encoding="utf-8")
    (args.output_dir/"training_metrics_trainval_only.json").write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
    print("Saved train/validation-only models and metrics to",args.output_dir,flush=True)
    for name,m in results["models"].items():
        tr=m["train"]["run_level"];va=m["validation"]["run_level"]
        print(f"{name}: train run acc/F1={tr['accuracy']:.4f}/{tr['f1_macro']:.4f}; validation run acc/F1={va['accuracy']:.4f}/{va['f1_macro']:.4f}",flush=True)
    print("Caution: validation has only 4 runs/class; treat results as exploratory, not final generalization.")

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print(f"TRAIN STOP: {type(exc).__name__}: {exc}",file=sys.stderr);raise
