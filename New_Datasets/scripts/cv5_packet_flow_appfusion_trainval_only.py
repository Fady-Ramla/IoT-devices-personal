#!/usr/bin/env python3
"""Five-fold run-stratified XGBoost CV: network-only vs app-fusion.

Uses only the V2 train.csv + validation.csv files (80 development runs),
re-stratifies at run level into 5 folds (4 runs/class/fold), and reports
out-of-fold run-level metrics for Packet and Flow with/without application
aggregates. Never opens test.csv or final_test raw data.
"""
from __future__ import annotations
import argparse, json, sys
from collections import defaultdict
from pathlib import Path
import numpy as np
import pandas as pd

import train_packet_flow_appfusion_trainval_only as fusion

LABELS=["Malicious_POST","Normal","Port_Scan","SYN_Flood"]


def run_weights(frame):
    ids=frame.run_id.astype(str);counts=ids.value_counts()
    w=ids.map(lambda x:1.0/counts[x]).to_numpy(dtype=float);w*=len(w)/w.sum();return w

def run_level_probabilities(model,x,frame):
    probs=pd.DataFrame(model.predict_proba(x),index=frame.index,columns=model.classes_)
    probs["run_id"]=frame.run_id.astype(str).to_numpy()
    mean=probs.groupby("run_id",sort=True).mean()
    actual=frame.assign(_rid=frame.run_id.astype(str)).groupby("_rid",sort=True).label.first().loc[mean.index]
    return mean,actual

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dataset-dir",type=Path,required=True)
    ap.add_argument("--project-root",type=Path,default=Path.cwd())
    ap.add_argument("--output",type=Path,required=True)
    ap.add_argument("--seed",type=int,default=42)
    a=ap.parse_args();ds=a.dataset_dir.resolve();root=a.project_root.resolve();out=a.output.resolve()
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
    from sklearn.model_selection import StratifiedKFold
    if out.exists():raise SystemExit(f"STOP: refusing to overwrite existing report: {out}")
    split_manifest=ds/"run_split_manifest.csv"
    if not split_manifest.is_file():raise SystemExit(f"STOP: missing split manifest: {split_manifest}")
    assignments=fusion.read_csv(split_manifest)
    if len(assignments)!=80 or len({r['run_id'] for r in assignments})!=80:raise SystemExit("STOP: expected exactly 80 unique development runs")
    if any(r.get("planned_split") not in {"train","validation"} for r in assignments):raise SystemExit("STOP: manifest includes non-development split")
    for label in LABELS:
        n=sum(r["label"]==label for r in assignments)
        if n!=20:raise SystemExit(f"STOP: expected 20 {label} runs in dev data, got {n}")
    run_ids=[r["run_id"] for r in assignments]
    app,events=fusion.app_aggregate(run_ids,root)
    for r in assignments:
        if r["label"] in {"Normal","Malicious_POST"} and not events.get(r["run_id"]):
            raise SystemExit(f"STOP: missing expected verified app telemetry for {r['profile_id']}")
    all_rows={}
    for level in ("packet","flow"):
        folder=ds/f"{level}_splits"
        train=pd.read_csv(folder/"train.csv");val=pd.read_csv(folder/"validation.csv")
        frame=pd.concat([train,val],ignore_index=True)
        if set(frame.run_id.astype(str))!=set(run_ids):raise SystemExit(f"STOP: {level} rows don't match the 80-run manifest")
        if set(frame.label.astype(str))!=set(LABELS):raise SystemExit(f"STOP: {level} labels invalid")
        frame[ fusion.APP_FEATURES ]=frame.run_id.astype(str).map(app).apply(pd.Series)[fusion.APP_FEATURES]
        all_rows[level]=frame
    run_df=pd.DataFrame(assignments).sort_values("run_id").reset_index(drop=True)
    splitter=StratifiedKFold(n_splits=5,shuffle=True,random_state=a.seed)
    folds=list(splitter.split(run_df.run_id,run_df.label))
    for i,(tr,va) in enumerate(folds,1):
        trids=set(run_df.iloc[tr].run_id.astype(str));vaids=set(run_df.iloc[va].run_id.astype(str))
        if trids&vaids:raise SystemExit("STOP: run leakage across CV folds")
        for label in LABELS:
            if sum(run_df.iloc[j].label==label for j in va)!=4:raise SystemExit("STOP: fold does not contain exactly 4 runs/class")
    from xgboost import XGBClassifier
    report={"purpose":"5-fold run-stratified development CV; final test not opened.","seed":a.seed,"folds":5,"runs_per_validation_fold_per_class":4,"models":{"xgboost":{"n_estimators":300,"max_depth":3,"learning_rate":0.05,"subsample":0.9,"colsample_bytree":0.9,"min_child_weight":2,"reg_lambda":1.0,"tree_method":"hist"}},"variants":{}}
    for level,net_features in (("packet",fusion.PACKET_FEATURES),("flow",fusion.FLOW_FEATURES)):
        frame=all_rows[level]
        for variant,cols in (("network_only",net_features),("network_plus_app",net_features+fusion.APP_FEATURES)):
            y_oof={};fold_scores=[];importances=[]
            for fold_idx,(tr_idx,va_idx) in enumerate(folds,1):
                trids=set(run_df.iloc[tr_idx].run_id.astype(str));vaids=set(run_df.iloc[va_idx].run_id.astype(str))
                tr=frame[frame.run_id.astype(str).isin(trids)].copy();va=frame[frame.run_id.astype(str).isin(vaids)].copy()
                xtr=fusion.encode(tr,cols);xva=fusion.encode(va,cols)
                enc_classes=LABELS;label_to_id={label:i for i,label in enumerate(enc_classes)}
                ytr=tr.label.astype(str).map(label_to_id).to_numpy();yva=va.label.astype(str).map(label_to_id).to_numpy()
                model=XGBClassifier(n_estimators=300,max_depth=3,learning_rate=0.05,subsample=0.9,colsample_bytree=0.9,min_child_weight=2,reg_lambda=1.0,objective="multi:softprob",eval_metric="mlogloss",random_state=a.seed,n_jobs=-1,tree_method="hist")
                model.fit(xtr,ytr,sample_weight=run_weights(tr),eval_set=[(xva,yva)],verbose=False)
                mean,actual=run_level_probabilities(model,xva,va)
                preds=np.asarray(LABELS)[mean.to_numpy().argmax(axis=1)]
                for rid,truth,pred in zip(mean.index,actual.to_numpy(),preds):
                    if rid in y_oof:raise SystemExit(f"STOP: duplicate OOF prediction for run {rid}")
                    y_oof[rid]={"actual":str(truth),"predicted":str(pred),"fold":fold_idx}
                fold_scores.append({"fold":fold_idx,"runs":int(len(actual)),"accuracy":float(accuracy_score(actual.to_numpy(),preds)),"macro_f1":float(f1_score(actual.to_numpy(),preds,labels=LABELS,average="macro",zero_division=0))})
                if variant=="network_plus_app":importances.append(model.feature_importances_)
            if len(y_oof)!=80:raise SystemExit(f"STOP: expected 80 OOF predictions for {level}/{variant}, got {len(y_oof)}")
            ytrue=np.asarray([y_oof[rid]["actual"] for rid in sorted(y_oof)]);ypred=np.asarray([y_oof[rid]["predicted"] for rid in sorted(y_oof)])
            result={"out_of_fold_runs":80,"accuracy":float(accuracy_score(ytrue,ypred)),"macro_f1":float(f1_score(ytrue,ypred,labels=LABELS,average="macro",zero_division=0)),"confusion_matrix":confusion_matrix(ytrue,ypred,labels=LABELS).tolist(),"classification_report":classification_report(ytrue,ypred,labels=LABELS,target_names=LABELS,output_dict=True,zero_division=0),"fold_metrics":fold_scores,"predictions":[{"run_id":rid,**y_oof[rid]} for rid in sorted(y_oof)]}
            if importances:
                avg=np.mean(importances,axis=0);result["mean_feature_importance"]=[{"feature":f,"importance":float(v)} for f,v in sorted(zip(cols,avg),key=lambda x:x[1],reverse=True)]
            report["variants"].setdefault(level,{})[variant]=result
            print(f"{level}/{variant}: OOF run acc={result['accuracy']:.4f}, macro-F1={result['macro_f1']:.4f}; fold F1={[round(x['macro_f1'],4) for x in fold_scores]}",flush=True)
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print("Saved CV report:",out)
    print("No test split/raw test rows read; each of 80 development runs received one out-of-fold prediction.")

if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"CV STOP: {type(e).__name__}: {e}",file=sys.stderr);raise
