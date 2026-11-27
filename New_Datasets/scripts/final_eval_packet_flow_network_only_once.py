#!/usr/bin/env python3
"""One-shot final evaluation of network-only Packet and Flow models.

Training source: repaired development V2 train+validation only (80 runs).
Test source: isolated V3 final_test only (80 runs). No app telemetry is used.
Uses the standard project features, encoding, equal-run sample weights, RF/
XGBoost hyperparameters, and run-level mean-probability aggregation. Refuses
existing output and enforces zero run leakage. Treat results as final; do not
retune against this test set.
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
import numpy as np
import pandas as pd

FLOW_FEATURES=["protocol","src_port","dst_port","packet_count","byte_count","packet_rate","byte_rate","duration_sec","avg_packet_size","syn_count","ack_count","rst_count","fin_count","syn_ack_ratio","rst_ratio","unique_dst_ports","failed_connection_count","tcp_fraction","udp_fraction","icmp_fraction"]
PACKET_FEATURES=["protocol","src_port","dst_port","packet_length","tcp_syn","tcp_ack","tcp_rst","tcp_fin","icmp_type","arp_operation"]
LABELS={"Malicious_POST","Normal","Port_Scan","SYN_Flood"}


def encode(frame,columns):
    missing=sorted(set(columns)-set(frame.columns))
    if missing:raise ValueError(f"Missing required features: {missing}")
    x=frame.loc[:,columns].copy()
    if "protocol" in x.columns:
        x["protocol"]=(x["protocol"].astype(str).str.strip().str.lower().map({"tcp":6,"udp":17,"icmp":1,"icmpv6":58,"igmp":2,"other":0,"unknown":0}).fillna(0))
    for c in x.columns:x[c]=pd.to_numeric(x[c],errors="coerce").fillna(0)
    if not np.isfinite(x.to_numpy(dtype=float)).all():raise ValueError("Non-finite encoded feature values")
    return x

def validate_frame(frame,name,expected_runs=20):
    if frame.empty:raise ValueError(f"{name} is empty")
    if frame[["run_id","label","observation_id"]].isna().any().any():raise ValueError(f"{name} has missing run/label/observation IDs")
    if set(frame.label.astype(str))!=LABELS:raise ValueError(f"{name} label set mismatch: {set(frame.label.astype(str))}")
    if frame.groupby("run_id").label.nunique().gt(1).any():raise ValueError(f"{name} contains conflicting labels within a run")
    if frame.observation_id.astype(str).duplicated().any():raise ValueError(f"{name} has duplicate observation_id")
    if frame.duplicated().any():raise ValueError(f"{name} has exact duplicate rows")
    run_labels=frame[["run_id","label"]].drop_duplicates()
    if len(run_labels)!=expected_runs:raise ValueError(f"{name} has {len(run_labels)} runs; expected {expected_runs}")
    by_label=run_labels.label.value_counts().to_dict()
    if by_label!={label:20 for label in LABELS}:raise ValueError(f"{name} expected 20 runs/class, found {by_label}")

def equal_run_weights(frame):
    ids=frame.run_id.astype(str);counts=ids.value_counts()
    w=ids.map(lambda rid:1.0/counts[rid]).to_numpy(dtype=float,copy=True)
    w*=len(w)/w.sum()
    return w

def wilson(success,total,z=1.959963984540054):
    if total<=0:return [None,None]
    p=success/total;den=1+z*z/total
    center=(p+z*z/(2*total))/den
    half=z*((p*(1-p)/total+z*z/(4*total*total))**0.5)/den
    return [max(0.0,center-half),min(1.0,center+half)]

def evaluate(model,x,frame,encoder):
    from sklearn.metrics import accuracy_score,classification_report,confusion_matrix,f1_score,precision_score,recall_score
    y=encoder.transform(frame.label.astype(str));pred=model.predict(x);ids=list(range(len(encoder.classes_)))
    row={"rows":int(len(frame)),"accuracy":float(accuracy_score(y,pred)),"precision_macro":float(precision_score(y,pred,average="macro",zero_division=0)),"recall_macro":float(recall_score(y,pred,average="macro",zero_division=0)),"f1_macro":float(f1_score(y,pred,average="macro",zero_division=0)),"f1_weighted":float(f1_score(y,pred,average="weighted",zero_division=0)),"confusion_matrix":confusion_matrix(y,pred,labels=ids).tolist(),"classification_report":classification_report(y,pred,labels=ids,target_names=encoder.classes_.tolist(),output_dict=True,zero_division=0)}
    prob=pd.DataFrame(model.predict_proba(x),index=frame.index,columns=model.classes_);prob["run_id"]=frame.run_id.astype(str).to_numpy()
    mean=prob.groupby("run_id",sort=True).mean()
    actual=frame.assign(_rid=frame.run_id.astype(str)).groupby("_rid",sort=True).label.first().loc[mean.index]
    ytrue=actual.to_numpy();ypred=encoder.inverse_transform(mean.to_numpy().argmax(axis=1))
    run={"runs":int(len(ytrue)),"aggregation":"mean class probability across observations in each run","accuracy":float(accuracy_score(ytrue,ypred)),"accuracy_wilson_95_ci":wilson(int((ytrue==ypred).sum()),len(ytrue)),"precision_macro":float(precision_score(ytrue,ypred,average="macro",zero_division=0)),"recall_macro":float(recall_score(ytrue,ypred,average="macro",zero_division=0)),"f1_macro":float(f1_score(ytrue,ypred,average="macro",zero_division=0)),"confusion_matrix":confusion_matrix(ytrue,ypred,labels=encoder.classes_.tolist()).tolist(),"classification_report":classification_report(ytrue,ypred,labels=encoder.classes_.tolist(),target_names=encoder.classes_.tolist(),output_dict=True,zero_division=0),"predictions":[{"run_id":str(rid),"actual":str(t),"predicted":str(p)} for rid,t,p in zip(mean.index,ytrue,ypred)]}
    return {"row_level":row,"run_level":run}

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--development-dir",type=Path,required=True,help="V2 repaired package containing only train and validation")
    ap.add_argument("--final-package-dir",type=Path,required=True,help="V3 original package containing isolated test.csv")
    ap.add_argument("--output-dir",type=Path,required=True)
    ap.add_argument("--seed",type=int,default=42)
    ap.add_argument("--resume-pre-score-failure",action="store_true",help="Resume only if output contains exactly the marker from a failure before model fitting/scoring")
    a=ap.parse_args();dev=a.development_dir.resolve();final=a.final_package_dir.resolve();out=a.output_dir.resolve()
    if out.exists():
        if not a.resume_pre_score_failure:raise SystemExit(f"STOP: output path already exists; refusing overwrite: {out}")
        names={p.name for p in out.iterdir()}
        if names!={"RUN_ONCE_IN_PROGRESS.txt"}:
            raise SystemExit(f"STOP: pre-score resume allowed only with the in-progress marker and no models/metrics; found {sorted(names)}")
        (out/"RUN_ONCE_IN_PROGRESS.txt").unlink()
        out.rmdir()
        print("Confirmed pre-score failure: no model, prediction, or metrics artifacts; safely resuming.",flush=True)
    dev_manifest=dev/"run_split_manifest.csv"
    if not dev_manifest.is_file():raise SystemExit(f"STOP: missing development manifest: {dev_manifest}")
    dm=pd.read_csv(dev_manifest)
    if not {"run_id","label","planned_split"}.issubset(dm.columns):raise SystemExit("STOP: unexpected development manifest schema")
    if len(dm)!=80 or dm.run_id.astype(str).nunique()!=80:raise SystemExit("STOP: development manifest must contain 80 unique runs")
    if set(dm.planned_split.astype(str))!={"train","validation"}:raise SystemExit("STOP: development manifest has unexpected split values")
    if set(dm.label.astype(str))!=LABELS:raise SystemExit("STOP: development manifest has incorrect labels")
    for label in LABELS:
        n=int((dm.label.astype(str)==label).sum())
        if n!=20:raise SystemExit(f"STOP: development manifest has {n} {label} runs, expected 20")
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import LabelEncoder
        import joblib
        from xgboost import XGBClassifier
    except ImportError as exc:raise SystemExit(f"STOP: missing ML dependency in active environment: {exc}")
    final_manifest_path=final/"run_split_manifest.csv"
    if not final_manifest_path.is_file():raise SystemExit(f"STOP: missing final package split manifest: {final_manifest_path}")
    fm=pd.read_csv(final_manifest_path)
    split_col="planned_split" if "planned_split" in fm.columns else ("split" if "split" in fm.columns else None)
    if split_col is None or not {"run_id","label"}.issubset(fm.columns):raise SystemExit("STOP: unexpected final package manifest schema")
    test_manifest=fm[fm[split_col].astype(str).str.lower().isin({"test","final_test"})].copy()
    if len(test_manifest)!=80 or test_manifest.run_id.astype(str).nunique()!=80:raise SystemExit("STOP: final manifest must contain exactly 80 unique test runs")
    if set(test_manifest.label.astype(str))!=LABELS:raise SystemExit("STOP: final test manifest has incorrect labels")
    if set(dm.run_id.astype(str)) & set(test_manifest.run_id.astype(str)):raise SystemExit("STOP: run leakage between development and final-test manifests")
    # Create an irreversible run-once marker before opening test feature CSVs.
    out.parent.mkdir(parents=True,exist_ok=True)
    out.mkdir(parents=True,exist_ok=False)
    (out/"RUN_ONCE_IN_PROGRESS.txt").write_text(
        "Final-test features may be accessed by this run. Do not delete this marker or rerun evaluation.\n"
        f"Development package: {dev}\nFinal package: {final}\nSeed: {a.seed}\n",
        encoding="utf-8")
    encoder=LabelEncoder().fit(sorted(LABELS))
    results={"purpose":"One-shot final run-level evaluation; network-only, no application telemetry.","development_source":str(dev),"test_source":str(final),"test_policy":"No retuning after viewing final_test results.","seed":a.seed,"features_by_level":{},"levels":{}}
    fitted={}
    for level,features in (("packet",PACKET_FEATURES),("flow",FLOW_FEATURES)):
        devdir=dev/f"{level}_splits";finaldir=final/f"{level}_splits"
        tr=pd.read_csv(devdir/"train.csv");va=pd.read_csv(devdir/"validation.csv")
        # Training only uses the repaired 80 development runs; validation labels are now development training data.
        train=pd.concat([tr,va],ignore_index=True)
        validate_frame(train,f"{level} combined development",expected_runs=80)
        train_ids=set(train.run_id.astype(str))
        manifest_ids=set(dm.run_id.astype(str))
        if train_ids!=manifest_ids:raise ValueError(f"STOP: {level} development rows do not exactly match repaired V2 manifest")
        # Only now open the held-out test observations, after development preflight passes.
        test=pd.read_csv(finaldir/"test.csv")
        validate_frame(test,f"{level} final_test",expected_runs=80)
        test_ids=set(test.run_id.astype(str))
        if train_ids & test_ids:raise ValueError(f"STOP: train/test run leakage for {level}")
        expected_test={r for r in test_manifest.run_id.astype(str)}
        if test_ids!=expected_test:raise ValueError(f"STOP: {level} test rows do not exactly match final package test manifest")
        xtr=encode(train,features);xtest=encode(test,features);y=encoder.transform(train.label.astype(str));weights=equal_run_weights(train)
        print(f"Fitting {level}: train/dev runs={len(train_ids)}; test runs={len(test_ids)}; features={len(features)}; equal run weights.",flush=True)
        rf=RandomForestClassifier(n_estimators=400,random_state=a.seed,n_jobs=-1)
        rf.fit(xtr,y,sample_weight=weights)
        xgb=XGBClassifier(n_estimators=300,max_depth=3,learning_rate=0.05,subsample=0.9,colsample_bytree=0.9,min_child_weight=2,reg_lambda=1.0,objective="multi:softprob",eval_metric="mlogloss",random_state=a.seed,n_jobs=-1,tree_method="hist")
        xgb.fit(xtr,y,sample_weight=weights,verbose=False)
        results["features_by_level"][level]=features
        results["levels"][level]={"development":{"rows":int(len(train)),"runs":int(len(train_ids)),"runs_per_class":{label:20 for label in sorted(LABELS)},"weighting":"equal total sample weight per run_id"},"final_test":{"rows":int(len(test)),"runs":int(len(test_ids)),"runs_per_class":{label:20 for label in sorted(LABELS)}},"models":{"random_forest":{"test":evaluate(rf,xtest,test,encoder)},"xgboost":{"test":evaluate(xgb,xtest,test,encoder)}}}
        fitted[level]={"random_forest":rf,"xgboost":xgb}
        leveldir=out/level;leveldir.mkdir()
        for model_name,model in fitted[level].items():joblib.dump(model,leveldir/f"{model_name}.joblib")
        joblib.dump(encoder,leveldir/"label_encoder.joblib")
        (leveldir/"feature_columns.json").write_text(json.dumps({"level":level,"features":features},indent=2)+"\n",encoding="utf-8")
        # Persist each level immediately: if a later level is interrupted, do not rerun this test.
        results["checkpoint_status"]={"completed_levels":list(fitted),"pending_levels":[x for x in ("packet","flow") if x not in fitted]}
        (out/"final_test_metrics.partial.json").write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
        print(f"{level} final test run macro-F1: RF={results['levels'][level]['models']['random_forest']['test']['run_level']['f1_macro']:.4f}; XGBoost={results['levels'][level]['models']['xgboost']['test']['run_level']['f1_macro']:.4f}",flush=True)
    results["checkpoint_status"]={"completed_levels":["packet","flow"],"pending_levels":[]}
    (out/"final_test_metrics.json").write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
    (out/"RUN_ONCE_IN_PROGRESS.txt").rename(out/"RUN_ONCE_COMPLETE.txt")
    print("Saved one-shot metrics and models:",out,flush=True)
    print("FINAL_TEST EVALUATION COMPLETE. Do not retune using these 80 test runs.",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print(f"FINAL EVAL STOP: {type(exc).__name__}: {exc}",file=sys.stderr);raise
