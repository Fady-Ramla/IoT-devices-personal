#!/usr/bin/env python3
"""One-shot, run/profile-grouped model improvement using the existing 160 clean runs.

Important: the old final_test has already been inspected/scored, so this script
repurposes its corrected rows as DEVELOPMENT data. It performs 5-fold OOF CV
with strict profile grouping, compares predeclared RF/XGBoost class-weighting
candidates, then fits selected Packet/Flow models on all 160 runs. It does not
claim an independent final accuracy; a fresh holdout is required for that.
"""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
import numpy as np
import pandas as pd

LABELS={"Malicious_POST","Normal","Port_Scan","SYN_Flood"}
PACKET_FEATURES=["protocol","src_port","dst_port","packet_length","tcp_syn","tcp_ack","tcp_rst","tcp_fin","icmp_type","arp_operation"]
FLOW_FEATURES=["protocol","src_port","dst_port","packet_count","byte_count","packet_rate","byte_rate","duration_sec","avg_packet_size","syn_count","ack_count","rst_count","fin_count","syn_ack_ratio","rst_ratio","unique_dst_ports","failed_connection_count","tcp_fraction","udp_fraction","icmp_fraction"]
PROTO={"tcp":6,"udp":17,"icmp":1,"icmpv6":58,"igmp":2,"other":0,"unknown":0}

def enc(frame,features):
 missing=sorted(set(features)-set(frame.columns))
 if missing:raise ValueError(f"Missing features: {missing}")
 x=frame[features].copy()
 if "protocol" in x:x["protocol"]=x["protocol"].astype(str).str.strip().str.lower().map(PROTO).fillna(0)
 for c in x.columns:x[c]=pd.to_numeric(x[c],errors="coerce").fillna(0)
 if not np.isfinite(x.to_numpy(dtype=float)).all():raise ValueError("Non-finite feature after encoding")
 return x

def check_rows(df,name,features):
 req={"run_id","observation_id","label",*features}
 miss=sorted(req-set(df.columns))
 if miss:raise ValueError(f"{name} missing columns: {miss}")
 if df[["run_id","observation_id","label"]].isna().any().any():raise ValueError(f"{name} has null IDs/labels")
 if set(df.label.astype(str))!=LABELS:raise ValueError(f"{name} class set mismatch")
 if df.groupby("run_id").label.nunique().gt(1).any():raise ValueError(f"{name} conflicting labels within a run")
 if df.observation_id.astype(str).duplicated().any():raise ValueError(f"{name} duplicate observation_id")
 if df.duplicated().any():raise ValueError(f"{name} exact duplicate rows")

def fold_map(meta,nfolds,seed):
 """Deterministic stratification by profile groups; all runs in a profile stay together."""
 if meta.groupby("profile_id").label.nunique().gt(1).any():raise ValueError("A profile_id maps to multiple labels")
 f={};rng=np.random.default_rng(seed)
 for label in sorted(LABELS):
  groups=meta.loc[meta.label.astype(str)==label,"profile_id"].astype(str).unique().tolist()
  if len(groups)<nfolds:raise ValueError(f"Not enough {label} profile groups for {nfolds} folds")
  rng.shuffle(groups)
  for i,g in enumerate(groups):f[g]=i%nfolds
 return f

def model_configs(seed):
 return [
  {"name":"rf_equal_run","family":"rf","normal_weight":1.0,"n_estimators":400,"max_depth":None,"min_samples_leaf":1},
  {"name":"rf_normal_x1_5","family":"rf","normal_weight":1.5,"n_estimators":400,"max_depth":None,"min_samples_leaf":1},
  {"name":"xgb_equal_run","family":"xgb","normal_weight":1.0,"n_estimators":300,"max_depth":3,"learning_rate":0.05,"min_child_weight":2},
  {"name":"xgb_normal_x1_5","family":"xgb","normal_weight":1.5,"n_estimators":300,"max_depth":3,"learning_rate":0.05,"min_child_weight":2},
  {"name":"xgb_normal_x2","family":"xgb","normal_weight":2.0,"n_estimators":300,"max_depth":3,"learning_rate":0.05,"min_child_weight":2},
  {"name":"xgb_depth2_normal_x1_5","family":"xgb","normal_weight":1.5,"n_estimators":350,"max_depth":2,"learning_rate":0.05,"min_child_weight":2},
 ]

def fit_model(cfg,x,y,weights,seed):
 if cfg["family"]=="rf":
  from sklearn.ensemble import RandomForestClassifier
  m=RandomForestClassifier(n_estimators=cfg["n_estimators"],max_depth=cfg["max_depth"],min_samples_leaf=cfg["min_samples_leaf"],max_features="sqrt",random_state=seed,n_jobs=-1)
 else:
  from xgboost import XGBClassifier
  m=XGBClassifier(n_estimators=cfg["n_estimators"],max_depth=cfg["max_depth"],learning_rate=cfg["learning_rate"],subsample=0.9,colsample_bytree=0.9,min_child_weight=cfg["min_child_weight"],reg_lambda=1.0,objective="multi:softprob",eval_metric="mlogloss",random_state=seed,n_jobs=-1,tree_method="hist")
 m.fit(x,y,sample_weight=weights,verbose=False) if cfg["family"]=="xgb" else m.fit(x,y,sample_weight=weights)
 return m

def scores_from_run_probs(probs,truth,class_names):
 from sklearn.metrics import accuracy_score,classification_report,confusion_matrix,f1_score
 runs=sorted(truth)
 pred={r:class_names[int(np.mean(probs[r],axis=0).argmax())] for r in runs}
 yt=[truth[r] for r in runs];yp=[pred[r] for r in runs]
 return {"runs":len(runs),"accuracy":float(accuracy_score(yt,yp)),"macro_f1":float(f1_score(yt,yp,labels=class_names,average="macro",zero_division=0)),"confusion_matrix":confusion_matrix(yt,yp,labels=class_names).tolist(),"classification_report":classification_report(yt,yp,labels=class_names,target_names=class_names,output_dict=True,zero_division=0),"predictions":[{"run_id":r,"actual":truth[r],"predicted":pred[r]} for r in runs]}

def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument("--development-package",type=Path,required=True,help="repaired V2 train+validation package")
 ap.add_argument("--historical-holdout-package",type=Path,required=True,help="corrected former test-only package; now repurposed as development")
 ap.add_argument("--output-dir",type=Path,required=True)
 ap.add_argument("--seed",type=int,default=42)
 a=ap.parse_args();dev=a.development_package.resolve();old=a.historical_holdout_package.resolve();out=a.output_dir.resolve()
 if out.exists():raise SystemExit(f"STOP: output already exists; refusing overwrite: {out}")
 from sklearn.preprocessing import LabelEncoder
 import joblib
 encoder=LabelEncoder().fit(sorted(LABELS));classes=encoder.classes_.tolist();cfgs=model_configs(a.seed)
 dm=pd.read_csv(dev/"run_split_manifest.csv");hm=pd.read_csv(old/"run_split_manifest.csv")
 for name,m in (("V2 development",dm),("corrected historical holdout",hm)):
  if not {"run_id","label","profile_id"}.issubset(m.columns):raise ValueError(f"{name} manifest schema mismatch")
  if m.run_id.astype(str).nunique()!=80 or len(m)!=80:raise ValueError(f"{name} manifest must have 80 unique runs")
  if set(m.label.astype(str))!=LABELS:raise ValueError(f"{name} manifest classes mismatch")
  if m.profile_id.astype(str).duplicated().any():raise ValueError(f"{name} has repeated profile_id groups")
 if set(dm.run_id.astype(str))&set(hm.run_id.astype(str)):raise ValueError("Run leakage between source packages")
 if set(dm.profile_id.astype(str))&set(hm.profile_id.astype(str)):raise ValueError("Profile leakage between source packages")
 for name,m in (("V2 development",dm),("corrected historical holdout",hm)):
  cnt=m.label.astype(str).value_counts().to_dict()
  if cnt!={c:20 for c in LABELS}:raise ValueError(f"{name} requires 20 runs/class, got {cnt}")
 all_manifest=pd.concat([dm.assign(source="v2_dev"),hm.assign(source="former_test_now_development")],ignore_index=True)
 if len(all_manifest)!=160 or all_manifest.run_id.astype(str).nunique()!=160 or all_manifest.profile_id.astype(str).nunique()!=160:raise ValueError("Expected 160 unique run and profile groups")
 if all_manifest.label.astype(str).value_counts().to_dict()!={c:40 for c in LABELS}:raise ValueError("Expected 40 development runs per class")
 if not {"run_id","label","planned_split"}.issubset(dm.columns):raise ValueError("V2 manifest missing expected split fields")
 results={"purpose":"Development-only grouped cross-validation and model selection; no independent test score.","data_policy":"Original 80-run development plus corrected former 80-run holdout are both development now. A fresh independent holdout is required for final accuracy.","run_count":160,"runs_per_class":{c:40 for c in sorted(LABELS)},"profile_grouped":True,"duplicate_checks":{"run_ids":0,"profile_ids":0,"observation_ids_by_level":0,"exact_rows_by_level":0},"candidate_policy":"Predeclared Random Forest/XGBoost variants; equal base weight per run; selected Normal-class multipliers are part of development tuning.","levels":{}}
 for level,features in (("packet",PACKET_FEATURES),("flow",FLOW_FEATURES)):
  ddir=dev/f"{level}_splits";hdir=old/f"{level}_splits"
  train=pd.concat([pd.read_csv(ddir/"train.csv"),pd.read_csv(ddir/"validation.csv")],ignore_index=True)
  added=pd.read_csv(hdir/"test.csv")
  df=pd.concat([train,added],ignore_index=True)
  check_rows(df,level,features)
  if set(df.run_id.astype(str))!=set(all_manifest.run_id.astype(str)):raise ValueError(f"{level} observations do not match the 160-run manifest")
  label_per_run=df.groupby("run_id").label.first().astype(str)
  if not label_per_run.to_dict()==all_manifest.set_index("run_id").label.astype(str).to_dict():raise ValueError(f"{level} feature labels differ from manifests")
  # Join the group metadata to every observation; splitting is always at profile level.
  groupmeta=all_manifest.set_index("run_id")["profile_id"].astype(str)
  df["profile_id"]=df.run_id.astype(str).map(groupmeta)
  x=enc(df,features);y=encoder.transform(df.label.astype(str));runs=df.run_id.astype(str)
  meta=all_manifest[["run_id","label","profile_id"]].copy();folds=fold_map(meta,5,a.seed)
  truth=meta.set_index("run_id").label.astype(str).to_dict()
  oof_results={};
  print(f"{level}: 160 runs, 40/class, {len(df)} observations; profile-grouped 5-fold CV.",flush=True)
  for ci,cfg in enumerate(cfgs):
   probs={}
   for fold in range(5):
    valid_ids={rid for rid,g in zip(meta.run_id.astype(str),meta.profile_id.astype(str)) if folds[g]==fold}
    train_idx=np.flatnonzero(~runs.isin(valid_ids).to_numpy());valid_idx=np.flatnonzero(runs.isin(valid_ids).to_numpy())
    tr=df.iloc[train_idx];ytr=y[train_idx]
    counts=tr.run_id.astype(str).value_counts();w=tr.run_id.astype(str).map(lambda r:1.0/counts[r]).to_numpy(float);w*=len(w)/w.sum()
    if cfg["normal_weight"]!=1.0:w*=np.where(tr.label.astype(str).to_numpy()=="Normal",cfg["normal_weight"],1.0)
    model=fit_model(cfg,x.iloc[train_idx],ytr,w,a.seed+fold)
    pp=model.predict_proba(x.iloc[valid_idx]);v_run_ids=runs.iloc[valid_idx].to_numpy()
    for rid in np.unique(v_run_ids):
     probs[str(rid)]=pp[v_run_ids==rid].mean(axis=0)
   # Each candidate now has exactly one OOF vector per run.
   score=scores_from_run_probs({r:[p] for r,p in probs.items()},truth,classes)
   oof_results[cfg["name"]]={"config":cfg,"oof_run_metrics":score}
   print(f"  {cfg['name']}: OOF run acc={score['accuracy']:.4f}; macro-F1={score['macro_f1']:.4f}",flush=True)
  best_name=max(oof_results,key=lambda n:(oof_results[n]["oof_run_metrics"]["macro_f1"],oof_results[n]["oof_run_metrics"]["accuracy"],n))
  best_cfg=oof_results[best_name]["config"]
  counts=df.run_id.astype(str).value_counts();weights=df.run_id.astype(str).map(lambda r:1.0/counts[r]).to_numpy(float);weights*=len(weights)/weights.sum()
  if best_cfg["normal_weight"]!=1.0:weights*=np.where(df.label.astype(str).to_numpy()=="Normal",best_cfg["normal_weight"],1.0)
  final_model=fit_model(best_cfg,x,y,weights,a.seed)
  results["levels"][level]={"rows":int(len(df)),"runs":160,"candidate_oof_run_metrics":oof_results,"selected_candidate":best_name,"selection_note":"Best candidate selected on these OOF folds; its selected score is development evidence, not an untouched final-test estimate.","oof_predictions_for_selected_candidate":oof_results[best_name]["oof_run_metrics"]["predictions"]}
  if level=="packet":models_dir=out/"models";models_dir.mkdir(parents=True,exist_ok=True)
  joblib.dump(final_model,models_dir/f"{level}_selected_model.joblib")
  (models_dir/f"{level}_selected_config.json").write_text(json.dumps(best_cfg,indent=2)+"\n",encoding="utf-8")
  print(f"  selected {best_name}; fitted final development model on 160 runs.",flush=True)
 out.mkdir(parents=True,exist_ok=True) if not out.exists() else None
 (out/"development_groupcv_report.json").write_text(json.dumps(results,indent=2)+"\n",encoding="utf-8")
 joblib.dump(encoder,out/"models/label_encoder.joblib")
 (out/"README.md").write_text("# Grouped CV model development\n\nThis run pools 160 unique historical runs (40/class) for development. The former final holdout has been repurposed as development after its results were inspected. Scores in this report are profile-grouped out-of-fold development estimates used for model selection, not a fresh independent test. Collect a new holdout after freezing the selected models before claiming final accuracy.\n",encoding="utf-8")
 print("DEVELOPMENT OPTIMIZATION COMPLETE. No independent test was evaluated.",flush=True)
 print("Report:",out/"development_groupcv_report.json",flush=True)
 print("Models:",out/"models",flush=True)

if __name__=="__main__":
 try:main()
 except Exception as exc:
  print(f"OPTIMIZATION STOP: {type(exc).__name__}: {exc}",file=sys.stderr);raise
