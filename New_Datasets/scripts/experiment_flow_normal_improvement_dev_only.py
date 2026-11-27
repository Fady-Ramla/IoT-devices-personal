#!/usr/bin/env python3
"""Development-only Flow experiments; never opens final-test data or changes frozen models.
Compares predetermined XGBoost/RF configurations and feature ablations using
5-fold stratification on the one-row-per-run manifest; every observation from a
run remains in one fold. Results are exploratory CV estimates, not a new final score.
"""
import json, hashlib, sys
from pathlib import Path
from collections import Counter
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

ROOT=Path.cwd();BASE=ROOT/'New_Datasets'
DEV=BASE/'AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026'
OUT=BASE/'reports/flow_normal_improvement_experiments_dev_only_20261026.json'
LABELS=['Malicious_POST','Normal','Port_Scan','SYN_Flood']
SEED=20261026

def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
def encode(frame,features):
    x=frame.loc[:,features].copy()
    if 'protocol' in x:
        x['protocol']=x['protocol'].astype(str).str.strip().str.lower().map({'tcp':6,'udp':17,'icmp':1,'icmpv6':58,'igmp':2,'other':0,'unknown':0}).fillna(0)
    for c in x:x[c]=pd.to_numeric(x[c],errors='coerce').fillna(0)
    if not np.isfinite(x.to_numpy(float)).all():raise ValueError('non-finite feature')
    return x
def sample_weights(frame,normal_multiplier=1.0):
    ids=frame.run_id.astype(str);cnt=ids.value_counts()
    w=ids.map(lambda r:1.0/cnt[r]).to_numpy(float)
    w*=np.where(frame.label.astype(str).to_numpy()=='Normal',normal_multiplier,1.0)
    return w*(len(w)/w.sum())
def aggregate_run_metrics(model,x,frame,encoder):
    probs=pd.DataFrame(model.predict_proba(x),index=frame.index,columns=model.classes_)
    probs['run_id']=frame.run_id.astype(str).to_numpy();mean=probs.groupby('run_id',sort=True).mean()
    actual=frame.assign(_rid=frame.run_id.astype(str)).groupby('_rid',sort=True).label.first().loc[mean.index]
    pred=encoder.inverse_transform(mean.to_numpy().argmax(axis=1));y=actual.to_numpy()
    return {'runs':len(y),'accuracy':float(accuracy_score(y,pred)),'macro_f1':float(f1_score(y,pred,average='macro',zero_division=0)),
      'confusion_matrix':confusion_matrix(y,pred,labels=encoder.classes_.tolist()).tolist(),
      'classification_report':classification_report(y,pred,labels=encoder.classes_.tolist(),target_names=encoder.classes_.tolist(),output_dict=True,zero_division=0)}
def main():
    if not DEV.is_dir():raise SystemExit(f'Missing development package: {DEV}')
    if OUT.exists():raise SystemExit(f'Refusing overwrite: {OUT}')
    if not (DEV/'SHA256SUMS.txt').is_file():raise SystemExit('Missing development package checksum manifest')
    for line in (DEV/'SHA256SUMS.txt').read_text().splitlines():
        if line.strip():
            expected,rel=line.split('  ',1)
            if sha(DEV/rel)!=expected:raise SystemExit(f'Development package checksum mismatch: {rel}')
    manifest=pd.read_csv(DEV/'run_split_manifest.csv',dtype={'run_id':str})
    if len(manifest)!=240 or manifest.run_id.duplicated().any() or manifest.profile_id.duplicated().any():raise SystemExit('Expected 240 unique development runs/profiles')
    if set(manifest.label.astype(str))!=set(LABELS):raise SystemExit('Unexpected development class set')
    for lab in LABELS:
        c=manifest.loc[manifest.label==lab,'planned_split'].value_counts().to_dict()
        if c!={'train':48,'validation':12}:raise SystemExit(f'Unexpected development split for {lab}: {c}')
    # Use only development TRAIN+VALIDATION observations; test paths are never formed/read.
    cfg=json.loads((DEV/'config/model_features.json').read_text())
    features=list(cfg['flow_features'])
    tr=pd.read_csv(DEV/'flow_splits/train.csv',keep_default_na=False,low_memory=False)
    va=pd.read_csv(DEV/'flow_splits/validation.csv',keep_default_na=False,low_memory=False)
    data=pd.concat([tr,va],ignore_index=True)
    if set(data.run_id.astype(str))!=set(manifest.run_id.astype(str)):raise SystemExit('Development feature rows do not match development manifest')
    if data.groupby('run_id').label.nunique().gt(1).any():raise SystemExit('Conflicting labels in development run')
    if data.observation_id.astype(str).eq('').any() or data.observation_id.astype(str).duplicated().any():raise SystemExit('Missing/duplicate development observation IDs')
    # Run-level stratified folds; all rows of a run share the same fold.
    split=manifest[['run_id','label']].copy();split['run_id']=split.run_id.astype(str)
    run_ids=split.run_id.to_numpy();y_run=LabelEncoder().fit(LABELS).transform(split.label.astype(str))
    cv=StratifiedKFold(n_splits=5,shuffle=True,random_state=SEED)
    folds=[]
    for a,b in cv.split(run_ids,y_run):
        trids=set(run_ids[a]);teids=set(run_ids[b])
        if trids&teids:raise SystemExit('Run leakage in CV fold')
        counts=Counter(split.iloc[b].label.astype(str))
        if any(counts[x]!=12 for x in LABELS):raise SystemExit(f'Unexpected held-out class balance: {dict(counts)}')
        folds.append((trids,teids))
    # Predeclared experiment grid. Class-weight variants are hypotheses, not guarantees.
    exps=[
      {'name':'xgb_frozen_hyperparams_baseline','model':'xgb','normal_weight':1.0,'feature_set':'all_flow','params':'frozen_v5'},
      {'name':'xgb_regularized_depth2','model':'xgb','normal_weight':1.0,'feature_set':'all_flow','params':'depth2'},
      {'name':'xgb_normal_weight_1p5','model':'xgb','normal_weight':1.5,'feature_set':'all_flow','params':'frozen_v5'},
      {'name':'xgb_normal_weight_2p0','model':'xgb','normal_weight':2.0,'feature_set':'all_flow','params':'frozen_v5'},
      {'name':'xgb_without_ports_diagnostic','model':'xgb','normal_weight':1.0,'feature_set':'without_ports','params':'frozen_v5'},
      {'name':'xgb_without_rate_duration_diagnostic','model':'xgb','normal_weight':1.0,'feature_set':'without_rates','params':'frozen_v5'},
      {'name':'rf_regularized_depth12_leaf2','model':'rf','normal_weight':1.0,'feature_set':'all_flow','params':'regularized'},
    ]
    def get_features(kind):
        if kind=='without_ports':return [x for x in features if x not in ('src_port','dst_port')]
        if kind=='without_rates':return [x for x in features if x not in ('packet_rate','byte_rate','duration_sec')]
        return features
    encoder=LabelEncoder().fit(LABELS);res={'scope':'Development train+validation only; final-test data, metrics, and paths were not accessed.',
      'method':'Predeclared candidate comparison with 5-fold run-grouped stratified CV; 12 held-out runs/class/fold; equal run contribution before optional Normal class multiplier.',
      'seed':SEED,'runs':240,'runs_per_class':60,'experiments':{}}
    for exp in exps:
        fs=get_features(exp['feature_set']);foldout=[]
        for fold,(train_ids,test_ids) in enumerate(folds,1):
            train=data[data.run_id.astype(str).isin(train_ids)].copy();test=data[data.run_id.astype(str).isin(test_ids)].copy()
            xtr=encode(train,fs);xte=encode(test,fs);ytr=encoder.transform(train.label.astype(str));w=sample_weights(train,exp['normal_weight'])
            if exp['model']=='rf':
                model=RandomForestClassifier(n_estimators=400,max_depth=12,min_samples_leaf=2,max_features='sqrt',random_state=42,n_jobs=-1)
                model.fit(xtr,ytr,sample_weight=w)
            else:
                params={'n_estimators':300,'max_depth':3,'learning_rate':0.05,'subsample':0.9,'colsample_bytree':0.9,'min_child_weight':2,'reg_lambda':1.0,'objective':'multi:softprob','eval_metric':'mlogloss','random_state':42,'n_jobs':-1,'tree_method':'hist'}
                if exp['params']=='depth2':params.update({'n_estimators':400,'max_depth':2,'learning_rate':0.03,'min_child_weight':4,'reg_lambda':2.0})
                model=XGBClassifier(**params);model.fit(xtr,ytr,sample_weight=w,verbose=False)
            trm=aggregate_run_metrics(model,xtr,train,encoder);tem=aggregate_run_metrics(model,xte,test,encoder)
            foldout.append({'fold':fold,'train':trm,'heldout':tem})
            print(f"{exp['name']}: fold {fold}/5 heldout acc={tem['accuracy']:.3f} macroF1={tem['macro_f1']:.3f} NormalRecall={tem['classification_report']['Normal']['recall']:.3f}",flush=True)
        result={}
        for k in ('accuracy','macro_f1'):
            vals=[f['heldout'][k] for f in foldout];result['mean_'+k]=float(np.mean(vals));result['sd_'+k]=float(np.std(vals,ddof=1))
        result['mean_normal_recall']=float(np.mean([f['heldout']['classification_report']['Normal']['recall'] for f in foldout]))
        result['mean_normal_precision']=float(np.mean([f['heldout']['classification_report']['Normal']['precision'] for f in foldout]))
        result['mean_train_accuracy']=float(np.mean([f['train']['accuracy'] for f in foldout]))
        result['mean_train_macro_f1']=float(np.mean([f['train']['macro_f1'] for f in foldout]))
        result['accuracy_train_cv_gap']=result['mean_train_accuracy']-result['mean_accuracy']
        result['folds']=foldout;result['feature_columns']=fs;result['normal_sample_weight_multiplier']=exp['normal_weight']
        res['experiments'][exp['name']]=result
        print(f"DONE {exp['name']}: CV acc={result['mean_accuracy']:.4f} macroF1={result['mean_macro_f1']:.4f} NormalRecall={result['mean_normal_recall']:.4f}",flush=True)
    res['interpretation_note']='Select candidate using development-only grouped CV and predeclared operational criteria. Candidate comparisons can still introduce selection optimism. No candidate result is a new final-test score; any materially selected change needs a new independent test.'
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(res,indent=2)+'\n',encoding='utf-8')
    print('DEVELOPMENT EXPERIMENTS COMPLETE:',OUT,flush=True)
    print('No final-test files opened. Frozen model artifacts unchanged.',flush=True)
if __name__=='__main__':
    try:main()
    except Exception as e:print(f'EXPERIMENT STOP: {type(e).__name__}: {e}',file=sys.stderr);raise
