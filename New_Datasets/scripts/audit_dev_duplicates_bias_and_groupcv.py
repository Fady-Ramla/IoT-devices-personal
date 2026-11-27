#!/usr/bin/env python3
"""Read-only development-only duplicate/leakage/bias audit + grouped CV.
The final-test directory, test feature CSVs, and final-test metrics are never opened.
"""
import csv, json, sys, hashlib
from pathlib import Path
from collections import Counter
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report
from sklearn.metrics import normalized_mutual_info_score
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

ROOT=Path.cwd(); BASE=ROOT/'New_Datasets'
DEV=BASE/'AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026'
OUT=BASE/'reports/dev_duplicates_bias_groupcv_audit_20261026.json'
LABELS=['Malicious_POST','Normal','Port_Scan','SYN_Flood']

def read_csv(p):
    return pd.read_csv(p,keep_default_na=False,low_memory=False)
def feature_hashes(frame,features):
    # Hash only normalized feature values; IDs and labels are intentionally excluded.
    vals=frame.loc[:,features]
    return pd.util.hash_pandas_object(vals,index=False).astype('uint64')
def equal_run_weights(frame):
    c=frame.run_id.astype(str).value_counts();w=frame.run_id.astype(str).map(lambda r:1.0/c[r]).to_numpy(float)
    return w*len(w)/w.sum()
def encode(frame,features):
    x=frame.loc[:,features].copy()
    if 'protocol' in x:
        x['protocol']=x['protocol'].astype(str).str.strip().str.lower().map({'tcp':6,'udp':17,'icmp':1,'icmpv6':58,'igmp':2,'other':0,'unknown':0}).fillna(0)
    for c in x:x[c]=pd.to_numeric(x[c],errors='coerce').fillna(0)
    if not np.isfinite(x.to_numpy(float)).all():raise ValueError('non-finite development feature value')
    return x

def run_metrics(model,x,frame,enc):
    p=pd.DataFrame(model.predict_proba(x),index=frame.index,columns=model.classes_)
    p['run_id']=frame.run_id.astype(str).to_numpy();m=p.groupby('run_id',sort=True).mean()
    actual=frame.assign(_rid=frame.run_id.astype(str)).groupby('_rid',sort=True).label.first().loc[m.index]
    pred=enc.inverse_transform(m.to_numpy().argmax(axis=1));y=actual.to_numpy()
    return {'accuracy':float(accuracy_score(y,pred)),'macro_f1':float(f1_score(y,pred,average='macro',zero_division=0)),
            'confusion_matrix':confusion_matrix(y,pred,labels=enc.classes_.tolist()).tolist(),
            'classification_report':classification_report(y,pred,labels=enc.classes_.tolist(),target_names=enc.classes_.tolist(),output_dict=True,zero_division=0)}

def main():
    if not DEV.is_dir():raise SystemExit(f'Missing development-only package: {DEV}')
    if OUT.exists():raise SystemExit(f'Report already exists; refusing overwrite: {OUT}')
    # Validate package hashes without opening any final-test path.
    sums=DEV/'SHA256SUMS.txt'
    for line in sums.read_text().splitlines():
        if not line.strip():continue
        expected,rel=line.split('  ',1);p=DEV/rel;h=hashlib.sha256(p.read_bytes()).hexdigest()
        if h!=expected:raise SystemExit(f'Checksum mismatch in dev package: {rel}')
    split=read_csv(DEV/'run_split_manifest.csv')
    required={'run_id','profile_id','label','planned_split'}
    if not required.issubset(split.columns):raise SystemExit(f'Unexpected split manifest columns: {split.columns.tolist()}')
    if split.run_id.astype(str).duplicated().any() or split.profile_id.astype(str).duplicated().any():raise SystemExit('Duplicate run/profile ID in development split manifest')
    if len(split)!=240 or split.label.value_counts().to_dict()!={x:60 for x in LABELS}:raise SystemExit('Dev manifest must have 240 runs, 60/class')
    if set(split.planned_split)!={'train','validation'}:raise SystemExit('Unexpected dev split labels')
    for lab in LABELS:
        c=split[split.label==lab].planned_split.value_counts().to_dict()
        if c!={'train':48,'validation':12}:raise SystemExit(f'Unbalanced dev split for {lab}: {c}')
    # Restrict full experiment manifest to the 240 known dev run IDs.
    exp=read_csv(BASE/'experiments/run_manifest.csv')
    exp=exp[exp.run_id.astype(str).isin(set(split.run_id.astype(str)))].copy()
    if exp.run_id.astype(str).duplicated().any() or set(exp.run_id.astype(str))!=set(split.run_id.astype(str)):
        raise SystemExit('Experiment manifest does not map one-to-one to all 240 dev runs')
    metadata=split.merge(exp,on='run_id',suffixes=('_split','_exp'),validate='one_to_one')
    metadata['label']=metadata['label_split'].astype(str)
    report={'scope':'Development package only; final-test package/captures/metrics not opened.',
            'dev_manifest':{'runs':len(split),'run_ids_unique':True,'profile_ids_unique':True,
              'runs_per_class':{k:int(v) for k,v in split.label.value_counts().to_dict().items()},
              'split_per_class':{lab:{s:int(((split.label==lab)&(split.planned_split==s)).sum()) for s in ('train','validation')} for lab in LABELS},
              'no_run_leakage':not bool(set(split.loc[split.planned_split=='train','run_id']) & set(split.loc[split.planned_split=='validation','run_id']))},
            'metadata_association':{},'levels':{},'grouped_cv':{}}
    meta_fields=['attacker_host','target_host','service_name','dst_port','protocol','rate_value','duration_sec']
    for col in meta_fields:
        if col not in metadata:continue
        vals=metadata[col].astype(str)
        if col in ('rate_value','duration_sec'):
            n=pd.to_numeric(vals,errors='coerce');vals=pd.qcut(n, q=min(5,n.nunique()),duplicates='drop').astype(str).fillna('missing') if n.notna().any() else vals
        nmi=float(normalized_mutual_info_score(metadata.label.astype(str),vals))
        tab=pd.crosstab(vals,metadata.label.astype(str))
        top=tab.loc[tab.sum(axis=1).sort_values(ascending=False).head(12).index]
        report['metadata_association'][col]={'normalized_mutual_information_with_label':nmi,'levels':int(vals.nunique()),'top_level_counts_by_class':{str(k):{str(c):int(v) for c,v in row.items()} for k,row in top.iterrows()}}
    cfg=json.loads((DEV/'config/model_features.json').read_text())
    enc=LabelEncoder().fit(LABELS)
    # Run-level stratified folds: split manifest is one row per independent run;
    # all observations from a run are assigned together, exactly 12/class/fold.
    splitter=StratifiedKFold(n_splits=5,shuffle=True,random_state=42)
    run_y=enc.transform(split.label.astype(str));run_ids=split.run_id.astype(str).to_numpy()
    folds=[]
    for tr_i,te_i in splitter.split(run_ids,run_y):
        tr_ids=set(run_ids[tr_i]);te_ids=set(run_ids[te_i])
        if tr_ids&te_ids:raise SystemExit('Grouped-CV leakage detected')
        fold_counts=Counter(split.iloc[te_i].label.astype(str))
        if any(fold_counts[k]!=12 for k in LABELS):raise SystemExit(f'CV fold not balanced: {dict(fold_counts)}')
        folds.append((tr_ids,te_ids))
    for level,features in [('packet',cfg['packet_features']),('flow',cfg['flow_features'])]:
        frames=[]
        for s in ('train','validation'):
            f=read_csv(DEV/f'{level}_splits/{s}.csv')
            if not {'run_id','observation_id','label',*features}.issubset(f.columns):raise SystemExit(f'{level}/{s}: missing schema columns')
            f['run_id']=f.run_id.astype(str);f['_split']=s;frames.append(f)
        allf=pd.concat(frames,ignore_index=True)
        expected=set(split.run_id.astype(str))
        if set(allf.run_id)!=expected:raise SystemExit(f'{level}: row run IDs do not match dev manifest')
        if allf.groupby('run_id').label.nunique().gt(1).any():raise SystemExit(f'{level}: conflicting label in run')
        if allf.observation_id.astype(str).eq('').any():raise SystemExit(f'{level}: empty observation ID')
        dup_obs=allf.observation_id.astype(str).duplicated().sum()
        if dup_obs:raise SystemExit(f'{level}: duplicate observation IDs: {dup_obs}')
        numeric=encode(allf,features)
        rowhash=feature_hashes(numeric,features)
        allf['_feature_hash']=rowhash
        train_h=set(allf.loc[allf._split=='train','_feature_hash']);val_h=set(allf.loc[allf._split=='validation','_feature_hash'])
        shared_hash=train_h&val_h
        cross_rows=int(allf._feature_hash.isin(shared_hash).sum())
        train_rep=int((allf.loc[allf._split=='train','_feature_hash'].value_counts()-1).clip(lower=0).sum())
        val_rep=int((allf.loc[allf._split=='validation','_feature_hash'].value_counts()-1).clip(lower=0).sum())
        # Profile-level feature means are a second, less row-count-sensitive overlap check.
        means=numeric.assign(run_id=allf.run_id).groupby('run_id').mean()
        rounded=means.round(6).astype(str).agg('|'.join,axis=1)
        rsplit=split.set_index('run_id').loc[rounded.index,'planned_split']
        trsig=set(rounded[rsplit=='train']);vasig=set(rounded[rsplit=='validation']);shared_runsig=trsig&vasig
        report['levels'][level]={'features':features,'rows_total':int(len(allf)),'runs':int(allf.run_id.nunique()),
          'observation_ids_unique':True,'duplicate_observation_id_count':0,
          'unique_feature_vectors_train':len(train_h),'unique_feature_vectors_validation':len(val_h),
          'within_split_repeated_feature_vector_rows':{'train':train_rep,'validation':val_rep},
          'feature_vector_hashes_shared_across_splits':len(shared_hash),'rows_with_a_feature_vector_also_seen_in_other_split':cross_rows,
          'identical_rounded_run_mean_profiles_shared_across_splits':len(shared_runsig),
          'note':'Repeated feature vectors are reported, not automatically removed; natural repeated network observations are not necessarily data leakage.'}
        model_res=[]
        xall=encode(allf,features);yall=enc.transform(allf.label.astype(str))
        for fold,(tr_ids,te_ids) in enumerate(folds,1):
            trmask=allf.run_id.isin(tr_ids).to_numpy();temask=allf.run_id.isin(te_ids).to_numpy()
            tr=allf.loc[trmask].copy();te=allf.loc[temask].copy()
            ytr=enc.transform(tr.label.astype(str));w=equal_run_weights(tr)
            models={'random_forest':RandomForestClassifier(n_estimators=400,random_state=42,n_jobs=-1),
                    'xgboost':XGBClassifier(n_estimators=300,max_depth=3,learning_rate=0.05,subsample=0.9,colsample_bytree=0.9,min_child_weight=2,reg_lambda=1.0,objective='multi:softprob',eval_metric='mlogloss',random_state=42,n_jobs=-1,tree_method='hist')}
            for name,m in models.items():
                m.fit(encode(tr,features),ytr,sample_weight=equal_run_weights(tr),**({'verbose':False} if name=='xgboost' else {}))
                trm=run_metrics(m,encode(tr,features),tr,enc);tem=run_metrics(m,encode(te,features),te,enc)
                model_res.append({'fold':fold,'model':name,'train_runs':len(tr_ids),'heldout_runs':len(te_ids),'train_accuracy':trm['accuracy'],'train_macro_f1':trm['macro_f1'],'heldout_accuracy':tem['accuracy'],'heldout_macro_f1':tem['macro_f1'],'heldout_confusion_matrix':tem['confusion_matrix'],'heldout_class_report':tem['classification_report']})
            print(f'{level}: completed development-only grouped fold {fold}/5',flush=True)
        summaries={}
        for name in ('random_forest','xgboost'):
            rr=[x for x in model_res if x['model']==name]
            summaries[name]={'mean_train_accuracy':float(np.mean([x['train_accuracy'] for x in rr])),'mean_train_macro_f1':float(np.mean([x['train_macro_f1'] for x in rr])),'mean_cv_accuracy':float(np.mean([x['heldout_accuracy'] for x in rr])),'sd_cv_accuracy':float(np.std([x['heldout_accuracy'] for x in rr],ddof=1)),'mean_cv_macro_f1':float(np.mean([x['heldout_macro_f1'] for x in rr])),'sd_cv_macro_f1':float(np.std([x['heldout_macro_f1'] for x in rr],ddof=1)),'accuracy_generalization_gap_train_minus_cv':float(np.mean([x['train_accuracy'] for x in rr])-np.mean([x['heldout_accuracy'] for x in rr])),'macro_f1_generalization_gap_train_minus_cv':float(np.mean([x['train_macro_f1'] for x in rr])-np.mean([x['heldout_macro_f1'] for x in rr]))}
        report['grouped_cv'][level]={'design':'5-fold StratifiedKFold on one-row-per-run development manifest; all observations grouped by run; 12 held-out runs/class/fold; equal total training weight per run. Final-test data not opened.','models':summaries,'folds':model_res}
        print(f"{level}: RF CV acc/F1={summaries['random_forest']['mean_cv_accuracy']:.4f}/{summaries['random_forest']['mean_cv_macro_f1']:.4f}; XGB={summaries['xgboost']['mean_cv_accuracy']:.4f}/{summaries['xgboost']['mean_cv_macro_f1']:.4f}",flush=True)
    OUT.parent.mkdir(parents=True,exist_ok=True)
    OUT.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('DEVELOPMENT-ONLY AUDIT COMPLETE:',OUT,flush=True)
    print('No final-test files, features, predictions, or metrics were opened.',flush=True)
if __name__=='__main__':
    try:main()
    except Exception as e:print(f'AUDIT STOP: {type(e).__name__}: {e}',file=sys.stderr);raise
