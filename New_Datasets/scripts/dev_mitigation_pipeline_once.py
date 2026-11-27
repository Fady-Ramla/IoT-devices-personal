#!/usr/bin/env python3
"""Development-only mitigation experiment for the IoT Packet/Flow project.

Reads only the expanded development package and development run-manifest records
(generations < 550). Runs grouped-by-run OOF comparisons for the current Flow-XGB
baseline, two Normal-weight variants, a regularized RF, per-run Flow summaries,
and a metadata-only confounding diagnostic. Adds leave-attacker-host-out stress
results when every eligible fold supports all four classes. Writes one new JSON
report; never opens final-test feature files, test predictions/metrics, saves or
replaces models, or changes any existing package.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, math, sys
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from xgboost import XGBClassifier

LABELS=['Malicious_POST','Normal','Port_Scan','SYN_Flood']
SEED=20261026


def sha256(path:Path)->str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda:f.read(1024*1024),b''): h.update(block)
    return h.hexdigest()


def read_dev_run_metadata(path:Path, wanted:set[str])->pd.DataFrame:
    """Read only development IDs from the append-ordered manifest; stop before final-test generations."""
    found={}
    with path.open(newline='',encoding='utf-8-sig') as f:
        rd=csv.DictReader(f)
        required={'run_id','generation','status','label','attacker_host','target_host','service_name','dst_port','rate_value','duration_sec'}
        if not rd.fieldnames or not required.issubset(rd.fieldnames):
            raise ValueError(f'Experiment manifest missing required fields: {required-set(rd.fieldnames or [])}')
        last_gen=0
        for r in rd:
            try:g=int(r.get('generation') or 0)
            except ValueError:continue
            if g<last_gen: raise ValueError('Manifest generations are not append-ordered; refusing to search beyond development boundary')
            last_gen=g
            if g>=550: break  # The independent holdout begins at generation 550; do not inspect later rows.
            rid=str(r.get('run_id') or '')
            if rid in wanted:
                if rid in found: raise ValueError(f'Duplicate development run in experiment manifest: {rid}')
                found[rid]={k:(r.get(k) or '') for k in required}
    missing=wanted-set(found)
    if missing: raise ValueError(f'{len(missing)} development IDs were not found before the final-test boundary')
    md=pd.DataFrame(found.values())
    md['generation']=pd.to_numeric(md['generation'],errors='raise').astype(int)
    return md


def numeric_features(frame:pd.DataFrame,features:list[str])->pd.DataFrame:
    x=frame.loc[:,features].copy()
    if 'protocol' in x:
        x['protocol']=x['protocol'].astype(str).str.strip().str.lower().map({'tcp':6,'udp':17,'icmp':1,'icmpv6':58,'igmp':2,'other':0,'unknown':0}).fillna(0)
    for c in x.columns: x[c]=pd.to_numeric(x[c],errors='coerce').fillna(0)
    if not np.isfinite(x.to_numpy(dtype=float)).all(): raise ValueError('Non-finite development feature value')
    return x


def equal_run_weights(frame:pd.DataFrame,normal_multiplier:float=1.0)->np.ndarray:
    ids=frame.run_id.astype(str);counts=ids.value_counts()
    w=ids.map(lambda rid:1.0/counts[rid]).to_numpy(float)
    w*=np.where(frame.label.astype(str).to_numpy()=='Normal',normal_multiplier,1.0)
    return w*(len(w)/w.sum())


def probabilities_by_run(model,x:pd.DataFrame,frame:pd.DataFrame,enc:LabelEncoder)->pd.DataFrame:
    columns=enc.inverse_transform(np.asarray(model.classes_,dtype=int)).tolist()
    q=pd.DataFrame(model.predict_proba(x),index=frame.index,columns=columns)
    q['_run_id']=frame.run_id.astype(str).to_numpy()
    return q.groupby('_run_id',sort=True)[LABELS].mean()


def metric_block(actual:list[str],pred:list[str])->dict:
    rep=classification_report(actual,pred,labels=LABELS,target_names=LABELS,output_dict=True,zero_division=0)
    return {'runs':len(actual),'accuracy':float(accuracy_score(actual,pred)),
            'macro_f1':float(f1_score(actual,pred,labels=LABELS,average='macro',zero_division=0)),
            'normal_precision':float(rep['Normal']['precision']),'normal_recall':float(rep['Normal']['recall']),
            'confusion_matrix':confusion_matrix(actual,pred,labels=LABELS).tolist(),
            'classification_report':rep}


def xgb_model():
    return XGBClassifier(n_estimators=300,max_depth=3,learning_rate=0.05,subsample=0.9,
      colsample_bytree=0.9,min_child_weight=2,reg_lambda=1.0,objective='multi:softprob',
      eval_metric='mlogloss',random_state=42,n_jobs=-1,tree_method='hist')


def run_level_cv(data:pd.DataFrame,manifest:pd.DataFrame,features:list[str],enc:LabelEncoder,kind:str,normal_weight:float=1.0):
    runmeta=manifest[['run_id','label']].copy();runmeta['run_id']=runmeta.run_id.astype(str)
    ids=runmeta.run_id.to_numpy(); y=enc.transform(runmeta.label.astype(str))
    cv=StratifiedKFold(n_splits=5,shuffle=True,random_state=SEED)
    oof={};folds=[]
    if kind=='run_mean' or kind=='run_mean_std':
        xall=numeric_features(data,features)
        grouped=xall.assign(run_id=data.run_id.astype(str)).groupby('run_id',sort=True)
        mean=grouped.mean()
        if kind=='run_mean_std':
            std=grouped.std(ddof=0).fillna(0);std.columns=[f'{c}__std' for c in std.columns]
            runx=pd.concat([mean,std],axis=1)
        else: runx=mean
        actual=runmeta.set_index('run_id').loc[runx.index,'label'].astype(str)
        for fold,(a,b) in enumerate(cv.split(ids,y),1):
            train_ids=set(ids[a]);test_ids=set(ids[b])
            if train_ids & test_ids: raise ValueError('Run leakage in CV')
            xtr=runx.loc[sorted(train_ids)];xte=runx.loc[sorted(test_ids)]
            ytr=enc.transform(actual.loc[xtr.index].tolist())
            model=xgb_model()
            w=np.ones(len(xtr),dtype=float)*np.where(actual.loc[xtr.index].to_numpy()=='Normal',normal_weight,1.0)
            model.fit(xtr,ytr,sample_weight=w,verbose=False)
            p=pd.DataFrame(model.predict_proba(xte),index=xte.index,columns=enc.inverse_transform(np.asarray(model.classes_,dtype=int)))
            p=p.reindex(columns=LABELS,fill_value=0)
            for rid,row in p.iterrows():oof[str(rid)]=row.to_dict()
            pred=enc.inverse_transform(p.to_numpy().argmax(axis=1)).astype(str)
            fm=metric_block(actual.loc[p.index].astype(str).tolist(),pred.tolist())
            folds.append({'fold':fold,**{k:fm[k] for k in ('runs','accuracy','macro_f1','normal_precision','normal_recall')}})
    else:
        xall=numeric_features(data,features)
        for fold,(a,b) in enumerate(cv.split(ids,y),1):
            train_ids=set(ids[a]);test_ids=set(ids[b])
            if train_ids & test_ids: raise ValueError('Run leakage in CV')
            tr=data[data.run_id.astype(str).isin(train_ids)].copy();te=data[data.run_id.astype(str).isin(test_ids)].copy()
            xtr=numeric_features(tr,features);xte=numeric_features(te,features);ytr=enc.transform(tr.label.astype(str))
            if kind=='rf':
                model=RandomForestClassifier(n_estimators=400,max_depth=12,min_samples_leaf=2,max_features='sqrt',random_state=42,n_jobs=-1)
                model.fit(xtr,ytr,sample_weight=equal_run_weights(tr))
            else:
                model=xgb_model();model.fit(xtr,ytr,sample_weight=equal_run_weights(tr,normal_weight),verbose=False)
            p=probabilities_by_run(model,xte,te,enc)
            actual=te.assign(_rid=te.run_id.astype(str)).groupby('_rid',sort=True).label.first().loc[p.index].astype(str)
            pred=enc.inverse_transform(p.to_numpy().argmax(axis=1)).astype(str)
            fm=metric_block(actual.tolist(),pred.tolist())
            for rid,row in p.iterrows():oof[str(rid)]=row.to_dict()
            folds.append({'fold':fold,**{k:fm[k] for k in ('runs','accuracy','macro_f1','normal_precision','normal_recall')}})
    ordered=sorted(oof)
    actual_map=manifest.set_index(manifest.run_id.astype(str)).label.astype(str).to_dict()
    pred=[max(LABELS,key=lambda c:oof[r].get(c,0.0)) for r in ordered]
    pooled=metric_block([actual_map[r] for r in ordered],pred)
    pooled['run_ids_scored']=len(ordered)
    return {'pooled_oof':pooled,'folds':folds,'mean_fold_accuracy':float(np.mean([f['accuracy'] for f in folds])),
      'sd_fold_accuracy':float(np.std([f['accuracy'] for f in folds],ddof=1)),
      'mean_fold_macro_f1':float(np.mean([f['macro_f1'] for f in folds])),
      'mean_fold_normal_recall':float(np.mean([f['normal_recall'] for f in folds])),'normal_weight':normal_weight,
      'feature_columns':(features if kind not in ('run_mean_std','run_mean') else [f'{c}__mean' for c in features]+([f'{c}__std' for c in features] if kind=='run_mean_std' else []))}


def metadata_only_cv(manifest:pd.DataFrame,metadata:pd.DataFrame,enc:LabelEncoder)->dict:
    cols=['attacker_host','target_host','service_name','dst_port','rate_value','duration_sec']
    frame=manifest[['run_id','label']].copy();frame['run_id']=frame.run_id.astype(str)
    frame=frame.merge(metadata[['run_id',*cols]],on='run_id',how='left',validate='one_to_one')
    if frame[cols].isna().any().any():raise ValueError('Missing metadata in dev-only confounding check')
    ids=frame.run_id.to_numpy();y=enc.transform(frame.label.astype(str));cv=StratifiedKFold(n_splits=5,shuffle=True,random_state=SEED)
    oof={};folds=[]
    for fold,(a,b) in enumerate(cv.split(ids,y),1):
        tr=frame.iloc[a];te=frame.iloc[b]
        model=make_pipeline(OneHotEncoder(handle_unknown='ignore'),LogisticRegression(max_iter=2000,random_state=42))
        model.fit(tr[cols],enc.transform(tr.label.astype(str)))
        p=model.predict_proba(te[cols]);class_names=enc.inverse_transform(model[-1].classes_.astype(int))
        for rid,row in zip(te.run_id,p):oof[str(rid)]={c:0.0 for c in LABELS}|dict(zip(class_names.tolist(),row.tolist()))
        pred=enc.inverse_transform(model.predict(te[cols])).astype(str)
        folds.append({'fold':fold,'runs':len(te),'accuracy':float(accuracy_score(te.label.astype(str),pred)),
          'macro_f1':float(f1_score(te.label.astype(str),pred,labels=LABELS,average='macro',zero_division=0))})
    ordered=sorted(oof);pred=[max(LABELS,key=lambda c:oof[r].get(c,0.0)) for r in ordered]
    actual=frame.set_index('run_id').label.astype(str).to_dict()
    return {'scope':'Metadata-only diagnostic. These context fields are not classifier inputs; predictability is not proof of model bias.',
      'metadata_columns':cols,'pooled_oof':metric_block([actual[r] for r in ordered],pred),'folds':folds}


def attacker_host_holdout(data:pd.DataFrame,manifest:pd.DataFrame,metadata:pd.DataFrame,features:list[str],enc:LabelEncoder)->dict:
    frame=manifest[['run_id','label']].copy();frame['run_id']=frame.run_id.astype(str)
    frame=frame.merge(metadata[['run_id','attacker_host']],on='run_id',how='left',validate='one_to_one')
    results=[];oof={};skipped=[]
    xall=numeric_features(data,features)
    for host in sorted(frame.attacker_host.astype(str).unique()):
        test_ids=set(frame.loc[frame.attacker_host.astype(str)==host,'run_id'])
        train_ids=set(frame.run_id)-test_ids
        trruns=frame[frame.run_id.isin(train_ids)];teruns=frame[frame.run_id.isin(test_ids)]
        test_counts=teruns.label.value_counts().to_dict();train_classes=set(trruns.label.astype(str))
        if set(test_counts)!=set(LABELS) or train_classes!=set(LABELS):
            skipped.append({'attacker_host':host,'reason':'held-out or training partition lacks one or more classes','test_class_counts':test_counts,'train_classes':sorted(train_classes)})
            continue
        tr=data[data.run_id.astype(str).isin(train_ids)].copy();te=data[data.run_id.astype(str).isin(test_ids)].copy()
        model=xgb_model();model.fit(numeric_features(tr,features),enc.transform(tr.label.astype(str)),sample_weight=equal_run_weights(tr),verbose=False)
        p=probabilities_by_run(model,numeric_features(te,features),te,enc)
        actual=te.assign(_rid=te.run_id.astype(str)).groupby('_rid',sort=True).label.first().loc[p.index].astype(str)
        pred=enc.inverse_transform(p.to_numpy().argmax(axis=1)).astype(str)
        fm=metric_block(actual.tolist(),pred.tolist());results.append({'attacker_host':host,**{k:fm[k] for k in ('runs','accuracy','macro_f1','normal_precision','normal_recall')},'class_counts':test_counts})
        for rid,row in p.iterrows():oof[str(rid)]=row.to_dict()
    if not oof:
        pooled=None
    else:
        ordered=sorted(oof);actual_map=manifest.set_index(manifest.run_id.astype(str)).label.astype(str).to_dict()
        pred=[max(LABELS,key=lambda c:oof[r].get(c,0.0)) for r in ordered]
        pooled=metric_block([actual_map[r] for r in ordered],pred);pooled['run_ids_scored']=len(ordered)
    return {'design':'Leave-one-attacker-host-out stress test; report only folds with all four classes in both train and test. Not used for model selection.',
      'eligible_host_folds':len(results),'skipped_host_folds':skipped,'folds':results,'pooled_eligible_host_oof':pooled,
      'coverage_warning':'If folds are skipped or class supports are sparse, this is a partial stress test and not a complete four-class generalization estimate.'}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-root',type=Path,default=Path.cwd())
    ap.add_argument('--output',type=Path,default=Path('New_Datasets/reports/dev_mitigation_pipeline_once_20261026.json'))
    args=ap.parse_args();root=args.project_root.resolve();base=root/'New_Datasets'
    dev=base/'AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026'
    out=args.output if args.output.is_absolute() else root/args.output
    if not dev.is_dir():raise SystemExit(f'Missing development-only package: {dev}')
    if out.exists():raise SystemExit(f'Refusing to overwrite existing report: {out}')
    if (base/'experiments/run_manifest.csv.in_flight.json').exists():raise SystemExit('STOP: active collector latch exists')
    sums=dev/'SHA256SUMS.txt'
    if not sums.is_file():raise SystemExit('Missing development package checksums')
    for line in sums.read_text(encoding='utf-8').splitlines():
        if line.strip():
            expected,rel=line.split('  ',1);p=dev/rel
            if not p.is_file() or sha256(p)!=expected:raise SystemExit(f'Development package checksum failure: {rel}')
    manifest=pd.read_csv(dev/'run_split_manifest.csv',keep_default_na=False,dtype={'run_id':str})
    required={'run_id','profile_id','generation','label','planned_split'}
    if not required.issubset(manifest.columns):raise SystemExit(f'Development manifest missing fields: {required-set(manifest.columns)}')
    if len(manifest)!=240 or manifest.run_id.duplicated().any() or manifest.profile_id.duplicated().any():raise SystemExit('Expected 240 unique development runs/profiles')
    if set(manifest.label.astype(str))!=set(LABELS):raise SystemExit('Unexpected development label set')
    for lab in LABELS:
        c=manifest.loc[manifest.label.astype(str)==lab,'planned_split'].value_counts().to_dict()
        if c!={'train':48,'validation':12}:raise SystemExit(f'Unexpected development split for {lab}: {c}')
    if pd.to_numeric(manifest.generation,errors='coerce').ge(550).any():raise SystemExit('Development package crosses the final-test generation boundary')
    metadata=read_dev_run_metadata(base/'experiments/run_manifest.csv',set(manifest.run_id.astype(str)))
    meta_check=manifest[['run_id','label']].merge(metadata[['run_id','label','status']],on='run_id',suffixes=('_pkg','_ledger'),validate='one_to_one')
    if (meta_check.label_pkg!=meta_check.label_ledger).any() or not meta_check.status.eq('completed').all():raise SystemExit('Development manifest disagrees with completed development ledger')
    cfg=json.loads((dev/'config/model_features.json').read_text(encoding='utf-8'))
    enc=LabelEncoder().fit(LABELS)
    configs=[('row_xgb_baseline','row_xgb',1.0),('row_xgb_normal_1p25','row_xgb',1.25),
      ('row_xgb_normal_1p5','row_xgb',1.5),('row_regularized_rf','rf',1.0),
      ('run_mean_xgb','run_mean',1.0),('run_mean_std_xgb','run_mean_std',1.0)]
    levels={}
    for level in ('packet','flow'):
        features=list(cfg[f'{level}_features'])
        frames=[]
        for split in ('train','validation'):
            f=pd.read_csv(dev/f'{level}_splits/{split}.csv',keep_default_na=False,low_memory=False)
            needed={'run_id','observation_id','label',*features}
            if not needed.issubset(f.columns):raise SystemExit(f'{level} {split} missing required columns')
            f['run_id']=f.run_id.astype(str);f['_split']=split;frames.append(f)
        data=pd.concat(frames,ignore_index=True)
        if set(data.run_id)!=set(manifest.run_id.astype(str)):raise SystemExit(f'{level} rows do not match development IDs')
        if data.observation_id.astype(str).eq('').any() or data.observation_id.astype(str).duplicated().any():raise SystemExit(f'{level} missing/duplicate development observation IDs')
        if data.groupby('run_id').label.nunique().gt(1).any():raise SystemExit(f'{level} run has conflicting labels')
        assignment=data[['run_id','_split']].drop_duplicates().merge(manifest[['run_id','planned_split']],on='run_id',validate='one_to_one')
        if not assignment['_split'].eq(assignment.planned_split).all():raise SystemExit(f'{level} rows disagree with their development run split')
        candidates={}
        print(f'{level}: starting six development-only candidates',flush=True)
        for name,kind,weight in configs:
            candidates[name]=run_level_cv(data,manifest,features,enc,kind,weight)
            m=candidates[name]['pooled_oof']
            print(f'{level}/{name}: acc={m["accuracy"]:.4f} macroF1={m["macro_f1"]:.4f} NormalP/R={m["normal_precision"]:.3f}/{m["normal_recall"]:.3f}',flush=True)
        host_cv=attacker_host_holdout(data,manifest,metadata,features,enc)
        levels[level]={'feature_count':len(features),'features':features,'rows':int(len(data)),
          'observation_ids_unique':True,'candidates':candidates,'attacker_host_holdout_stress':host_cv}
    md_cv=metadata_only_cv(manifest,metadata,enc)
    report={'scope':'Expanded development package only (240 runs; generations <550). Final-test feature files, predictions, metrics, and model artifacts were not read or modified.',
      'protocol':{'cv':'5-fold stratified OOF on one manifest row per run; all Packet/Flow observations from each run are assigned together.','seed':SEED,
        'run_summaries':'Mean or mean+population-standard-deviation of each feature computed within each run and separately inside each CV fold.',
        'model_artifacts':'No model files are saved or replaced; CV candidate estimators exist only in memory.',
        'selection':'No winning candidate is promoted automatically. Compare to the frozen baseline and require a new independent holdout for any changed production claim.'},
      'dataset_qc':{'runs':len(manifest),'runs_per_class':{str(k):int(v) for k,v in manifest.label.value_counts().items()},
        'train_validation_per_class':{lab:{split:int(((manifest.label==lab)&(manifest.planned_split==split)).sum()) for split in ('train','validation')} for lab in LABELS},
        'run_ids_unique':True,'profile_ids_unique':True,'no_run_split_leakage':True,
        'development_generation_max':int(pd.to_numeric(manifest.generation).max()),'final_test_generation_boundary':550},
      'levels':levels,'metadata_only_diagnostic':md_cv,
      'decision_note':'Normal class weighting and thresholds did not improve the prior nested outer-fold argmax baseline. This pipeline adds run-summary candidates and condition-aware stress tests for both Packet and Flow; results are development diagnostics, not evidence of a final-test accuracy increase.'}
    print('Both Packet and Flow development experiments complete; writing report.',flush=True)
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print('DEVELOPMENT MITIGATION PIPELINE COMPLETE:',out,flush=True)
    print('No final-test features, scores, or models accessed; no frozen model replaced.',flush=True)

if __name__=='__main__':
    try:main()
    except Exception as exc:
        print(f'DEV MITIGATION PIPELINE STOP: {type(exc).__name__}: {exc}',file=sys.stderr)
        raise
