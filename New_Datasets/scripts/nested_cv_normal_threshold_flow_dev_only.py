#!/usr/bin/env python3
"""Nested run-grouped CV for Flow-XGBoost Normal recall/precision trade-off.
Uses development package only. Inner folds select Normal weight and probability
threshold; outer folds estimate the selected policy. No final-test paths are read,
no frozen model is changed, and no artifacts other than a new JSON report are saved.
"""
import json, hashlib, sys
from pathlib import Path
from collections import Counter
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report, precision_recall_fscore_support
from xgboost import XGBClassifier

ROOT=Path.cwd();BASE=ROOT/'New_Datasets';DEV=BASE/'AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026'
OUT=BASE/'reports/nested_cv_flow_normal_policy_dev_only_20261026.json'
LABELS=['Malicious_POST','Normal','Port_Scan','SYN_Flood'];SEED=2601026
WEIGHTS=[1.0,1.25,1.5]
THRESHOLDS=[round(x,3) for x in np.arange(0.20,0.801,0.025)]
MIN_NORMAL_RECALL=0.80;MIN_NORMAL_PRECISION=0.70

def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def encode(df,cols):
 x=df.loc[:,cols].copy()
 if 'protocol' in x:x['protocol']=x['protocol'].astype(str).str.strip().str.lower().map({'tcp':6,'udp':17,'icmp':1,'icmpv6':58,'igmp':2,'other':0,'unknown':0}).fillna(0)
 for c in x:x[c]=pd.to_numeric(x[c],errors='coerce').fillna(0)
 if not np.isfinite(x.to_numpy(float)).all():raise ValueError('nonfinite feature')
 return x
def weights_for(df,normal_multiplier):
 ids=df.run_id.astype(str);counts=ids.value_counts();w=ids.map(lambda x:1.0/counts[x]).to_numpy(float)
 w*=np.where(df.label.astype(str).to_numpy()=='Normal',normal_multiplier,1.0)
 return w*len(w)/w.sum()
def new_model():
 return XGBClassifier(n_estimators=300,max_depth=3,learning_rate=.05,subsample=.9,colsample_bytree=.9,min_child_weight=2,reg_lambda=1.0,objective='multi:softprob',eval_metric='mlogloss',random_state=42,n_jobs=-1,tree_method='hist')
def run_probabilities(model,x,df):
 q=pd.DataFrame(model.predict_proba(x),index=df.index,columns=model.classes_)
 q['run_id']=df.run_id.astype(str).to_numpy()
 return q.groupby('run_id',sort=True).mean()
def labels_and_probs(mean,actual,encoder):
 # Reorder model columns into the frozen label-encoder order.
 p=mean.reindex(columns=encoder.transform(encoder.classes_),fill_value=0).to_numpy(float)
 y=np.array([actual[r] for r in mean.index],dtype=object)
 return y,p,list(mean.index)
def predict_policy(p,encoder,threshold=None):
 classes=list(encoder.classes_);normal_i=classes.index('Normal')
 arg=encoder.inverse_transform(p.argmax(axis=1))
 if threshold is None:return arg.astype(str)
 nonnormal=[i for i,c in enumerate(classes) if c!='Normal']
 pred=[]
 for row,base in zip(p,arg):
  if row[normal_i]>=threshold:pred.append('Normal')
  else:pred.append(classes[nonnormal[int(np.argmax(row[nonnormal]))]])
 return np.asarray(pred,dtype=object)
def scores(y,pred):
 return {'accuracy':float(accuracy_score(y,pred)),'macro_f1':float(f1_score(y,pred,labels=LABELS,average='macro',zero_division=0)),
         'confusion_matrix':confusion_matrix(y,pred,labels=LABELS).tolist(),
         'classification_report':classification_report(y,pred,labels=LABELS,target_names=LABELS,output_dict=True,zero_division=0)}
def choose_policy(y,p,ids,encoder):
 options=[]
 for threshold in THRESHOLDS:
  pred=predict_policy(p,encoder,threshold)
  r=classification_report(y,pred,labels=LABELS,target_names=LABELS,output_dict=True,zero_division=0)
  options.append({'threshold':threshold,'normal_weight':None,'metrics':scores(y,pred),
    'normal_recall':float(r['Normal']['recall']),'normal_precision':float(r['Normal']['precision'])})
 # Add ordinary multiclass argmax as a candidate policy.
 pred=predict_policy(p,encoder,None);r=classification_report(y,pred,labels=LABELS,target_names=LABELS,output_dict=True,zero_division=0)
 options.append({'threshold':None,'normal_weight':None,'metrics':scores(y,pred),
   'normal_recall':float(r['Normal']['recall']),'normal_precision':float(r['Normal']['precision'])})
 feasible=[o for o in options if o['normal_recall']>=MIN_NORMAL_RECALL and o['normal_precision']>=MIN_NORMAL_PRECISION]
 pool=feasible if feasible else options
 # Primary objective macro-F1, then accuracy, then Normal precision; constraint status is reported.
 best=max(pool,key=lambda o:(o['metrics']['macro_f1'],o['metrics']['accuracy'],o['normal_precision']))
 return best,bool(feasible)
def main():
 if OUT.exists():raise SystemExit(f'Refusing overwrite of prior nested-CV result: {OUT}')
 if not DEV.is_dir():raise SystemExit(f'Missing development package: {DEV}')
 for line in (DEV/'SHA256SUMS.txt').read_text().splitlines():
  if line.strip():
   expected,rel=line.split('  ',1)
   if sha(DEV/rel)!=expected:raise SystemExit(f'Development package checksum mismatch: {rel}')
 sm=pd.read_csv(DEV/'run_split_manifest.csv',dtype={'run_id':str})
 if len(sm)!=240 or sm.run_id.duplicated().any() or sm.profile_id.duplicated().any():raise SystemExit('Expected 240 unique development runs and profiles')
 for lab in LABELS:
  c=sm.loc[sm.label==lab,'planned_split'].value_counts().to_dict()
  if c!={'train':48,'validation':12}:raise SystemExit(f'Unexpected split for {lab}: {c}')
 cfg=json.loads((DEV/'config/model_features.json').read_text());cols=list(cfg['flow_features'])
 tr=pd.read_csv(DEV/'flow_splits/train.csv',keep_default_na=False,low_memory=False);va=pd.read_csv(DEV/'flow_splits/validation.csv',keep_default_na=False,low_memory=False)
 data=pd.concat([tr,va],ignore_index=True);data['run_id']=data.run_id.astype(str)
 if set(data.run_id)!=set(sm.run_id.astype(str)):raise SystemExit('Flow observations do not match development run manifest')
 if data.groupby('run_id').label.nunique().gt(1).any():raise SystemExit('Conflicting run labels')
 if data.observation_id.astype(str).eq('').any() or data.observation_id.astype(str).duplicated().any():raise SystemExit('Missing/duplicate observation IDs')
 enc=LabelEncoder().fit(LABELS);runmeta=sm[['run_id','label']].copy();runmeta['run_id']=runmeta.run_id.astype(str)
 ids=runmeta.run_id.to_numpy();y=enc.transform(runmeta.label.astype(str))
 outer=StratifiedKFold(n_splits=5,shuffle=True,random_state=SEED);folds=[]
 for a,b in outer.split(ids,y):
  tri=set(ids[a]);tei=set(ids[b]);cc=Counter(runmeta.iloc[b].label.astype(str))
  if tri&tei or any(cc[k]!=12 for k in LABELS):raise SystemExit('Outer fold grouping/balance failure')
  folds.append((tri,tei))
 all_outer=[];report={'scope':'Development-only nested run-grouped CV; final-test files and metrics were never accessed.',
  'outer_folds':5,'inner_folds':4,'candidate_normal_weights':WEIGHTS,'threshold_grid':THRESHOLDS,
  'selection_rule':f'Maximize inner-OOF macro-F1 subject to Normal recall >= {MIN_NORMAL_RECALL:.2f} and Normal precision >= {MIN_NORMAL_PRECISION:.2f}; if no feasible candidate, maximize macro-F1 then accuracy then Normal precision. Threshold applies Normal if P(Normal)>=threshold, otherwise choose highest-probability attack class.',
  'seed':SEED,'folds':[]}
 for oi,(outer_train_ids,outer_test_ids) in enumerate(folds,1):
  outer_train=data[data.run_id.isin(outer_train_ids)].copy();outer_test=data[data.run_id.isin(outer_test_ids)].copy()
  rmeta=runmeta[runmeta.run_id.isin(outer_train_ids)].reset_index(drop=True);rids=rmeta.run_id.to_numpy();ry=enc.transform(rmeta.label.astype(str))
  inner=StratifiedKFold(n_splits=4,shuffle=True,random_state=SEED+oi);inner_folds=list(inner.split(rids,ry))
  candidate_predictions={w:{} for w in WEIGHTS};candidate_actual={}
  for w in WEIGHTS:
   for ii,(ia,ib) in enumerate(inner_folds,1):
    itrids=set(rids[ia]);iteids=set(rids[ib])
    itr=outer_train[outer_train.run_id.isin(itrids)].copy();ite=outer_train[outer_train.run_id.isin(iteids)].copy()
    model=new_model();model.fit(encode(itr,cols),enc.transform(itr.label.astype(str)),sample_weight=weights_for(itr,w),verbose=False)
    means=run_probabilities(model,encode(ite,cols),ite)
    act=ite.assign(_rid=ite.run_id).groupby('_rid',sort=True).label.first().to_dict()
    yy,pp,run_order=labels_and_probs(means,act,enc)
    for rid,label,prob in zip(run_order,yy,pp):candidate_predictions[w][rid]=prob;candidate_actual[rid]=label
    print(f'outer {oi}/5 inner {ii}/4 weight={w}: done',flush=True)
  inner_ids=sorted(candidate_actual)
  yinner=np.asarray([candidate_actual[r] for r in inner_ids],dtype=object)
  policies=[]
  for w in WEIGHTS:
   pin=np.vstack([candidate_predictions[w][r] for r in inner_ids])
   chosen,feasible=choose_policy(yinner,pin,inner_ids,enc)
   chosen['normal_weight']=w;chosen['constraint_feasible']=feasible
   policies.append(chosen)
  selected=max(policies,key=lambda o:(o['metrics']['macro_f1'],o['metrics']['accuracy'],o['normal_precision']))
  # Outer held-out estimate: refit selected weight on all outer-training runs, use inner-selected threshold.
  final=new_model();final.fit(encode(outer_train,cols),enc.transform(outer_train.label.astype(str)),sample_weight=weights_for(outer_train,selected['normal_weight']),verbose=False)
  outer_means=run_probabilities(final,encode(outer_test,cols),outer_test)
  act=outer_test.assign(_rid=outer_test.run_id).groupby('_rid',sort=True).label.first().to_dict();yo,po,outer_order=labels_and_probs(outer_means,act,enc)
  pred_sel=predict_policy(po,enc,selected['threshold']);metric_sel=scores(yo,pred_sel)
  # Same fitted model's default argmax as a within-fold comparator.
  pred_arg=predict_policy(po,enc,None);metric_arg=scores(yo,pred_arg)
  fold={'outer_fold':oi,'outer_train_runs':len(outer_train_ids),'outer_test_runs':len(outer_test_ids),
    'selected_normal_weight':selected['normal_weight'],'selected_normal_threshold':selected['threshold'],
    'inner_constraints_feasible_for_selected_weight':selected['constraint_feasible'],
    'inner_selected_metrics':selected['metrics'],'outer_selected_policy':metric_sel,'outer_default_argmax':metric_arg,
    'outer_selected_normal_precision':metric_sel['classification_report']['Normal']['precision'],
    'outer_selected_normal_recall':metric_sel['classification_report']['Normal']['recall'],
    'candidate_inner_results':[{'normal_weight':o['normal_weight'],'threshold':o['threshold'],'constraint_feasible':o['constraint_feasible'],'accuracy':o['metrics']['accuracy'],'macro_f1':o['metrics']['macro_f1'],'normal_precision':o['normal_precision'],'normal_recall':o['normal_recall']} for o in policies]}
  report['folds'].append(fold);all_outer.extend([{'actual':a,'selected':p,'default':d} for a,p,d in zip(yo,pred_sel,pred_arg)])
  print(f"OUTER {oi}/5 selected weight={selected['normal_weight']} threshold={selected['threshold']}; heldout acc={metric_sel['accuracy']:.3f} F1={metric_sel['macro_f1']:.3f} Normal P/R={metric_sel['classification_report']['Normal']['precision']:.3f}/{metric_sel['classification_report']['Normal']['recall']:.3f}",flush=True)
 yall=[x['actual'] for x in all_outer];ps=[x['selected'] for x in all_outer];pd0=[x['default'] for x in all_outer]
 report['outer_oof_selected_policy']=scores(yall,ps);report['outer_oof_default_argmax']=scores(yall,pd0)
 report['outer_fold_mean']={
  'selected_accuracy':float(np.mean([f['outer_selected_policy']['accuracy'] for f in report['folds']])),
  'selected_macro_f1':float(np.mean([f['outer_selected_policy']['macro_f1'] for f in report['folds']])),
  'selected_normal_precision':float(np.mean([f['outer_selected_normal_precision'] for f in report['folds']])),
  'selected_normal_recall':float(np.mean([f['outer_selected_normal_recall'] for f in report['folds']])),
  'default_accuracy':float(np.mean([f['outer_default_argmax']['accuracy'] for f in report['folds']])),
  'default_macro_f1':float(np.mean([f['outer_default_argmax']['macro_f1'] for f in report['folds']])),
  'normal_weights_selected':{str(w):sum(f['selected_normal_weight']==w for f in report['folds']) for w in WEIGHTS},
  'thresholds_selected':[f['selected_normal_threshold'] for f in report['folds']]}
 report['note']='Outer-fold performance estimates the inner selection procedure on development only. It does not replace the final holdout result. Because this is a new candidate-selection analysis, any chosen policy needs a new independent holdout for a confirmatory accuracy claim.'
 OUT.parent.mkdir(parents=True,exist_ok=True);OUT.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 print('NESTED DEVELOPMENT CV COMPLETE:',OUT,flush=True)
 print('No final-test data opened; no models or existing project files changed.',flush=True)
if __name__=='__main__':
 try:main()
 except Exception as e:print(f'NESTED CV STOP: {type(e).__name__}: {e}',file=sys.stderr);raise
