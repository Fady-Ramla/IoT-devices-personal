#!/usr/bin/env python3
"""Build and train a leakage-safe expanded development-only Packet/Flow dataset.

Combines the existing repaired V2 train/validation candidate (80 runs) with
160 verified expanded-campaign runs (154 successful planned runs + 6 split-
preserving replacements). The six failed original campaign captures are
excluded. This program never opens or scores any final-test split or raw test
capture. It uses equal total training weight per run and reports train/validation
metrics only.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, math, os, shutil, sys, tempfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

LABELS=("Malicious_POST","Normal","Port_Scan","SYN_Flood")
SPLITS=("train","validation")
PROTO={"1":"icmp","6":"tcp","17":"udp","41":"ipv6","58":"icmpv6"}
FAILED={
 429:("cef79fd4-31e6-4d78-b442-984c3dfd79ab","SYNNEW037","validation"),
 468:("d3c58f4d-8978-4ab2-82ad-56976756f15d","NNEW055","train"),
 491:("588e6022-94e4-4976-84fd-13226525f0b4","SYNNEW080","train"),
 492:("db52e485-6048-4fd3-acf4-2019cd129aeb","SYNNEW035","train"),
 495:("d15ef3ec-149a-41f4-9f71-e847501f1c4e","SYNNEW010","train"),
 517:("7031432b-fc51-4721-a87a-c3bdb816f754","SYNNEW009","train"),
}
REPLACEMENTS={
 536:("0f332267-7c24-4750-ad1d-db8bfed5a3be","NREPL001","Normal","train"),
 537:("6437f0ea-3ed4-46d3-bfc3-72488f9a64ef","SYNREPL001","SYN_Flood","validation"),
 538:("186cfc21-479e-43f4-99bb-f742ef8e1df0","SYNREPL002","SYN_Flood","train"),
 539:("b20a942c-e3f6-4f67-b58d-54314e34cfa5","SYNREPL003","SYN_Flood","train"),
 540:("c034cf33-f5e9-439b-997a-dff58bd490ca","SYNREPL004","SYN_Flood","train"),
 541:("bb3eb80a-a857-4b5b-a080-61f817b6d6e7","SYNREPL005","SYN_Flood","train"),
}


def read_csv(path:Path):
    with path.open("r",newline="",encoding="utf-8-sig") as f:
        reader=csv.DictReader(f)
        if not reader.fieldnames: raise ValueError(f"CSV has no header: {path}")
        return reader.fieldnames,list(reader)


def sha256(path:Path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda:f.read(1024*1024),b""): h.update(block)
    return h.hexdigest()


def protocol_name(value):
    value=(value or "").strip()
    try: key=str(int(float(value)))
    except (ValueError,TypeError): return value.lower() or "unknown"
    return PROTO.get(key,"ip_proto_"+key)


def numeric(value,integer=False):
    value=(value or "").strip()
    if not value:return "0"
    x=float(value)
    if not math.isfinite(x): raise ValueError(f"non-finite numeric value {value!r}")
    return str(int(x)) if integer else format(x,".12g")


def packet_values(row,features):
    flags=int(float(row.get("tcp_flags") or 0))
    d={"protocol":protocol_name(row.get("protocol","")),
       "src_port":numeric(row.get("src_port","")),"dst_port":numeric(row.get("dst_port","")),
       "packet_length":numeric(row.get("packet_length",""),True),
       "tcp_syn":str(int(bool(flags&0x02))),"tcp_ack":str(int(bool(flags&0x10))),
       "tcp_rst":str(int(bool(flags&0x04))),"tcp_fin":str(int(bool(flags&0x01))),
       "icmp_type":numeric(row.get("icmp_type",""),True),
       "arp_operation":numeric(row.get("arp_operation",""),True)}
    missing=[x for x in features if x not in d]
    if missing:raise ValueError(f"Unsupported Packet feature(s): {missing}")
    return {x:d[x] for x in features}


def flow_values(row,features):
    d=dict(row);d["protocol"]=protocol_name(row.get("protocol",""))
    missing=[x for x in features if x not in d]
    if missing:raise ValueError(f"Flow raw data missing feature(s): {missing}")
    ints={"src_port","dst_port","packet_count","byte_count","syn_count","ack_count","rst_count","fin_count","unique_dst_ports","failed_connection_count"}
    return {x:(d[x] if x=="protocol" else numeric(d[x],x in ints)) for x in features}


def app_events(base:Path,run_id:str):
    dirs=[p for p in (base/"raw").glob("application*") if p.is_dir()]
    paths=[p for d in dirs for p in d.rglob(run_id+".csv")]
    events=[]
    for path in paths:
        _,rows=read_csv(path);events.extend(rows)
    return events


def event_value(row,*keys):
    for k in keys:
        if row.get(k) not in (None,""): return str(row[k]).strip()
    return ""


def validate_app_evidence(base, selected):
    issues=[]; evidence={}
    for item in selected:
        if item["label"] not in ("Malicious_POST","Normal"):
            continue
        # All new attack-POST runs must have observable failed-auth POST evidence.
        # The explicitly planned Normal login-success replacement must show 200.
        must_check=(item["label"]=="Malicious_POST" or item["profile_id"]=="NREPL001")
        if not must_check: continue
        events=app_events(base,item["run_id"])
        matches=[]
        for e in events:
            method=event_value(e,"http_method","method").upper()
            route=event_value(e,"route_category","route").lower()
            status=event_value(e,"response_status","status")
            expected_status="401" if item["label"]=="Malicious_POST" else "200"
            if method=="POST" and route=="auth" and status==expected_status:
                matches.append(e)
        if not matches:
            issues.append(f"{item['profile_id']} gen={item['generation']} run={item['run_id']}: missing POST/auth/{'401' if item['label']=='Malicious_POST' else '200'} application evidence")
        evidence[item["profile_id"]]=len(matches)
    if issues:
        raise ValueError("Application-layer label verification failed:\n  " + "\n  ".join(issues))
    return evidence


def exact_manifest_match(r,planned):
    """Check fields available in the run manifest against the planned command."""
    parts=(planned.get("command") or "").split()
    if not parts:return False
    label=planned.get("expected_label")
    if r.get("label")!=label:return False
    def eqnum(a,b):
        try:return math.isclose(float(a),float(b),rel_tol=0,abs_tol=1e-8)
        except (TypeError,ValueError):return False
    def scan_delay_ms(row):
        try:notes=json.loads(row.get("notes") or "{}")
        except (TypeError,ValueError):return None
        operator=notes.get("operator_notes",{}) if isinstance(notes,dict) else {}
        if isinstance(operator,str):
            try:operator=json.loads(operator)
            except (TypeError,ValueError):return None
        return operator.get("scan_delay_ms") if isinstance(operator,dict) else None
    if parts[0]=="normal":
        return (r.get("service_name")==parts[2] and r.get("target_host")==parts[3]
                and eqnum(r.get("duration_sec"),parts[4]) and eqnum(r.get("rate_value"),parts[5]))
    if len(parts)>=3 and parts[2]=="syn_flood":
        return (r.get("attack_type")=="syn_flood" and r.get("target_host")==parts[3]
                and eqnum(r.get("dst_port"),parts[4]) and eqnum(r.get("rate_value"),parts[5])
                and eqnum(r.get("duration_sec"),parts[6]))
    if len(parts)>=3 and parts[2]=="malicious_post":
        # Attack profile count/rate/duration is checked where the collector persists
        # the normalized rate; identity and label are mandatory in every case.
        return (r.get("attack_type")=="malicious_post" and r.get("target_host")==parts[3]
                and eqnum(r.get("duration_sec"),parts[8]))
    if len(parts)>=3 and parts[2]=="port_scan":
        return (r.get("attack_type")=="port_scan" and r.get("target_host")==parts[3]
                and r.get("dst_port")==parts[4]
                and eqnum(scan_delay_ms(r),parts[5])
                and eqnum(r.get("rate_value"),1000.0/float(parts[5]))
                and eqnum(r.get("duration_sec"),parts[6]))
    return False


def load_base_runs(pkg:Path):
    sm_path=pkg/"run_split_manifest.csv"
    if not sm_path.is_file():raise ValueError(f"Missing base run manifest: {sm_path}")
    _,rows=read_csv(sm_path)
    records=[]
    for r in rows:
        split=r.get("planned_split")
        if split not in SPLITS: raise ValueError(f"Unexpected base split {split!r}; only train/validation are allowed")
        records.append({"generation":r.get("generation",""),"run_id":r["run_id"],"label":r["label"],
                        "profile_id":r["profile_id"],"split":split,"plan_index":r.get("plan_index",""),
                        "source":"repaired_trainval_v2"})
    if len(records)!=80:raise ValueError(f"Expected 80 base development runs; got {len(records)}")
    for label in LABELS:
        counts={s:sum(x["split"]==s and x["label"]==label for x in records) for s in SPLITS}
        if counts!={"train":16,"validation":4}:
            raise ValueError(f"Base repaired package split mismatch for {label}: {counts}")
    return records


def encode(frame,columns):
    missing=sorted(set(columns)-set(frame.columns))
    if missing:raise ValueError(f"Missing model feature(s): {missing}")
    x=frame.loc[:,columns].copy()
    if "protocol" in x.columns:
        x["protocol"]=(x["protocol"].astype(str).str.strip().str.lower()
          .map({"tcp":6,"udp":17,"icmp":1,"icmpv6":58,"igmp":2,"other":0,"unknown":0}).fillna(0))
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
    row={"rows":int(len(frame)),"runs":int(frame.run_id.nunique()),
         "accuracy":float(accuracy_score(y,pred)),"precision_macro":float(precision_score(y,pred,average="macro",zero_division=0)),
         "recall_macro":float(recall_score(y,pred,average="macro",zero_division=0)),"f1_macro":float(f1_score(y,pred,average="macro",zero_division=0)),
         "confusion_matrix":confusion_matrix(y,pred,labels=ids).tolist(),
         "classification_report":classification_report(y,pred,labels=ids,target_names=encoder.classes_.tolist(),output_dict=True,zero_division=0)}
    probs=pd.DataFrame(model.predict_proba(x),index=frame.index,columns=model.classes_)
    probs["run_id"]=frame["run_id"].astype(str).to_numpy();mean=probs.groupby("run_id",sort=True).mean()
    actual=frame.assign(_rid=frame["run_id"].astype(str)).groupby("_rid",sort=True)["label"].first().loc[mean.index]
    yp=encoder.inverse_transform(mean.to_numpy().argmax(axis=1));yt=actual.to_numpy()
    run={"runs":int(len(yt)),"aggregation":"mean class probability across observations in each run",
         "accuracy":float(accuracy_score(yt,yp)),"precision_macro":float(precision_score(yt,yp,average="macro",zero_division=0)),
         "recall_macro":float(recall_score(yt,yp,average="macro",zero_division=0)),"f1_macro":float(f1_score(yt,yp,average="macro",zero_division=0)),
         "confusion_matrix":confusion_matrix(yt,yp,labels=encoder.classes_.tolist()).tolist(),
         "classification_report":classification_report(yt,yp,labels=encoder.classes_.tolist(),target_names=encoder.classes_.tolist(),output_dict=True,zero_division=0),
         "predictions":[{"run_id":str(i),"actual":str(a),"predicted":str(p)} for i,a,p in zip(mean.index,yt,yp)]}
    return {"row_level":row,"run_level":run}


def verify_package_checksums(pkg:Path):
    sums=pkg/"SHA256SUMS.txt"
    if not sums.is_file():raise ValueError(f"Base package checksum file missing: {sums}")
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():continue
        expected,rel=line.split("  ",1);path=pkg/rel
        if not path.is_file() or sha256(path)!=expected:
            raise ValueError(f"Base package checksum mismatch: {rel}")


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root",type=Path,default=Path.cwd())
    ap.add_argument("--base-package",type=Path,default=Path("New_Datasets/AI_OFFLINE_LEARNING_REPAIRED_TRAIN_VAL_V2_20261025"))
    ap.add_argument("--expanded-plan",type=Path,default=Path("New_Datasets/scripts/collection_plan_expanded_development_160_20261025.csv"))
    ap.add_argument("--replacement-plan",type=Path,default=Path("New_Datasets/scripts/collection_plan_replace_failed_expanded_dev_6runs.csv"))
    ap.add_argument("--output-package",type=Path,default=Path("New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026"))
    ap.add_argument("--seed",type=int,default=42)
    args=ap.parse_args();root=args.project_root.resolve();base=root/"New_Datasets"
    def resolve(p):return p if p.is_absolute() else root/p
    basepkg=resolve(args.base_package);plan_path=resolve(args.expanded_plan);replacement_path=resolve(args.replacement_plan);out=resolve(args.output_package)
    latch=base/"experiments/run_manifest.csv.in_flight.json"
    if latch.exists():raise SystemExit(f"STOP: active run latch exists: {latch}")
    for p in (base/"experiments/run_manifest.csv",plan_path,replacement_path,basepkg/"SHA256SUMS.txt",basepkg/"run_split_manifest.csv",basepkg/"config/model_features.json"):
        if not p.is_file():raise SystemExit(f"STOP: required input missing: {p}")
    verify_package_checksums(basepkg)
    cfg=json.loads((basepkg/"config/model_features.json").read_text(encoding="utf-8"))
    pf=list(cfg["packet_features"]);ff=list(cfg["flow_features"])
    manifest=read_csv(base/"experiments/run_manifest.csv")[1]
    generations={}
    for r in manifest:
        try:g=int(r.get("generation") or 0)
        except ValueError:continue
        if 376<=g<=541:
            if g in generations:raise ValueError(f"Duplicate manifest generation {g}")
            generations[g]=r
    if set(generations)!=set(range(376,542)):
        raise ValueError(f"Campaign generations 376..541 incomplete; missing={sorted(set(range(376,542))-set(generations))}")
    plan=read_csv(plan_path)[1]
    if len(plan)!=160 or len({int(r["plan_index"]) for r in plan})!=160:
        raise ValueError("Expanded development plan must have 160 unique plan indices")
    if len({r["profile_id"] for r in plan})!=160 or len({r["command"] for r in plan})!=160:
        raise ValueError("Expanded development plan has duplicate profiles/commands")
    # The development CSV preserves execution order but its plan_index values
    # are sparse global indices from the combined 320-profile campaign (the
    # interleaved fresh-test rows were removed). Generation 376 is therefore
    # the first CSV row, not necessarily plan_index 1.
    generation_plan={376+i:r for i,r in enumerate(plan)}
    for lab in LABELS:
        subset=[r for r in plan if r["expected_label"]==lab]
        if len(subset)!=40 or Counter(r["planned_split"] for r in subset)!={"train":32,"validation":8}:
            raise ValueError(f"Expanded plan balance/split mismatch for {lab}")
    replacement_rows=read_csv(replacement_path)[1]
    if len(replacement_rows)!=6 or len({r["profile_id"] for r in replacement_rows})!=6:
        raise ValueError("Replacement plan must contain six unique profiles")
    replacement_by_profile={r["profile_id"]:r for r in replacement_rows}
    if set(replacement_by_profile)!={spec[1] for spec in REPLACEMENTS.values()}:
        raise ValueError("Replacement plan profile IDs differ from the audited six-profile plan")

    excluded=[];expanded_selected=[]
    for g in range(376,536):
        r=generations[g];p=generation_plan[g];pi=int(p["plan_index"])
        if r.get("label")!=p.get("expected_label"):
            raise ValueError(f"Label mismatch gen {g}: manifest={r.get('label')} plan={p.get('expected_label')}")
        if r.get("status")=="failed":
            spec=FAILED.get(g)
            if not spec or r.get("run_id")!=spec[0] or p.get("profile_id")!=spec[1] or p.get("planned_split")!=spec[2]:
                raise ValueError(f"Unexpected failed campaign record at generation {g}")
            excluded.append({"generation":g,"run_id":r.get("run_id"),"profile_id":p["profile_id"],"label":p["expected_label"],"planned_split":p["planned_split"],"reason":"manifest status failed; excluded"})
            continue
        if r.get("status")!="completed":raise ValueError(f"Unexpected manifest status at generation {g}: {r.get('status')}")
        if not exact_manifest_match(r,p):raise ValueError(f"Manifest does not match planned capture for generation {g}, profile {p['profile_id']}")
        expanded_selected.append({"generation":g,"run_id":r["run_id"],"profile_id":p["profile_id"],"label":p["expected_label"],"split":p["planned_split"],"plan_index":pi,"source":"expanded_campaign"})
    if set(FAILED)!={g for g in range(376,536) if generations[g].get("status")=="failed"}:
        raise ValueError("Failed generations in manifest differ from the six audited failures")

    for g,(expected_id,pid,label,split) in REPLACEMENTS.items():
        r=generations[g];p=replacement_by_profile[pid]
        if r.get("run_id")!=expected_id or r.get("status")!="completed" or r.get("label")!=label:
            raise ValueError(f"Replacement generation/run/status mismatch at {g}")
        if p.get("expected_label")!=label or p.get("planned_split")!=split or not exact_manifest_match(r,p):
            raise ValueError(f"Replacement manifest/plan mismatch at generation {g}, profile {pid}")
        expanded_selected.append({"generation":g,"run_id":r["run_id"],"profile_id":pid,"label":label,"split":split,"plan_index":int(p["plan_index"]),"source":"verified_replacement"})
    if len(expanded_selected)!=160:raise ValueError(f"Expected 160 valid expanded runs, found {len(expanded_selected)}")

    base_selected=load_base_runs(basepkg)
    all_selected=base_selected+expanded_selected
    run_ids=[x["run_id"] for x in all_selected];profiles=[x["profile_id"] for x in all_selected]
    if len(set(run_ids))!=len(run_ids):raise ValueError("Duplicate run_id across base and expanded development data")
    if len(set(profiles))!=len(profiles):raise ValueError("Duplicate profile_id across base and expanded development data")
    split_counts={s:Counter() for s in SPLITS}
    for x in all_selected:
        if x["split"] not in SPLITS or x["label"] not in LABELS:raise ValueError(f"Invalid assignment: {x}")
        split_counts[x["split"]][x["label"]]+=1
    for lab in LABELS:
        got={s:split_counts[s][lab] for s in SPLITS}
        if got!={"train":48,"validation":12}:raise ValueError(f"Combined run balance mismatch for {lab}: {got}")

    # Verify required application-layer evidence before writing any package.
    app_evidence=validate_app_evidence(base,expanded_selected)
    print("PASS: application verification for expanded Malicious_POST and replacement Normal:",len(app_evidence),"profiles",flush=True)

    if out.exists():
        # Safe rerun path after model-training interruption: accept only a complete,
        # matching dataset package verified by hashes and run counts.
        verify_package_checksums(out)
        qc=json.loads((out/"qc_report.json").read_text(encoding="utf-8"))
        if qc.get("selected_runs")!=240 or qc.get("run_counts_by_label_split")!={lab:{s:(48 if s=="train" else 12) for s in SPLITS} for lab in LABELS}:
            raise SystemExit(f"STOP: existing output is not this expected 240-run package: {out}")
        print("Verified existing complete development package; skipping rebuild.",flush=True)
    else:
        staging=Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-",dir=str(out.parent)))
        handles=[];writers={};obs_seen={"packet":set(),"flow":set()};exact={"packet":set(),"flow":set()};counts={"packet":Counter(),"flow":Counter()}
        try:
            for level,features in (("packet",pf),("flow",ff)):
                d=staging/f"{level}_splits";d.mkdir(parents=True,exist_ok=True)
                for split in SPLITS:
                    h=(d/f"{split}.csv").open("w",newline="",encoding="utf-8");handles.append(h)
                    writers[level,split]=csv.DictWriter(h,fieldnames=["run_id","observation_id",*features,"label","label_status"]);writers[level,split].writeheader()
            # Stream the already QC'd base V2 train/validation feature tables; never open test.
            for level,features in (("packet",pf),("flow",ff)):
                base_split_ids={s:{x["run_id"] for x in base_selected if x["split"]==s} for s in SPLITS}
                for split in SPLITS:
                    src=basepkg/f"{level}_splits/{split}.csv"
                    if not src.is_file():raise ValueError(f"Missing base development split: {src}")
                    _,rows=read_csv(src)
                    for row in rows:
                        if row.get("run_id") not in base_split_ids[split]:
                            raise ValueError(f"Unexpected base run in {src}: {row.get('run_id')}")
                        rid=row["run_id"];obs=row.get("observation_id","");label=row["label"]
                        if not obs or obs in obs_seen[level]:raise ValueError(f"Base {level} missing/duplicate observation ID: {obs}")
                        obs_seen[level].add(obs)
                        outrow={k:row[k] for k in ["run_id","observation_id",*features,"label","label_status"]}
                        sig=tuple(outrow[k] for k in outrow)
                        if sig in exact[level]:raise ValueError(f"Exact duplicate {level} row in base data")
                        exact[level].add(sig);writers[level,split].writerow(outrow);counts[level][split]+=1
            base_ids={x["run_id"] for x in base_selected}
            # Ensure source split tables contain exactly their manifest-assigned run IDs.
            for level in ("packet","flow"):
                for split in SPLITS:
                    src=basepkg/f"{level}_splits/{split}.csv"
                    _,rows=read_csv(src)
                    observed={r["run_id"] for r in rows}
                    expected={x["run_id"] for x in base_selected if x["split"]==split}
                    if observed!=expected:raise ValueError(f"Base {level}/{split} run IDs disagree with manifest")
            for item in expanded_selected:
                for level,features,converter in (("packet",pf,packet_values),("flow",ff,flow_values)):
                    src=base/f"raw/{level}/{item['run_id']}.csv"
                    if not src.is_file() or src.stat().st_size==0:raise ValueError(f"Missing/empty raw {level} file: {src}")
                    _,rows=read_csv(src)
                    if not rows:raise ValueError(f"Header-only raw input: {src}")
                    for raw in rows:
                        if raw.get("run_id")!=item["run_id"]:raise ValueError(f"run_id mismatch in {src}")
                        obs=raw.get("observation_id","")
                        if not obs or obs in obs_seen[level]:raise ValueError(f"Missing/duplicate {level} observation_id {obs!r} in {src}")
                        obs_seen[level].add(obs);values=converter(raw,features)
                        outrow={"run_id":item["run_id"],"observation_id":obs,**values,"label":item["label"],"label_status":"matched"}
                        sig=tuple(outrow[k] for k in outrow)
                        if sig in exact[level]:raise ValueError(f"Exact duplicate transformed {level} row in {src}")
                        exact[level].add(sig);writers[level,item["split"]].writerow(outrow);counts[level][item["split"]]+=1
            for h in handles:h.flush();os.fsync(h.fileno());h.close()
            handles.clear()
            (staging/"config").mkdir();shutil.copy2(basepkg/"config/model_features.json",staging/"config/model_features.json")
            with (staging/"run_split_manifest.csv").open("w",newline="",encoding="utf-8") as h:
                cols=["generation","run_id","label","plan_index","profile_id","planned_split","source"]
                w=csv.DictWriter(h,fieldnames=cols);w.writeheader()
                for x in sorted(all_selected,key=lambda q:(q["split"],q["label"],q["profile_id"])):
                    w.writerow({"generation":x.get("generation",""),"run_id":x["run_id"],"label":x["label"],"plan_index":x.get("plan_index",""),"profile_id":x["profile_id"],"planned_split":x["split"],"source":x["source"]})
            with (staging/"excluded_failed_runs.csv").open("w",newline="",encoding="utf-8") as h:
                cols=["generation","run_id","profile_id","label","planned_split","reason"]
                w=csv.DictWriter(h,fieldnames=cols);w.writeheader()
                for x in sorted(excluded,key=lambda q:q["generation"]):w.writerow(x)
            qc={"purpose":"Development-only Packet/Flow modeling. No final-test split or test raw files were opened.",
                "base_source":"AI_OFFLINE_LEARNING_REPAIRED_TRAIN_VAL_V2_20261025 (80 runs)",
                "expanded_completed_and_replacement_runs":len(expanded_selected),"selected_runs":len(all_selected),
                "run_counts_by_label_split":{lab:{s:sum(x["split"]==s and x["label"]==lab for x in all_selected) for s in SPLITS} for lab in LABELS},
                "expanded_failed_captures_excluded":excluded,"application_evidence_counts":app_evidence,
                "packet_rows_by_split":dict(counts["packet"]),"flow_rows_by_split":dict(counts["flow"]),
                "packet_unique_observation_ids":len(obs_seen["packet"]),"flow_unique_observation_ids":len(obs_seen["flow"]),
                "exact_duplicate_packet_rows":0,"exact_duplicate_flow_rows":0,
                "cross_split_run_leakage":False,"balanced_train_runs_per_class":48,"balanced_validation_runs_per_class":12,
                "note":"No oversampling/synthetic data. Repeated feature patterns are not removed unless the complete exported row is an exact duplicate; all selected observation IDs are unique."}
            (staging/"qc_report.json").write_text(json.dumps(qc,indent=2)+"\n",encoding="utf-8")
            (staging/"README.md").write_text("# Expanded development Packet/Flow dataset\n\nThis package combines the prior repaired train/validation-only candidate (80 runs) with 160 successful expanded-development profiles, including six verified replacements for six failed captures. Final test data is neither included nor read. Each of four classes has 48 training runs and 12 validation runs. Splits are run/profile-grouped; no oversampling or synthetic rows are used.\n\nValidation metrics are for model development only and are not final-test performance.\n",encoding="utf-8")
            files=sorted(p for p in staging.rglob("*") if p.is_file() and p.name!="SHA256SUMS.txt")
            (staging/"SHA256SUMS.txt").write_text("".join(f"{sha256(p)}  {p.relative_to(staging).as_posix()}\n" for p in files),encoding="utf-8")
            if out.exists():raise FileExistsError(f"Output appeared during build: {out}")
            staging.rename(out)
        except BaseException:
            for h in handles:
                try:h.close()
                except Exception:pass
            shutil.rmtree(staging,ignore_errors=True);raise
        print("DEVELOPMENT PACKAGE CREATED:",out,flush=True)
        print("Runs: 240 total; train=192, validation=48; 48 train and 12 validation per class.",flush=True)
        print("Packet rows:",dict(counts["packet"]),"Flow rows:",dict(counts["flow"]),flush=True)
        print("No final-test data was read.",flush=True)

    # Train only after a complete, checksummed package exists. Training output is
    # built in a separate staging directory so an interrupted fit can be retried.
    train_out=out/"models/final_trainval_20261026"
    if train_out.exists():raise SystemExit(f"STOP: model output exists; refusing to overwrite: {train_out}")
    train=pd.read_csv(out/"packet_splits/train.csv")
    val=pd.read_csv(out/"packet_splits/validation.csv")
    # The run split is shared by Packet and Flow; training/evaluation runs each level independently.
    sm=pd.read_csv(out/"run_split_manifest.csv",dtype={"run_id":str})
    if sm.run_id.duplicated().any() or sm.profile_id.duplicated().any():raise ValueError("Split manifest contains duplicate run/profile IDs")
    for s,n in (("train",48),("validation",12)):
        assigns=sm[sm.planned_split==s]
        c=assigns.groupby("label").run_id.nunique().to_dict()
        if any(int(c.get(l,0))!=n for l in LABELS):raise ValueError(f"Unexpected {s} run balance in manifest: {c}")
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import LabelEncoder
    from xgboost import XGBClassifier
    import joblib
    train_out.parent.mkdir(parents=True,exist_ok=True)
    staging=Path(tempfile.mkdtemp(prefix=".final_trainval_20261026.staging-",dir=str(train_out.parent)))
    try:
        all_metrics={"purpose":"Development model training/validation only. No final-test CSV, test features, or test scores were loaded or computed.",
                     "dataset_package":str(out),"seed":args.seed,"training_weighting":"equal total sample weight per run_id",
                     "run_counts_per_class":{"train":48,"validation":12},"levels":{}}
        for level,features in (("packet",pf),("flow",ff)):
            train_df=pd.read_csv(out/f"{level}_splits/train.csv");val_df=pd.read_csv(out/f"{level}_splits/validation.csv")
            for name,frame in (("train",train_df),("validation",val_df)):
                if set(frame.label.astype(str))!=set(LABELS):raise ValueError(f"{level} {name}: class mismatch")
                if frame.groupby("run_id").label.nunique().gt(1).any():raise ValueError(f"{level} {name}: conflicting labels within run")
            train_ids=set(train_df.run_id.astype(str));val_ids=set(val_df.run_id.astype(str))
            if train_ids&val_ids:raise ValueError(f"{level}: run leakage across train/validation")
            for split,frame in (("train",train_df),("validation",val_df)):
                wanted=set(sm.loc[sm.planned_split==split,"run_id"].astype(str))
                if set(frame.run_id.astype(str))!=wanted:raise ValueError(f"{level}/{split} rows disagree with split manifest")
            xtr=encode(train_df,features);xva=encode(val_df,features)
            enc=LabelEncoder().fit(train_df.label.astype(str));ytr=enc.transform(train_df.label.astype(str));yva=enc.transform(val_df.label.astype(str));weights=equal_run_weights(train_df)
            models={"random_forest":RandomForestClassifier(n_estimators=400,random_state=args.seed,n_jobs=-1),
                    "xgboost":XGBClassifier(n_estimators=300,max_depth=3,learning_rate=0.05,subsample=0.9,colsample_bytree=0.9,min_child_weight=2,reg_lambda=1.0,objective="multi:softprob",eval_metric="mlogloss",random_state=args.seed,n_jobs=-1,tree_method="hist")}
            level_dir=staging/level;level_dir.mkdir()
            metrics={"features":features,"train_summary":{"rows":int(len(train_df)),"runs":int(train_df.run_id.nunique())},"validation_summary":{"rows":int(len(val_df)),"runs":int(val_df.run_id.nunique())},"models":{}}
            for name,model in models.items():
                model.fit(xtr,ytr,sample_weight=weights,**({"eval_set":[(xva,yva)],"verbose":False} if name=="xgboost" else {}))
                metrics["models"][name]={"train":evaluate(model,xtr,train_df,enc),"validation":evaluate(model,xva,val_df,enc)}
                joblib.dump(model,level_dir/f"{name}.joblib")
            joblib.dump(enc,level_dir/"label_encoder.joblib")
            (level_dir/"feature_columns.json").write_text(json.dumps({"level":level,"features":features},indent=2)+"\n",encoding="utf-8")
            (level_dir/"metrics_trainval_only.json").write_text(json.dumps(metrics,indent=2)+"\n",encoding="utf-8")
            all_metrics["levels"][level]=metrics
            for name,result in metrics["models"].items():
                print(f"{level}/{name}: train run accuracy/F1={result['train']['run_level']['accuracy']:.4f}/{result['train']['run_level']['f1_macro']:.4f}; validation run accuracy/F1={result['validation']['run_level']['accuracy']:.4f}/{result['validation']['run_level']['f1_macro']:.4f}",flush=True)
        (staging/"training_summary.json").write_text(json.dumps(all_metrics,indent=2)+"\n",encoding="utf-8")
        if train_out.exists():raise FileExistsError(f"Training output appeared during fit: {train_out}")
        staging.rename(train_out)
    except BaseException:
        shutil.rmtree(staging,ignore_errors=True);raise
    print("TRAINING COMPLETE:",train_out,flush=True)
    print("Validation only; final test remained sealed and unopened.",flush=True)

if __name__=="__main__":
    try:main()
    except Exception as exc:
        print(f"PIPELINE STOP: {type(exc).__name__}: {exc}",file=sys.stderr);raise
