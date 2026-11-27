#!/usr/bin/env python3
"""Build a repaired Packet/Flow TRAIN+VALIDATION candidate only.

Inputs are read-only. Never opens final_test raw files and writes no test split.
Excludes original Malicious_POST runs without observed application POST events,
keeps one successful replacement profile, and excludes accidental duplicate runs.
The original V3 package is never modified.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, os, shutil, sys, tempfile
from collections import Counter
from pathlib import Path

LABELS=("Normal","Malicious_POST","Port_Scan","SYN_Flood")
SPLITS=("train","validation")
PROTO={"1":"icmp","6":"tcp","17":"udp","41":"ipv6","58":"icmpv6"}
BAD_ORIGINAL_PROFILES={"MP002","MP027","MP012","MP013","MP036"}
# One unique profile/run per planned split; duplicated second execution (gens 360-364) is excluded.
REPLACEMENTS={
 355:{"run_id":"df4cf789-576a-456f-820c-49d8e23975d1","profile_id":"MP041","split":"train","plan_index":162},
 356:{"run_id":"15d8dfa7-ee6c-4efa-a56c-21db6472e7a7","profile_id":"MP042","split":"train","plan_index":163},
 357:{"run_id":"b037565c-d6cd-4873-a449-2cf08fe7d302","profile_id":"MP043","split":"validation","plan_index":164},
 358:{"run_id":"755be19e-5141-4fc8-a035-b55da7e0b8e7","profile_id":"MP044","split":"validation","plan_index":165},
 365:{"run_id":"28e4d85e-6654-4583-ae0e-653eb69464d6","profile_id":"MP046","split":"validation","plan_index":167},
}
EXCLUDED_EXTRA={
 354:("de3deed9-bf9d-4903-b74d-8a6558ce10c4","diagnostic preflight; not part of campaign"),
 359:("a326313b-3fd4-4a87-b922-a78b73fc7f48","MP045 had no observed application POST; invalid replacement"),
 360:("6ecf2a8b-36a5-463a-b31e-3b4635ce294c","duplicate second execution of replacement plan"),
 361:("bde18f8b-f7c2-4e87-b574-4181d1306da3","duplicate second execution of replacement plan"),
 362:("cda7ddc6-5a59-4319-ab99-d44687340dd1","duplicate second execution of replacement plan"),
 363:("b16a349e-f9a8-460f-ac52-9416b3cf9bd3","duplicate second execution of replacement plan"),
 364:("0bb3e3c2-315f-4328-ad48-486db4db7c83","duplicate MP045; no observed application POST"),
}
BAD_RUN_IDS={
 "MP002":"e57e1ff0-2339-482f-830e-58cf3a3025f7",
 "MP027":"3d8bec07-6833-483b-8005-c9b95993ea48",
 "MP012":"3989d142-5a7a-46f0-82bc-507ad1354de9",
 "MP013":"fd5b92ec-4ad6-4596-b5f5-99e5c0898f28",
 "MP036":"0dffcedb-e128-4087-99e6-ce270400a2a3",
}


def read_csv(path):
    with path.open("r",newline="",encoding="utf-8") as f:
        reader=csv.DictReader(f)
        if not reader.fieldnames: raise ValueError(f"CSV has no header: {path}")
        return reader.fieldnames,list(reader)


def generation_to_plan(g):
    if 191<=g<=199:return g-190
    if 201<=g<=338:return g-191
    if g==340:return 148
    if g==342:return 149
    if 343<=g<=353:return g-193
    return None


def file_hash(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for c in iter(lambda:f.read(1024*1024),b""):h.update(c)
    return h.hexdigest()


def protocol_name(v):
    v=(v or "").strip()
    try:k=str(int(float(v)))
    except (ValueError,TypeError):return v.lower() or "unknown"
    return PROTO.get(k,"ip_proto_"+k)


def numeric(v,integer=False):
    v=(v or "").strip()
    if not v:return "0"
    x=float(v)
    if not (x==x and abs(x)!=float("inf")):raise ValueError(f"non-finite value {v!r}")
    return str(int(x)) if integer else format(x,".12g")


def packet_values(row,features):
    flags=int(float(row.get("tcp_flags") or 0))
    d={"protocol":protocol_name(row.get("protocol","")),"src_port":numeric(row.get("src_port","")),
       "dst_port":numeric(row.get("dst_port","")),"packet_length":numeric(row.get("packet_length",""),True),
       "tcp_syn":str(int(bool(flags&0x02))),"tcp_ack":str(int(bool(flags&0x10)),),
       "tcp_rst":str(int(bool(flags&0x04))),"tcp_fin":str(int(bool(flags&0x01))),
       "icmp_type":numeric(row.get("icmp_type",""),True),"arp_operation":numeric(row.get("arp_operation",""),True)}
    miss=[x for x in features if x not in d]
    if miss:raise ValueError(f"Unsupported packet feature(s): {miss}")
    return {x:d[x] for x in features}


def flow_values(row,features):
    d=dict(row);d["protocol"]=protocol_name(row.get("protocol",""))
    miss=[x for x in features if x not in d]
    if miss:raise ValueError(f"Flow raw data missing feature(s): {miss}")
    ints={"src_port","dst_port","packet_count","byte_count","syn_count","ack_count","rst_count","fin_count","unique_dst_ports","failed_connection_count"}
    return {x:(d[x] if x=="protocol" else numeric(d[x],x in ints)) for x in features}


def assert_app_post(root,run_id,profile):
    appdirs=[p for p in (root/"New_Datasets/raw").glob("application*") if p.is_dir()]
    paths=[p for d in appdirs for p in d.rglob(f"{run_id}.csv")]
    events=[]
    for p in paths:events.extend(read_csv(p)[1])
    posts=[r for r in events if (r.get("http_method") or "").upper()=="POST"]
    valid=[r for r in posts if r.get("route_category")=="auth" and str(r.get("response_status"))=="401"]
    if not valid:raise ValueError(f"No observed POST/auth/401 evidence for eligible {profile} ({run_id})")
    if len(valid)!=len(posts):raise ValueError(f"Unexpected non-auth or non-401 POST rows for {profile}: {len(valid)}/{len(posts)} valid")
    return len(valid)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root",type=Path,default=Path.cwd())
    ap.add_argument("--output",type=Path,default=Path("New_Datasets/AI_OFFLINE_LEARNING_REPAIRED_TRAIN_VAL_V1_20261025"))
    args=ap.parse_args();root=args.project_root.resolve()
    base=root/"New_Datasets";out=args.output if args.output.is_absolute() else root/args.output
    if out.exists():raise SystemExit(f"STOP: refusing to overwrite {out}")
    latch=base/"experiments/run_manifest.csv.in_flight.json"
    if latch.exists():raise SystemExit(f"STOP: in-flight latch exists: {latch}")
    manifest_path=base/"experiments/run_manifest.csv"
    original_plan_path=base/"scripts/collection_plan_packet_flow_final_v3_160runs.csv"
    config_path=base/"AI_OFFLINE_LEARNING_V2_FINAL/config/model_features.json"
    for p in (manifest_path,original_plan_path,config_path):
        if not p.is_file():raise SystemExit(f"STOP: missing {p}")
    manifest=read_csv(manifest_path)[1]
    planrows=read_csv(original_plan_path)[1]
    plan={int(r["plan_index"]):r for r in planrows}
    if len(plan)!=160:raise SystemExit("STOP: expected original 160-row plan")
    bygen={int(r["generation"]):r for r in manifest if (r.get("generation") or "").isdigit()}

    selected=[];excluded=[];profiles=set();split_counts={s:Counter() for s in SPLITS}
    # Select original successful TRAIN/VALIDATION runs only. Never open final_test raw files.
    for g in range(191,354):
        r=bygen.get(g)
        if not r:continue
        pi=generation_to_plan(g)
        if pi not in plan:continue
        p=plan[pi];split=p.get("planned_split")
        if split not in SPLITS:continue
        profile=p["profile_id"]
        if r.get("status")!="completed":
            excluded.append({"generation":g,"run_id":r.get("run_id"),"profile_id":profile,"split":split,"reason":"manifest capture failed"});continue
        if profile in BAD_ORIGINAL_PROFILES:
            expected=BAD_RUN_IDS[profile]
            if r.get("run_id")!=expected:raise SystemExit(f"STOP: failed POST run ID mismatch for {profile}")
            excluded.append({"generation":g,"run_id":r.get("run_id"),"profile_id":profile,"split":split,"reason":"no observed application POST; curl timeouts/no route"})
            continue
        item={"generation":g,"run_id":r["run_id"],"profile_id":profile,"split":split,"label":p["expected_label"],"plan_index":pi}
        selected.append(item)

    # Add only explicitly verified replacements. Do not select duplicate generations 360-364.
    for g,spec in REPLACEMENTS.items():
        r=bygen.get(g)
        if not r or r.get("run_id")!=spec["run_id"] or r.get("status")!="completed":
            raise SystemExit(f"STOP: replacement generation/run/status mismatch at {g}: {r}")
        p=read_csv(base/"scripts/collection_plan_replace_failed_mp_trainval_v1.csv")[1]
        # Explicit split/profile map is authoritative; verify matching planned row where present.
        if g<=359:
            expected=next((x for x in p if x["profile_id"]==spec["profile_id"]),None)
            if not expected or expected["planned_split"]!=spec["split"] or expected["expected_label"]!="Malicious_POST":
                raise SystemExit(f"STOP: replacement plan mismatch for {spec['profile_id']}")
        else:
            single=read_csv(base/"scripts/collection_plan_replace_mp045_validation_single.csv")[1]
            if len(single)!=1 or single[0]["profile_id"]!=spec["profile_id"] or single[0]["planned_split"]!=spec["split"]:
                raise SystemExit("STOP: MP046 replacement plan mismatch")
        app_count=assert_app_post(root,spec["run_id"],spec["profile_id"])
        selected.append({"generation":g,"run_id":spec["run_id"],"profile_id":spec["profile_id"],"split":spec["split"],"label":"Malicious_POST","plan_index":spec["plan_index"],"observed_post_401_events":app_count})

    # Document diagnostics, failed replacements, and duplicate executions; do not package them.
    for g,(rid,reason) in EXCLUDED_EXTRA.items():
        r=bygen.get(g)
        if not r or r.get("run_id")!=rid:raise SystemExit(f"STOP: excluded extra generation {g} differs from expected")
        excluded.append({"generation":g,"run_id":rid,"profile_id":"MP045" if g in (359,364) else ("PRECHECK_MP" if g==354 else "duplicate_replacement"),"split":"diagnostic" if g==354 else ("validation" if g in (359,364) else "duplicate"),"reason":reason})

    for x in selected:
        if x["profile_id"] in profiles:raise SystemExit(f"STOP: duplicate eligible profile {x['profile_id']}")
        profiles.add(x["profile_id"]);split_counts[x["split"]][x["label"]]+=1
    expected={"train":16,"validation":4}
    for lab in LABELS:
        got={s:split_counts[s][lab] for s in SPLITS}
        if got!={s:expected[s] for s in SPLITS}:raise SystemExit(f"STOP: repaired class split mismatch for {lab}: {got}")
    if len(selected)!=80:raise SystemExit(f"STOP: expected 80 selected train/validation runs, got {len(selected)}")

    cfg=json.loads(config_path.read_text(encoding="utf-8"));pf=list(cfg["packet_features"]);ff=list(cfg["flow_features"])
    staging=Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-",dir=str(out.parent)))
    handles=[];writers={};counts={"packet":Counter(),"flow":Counter()};obs_seen={"packet":set(),"flow":set()};exact={"packet":set(),"flow":set()}
    try:
        for level,features in (("packet",pf),("flow",ff)):
            d=staging/f"{level}_splits";d.mkdir(parents=True,exist_ok=True)
            for split in SPLITS:
                path=d/f"{split}.csv";h=path.open("w",newline="",encoding="utf-8");handles.append(h)
                w=csv.DictWriter(h,fieldnames=["run_id","observation_id",*features,"label","label_status"]);w.writeheader();writers[level,split]=w
        sm=staging/"run_split_manifest.csv"
        with sm.open("w",newline="",encoding="utf-8") as h:
            cols=["generation","run_id","label","plan_index","profile_id","planned_split"]
            w=csv.DictWriter(h,fieldnames=cols);w.writeheader()
            for x in sorted(selected,key=lambda q:(q["split"],q["label"],q["profile_id"])):
                w.writerow({"generation":x["generation"],"run_id":x["run_id"],"label":x["label"],"plan_index":x["plan_index"],"profile_id":x["profile_id"],"planned_split":x["split"]})
        excluded_path=staging/"excluded_runs.csv"
        with excluded_path.open("w",newline="",encoding="utf-8") as h:
            w=csv.DictWriter(h,fieldnames=["generation","run_id","profile_id","split","reason"]);w.writeheader();w.writerows(sorted(excluded,key=lambda x:int(x["generation"])))

        for item in sorted(selected,key=lambda q:q["generation"]):
            for level,features,conv in (("packet",pf,packet_values),("flow",ff,flow_values)):
                src=base/f"raw/{level}/{item['run_id']}.csv"
                if not src.is_file() or src.stat().st_size==0:raise ValueError(f"Missing/empty {level} input: {src}")
                _,rows=read_csv(src)
                if not rows:raise ValueError(f"Header-only {src}")
                for raw in rows:
                    if raw.get("run_id")!=item["run_id"]:raise ValueError(f"run_id mismatch in {src}")
                    obs=raw.get("observation_id","")
                    if not obs or obs in obs_seen[level]:raise ValueError(f"missing/duplicate {level} observation id {obs!r}")
                    obs_seen[level].add(obs)
                    vals=conv(raw,features)
                    outrow={"run_id":item["run_id"],"observation_id":obs,**vals,"label":item["label"],"label_status":"matched"}
                    sig=tuple(outrow[k] for k in outrow)
                    if sig in exact[level]:raise ValueError(f"exact duplicate transformed {level} row in {src}")
                    exact[level].add(sig);writers[level,item["split"]].writerow(outrow);counts[level][item["split"]]+=1
        for h in handles:h.flush();os.fsync(h.fileno());h.close()
        handles.clear()
        (staging/"config").mkdir();shutil.copy2(config_path,staging/"config/model_features.json")
        qc={"purpose":"Development candidate only; train+validation, no test split included or read.",
            "original_package_untouched":True,"selected_runs":len(selected),"selected_runs_by_split":{s:sum(x["split"]==s for x in selected) for s in SPLITS},
            "run_counts_by_label_split":{lab:{s:split_counts[s][lab] for s in SPLITS} for lab in LABELS},
            "packet_rows_by_split":dict(counts["packet"]),"flow_rows_by_split":dict(counts["flow"]),
            "packet_unique_observation_ids":len(obs_seen["packet"]),"flow_unique_observation_ids":len(obs_seen["flow"]),
            "exact_duplicate_packet_rows":0,"exact_duplicate_flow_rows":0,
            "verified_malicious_post_runs":{x["profile_id"]:x.get("observed_post_401_events") for x in selected if x["label"]=="Malicious_POST"},
            "excluded_runs":excluded,"excluded_duplicate_generations":[360,361,362,363,364],
            "note":"Current test set and its raw features were not read. This package is not for final performance claims."}
        (staging/"qc_report.json").write_text(json.dumps(qc,indent=2)+"\n",encoding="utf-8")
        (staging/"README.md").write_text("# Repaired Packet/Flow development candidate\n\nThis is a train/validation-only candidate (16 train + 4 validation runs per class). It excludes five original Malicious_POST runs with no observed application POST and keeps verified replacements MP041–MP044 and MP046 exactly once. Accidental second-batch duplicate profiles and failed MP045 attempts are listed in `excluded_runs.csv`.\n\nNo test split is included or read. Do not treat validation results from this small split as final test performance. The original V3 package and all source raw files remain untouched.\n",encoding="utf-8")
        files=sorted(p for p in staging.rglob("*") if p.is_file() and p.name!="SHA256SUMS.txt")
        (staging/"SHA256SUMS.txt").write_text("".join(f"{file_hash(p)}  {p.relative_to(staging).as_posix()}\n" for p in files),encoding="utf-8")
        out.parent.mkdir(parents=True,exist_ok=True)
        if out.exists():raise FileExistsError(f"Output appeared during build; refusing overwrite: {out}")
        staging.rename(out)
    except BaseException:
        for h in handles:
            try:h.close()
            except Exception:pass
        shutil.rmtree(staging,ignore_errors=True)
        raise
    print("REPAIRED TRAIN/VALIDATION CANDIDATE CREATED:",out)
    print("Selected runs:",len(selected),"(16/class train, 4/class validation); no test split was read or written.")
    print("Packet rows:",dict(counts["packet"]));print("Flow rows:",dict(counts["flow"]))
    print("Check with: cd",out,"&& sha256sum -c SHA256SUMS.txt")

if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BUILD STOP: {type(e).__name__}: {e}",file=sys.stderr);raise
