#!/usr/bin/env python3
"""Build repaired Packet/Flow TRAIN+VALIDATION V2 only.

Retains the prior repaired candidate rules, excludes eight Normal runs whose
HTTP clients timed out, and adds eight explicitly verified Normal replacements.
Reads only selected train/validation raw files; never opens final_test CSVs.
The original V3 and prior repaired packages are left untouched.
"""
from __future__ import annotations
import argparse, csv, hashlib, json, os, shutil, sys, tempfile
from collections import Counter
from pathlib import Path

LABELS=("Normal","Malicious_POST","Port_Scan","SYN_Flood")
SPLITS=("train","validation")
PROTO={"1":"icmp","6":"tcp","17":"udp","41":"ipv6","58":"icmpv6"}
BAD_ORIGINAL_PROFILES={"MP002","MP027","MP012","MP013","MP036"}
BAD_RUN_IDS={"MP002":"e57e1ff0-2339-482f-830e-58cf3a3025f7","MP027":"3d8bec07-6833-483b-8005-c9b95993ea48","MP012":"3989d142-5a7a-46f0-82bc-507ad1354de9","MP013":"fd5b92ec-4ad6-4596-b5f5-99e5c0898f28","MP036":"0dffcedb-e128-4087-99e6-ce270400a2a3"}
BAD_NORMAL={
 "N001":{"run_id":"9c3e37e3-b4f9-4ec9-9b47-55bdc3f7d483","split":"train"},
 "N006":{"run_id":"904834ef-02ac-446c-96e6-a47c53ba500d","split":"train"},
 "N009":{"run_id":"50f5fb81-429c-49e3-8492-9a26a4ddecae","split":"train"},
 "N020":{"run_id":"3c2acc1b-2723-4700-80bf-5548c6c48ebd","split":"validation"},
 "N031":{"run_id":"afd6ef07-d0e0-4221-8e10-3137f0889102","split":"train"},
 "N032":{"run_id":"9f43f53e-3730-4de8-8981-bc03dc72ca00","split":"train"},
 "N033":{"run_id":"b545eff0-a196-4d9d-849f-d804cb614bb8","split":"train"},
 "N040":{"run_id":"d0431a5b-50c0-4554-8089-09d7fe37720d","split":"validation"},
}
MP_REPLACEMENTS={
 355:{"run_id":"df4cf789-576a-456f-820c-49d8e23975d1","profile_id":"MP041","split":"train","plan_index":162},
 356:{"run_id":"15d8dfa7-ee6c-4efa-a56c-21db6472e7a7","profile_id":"MP042","split":"train","plan_index":163},
 357:{"run_id":"b037565c-d6cd-4873-a449-2cf08fe7d302","profile_id":"MP043","split":"validation","plan_index":164},
 358:{"run_id":"755be19e-5141-4fc8-a035-b55da7e0b8e7","profile_id":"MP044","split":"validation","plan_index":165},
 365:{"run_id":"28e4d85e-6654-4583-ae0e-653eb69464d6","profile_id":"MP046","split":"validation","plan_index":167},
}
NORMAL_REPLACEMENTS={
 366:{"run_id":"c596b9e6-d817-40b5-88df-dd4b47282d97","profile_id":"N041","split":"train","plan_index":161,"service":"http_api_telemetry","route":"iot_api","status":"202"},
 367:{"run_id":"77363cf7-ddbf-4222-bb46-7f0bb958c18a","profile_id":"N042","split":"train","plan_index":162,"service":"http_api_login_success","route":"auth","status":"200"},
 368:{"run_id":"cd5f6964-9ab4-412d-80d5-bdca7fd851eb","profile_id":"N043","split":"train","plan_index":163,"service":"http_api_telemetry","route":"iot_api","status":"202"},
 369:{"run_id":"cb015996-781e-4bee-89ce-b1e86e8ac328","profile_id":"N044","split":"train","plan_index":164,"service":"http_api_telemetry","route":"iot_api","status":"202"},
 370:{"run_id":"a2bb904f-3c29-460d-9f27-2d274735cd46","profile_id":"N045","split":"train","plan_index":165,"service":"http_api_login_success","route":"auth","status":"200"},
 371:{"run_id":"d59b88b7-7b22-4197-9c03-643c75c9dd9c","profile_id":"N046","split":"train","plan_index":166,"service":"http_api_telemetry","route":"iot_api","status":"202"},
 372:{"run_id":"1e8e97c8-6bda-4cbb-bfd4-55c9c654c433","profile_id":"N047","split":"validation","plan_index":167,"service":"http_api_telemetry","route":"iot_api","status":"202"},
 373:{"run_id":"037ce942-3c8b-4fe9-8af5-f37231352401","profile_id":"N048","split":"validation","plan_index":168,"service":"http_api_login_success","route":"auth","status":"200"},
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


def read_csv(path):
    with path.open("r",newline="",encoding="utf-8") as f:
        reader=csv.DictReader(f)
        if not reader.fieldnames:raise ValueError(f"CSV has no header: {path}")
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
    d={"protocol":protocol_name(row.get("protocol","")),"src_port":numeric(row.get("src_port","")),"dst_port":numeric(row.get("dst_port","")),"packet_length":numeric(row.get("packet_length",""),True),"tcp_syn":str(int(bool(flags&0x02))),"tcp_ack":str(int(bool(flags&0x10))),"tcp_rst":str(int(bool(flags&0x04))),"tcp_fin":str(int(bool(flags&0x01))),"icmp_type":numeric(row.get("icmp_type",""),True),"arp_operation":numeric(row.get("arp_operation",""),True)}
    miss=[x for x in features if x not in d]
    if miss:raise ValueError(f"Unsupported packet feature(s): {miss}")
    return {x:d[x] for x in features}

def flow_values(row,features):
    d=dict(row);d["protocol"]=protocol_name(row.get("protocol",""))
    miss=[x for x in features if x not in d]
    if miss:raise ValueError(f"Flow raw data missing feature(s): {miss}")
    ints={"src_port","dst_port","packet_count","byte_count","syn_count","ack_count","rst_count","fin_count","unique_dst_ports","failed_connection_count"}
    return {x:(d[x] if x=="protocol" else numeric(d[x],x in ints)) for x in features}

def application_events(root,run_id):
    appdirs=[p for p in (root/"New_Datasets/raw").glob("application*") if p.is_dir()]
    paths=[p for d in appdirs for p in d.rglob(f"{run_id}.csv")]
    events=[]
    for p in paths:events.extend(read_csv(p)[1])
    return events

def assert_app_post(root,run_id,profile):
    events=application_events(root,run_id)
    posts=[r for r in events if (r.get("http_method") or "").upper()=="POST"]
    valid=[r for r in posts if r.get("route_category")=="auth" and str(r.get("response_status"))=="401"]
    if not valid:raise ValueError(f"No observed POST/auth/401 evidence for eligible {profile} ({run_id})")
    if len(valid)!=len(posts):raise ValueError(f"Unexpected POST rows for {profile}: {len(valid)}/{len(posts)} valid")
    return len(valid)

def assert_app_normal(root,spec):
    events=application_events(root,spec["run_id"])
    if not events:raise ValueError(f"No application events for Normal replacement {spec['profile_id']}")
    valid=[r for r in events if (r.get("http_method") or "").upper()=="POST" and r.get("route_category")==spec["route"] and str(r.get("response_status"))==spec["status"]]
    if len(valid)!=len(events):raise ValueError(f"Unexpected/mismatched app telemetry rows for {spec['profile_id']}: {len(valid)}/{len(events)} expected")
    return len(valid)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--project-root",type=Path,default=Path.cwd())
    ap.add_argument("--output",type=Path,default=Path("New_Datasets/AI_OFFLINE_LEARNING_REPAIRED_TRAIN_VAL_V2_20261025"))
    args=ap.parse_args();root=args.project_root.resolve();base=root/"New_Datasets"
    out=args.output if args.output.is_absolute() else root/args.output
    if out.exists():raise SystemExit(f"STOP: refusing to overwrite {out}")
    if (base/"experiments/run_manifest.csv.in_flight.json").exists():raise SystemExit("STOP: active collection latch exists")
    manifest_path=base/"experiments/run_manifest.csv";original_plan_path=base/"scripts/collection_plan_packet_flow_final_v3_160runs.csv";mp_plan_path=base/"scripts/collection_plan_replace_failed_mp_trainval_v1.csv";mp046_path=base/"scripts/collection_plan_replace_mp045_validation_single.csv";normal_plan_path=base/"scripts/collection_plan_normal_http_replacements_trainval_v1.csv";config_path=base/"AI_OFFLINE_LEARNING_V2_FINAL/config/model_features.json"
    for p in (manifest_path,original_plan_path,mp_plan_path,mp046_path,normal_plan_path,config_path):
        if not p.is_file():raise SystemExit(f"STOP: missing required input {p}")
    manifest=read_csv(manifest_path)[1];planrows=read_csv(original_plan_path)[1];plan={int(r["plan_index"]):r for r in planrows}
    if len(plan)!=160:raise SystemExit("STOP: expected original 160-row plan")
    bygen={int(r["generation"]):r for r in manifest if (r.get("generation") or "").isdigit()}
    selected=[];excluded=[];profiles=set();split_counts={s:Counter() for s in SPLITS}
    # Select successful original development runs only; never read final_test raw files.
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
            if r.get("run_id")!=BAD_RUN_IDS[profile]:raise SystemExit(f"STOP: failed POST run mismatch for {profile}")
            excluded.append({"generation":g,"run_id":r.get("run_id"),"profile_id":profile,"split":split,"reason":"no observed application POST; curl timeout"});continue
        if profile in BAD_NORMAL:
            spec=BAD_NORMAL[profile]
            if r.get("run_id")!=spec["run_id"] or split!=spec["split"]:raise SystemExit(f"STOP: failed Normal run identity/split mismatch for {profile}")
            excluded.append({"generation":g,"run_id":r.get("run_id"),"profile_id":profile,"split":split,"reason":"curl timeout; expected application request not verified"});continue
        selected.append({"generation":g,"run_id":r["run_id"],"profile_id":profile,"split":split,"label":p["expected_label"],"plan_index":pi})
    # Preserve exactly the previously verified POST-attack replacements.
    mp_plan=read_csv(mp_plan_path)[1];mp046_plan=read_csv(mp046_path)[1]
    for g,spec in MP_REPLACEMENTS.items():
        r=bygen.get(g)
        if not r or r.get("run_id")!=spec["run_id"] or r.get("status")!="completed":raise SystemExit(f"STOP: MP replacement generation/run/status mismatch at {g}")
        if g<=359:
            expected=next((x for x in mp_plan if x["profile_id"]==spec["profile_id"]),None)
            if not expected or expected["planned_split"]!=spec["split"] or expected["expected_label"]!="Malicious_POST":raise SystemExit(f"STOP: MP replacement plan mismatch for {spec['profile_id']}")
        else:
            if len(mp046_plan)!=1 or mp046_plan[0]["profile_id"]!=spec["profile_id"] or mp046_plan[0]["planned_split"]!=spec["split"]:raise SystemExit("STOP: MP046 plan mismatch")
        app_count=assert_app_post(root,spec["run_id"],spec["profile_id"])
        selected.append({"generation":g,"run_id":spec["run_id"],"profile_id":spec["profile_id"],"split":spec["split"],"label":"Malicious_POST","plan_index":spec["plan_index"],"observed_post_401_events":app_count})
    # Validate and add exactly eight new, telemetry-verified Normal runs.
    normal_plan=read_csv(normal_plan_path)[1];normal_by_profile={r["profile_id"]:r for r in normal_plan}
    if len(normal_plan)!=8 or len(normal_by_profile)!=8:raise SystemExit("STOP: replacement Normal plan must contain 8 unique profile IDs")
    for g,spec in NORMAL_REPLACEMENTS.items():
        p=normal_by_profile.get(spec["profile_id"]);r=bygen.get(g)
        if not p or p.get("expected_label")!="Normal" or p.get("planned_split")!=spec["split"]:raise SystemExit(f"STOP: replacement Normal plan profile/split mismatch: {spec['profile_id']}")
        if not r or r.get("run_id")!=spec["run_id"] or r.get("status")!="completed" or r.get("label")!="Normal":raise SystemExit(f"STOP: replacement Normal run/generation/status mismatch at {g}")
        try:notes=json.loads(r.get("notes") or "{}")
        except Exception:notes={}
        if notes.get("errors") or "timeout" in str(notes.get("output_tail","")).lower():raise SystemExit(f"STOP: client error/timeout noted for {spec['profile_id']}")
        app_count=assert_app_normal(root,spec)
        selected.append({"generation":g,"run_id":spec["run_id"],"profile_id":spec["profile_id"],"split":spec["split"],"label":"Normal","plan_index":spec["plan_index"],"observed_app_events":app_count})
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
    if len(selected)!=80:raise SystemExit(f"STOP: expected 80 selected development runs, got {len(selected)}")
    cfg=json.loads(config_path.read_text(encoding="utf-8"));pf=list(cfg["packet_features"]);ff=list(cfg["flow_features"])
    out.parent.mkdir(parents=True,exist_ok=True)
    staging=Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-",dir=str(out.parent)))
    handles=[];writers={};counts={"packet":Counter(),"flow":Counter()};obs_seen={"packet":set(),"flow":set()};exact={"packet":set(),"flow":set()}
    try:
        for level,features in (("packet",pf),("flow",ff)):
            d=staging/f"{level}_splits";d.mkdir(parents=True,exist_ok=True)
            for split in SPLITS:
                path=d/f"{split}.csv";h=path.open("w",newline="",encoding="utf-8");handles.append(h)
                w=csv.DictWriter(h,fieldnames=["run_id","observation_id",*features,"label","label_status"]);w.writeheader();writers[level,split]=w
        with (staging/"run_split_manifest.csv").open("w",newline="",encoding="utf-8") as h:
            cols=["generation","run_id","label","plan_index","profile_id","planned_split"]
            w=csv.DictWriter(h,fieldnames=cols);w.writeheader()
            for x in sorted(selected,key=lambda q:(q["split"],q["label"],q["profile_id"])):
                w.writerow({"generation":x["generation"],"run_id":x["run_id"],"label":x["label"],"plan_index":x["plan_index"],"profile_id":x["profile_id"],"planned_split":x["split"]})
        with (staging/"excluded_runs.csv").open("w",newline="",encoding="utf-8") as h:
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
                    obs_seen[level].add(obs);vals=conv(raw,features)
                    outrow={"run_id":item["run_id"],"observation_id":obs,**vals,"label":item["label"],"label_status":"matched"}
                    sig=tuple(outrow[k] for k in outrow)
                    if sig in exact[level]:raise ValueError(f"exact duplicate transformed {level} row in {src}")
                    exact[level].add(sig);writers[level,item["split"]].writerow(outrow);counts[level][item["split"]]+=1
        for h in handles:h.flush();os.fsync(h.fileno());h.close()
        handles.clear()
        (staging/"config").mkdir();shutil.copy2(config_path,staging/"config/model_features.json")
        qc={"purpose":"Development candidate only; train+validation, no test split included or read.","original_package_untouched":True,"selected_runs":len(selected),"selected_runs_by_split":{s:sum(x["split"]==s for x in selected) for s in SPLITS},"run_counts_by_label_split":{lab:{s:split_counts[s][lab] for s in SPLITS} for lab in LABELS},"packet_rows_by_split":dict(counts["packet"]),"flow_rows_by_split":dict(counts["flow"]),"packet_unique_observation_ids":len(obs_seen["packet"]),"flow_unique_observation_ids":len(obs_seen["flow"]),"exact_duplicate_packet_rows":0,"exact_duplicate_flow_rows":0,"verified_malicious_post_runs":{x["profile_id"]:x.get("observed_post_401_events") for x in selected if x["label"]=="Malicious_POST"},"verified_normal_app_runs":{x["profile_id"]:x.get("observed_app_events") for x in selected if x["label"]=="Normal" and x["generation"]>=366},"excluded_failed_http_normal_profiles":sorted(BAD_NORMAL),"excluded_runs":excluded,"excluded_duplicate_generations":[360,361,362,363,364],"note":"Final test split and its raw features were not read. This package is not for final performance claims."}
        (staging/"qc_report.json").write_text(json.dumps(qc,indent=2)+"\n",encoding="utf-8")
        (staging/"README.md").write_text("# Repaired Packet/Flow development candidate V2\n\nTrain/validation only: 16 train and 4 validation runs per class. This build excludes five Malicious_POST captures without observed POST telemetry and eight Normal HTTP captures whose client commands timed out. It includes five previously verified Malicious_POST replacements and eight new Normal replacements with matching application telemetry. Duplicate replacement attempts are excluded.\n\nNo final_test files were included or read. Original dataset packages and raw source files remain untouched. Validation is for model development only, not final performance claims.\n",encoding="utf-8")
        files=sorted(p for p in staging.rglob("*") if p.is_file() and p.name!="SHA256SUMS.txt")
        (staging/"SHA256SUMS.txt").write_text("".join(f"{file_hash(p)}  {p.relative_to(staging).as_posix()}\n" for p in files),encoding="utf-8")
        if out.exists():raise FileExistsError(f"Output appeared during build; refusing overwrite: {out}")
        staging.rename(out)
    except BaseException:
        for h in handles:
            try:h.close()
            except Exception:pass
        shutil.rmtree(staging,ignore_errors=True);raise
    print("REPAIRED TRAIN/VALIDATION V2 CREATED:",out)
    print("Selected runs:",len(selected),"(16/class train, 4/class validation); final_test was not read or written.")
    print("Packet rows:",dict(counts["packet"]));print("Flow rows:",dict(counts["flow"]))
    print("Verify with: cd",out,"&& sha256sum -c SHA256SUMS.txt")

if __name__=="__main__":
    try:main()
    except Exception as e:
        print(f"BUILD STOP: {type(e).__name__}: {e}",file=sys.stderr);raise
