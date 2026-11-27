#!/usr/bin/env python3
"""Metadata-only QC for the completed fresh final-test campaign.
Never opens Packet/Flow capture files or computes model scores."""
import csv, importlib.util, json
from pathlib import Path

root=Path.cwd();base=root/"New_Datasets"
plan_path=base/"scripts/collection_plan_fresh_test_160_20261025.csv"
builder_path=base/"scripts/build_train_expanded_dev_once_v5.py"
manifest_path=base/"experiments/run_manifest.csv"
spec=importlib.util.spec_from_file_location("builder",builder_path)
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
def read(p):
    with p.open(newline="",encoding="utf-8-sig") as f:return list(csv.DictReader(f))
plan=read(plan_path);manifest=read(manifest_path)
bygen={}
for r in manifest:
    try:g=int(r.get("generation") or 0)
    except ValueError:continue
    bygen.setdefault(g,[]).append(r)
issues=[]
print("Metadata-only audit; Packet/Flow feature files are not opened.")
print("Assumed contiguous fresh-test generation range: 550-709; plan row order follows Batch run order.")
for i,p in enumerate(plan):
    expected=550+i;rows=bygen.get(expected,[])
    if len(rows)!=1:
        issues.append(f"{p['profile_id']}: generation {expected} has {len(rows)} manifest rows")
        continue
    r=rows[0];match=b.exact_manifest_match(r,p)
    hist=[x for x in manifest if b.exact_manifest_match(x,p)]
    status=r.get("status");label=r.get("label");rid=r.get("run_id")
    if not match or status!="completed" or label!=p["expected_label"]:
        issues.append(f"{p['profile_id']}: gen={expected} match={match} status={status} manifest_label={label} plan_label={p['expected_label']}")
    if p["expected_label"]=="Malicious_POST":
        events=b.app_events(base,rid);valid=[]
        for e in events:
            if (b.event_value(e,"http_method","method").upper()=="POST" and
                b.event_value(e,"route_category","route").lower()=="auth" and
                b.event_value(e,"response_status","status")=="401"):
                valid.append(e)
        print(f"POST profile={p['profile_id']} gen={expected} run={rid} prior+test signature matches={len(hist)} app_events={len(events)} valid_POST_auth_401={len(valid)}")
    elif len(hist)>1:
        print(f"AMBIGUOUS_SIGNATURE profile={p['profile_id']} expected_gen={expected} all_manifest_matches={len(hist)} expected_gen_match={match}")
print("\nQC summary:")
print("Planned profiles:",len(plan),"; expected generations:",550,"to",709)
print("Issues:",len(issues))
for item in issues:print("ISSUE:",item)
print("No Packet/Flow features read; no predictions or scores computed.")
