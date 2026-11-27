#!/usr/bin/env python3
"""Build a corrected, test-only Packet/Flow holdout package.

Keeps all eligible V3 final_test runs except MP031/MP008, whose Malicious_POST
clients timed out and produced no app telemetry. Adds MP047/MP048 only after
verifying completed manifest, packet+flow data, and application POST/auth/401.
Never modifies V3 or reads its train/validation feature files. Checks 80 test
runs (20/class), no overlap with repaired V2 development IDs, no duplicate
observations/exact rows, and writes a standalone test-only package + checksums.
"""
from __future__ import annotations
import argparse,csv,hashlib,json,os,shutil,sys,tempfile
from collections import Counter
from pathlib import Path

LABELS={"Malicious_POST","Normal","Port_Scan","SYN_Flood"}
FEATURES={
 "packet":["protocol","src_port","dst_port","packet_length","tcp_syn","tcp_ack","tcp_rst","tcp_fin","icmp_type","arp_operation"],
 "flow":["protocol","src_port","dst_port","packet_count","byte_count","packet_rate","byte_rate","duration_sec","avg_packet_size","syn_count","ack_count","rst_count","fin_count","syn_ack_ratio","rst_ratio","unique_dst_ports","failed_connection_count","tcp_fraction","udp_fraction","icmp_fraction"],
}
PROTO={"1":"icmp","6":"tcp","17":"udp","41":"ipv6","58":"icmpv6"}
OMIT={"MP031":"e59f0bba-b1f3-460b-8c55-1cc47c4de524","MP008":"3d7cbaf3-ab74-4403-a290-f6eb05297d15"}
REPLACEMENTS={
 "MP047":{"run_id":"b59f603c-a371-4045-9b8a-ca6cf07c173d","generation":"374","plan_index":"161","label":"Malicious_POST","split":"final_test","command":"attack h7 malicious_post h2 /login 10 1000 1 16"},
 "MP048":{"run_id":"7770531d-82a9-4895-afb1-6cb2454a29a0","generation":"375","plan_index":"162","label":"Malicious_POST","split":"final_test","command":"attack h14 malicious_post h2 /login 19 200 1 6"},
}

def read_csv(path):
 with path.open("r",newline="",encoding="utf-8") as f:
  rd=csv.DictReader(f)
  if not rd.fieldnames:raise ValueError(f"CSV has no header: {path}")
  return rd.fieldnames,list(rd)
def digest(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for b in iter(lambda:f.read(1024*1024),b""):h.update(b)
 return h.hexdigest()
def protocol_name(v):
 v=(v or "").strip()
 try:k=str(int(float(v)))
 except (ValueError,TypeError):return v.lower() or "unknown"
 return PROTO.get(k,"ip_proto_"+k)
def number(v,integer=False):
 v=(v or "").strip()
 if not v:return "0"
 x=float(v)
 if not (x==x and abs(x)!=float("inf")):raise ValueError(f"non-finite value {v!r}")
 return str(int(x)) if integer else format(x,".12g")
def packet_features(r):
 flags=int(float(r.get("tcp_flags") or 0))
 d={"protocol":protocol_name(r.get("protocol")),"src_port":number(r.get("src_port")),"dst_port":number(r.get("dst_port")),"packet_length":number(r.get("packet_length"),True),"tcp_syn":str(int(bool(flags&2))),"tcp_ack":str(int(bool(flags&16))),"tcp_rst":str(int(bool(flags&4))),"tcp_fin":str(int(bool(flags&1))),"icmp_type":number(r.get("icmp_type"),True),"arp_operation":number(r.get("arp_operation"),True)}
 return {k:d[k] for k in FEATURES["packet"]}
def flow_features(r):
 d=dict(r);d["protocol"]=protocol_name(r.get("protocol"));ints={"src_port","dst_port","packet_count","byte_count","syn_count","ack_count","rst_count","fin_count","unique_dst_ports","failed_connection_count"}
 missing=set(FEATURES["flow"])-set(d)
 if missing:raise ValueError(f"Flow raw data missing features: {sorted(missing)}")
 return {k:(d[k] if k=="protocol" else number(d[k],k in ints)) for k in FEATURES["flow"]}
def app_evidence(rawroot,rid):
 paths=[p for d in (rawroot/"New_Datasets"/"raw").glob("application*") if d.is_dir() for p in d.rglob(f"{rid}.csv")]
 if len(paths)!=1:raise ValueError(f"Expected exactly one app telemetry file for {rid}; found {len(paths)}")
 events=read_csv(paths[0])[1]
 if not events:raise ValueError(f"Empty app telemetry for {rid}")
 posts=[e for e in events if (e.get("http_method") or "").upper()=="POST"]
 valid=[e for e in posts if e.get("route_category")=="auth" and str(e.get("response_status"))=="401"]
 if not valid or len(valid)!=len(posts):raise ValueError(f"No exclusive POST/auth/401 evidence for {rid}")
 return len(events),len(valid)
def validate_table(rows,level):
 if not rows:raise ValueError(f"No {level} test observations")
 ids=set();exact=set()
 keys=["run_id","observation_id",*FEATURES[level],"label","label_status"]
 for r in rows:
  if not r.get("run_id") or not r.get("observation_id"):raise ValueError(f"Missing IDs in {level} row")
  if r["observation_id"] in ids:raise ValueError(f"Duplicate {level} observation_id {r['observation_id']}")
  ids.add(r["observation_id"])
  sig=tuple(r.get(k,"") for k in keys)
  if sig in exact:raise ValueError(f"Exact duplicate {level} row")
  exact.add(sig)
 return len(ids)
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 ap.add_argument("--project-root",type=Path,default=Path.cwd())
 ap.add_argument("--source-package",type=Path,default=Path("New_Datasets/AI_OFFLINE_LEARNING_FINAL_V3_20261025"))
 ap.add_argument("--development-package",type=Path,default=Path("New_Datasets/AI_OFFLINE_LEARNING_REPAIRED_TRAIN_VAL_V2_20261025"))
 ap.add_argument("--output",type=Path,default=Path("New_Datasets/AI_OFFLINE_LEARNING_FINAL_TEST_REPAIRED_V1_20261025"))
 a=ap.parse_args();root=a.project_root.resolve()
 def absolute(p):return p if p.is_absolute() else root/p
 source=absolute(a.source_package);dev=absolute(a.development_package);out=absolute(a.output);base=root/"New_Datasets"
 if out.exists():raise SystemExit(f"STOP: refusing to overwrite {out}")
 latch=base/"experiments/run_manifest.csv.in_flight.json"
 if latch.exists():raise SystemExit(f"STOP: active collection latch exists: {latch}")
 source_manifest=source/"run_split_manifest.csv";dev_manifest=dev/"run_split_manifest.csv";run_manifest=base/"experiments/run_manifest.csv";plan_path=base/"scripts/collection_plan_replace_invalid_mp_test_v1.csv"
 for p in (source_manifest,dev_manifest,run_manifest,plan_path):
  if not p.is_file():raise SystemExit(f"STOP: missing required file: {p}")
 original=read_csv(source_manifest)[1];
 if not original or not {"run_id","label","profile_id"}.issubset(original[0]):raise SystemExit("STOP: unexpected source split manifest schema")
 split_col="planned_split" if "planned_split" in original[0] else ("split" if "split" in original[0] else None)
 if not split_col:raise SystemExit("STOP: source manifest has no split field")
 original_test=[r for r in original if (r.get(split_col) or "").lower() in {"test","final_test"}]
 if len(original_test)!=80 or len({r["run_id"] for r in original_test})!=80:raise SystemExit("STOP: original holdout is not exactly 80 unique runs")
 by_profile={r["profile_id"]:r for r in original_test}
 for profile,rid in OMIT.items():
  r=by_profile.get(profile)
  if not r or r["run_id"]!=rid or r["label"]!="Malicious_POST":raise SystemExit(f"STOP: source invalid-test identity mismatch for {profile}")
 manifests=read_csv(run_manifest)[1];manifest_by_id={r.get("run_id"):r for r in manifests}
 plans=read_csv(plan_path)[1];plan_by_profile={r["profile_id"]:r for r in plans}
 for profile,spec in REPLACEMENTS.items():
  plan=plan_by_profile.get(profile)
  if not plan or plan.get("planned_split")!="final_test" or plan.get("expected_label")!="Malicious_POST" or plan.get("command")!=spec["command"]:raise SystemExit(f"STOP: replacement plan mismatch for {profile}")
  m=manifest_by_id.get(spec["run_id"])
  if not m or m.get("generation")!=spec["generation"] or m.get("status")!="completed" or m.get("label")!="Malicious_POST" or m.get("attack_type")!="malicious_post":raise SystemExit(f"STOP: replacement manifest mismatch for {profile}: {m}")
  app_events,valid_posts=app_evidence(root,spec["run_id"])
  spec["observed_app_events"]=app_events;spec["observed_post_auth_401_events"]=valid_posts
 dev_rows=read_csv(dev_manifest)[1]
 dev_ids={r["run_id"] for r in dev_rows}
 dev_profiles={r["profile_id"] for r in dev_rows}
 if dev_ids & {r["run_id"] for r in original_test}:raise SystemExit("STOP: source test contains run IDs that overlap development")
 selected=[r.copy() for r in original_test if r["profile_id"] not in OMIT]
 for profile,spec in REPLACEMENTS.items():
  if spec["run_id"] in dev_ids or profile in dev_profiles:raise SystemExit(f"STOP: replacement overlaps development: {profile}")
  selected.append({"generation":spec["generation"],"run_id":spec["run_id"],"label":spec["label"],"plan_index":spec["plan_index"],"profile_id":profile,"planned_split":"final_test"})
 if len(selected)!=80 or len({r["run_id"] for r in selected})!=80 or len({r["profile_id"] for r in selected})!=80:raise SystemExit("STOP: corrected test manifest must contain 80 unique runs and profiles")
 counts=Counter(r["label"] for r in selected)
 if counts!={lab:20 for lab in LABELS}:raise SystemExit(f"STOP: corrected test class counts differ: {counts}")
 source_rows={}
 for level in ("packet","flow"):
  src=source/f"{level}_splits/test.csv"
  _,rows=read_csv(src)
  if not rows:raise SystemExit(f"STOP: original {level} test split is empty")
  excluded={rid for rid in OMIT.values()}
  kept=[r for r in rows if r.get("run_id") not in excluded]
  present={r.get("run_id") for r in kept}
  expected_original={r["run_id"] for r in original_test if r["profile_id"] not in OMIT}
  if present!=expected_original:raise SystemExit(f"STOP: {level} source test rows do not match eligible source manifest")
  rawroot=base/f"raw/{level}"
  for profile,spec in REPLACEMENTS.items():
   path=rawroot/(spec["run_id"]+".csv")
   if not path.is_file() or path.stat().st_size==0:raise SystemExit(f"STOP: missing replacement {level} raw file: {path}")
   raw=read_csv(path)[1]
   if not raw:raise SystemExit(f"STOP: empty replacement {level} file: {path}")
   conv=packet_features if level=="packet" else flow_features
   for row in raw:
    if row.get("run_id")!=spec["run_id"]:raise SystemExit(f"STOP: run_id mismatch in {path}")
    kept.append({"run_id":spec["run_id"],"observation_id":row.get("observation_id",""),**conv(row),"label":"Malicious_POST","label_status":"matched"})
  kept.sort(key=lambda r:(r["run_id"],r["observation_id"]))
  validate_table(kept,level)
  if {r["run_id"] for r in kept}!={r["run_id"] for r in selected}:raise SystemExit(f"STOP: {level} corrected test row IDs mismatch manifest")
  source_rows[level]=kept
 out.parent.mkdir(parents=True,exist_ok=True)
 staging=Path(tempfile.mkdtemp(prefix=f".{out.name}.staging-",dir=str(out.parent)))
 try:
  for level,rows in source_rows.items():
   d=staging/f"{level}_splits";d.mkdir(parents=True)
   path=d/"test.csv"
   cols=["run_id","observation_id",*FEATURES[level],"label","label_status"]
   with path.open("w",newline="",encoding="utf-8") as f:
    w=csv.DictWriter(f,fieldnames=cols);w.writeheader();w.writerows(rows)
  manifest_cols=["generation","run_id","label","plan_index","profile_id","planned_split"]
  with (staging/"run_split_manifest.csv").open("w",newline="",encoding="utf-8") as f:
   w=csv.DictWriter(f,fieldnames=manifest_cols);w.writeheader()
   for r in sorted(selected,key=lambda x:(x["label"],x["profile_id"])):
    w.writerow({k:r.get(k,"") for k in manifest_cols})
  with (staging/"excluded_invalid_test_runs.csv").open("w",newline="",encoding="utf-8") as f:
   w=csv.DictWriter(f,fieldnames=["profile_id","run_id","reason"]);w.writeheader()
   w.writerows([{"profile_id":p,"run_id":rid,"reason":"all malicious POST client attempts timed out; no app telemetry observed, so application-layer attack label was unverified"} for p,rid in OMIT.items()])
  cfg_path=source/"config/model_features.json"
  if cfg_path.is_file():
   (staging/"config").mkdir();shutil.copy2(cfg_path,staging/"config/model_features.json")
  qc={"purpose":"Test-only corrected holdout for one-shot network-only final evaluation.","original_v3_package_untouched":True,"development_package_not_modified":True,"test_runs":len(selected),"test_runs_by_label":dict(counts),"original_invalid_test_runs_excluded":OMIT,"verified_replacements":{p:{k:v for k,v in spec.items() if k in {"run_id","generation","plan_index","label","split","command","observed_app_events","observed_post_auth_401_events"}} for p,spec in REPLACEMENTS.items()},"packet_rows":len(source_rows["packet"]),"flow_rows":len(source_rows["flow"]),"packet_unique_observation_ids":len({r["observation_id"] for r in source_rows["packet"]}),"flow_unique_observation_ids":len({r["observation_id"] for r in source_rows["flow"]}),"exact_duplicate_packet_rows":0,"exact_duplicate_flow_rows":0,"train_test_run_overlap":0,"app_fusion_policy":"Not recommended as primary evaluation because test application telemetry coverage is inconsistent; use network-only features for the main result.","test_features_scored_or_models_trained":False}
  (staging/"qc_report.json").write_text(json.dumps(qc,indent=2)+"\n",encoding="utf-8")
  (staging/"README.md").write_text("# Corrected final test holdout (test-only)\n\nStandalone test-only package: 80 runs, 20 per class. It retains eligible original V3 final_test rows, excludes MP031 and MP008 because every malicious POST curl attempt timed out and application telemetry was absent, and replaces them with MP047 and MP048 after application POST/auth/401 telemetry verification. The original V3 package and repaired V2 development package are unchanged.\n\nUse only after model/hyperparameters are frozen. Primary evaluation should use network-only Packet/Flow models because application telemetry availability varies across test runs. Do not tune against these test results.\n",encoding="utf-8")
  files=sorted(p for p in staging.rglob("*") if p.is_file() and p.name!="SHA256SUMS.txt")
  (staging/"SHA256SUMS.txt").write_text("".join(f"{digest(p)}  {p.relative_to(staging).as_posix()}\n" for p in files),encoding="utf-8")
  if out.exists():raise FileExistsError(f"Output appeared during build: {out}")
  staging.rename(out)
 except BaseException:
  shutil.rmtree(staging,ignore_errors=True);raise
 print("CORRECTED TEST-ONLY PACKAGE CREATED:",out)
 print("80 runs (20/class); original package untouched; no model scores/test evaluation computed.")
 print("Verify: cd",out,"&& sha256sum -c SHA256SUMS.txt")
if __name__=="__main__":
 try:main()
 except Exception as e:
  print(f"BUILD STOP: {type(e).__name__}: {e}",file=sys.stderr);raise
