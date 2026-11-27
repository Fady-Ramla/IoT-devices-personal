#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/Graduation_Project/IoT-devices"

PLAN="New_Datasets/scripts/collection_plan_fresh_test_160_20261025.csv"
BUILDER="New_Datasets/scripts/build_train_expanded_dev_once_v5.py"
EVALUATOR="New_Datasets/scripts/eval_fresh_final_test_frozen_v5_once.py"
MAIN_LOG="New_Datasets/reports/fresh_final_test_collection_and_qc_20261026.log"
COLLECT_LOG="New_Datasets/reports/fresh_final_test_collection_160_20261026.log"
PIDFILE="New_Datasets/reports/fresh_final_test_collection_20261026.pid"
PLAN_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/kQZDhCYjKIaAeyCh.csv"
BUILDER_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/MvegMNQBtdNscmyY.py"
EVALUATOR_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/yPPRJaYcmuNsnJlO.py"

download_atomic() {
  local dest="$1" url="$2" tmp="${1}.download.$$"
  if [ -s "$dest" ]; then echo "Using existing file: $dest"; return; fi
  if [ -e "$dest" ]; then echo "STOP: empty destination exists: $dest"; exit 1; fi
  wget --tries=5 --waitretry=2 -O "$tmp" "$url"
  test -s "$tmp" || { echo "STOP: download empty: $dest"; exit 1; }
  mv "$tmp" "$dest"
  echo "Downloaded: $dest"
}

mkdir -p New_Datasets/scripts New_Datasets/reports
download_atomic "$PLAN" "$PLAN_URL"
download_atomic "$BUILDER" "$BUILDER_URL"
download_atomic "$EVALUATOR" "$EVALUATOR_URL"

if [ "${1:-}" != "--worker" ]; then
  for f in "$MAIN_LOG" "$COLLECT_LOG" "$PIDFILE"; do
    [ ! -e "$f" ] || { echo "STOP: output already exists; do not restart blindly: $f"; exit 1; }
  done
  [ ! -e "New_Datasets/experiments/run_manifest.csv.in_flight.json" ] || { echo "STOP: collector latch exists."; exit 1; }
  if pgrep -af '[R]eal_network_topology_packet_flow_final_v3.py'; then echo "STOP: topology already running."; exit 1; fi
  [ ! -e "New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_FINAL_TEST_V1_20261026" ] || { echo "STOP: final test package already exists."; exit 1; }
  ./dataset_env/bin/python -m py_compile "$BUILDER"
  ./dataset_env/bin/python -m py_compile "$EVALUATOR"
  ./dataset_env/bin/python - "$PLAN" <<'PY'
import csv,sys
from pathlib import Path
p=Path(sys.argv[1])
with p.open(newline="",encoding="utf-8-sig") as f:rows=list(csv.DictReader(f))
labels={"Malicious_POST","Normal","Port_Scan","SYN_Flood"}
if len(rows)!=160 or len({r["profile_id"] for r in rows})!=160 or len({r["command"] for r in rows})!=160:
    raise SystemExit("STOP: fresh test plan must contain 160 unique profiles/commands")
if {r["planned_split"] for r in rows}!={"final_test"}:raise SystemExit("STOP: plan contains non-final_test assignments")
if {r["expected_label"] for r in rows}!=labels:raise SystemExit("STOP: plan class set mismatch")
if any(sum(r["expected_label"]==lab for r in rows)!=40 for lab in labels):raise SystemExit("STOP: expected exactly 40 profiles per class")
commands={r["command"]:r["profile_id"] for r in rows};profiles={r["profile_id"]:r["command"] for r in rows}
for other in p.parent.glob("collection_plan*.csv"):
    if other.resolve()==p.resolve():continue
    try:
        with other.open(newline="",encoding="utf-8-sig") as f:prior=list(csv.DictReader(f))
    except Exception:continue
    for old in prior:
        c=old.get("command","");pid=old.get("profile_id","")
        if c in commands and pid!=commands[c]:raise SystemExit(f"STOP: command collision with {other.name}: {c}")
        if pid in profiles and c!=profiles[pid]:raise SystemExit(f"STOP: profile collision with {other.name}: {pid}")
print("PASS: 160 unique sealed-test profiles, 40/class, no plan/profile conflicts.")
PY
  STATUS=$(curl -fsS --max-time 5 http://127.0.0.1:8080/dataset/run/status) || { echo "STOP: collector REST unavailable; no capture started."; exit 1; }
  printf '%s' "$STATUS" | ./dataset_env/bin/python -c 'import json,sys; s=json.load(sys.stdin).get("state"); print("Collector state:",s); sys.exit(0 if s in ("drained","idle") else 1)' || { echo "STOP: collector is not idle/drained."; exit 1; }
  ./dataset_env/bin/python - "New_Datasets/experiments/run_manifest.csv" <<'PY'
import csv,sys
with open(sys.argv[1],newline="",encoding="utf-8-sig") as f:rows=list(csv.DictReader(f))
g=[int(r["generation"]) for r in rows if str(r.get("generation","")).isdigit()]
if not g or max(g)!=549:raise SystemExit(f"STOP: expected latest generation 549 before fresh test; found {max(g) if g else 'none'}")
print("PASS: development ends at generation 549; fresh test collection will start after it.")
PY
  sudo -v
  sudo -n true || { echo "STOP: sudo credential check failed; nothing started."; exit 1; }
  nohup bash "$0" --worker > "$MAIN_LOG" 2>&1 < /dev/null &
  worker=$!; printf '%s\n' "$worker" > "$PIDFILE"
  echo "Started 160-run fresh final-test collection in background. No model scores are computed by this job."
  echo "PID: $worker"
  echo "Collection log: $COLLECT_LOG"
  echo "QC log: $MAIN_LOG"
  exit 0
fi

echo "=== Collecting 160 fresh final-test runs ==="
if ! sudo -n env SECUREIOT_BATCH_PLAN="$PWD/$PLAN" python3 mininet/Real_network_topology_packet_flow_final_v3.py > "$COLLECT_LOG" 2>&1; then
  echo "STOP: collection batch failed. No test Packet/Flow features or model scores were read."
  tail -n 40 "$COLLECT_LOG" || true
  exit 1
fi

echo "=== Metadata/application-label QC only; Packet/Flow test features stay unopened ==="
./dataset_env/bin/python - "$PLAN" "$BUILDER" <<'PY'
import csv,importlib.util,sys
from pathlib import Path
root=Path.cwd();base=root/"New_Datasets";plan_path=Path(sys.argv[1]);builder_path=Path(sys.argv[2])
spec=importlib.util.spec_from_file_location("builder",builder_path);b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
with plan_path.open(newline="",encoding="utf-8-sig") as f:plan=list(csv.DictReader(f))
with (base/"experiments/run_manifest.csv").open(newline="",encoding="utf-8-sig") as f:manifest=list(csv.DictReader(f))
with (base/"AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026/run_split_manifest.csv").open(newline="",encoding="utf-8-sig") as f:dev=list(csv.DictReader(f))
dev_ids={r["run_id"] for r in dev};used=set();gens=[];issues=[];counts={x:0 for x in ("Malicious_POST","Normal","Port_Scan","SYN_Flood")}
for p in plan:
    matches=[r for r in manifest if b.exact_manifest_match(r,p)]
    if len(matches)!=1:issues.append(f"{p['profile_id']}: manifest matches={len(matches)}");continue
    r=matches[0];rid=r.get("run_id","")
    if r.get("status")!="completed":issues.append(f"{p['profile_id']}: status={r.get('status')}");continue
    if rid in used or rid in dev_ids:issues.append(f"{p['profile_id']}: duplicate/leaked run_id {rid}");continue
    used.add(rid);counts[p["expected_label"]]+=1
    try:gens.append(int(r["generation"]))
    except Exception:issues.append(f"{p['profile_id']}: invalid generation")
    for level in ("packet","flow"):
        path=base/"raw"/level/(rid+".csv")
        if not path.is_file() or path.stat().st_size==0:issues.append(f"{p['profile_id']}: missing/empty {level} file")
    if p["expected_label"]=="Malicious_POST":
        events=b.app_events(base,rid);valid=[]
        for e in events:
            if (b.event_value(e,"http_method","method").upper()=="POST" and
                b.event_value(e,"route_category","route").lower()=="auth" and
                b.event_value(e,"response_status","status")=="401"):
                valid.append(e)
        if not valid:issues.append(f"{p['profile_id']}: missing POST/auth/401 app evidence")
if len(used)!=160:issues.append(f"unique valid runs={len(used)}, expected 160")
if counts!={x:40 for x in counts}:issues.append(f"class counts={counts}")
if len(gens)!=160 or set(gens)!=set(range(550,710)):issues.append(f"test generations are not exactly 550-709: count={len(gens)}")
if issues:raise SystemExit("STOP: final-test pre-score QC failed; do not evaluate:\n  "+"\n  ".join(issues[:30]))
print("PASS: all 160 captures completed; 40/class; Packet/Flow files exist; malicious POST app evidence present; development/test run IDs disjoint.")
print("Packet/Flow feature rows were not opened and no model predictions or scores were computed.")
PY

echo "FINAL-TEST CAPTURE QC COMPLETE. The holdout remains unscored."
echo "=== Score the sealed holdout once with frozen v5 models; no retraining ==="
./dataset_env/bin/python -u "$EVALUATOR"
PKG="New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_FINAL_TEST_V1_20261026"
(cd "$PKG" && sha256sum -c SHA256SUMS.txt)
echo "FINAL-TEST ONE-SHOT COMPLETE: $PKG"
