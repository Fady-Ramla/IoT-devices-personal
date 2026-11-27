#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/Graduation_Project/IoT-devices"

PLAN="New_Datasets/scripts/collection_plan_replace_missing_app_post_8runs_20261026.csv"
REPLACEMENT="New_Datasets/scripts/collection_plan_expanded_dev_replacements_14_20261026.csv"
EXPANDED="New_Datasets/scripts/collection_plan_expanded_development_160_20261025.csv"
BUILDER="New_Datasets/scripts/build_train_expanded_dev_once_v5.py"
MAIN_LOG="New_Datasets/reports/app_post_replacements_and_training_v5.log"
COLLECT_LOG="New_Datasets/reports/replace_missing_app_post_8runs_20261026.log"
PIDFILE="New_Datasets/reports/app_post_replacements_and_training_v5.pid"
PLAN_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/kxRecNVnsMGeJTDr.csv"
REPLACEMENT_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/UoutbQujouhPSXuc.csv"
EXPANDED_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/IIUOOiDNmPYtgnTU.csv"
BUILDER_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/MvegMNQBtdNscmyY.py"

mkdir -p New_Datasets/scripts New_Datasets/reports

download_atomic() {
  local dest="$1" url="$2" tmp="${1}.download.$$"
  if [ -s "$dest" ]; then echo "Using existing file: $dest"; return; fi
  if [ -e "$dest" ]; then echo "STOP: empty destination exists: $dest"; exit 1; fi
  wget --tries=5 --waitretry=2 -O "$tmp" "$url"
  test -s "$tmp" || { echo "STOP: download empty: $dest"; exit 1; }
  mv "$tmp" "$dest"
  echo "Downloaded: $dest"
}

download_atomic "$PLAN" "$PLAN_URL"
download_atomic "$REPLACEMENT" "$REPLACEMENT_URL"
download_atomic "$EXPANDED" "$EXPANDED_URL"
download_atomic "$BUILDER" "$BUILDER_URL"

if [ "${1:-}" != "--worker" ]; then
  for f in "$MAIN_LOG" "$COLLECT_LOG" "$PIDFILE"; do
    [ ! -e "$f" ] || { echo "STOP: output already exists; inspect it before any retry: $f"; exit 1; }
  done
  [ ! -e "New_Datasets/experiments/run_manifest.csv.in_flight.json" ] || { echo "STOP: collector latch exists."; exit 1; }
  if pgrep -af '[R]eal_network_topology_packet_flow_final_v3.py'; then
    echo "STOP: Mininet topology is already running."; exit 1
  fi
  [ ! -e "New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026" ] || { echo "STOP: development package already exists; refusing another build."; exit 1; }
  [ ! -e "New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026/models/final_trainval_20261026" ] || { echo "STOP: model directory already exists."; exit 1; }
  [ ! -e "New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026" ] || { echo "STOP: development package already exists; inspect it before continuing."; exit 1; }
  test -x ./dataset_env/bin/python || { echo "STOP: dataset_env Python is missing."; exit 1; }
  ./dataset_env/bin/python -m py_compile "$BUILDER"

  ./dataset_env/bin/python - "$PLAN" "$REPLACEMENT" <<'PY'
import csv,sys
from pathlib import Path
p=Path(sys.argv[1]); combined=Path(sys.argv[2])
def read(path):
    with path.open(newline="",encoding="utf-8-sig") as f:return list(csv.DictReader(f))
rows=read(p); allrepl=read(combined)
if len(rows)!=8 or len({r["profile_id"] for r in rows})!=8 or len({r["command"] for r in rows})!=8:
    raise SystemExit("STOP: replacement batch must have eight unique profiles and commands")
if {r["profile_id"] for r in rows}!={f"MPREPL{i:03d}" for i in range(6,14)}:
    raise SystemExit("STOP: replacement batch profile IDs differ from audited plan")
if any(r["expected_label"]!="Malicious_POST" for r in rows):raise SystemExit("STOP: non-POST label in replacement batch")
if sum(r["planned_split"]=="train" for r in rows)!=6 or sum(r["planned_split"]=="validation" for r in rows)!=2:
    raise SystemExit("STOP: replacement batch must preserve 6 train / 2 validation")
if len(allrepl)!=14:raise SystemExit("STOP: combined replacement ledger must contain fourteen profiles")
commands={r["command"]:r["profile_id"] for r in rows}
profiles={r["profile_id"]:r["command"] for r in rows}
for row in rows:
    q=row["command"].split()
    if len(q)!=9 or q[0]!="attack" or q[2]!="malicious_post":raise SystemExit("STOP: unsupported command: "+row["command"])
    count,delay,duration=int(q[5]),int(q[6]),int(q[8])
    if count>1000/delay*duration:raise SystemExit("STOP: POST count exceeds rate-duration capacity: "+row["command"])
script_dir=p.parent
for other in script_dir.glob("collection_plan*.csv"):
    if other.resolve()==p.resolve():continue
    if "fresh_test" in other.name:continue
    try: prior=read(other)
    except Exception:continue
    for old in prior:
        c=old.get("command","");pid=old.get("profile_id","")
        if c in commands and pid!=commands[c]:
            raise SystemExit(f"STOP: exact command duplicate in {other.name}: {c}")
        if pid in profiles and c!=profiles[pid]:
            raise SystemExit(f"STOP: profile ID collision in {other.name}: {pid}")
print("PASS: eight unique POST replacements; 6 train / 2 validation; command/rate checks passed.")
PY

  STATUS=$(curl -fsS --max-time 5 http://127.0.0.1:8080/dataset/run/status) || { echo "STOP: Ryu collector REST is not reachable; no batch started."; exit 1; }
  printf '%s' "$STATUS" | ./dataset_env/bin/python -c 'import json,sys; d=json.load(sys.stdin); assert d.get("state") in ("drained","idle"), f"collector not idle/drained: {d.get(chr(115)+chr(116)+chr(97)+chr(116)+chr(101))}"'
  ./dataset_env/bin/python - "New_Datasets/experiments/run_manifest.csv" <<'PY'
import csv,sys
with open(sys.argv[1],newline="",encoding="utf-8-sig") as f: rows=list(csv.DictReader(f))
g=[int(r["generation"]) for r in rows if str(r.get("generation","")).isdigit()]
if not g or max(g)!=541:raise SystemExit(f"STOP: expected current last generation 541; found {max(g) if g else 'none'}")
last=[r for r in rows if int(r.get("generation") or 0)==541]
if len(last)!=1 or last[0].get("status")!="completed":raise SystemExit("STOP: generation 541 is not uniquely completed")
print("PASS: latest manifest generation is 541; next batch should occupy 542-549.")
PY
  sudo -v
  sudo -n true || { echo "STOP: sudo credential check failed; no batch started."; exit 1; }
  nohup bash "$0" --worker > "$MAIN_LOG" 2>&1 < /dev/null &
  worker=$!
  printf '%s\n' "$worker" > "$PIDFILE"
  echo "Started guarded replacement + verification + development training worker."
  echo "PID: $worker"
  echo "Main log: $MAIN_LOG"
  echo "Collection log: $COLLECT_LOG"
  exit 0
fi

# Worker: run the eight replacement captures; any capture failure aborts before QC/training.
echo "=== Eight POST telemetry replacements: starting ==="
if ! sudo -n env SECUREIOT_BATCH_PLAN="$PWD/$PLAN" python3 mininet/Real_network_topology_packet_flow_final_v3.py > "$COLLECT_LOG" 2>&1; then
  echo "STOP: collection batch failed; training was not started. Collection log: $COLLECT_LOG"
  tail -n 40 "$COLLECT_LOG" || true
  exit 1
fi

echo "=== Verify generations 542-549 and required POST/auth/401 telemetry ==="
./dataset_env/bin/python - "$PLAN" "$BUILDER" <<'PY'
import csv,importlib.util,sys
from pathlib import Path
root=Path.cwd(); base=root/"New_Datasets"; plan_path=Path(sys.argv[1]); builder_path=Path(sys.argv[2])
spec=importlib.util.spec_from_file_location("builder",builder_path);b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
with plan_path.open(newline="",encoding="utf-8-sig") as f: plan=list(csv.DictReader(f))
with (base/"experiments/run_manifest.csv").open(newline="",encoding="utf-8-sig") as f: manifest=list(csv.DictReader(f))
issues=[]
for i,p in enumerate(plan):
    gen=542+i; matches=[r for r in manifest if int(r.get("generation") or 0)==gen]
    if len(matches)!=1:issues.append(f"generation {gen}: manifest rows={len(matches)}");continue
    r=matches[0]
    if r.get("status")!="completed" or r.get("label")!="Malicious_POST":issues.append(f"generation {gen}: status/label={r.get('status')}/{r.get('label')}");continue
    profile_matches=[q for q in plan if b.exact_manifest_match(r,q)]
    if len(profile_matches)!=1 or profile_matches[0]["profile_id"]!=p["profile_id"]:
        issues.append(f"generation {gen}: manifest does not uniquely match {p['profile_id']}");continue
    events=b.app_events(base,r["run_id"]);valid=[]
    for e in events:
        method=b.event_value(e,"http_method","method").upper()
        route=b.event_value(e,"route_category","route").lower()
        status=b.event_value(e,"response_status","status")
        if method=="POST" and route=="auth" and status=="401":valid.append(e)
    print(f"{p['profile_id']} gen={gen} split={p['planned_split']}: app_events={len(events)}, POST/auth/401={len(valid)}")
    if not valid:issues.append(f"{p['profile_id']} gen={gen}: missing POST/auth/401")
if issues:
    raise SystemExit("STOP: telemetry replacement QC failed; no training started:\n  "+"\n  ".join(issues))
print("PASS: all eight replacement captures have verified POST/auth/401 telemetry.")
PY

echo "=== Build balanced development package and train models ==="
./dataset_env/bin/python -u "$BUILDER" --project-root "$PWD" --replacement-plan "$REPLACEMENT"
PKG="New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026"
(cd "$PKG" && sha256sum -c SHA256SUMS.txt)
echo "ONE-SHOT COMPLETE. Development package: $PKG"
echo "Training summary: $PKG/models/final_trainval_20261026/training_summary.json"
echo "Final-test data remained unopened."
