#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/Graduation_Project/IoT-devices"
PLAN="New_Datasets/scripts/collection_plan_final_test_post_replacements_6_20261026.csv"
TESTPLAN="New_Datasets/scripts/collection_plan_fresh_test_160_20261025.csv"
HELPER="New_Datasets/scripts/build_train_expanded_dev_once_v5.py"
EVALUATOR="New_Datasets/scripts/eval_final_test_with_six_replacements_frozen_v5.py"
LOG="New_Datasets/reports/final_test_replace6_and_eval_20261026.log"
COLLECTLOG="New_Datasets/reports/final_test_replace6_collection_20261026.log"
PIDFILE="New_Datasets/reports/final_test_replace6_20261026.pid"
HELPER_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/MvegMNQBtdNscmyY.py"
EVALUATOR_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/IMBvEdPBXkTnWmtt.py"

fetch_if_missing(){ local dst="$1" url="$2" tmp="${1}.download.$$"; if [ -s "$dst" ]; then return; fi; [ ! -e "$dst" ] || { echo "STOP: empty existing file: $dst"; exit 1; }; wget --tries=5 --waitretry=2 -O "$tmp" "$url"; test -s "$tmp"; mv "$tmp" "$dst"; }
mkdir -p New_Datasets/scripts New_Datasets/reports
fetch_if_missing "$HELPER" "$HELPER_URL"
fetch_if_missing "$EVALUATOR" "$EVALUATOR_URL"

if [ "${1:-}" != "--worker" ]; then
  for f in "$PLAN" "$LOG" "$COLLECTLOG" "$PIDFILE"; do [ ! -e "$f" ] || { echo "STOP: recovery artifact already exists; don't rerun blindly: $f"; exit 1; }; done
  [ ! -e "New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_FINAL_TEST_V1_20261026" ] || { echo "STOP: final evaluation output exists."; exit 1; }
  [ ! -e "New_Datasets/experiments/run_manifest.csv.in_flight.json" ] || { echo "STOP: active run latch exists."; exit 1; }
  if pgrep -af '[R]eal_network_topology_packet_flow_final_v3.py'; then echo "STOP: topology process is still running."; exit 1; fi
  if pgrep -af '[e]val_final_test_with_six_replacements_frozen_v5.py'; then echo "STOP: evaluator process is already running."; exit 1; fi
  ./dataset_env/bin/python -m py_compile "$HELPER" "$EVALUATOR"
  ./dataset_env/bin/python - "$TESTPLAN" "$HELPER" "$PLAN" <<'PY'
import csv,importlib.util,sys,itertools
from pathlib import Path
root=Path.cwd();base=root/'New_Datasets';test_path=Path(sys.argv[1]);helper_path=Path(sys.argv[2]);out=Path(sys.argv[3])
spec=importlib.util.spec_from_file_location('b',helper_path);b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
def read(p):
 with p.open(newline='',encoding='utf-8-sig') as f:return list(csv.DictReader(f))
plan=read(test_path);manifest=read(base/'experiments/run_manifest.csv')
BAD={'MPNEW064','MPNEW072','MPNEW020','MPNEW004','MPNEW068','MPNEW001'}
if len(plan)!=160:raise SystemExit(f'STOP: expected original 160-row plan, got {len(plan)}')
if {p['profile_id'] for p in plan if p['profile_id'] in BAD}!=BAD:raise SystemExit('STOP: expected six invalid POST profiles not present')
bygen={}
for r in manifest:
 try:g=int(r.get('generation') or 0)
 except ValueError:continue
 bygen.setdefault(g,[]).append(r)
for i,p in enumerate(plan):
 g=550+i;rs=bygen.get(g,[])
 if len(rs)!=1 or rs[0].get('status')!='completed' or not b.exact_manifest_match(rs[0],p):raise SystemExit(f"STOP: test run/order mismatch at {p['profile_id']} generation {g}")
 if p['expected_label']=='Malicious_POST':
  ev=b.app_events(base,rs[0]['run_id']);ok=[e for e in ev if b.event_value(e,'http_method','method').upper()=='POST' and b.event_value(e,'route_category','route').lower()=='auth' and b.event_value(e,'response_status','status')=='401']
  if (p['profile_id'] in BAD) == bool(ok):raise SystemExit(f"STOP: app evidence set changed for {p['profile_id']}; expected invalid={p['profile_id'] in BAD}, found valid_events={len(ok)}")
# Existing profile/command protection across all known plans.
used_profiles=set();used_commands=set()
for q in (base/'scripts').glob('collection_plan*.csv'):
 try:
  for r in read(q):
   if r.get('profile_id'):used_profiles.add(r['profile_id'])
   if r.get('command'):used_commands.add(r['command'])
 except Exception:pass
labels=('Malicious_POST',);hosts=range(5,17);intervals=(200,250,400,500,750,1000);durations=(8,9,10,11,12,13,14,15,16,17,18,19)
signatures=set();chosen=[]
for h,interval,dur in itertools.product(hosts,intervals,durations):
 idx=len(chosen);pid=f'MPTESTREPL{idx+1:03d}'
 count=12+(idx*3)%13
 cmd=f'attack h{h} malicious_post h2 /login {count} {interval} 1 {dur}'
 p={'command':cmd,'expected_label':'Malicious_POST','planned_split':'final_test','profile_id':pid}
 # matcher-relevant signature: source, target, rate parameter, duration (count excluded by collector normalization)
 sig=(h,2,interval,dur)
 if pid in used_profiles or cmd in used_commands or sig in signatures:continue
 if any(b.exact_manifest_match(r,p) for r in manifest):continue
 chosen.append({'plan_index':str(1001+idx),'command':cmd,'pause_after_sec':'2','expected_label':'Malicious_POST','planned_split':'final_test','profile_id':pid})
 used_profiles.add(pid);used_commands.add(cmd);signatures.add(sig)
 if len(chosen)==6:break
if len(chosen)!=6:raise SystemExit('STOP: could not synthesize six command-unique POST replacements; no collection started')
with out.open('x',newline='',encoding='utf-8') as f:
 w=csv.DictWriter(f,fieldnames=['plan_index','command','pause_after_sec','expected_label','planned_split','profile_id']);w.writeheader();w.writerows(chosen)
print('PASS: original test batch maps to generations 550-709; six and only six original POST captures lack app evidence.')
print('Prepared six unique final-test replacements (no test Packet/Flow features opened):')
for r in chosen:print(r['profile_id'],r['command'])
PY
  STATUS=$(curl -fsS --max-time 5 http://127.0.0.1:8080/dataset/run/status) || { echo "STOP: collector REST unavailable; no replacement started."; exit 1; }
  printf '%s' "$STATUS" | ./dataset_env/bin/python -c 'import json,sys;s=json.load(sys.stdin).get("state");print("Collector state:",s);sys.exit(0 if s in ("drained","idle") else 1)' || { echo "STOP: collector not idle/drained."; exit 1; }
  ./dataset_env/bin/python - "New_Datasets/experiments/run_manifest.csv" <<'PY'
import csv,sys
with open(sys.argv[1],newline='',encoding='utf-8-sig') as f:r=list(csv.DictReader(f))
g=[int(x['generation']) for x in r if str(x.get('generation','')).isdigit()]
if max(g)!=709:raise SystemExit(f'STOP: expected generation 709 before replacement batch; found {max(g)}')
print('PASS: fresh-test batch ends at generation 709; replacements start at 710.')
PY
  sudo -v
  sudo -n true || { echo "STOP: sudo check failed; nothing started."; exit 1; }
  nohup bash "$0" --worker > "$LOG" 2>&1 < /dev/null &
  pid=$!; printf '%s\n' "$pid" > "$PIDFILE"
  echo "Started six-run repair workflow in background. It will evaluate only if all six replacements pass POST/auth/401 QC."
  echo "PID=$pid ; replacement log=$COLLECTLOG ; workflow log=$LOG"
  exit 0
fi

echo "=== Collect exactly six POST replacements ==="
if ! sudo -n env SECUREIOT_BATCH_PLAN="$PWD/$PLAN" python3 mininet/Real_network_topology_packet_flow_final_v3.py > "$COLLECTLOG" 2>&1; then echo "STOP: replacement collection batch failed; final-test features not read."; tail -n 35 "$COLLECTLOG" || true; exit 1; fi

echo "=== QC replacements then score once with frozen models ==="
./dataset_env/bin/python -u "$EVALUATOR"
PKG="New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_FINAL_TEST_V1_20261026"
(cd "$PKG" && sha256sum -c SHA256SUMS.txt)
echo "FINAL-TEST ONE-SHOT COMPLETE: $PKG"
