#!/usr/bin/env bash
# Single guarded workflow: corrected test QC/build -> checksum -> final network-only evaluation once.
set -Eeuo pipefail

ROOT="${PROJECT_ROOT:-$PWD}"
cd "$ROOT"
if [[ ! -x "$ROOT/dataset_env/bin/python" ]]; then
  echo "STOP: expected project venv at $ROOT/dataset_env/bin/python"
  exit 1
fi
if [[ ! -f "$ROOT/mininet/Real_network_topology_packet_flow_final_v3.py" ]]; then
  echo "STOP: run this from the IoT-devices project root."
  exit 1
fi

mkdir -p "$ROOT/New_Datasets/reports"
LOG="$ROOT/New_Datasets/reports/final_one_shot_pipeline_20261025.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== FINAL ONE-SHOT PIPELINE ==="
echo "Project: $ROOT"
echo "Log: $LOG"
echo "Policy: network-only Packet/Flow; final test accessed once; no retuning afterward."

if [[ -e "$ROOT/New_Datasets/experiments/run_manifest.csv.in_flight.json" ]]; then
  echo "STOP: active collection latch exists. Do not build or evaluate while a run is in flight."
  exit 1
fi

SCRIPTS="$ROOT/New_Datasets/scripts"
mkdir -p "$SCRIPTS"
BUILDER="$SCRIPTS/build_corrected_final_test_packet_flow_v1.py"
EVALUATOR="$SCRIPTS/final_eval_packet_flow_network_only_once.py"

download_python_atomic() {
  local url="$1" dest="$2" tmp attempt
  tmp="${dest}.download.$$"
  for attempt in {1..8}; do
    rm -f "$tmp"
    if wget --timeout=20 --tries=1 -O "$tmp" "$url" \
       && [[ -s "$tmp" ]] \
       && "$ROOT/dataset_env/bin/python" -c \
          'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))' "$tmp"; then
      mv -f "$tmp" "$dest"
      echo "Verified script downloaded: $(basename "$dest")"
      return 0
    fi
    rm -f "$tmp"
    echo "Download/validation attempt $attempt/8 failed; retrying without changing existing files."
    sleep $((attempt * 2))
  done
  echo "STOP: could not obtain a verified script after retries: $dest"
  return 1
}

download_python_atomic \
  "https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/zOStKskqbwhLbCSR.py" \
  "$BUILDER"
download_python_atomic \
  "https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/UKvRGgXFmJVPWlRD.py" \
  "$EVALUATOR"

TESTPKG="$ROOT/New_Datasets/AI_OFFLINE_LEARNING_FINAL_TEST_REPAIRED_V1_20261025"
DEV="$ROOT/New_Datasets/AI_OFFLINE_LEARNING_REPAIRED_TRAIN_VAL_V2_20261025"
SOURCE="$ROOT/New_Datasets/AI_OFFLINE_LEARNING_FINAL_V3_20261025"
OUT="$ROOT/New_Datasets/AI_OFFLINE_LEARNING_REPAIRED_TRAIN_VAL_V2_20261025/models/FINAL_NETWORK_ONLY_ONCE_20261025"

if [[ ! -d "$TESTPKG" ]]; then
  if [[ -e "$TESTPKG" ]]; then
    echo "STOP: test-package path exists but is not a directory."
    exit 1
  fi
  echo "Building corrected test-only package (original V3 remains untouched)..."
  "$ROOT/dataset_env/bin/python" -u "$BUILDER" --project-root "$ROOT"
else
  echo "Corrected test package already exists; verifying rather than rebuilding."
fi

if [[ ! -s "$TESTPKG/SHA256SUMS.txt" ]]; then
  echo "STOP: corrected package checksum file missing; preserve files and send this log."
  exit 1
fi
(cd "$TESTPKG" && sha256sum -c SHA256SUMS.txt)
"$ROOT/dataset_env/bin/python" - "$TESTPKG/qc_report.json" <<'PY'
import json, sys
from pathlib import Path
q=json.loads(Path(sys.argv[1]).read_text())
assert q.get("test_runs")==80, q
assert q.get("test_runs_by_label")=={"Normal":20,"Malicious_POST":20,"Port_Scan":20,"SYN_Flood":20}, q
assert q.get("train_test_run_overlap")==0, q
assert q.get("test_features_scored_or_models_trained") is False, q
assert set(q.get("original_invalid_test_runs_excluded",{}))=={"MP031","MP008"}, q
assert set(q.get("verified_replacements",{}))=={"MP047","MP048"}, q
print("Holdout QC: PASS (80 runs, 20/class; replacements verified; no test score computed yet).")
PY

if [[ -f "$OUT/final_test_metrics.json" && -f "$OUT/RUN_ONCE_COMPLETE.txt" ]]; then
  echo "Final evaluation already completed. Refusing to run again; showing saved summary."
  "$ROOT/dataset_env/bin/python" - "$OUT/final_test_metrics.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
for level in ("packet","flow"):
  print("\n",level.upper())
  for model in ("random_forest","xgboost"):
    m=r["levels"][level]["models"][model]["test"]
    run=m["run_level"]
    row=m["row_level"]
    print(f"{model}: run acc={run['accuracy']:.4f}, run macro-F1={run['f1_macro']:.4f}; row acc={row['accuracy']:.4f}, row macro-F1={row['f1_macro']:.4f}")
    print("  run confusion:",run["confusion_matrix"])
PY
  echo "Saved results are final; do not retune on this test set."
  exit 0
fi
RESUME_FLAGS=()
if [[ -e "$OUT" ]]; then
  KNOWN_PRESCORE_FAILURE=0
  if grep -Eq 'ValueError: packet (combined development|final_test) has 80 runs; expected 20' "$LOG"; then
    KNOWN_PRESCORE_FAILURE=1
  fi
  if [[ -f "$OUT/RUN_ONCE_IN_PROGRESS.txt" \
        && ! -e "$OUT/final_test_metrics.partial.json" \
        && ! -e "$OUT/final_test_metrics.json" \
        && ! -e "$OUT/RUN_ONCE_COMPLETE.txt" \
        && "$(find "$OUT" -mindepth 1 -maxdepth 1 | wc -l)" -eq 1 \
        && "$KNOWN_PRESCORE_FAILURE" -eq 1 ]]; then
    echo "Confirmed from prior log: the run stopped at data preflight before model fitting or scoring. Resuming that incomplete preflight safely."
    RESUME_FLAGS=(--resume-pre-score-failure)
  else
    echo "STOP: evaluation output/one-shot marker exists but is not the known pre-score failure. Preserve it; do not rerun."
    exit 1
  fi
fi

echo "Starting the one-shot evaluation: train on repaired development V2 (80 runs), score corrected final test (80 runs)."
"$ROOT/dataset_env/bin/python" -u "$EVALUATOR" \
  --development-dir "$DEV" \
  --final-package-dir "$TESTPKG" \
  --output-dir "$OUT" \
  --seed 42 \
  "${RESUME_FLAGS[@]}"

echo "=== FINAL SAVED METRICS ==="
"$ROOT/dataset_env/bin/python" - "$OUT/final_test_metrics.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
for level in ("packet","flow"):
  print("\n",level.upper())
  for model in ("random_forest","xgboost"):
    m=r["levels"][level]["models"][model]["test"]
    run=m["run_level"]
    row=m["row_level"]
    lo,hi=run["accuracy_wilson_95_ci"]
    print(f"{model}: run acc={run['accuracy']:.4f} (Wilson95% CI {lo:.3f}-{hi:.3f}), run macro-F1={run['f1_macro']:.4f}; row acc={row['accuracy']:.4f}, row macro-F1={row['f1_macro']:.4f}")
    print("  run confusion:",run["confusion_matrix"])
print("\nOne-shot final test complete. Do not tune using these test results.")
PY

echo "Full machine-readable report: $OUT/final_test_metrics.json"
echo "Run log: $LOG"
