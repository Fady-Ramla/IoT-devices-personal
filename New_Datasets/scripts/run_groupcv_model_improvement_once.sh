#!/usr/bin/env bash
# One-shot model improvement using the 160 existing clean runs as development only.
set -Eeuo pipefail
ROOT="${PROJECT_ROOT:-$PWD}"
cd "$ROOT"
PY="$ROOT/dataset_env/bin/python"
if [[ ! -x "$PY" ]]; then echo "STOP: expected dataset_env/bin/python"; exit 1; fi
DEV="$ROOT/New_Datasets/AI_OFFLINE_LEARNING_REPAIRED_TRAIN_VAL_V2_20261025"
OLD="$ROOT/New_Datasets/AI_OFFLINE_LEARNING_FINAL_TEST_REPAIRED_V1_20261025"
SCRIPTS="$ROOT/New_Datasets/scripts"
mkdir -p "$ROOT/New_Datasets/reports" "$SCRIPTS"
LOG="$ROOT/New_Datasets/reports/groupcv_model_improvement_20261025.log"
exec > >(tee -a "$LOG") 2>&1

echo "=== GROUPED-CV MODEL IMPROVEMENT (DEVELOPMENT ONLY) ==="
echo "All 160 verified historical runs will be used as development; no independent test score will be claimed."

if [[ -e "$ROOT/New_Datasets/experiments/run_manifest.csv.in_flight.json" ]]; then
  echo "STOP: collection latch exists; wait until the run is resolved."
  exit 1
fi
for p in "$DEV/run_split_manifest.csv" "$OLD/run_split_manifest.csv" "$OLD/SHA256SUMS.txt"; do
  if [[ ! -s "$p" ]]; then echo "STOP: required package file missing: $p"; exit 1; fi
done
(cd "$OLD" && sha256sum -c SHA256SUMS.txt)

OUT="$ROOT/New_Datasets/AI_OFFLINE_LEARNING_MODEL_IMPROVED_GROUPCV_V1_20261025"
if [[ -f "$OUT/development_groupcv_report.json" ]]; then
  echo "A completed report already exists; not rerunning. Report: $OUT/development_groupcv_report.json"
  exit 0
fi
if [[ -e "$OUT" ]]; then
  echo "STOP: output folder exists but is incomplete; preserve it and send the log."
  exit 1
fi
SCRIPT="$SCRIPTS/optimize_packet_flow_groupcv_once.py"
TMP="$SCRIPT.download.$$"
URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/YZxYqrrKrltacimV.py"
DOWNLOADED=0
for attempt in {1..8}; do
  rm -f "$TMP"
  if wget --timeout=20 --tries=1 -O "$TMP" "$URL" \
     && test -s "$TMP" \
     && "$PY" -c 'import ast,pathlib,sys;ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))' "$TMP"; then
    mv -f "$TMP" "$SCRIPT"; DOWNLOADED=1; break
  fi
  rm -f "$TMP"; echo "Download attempt $attempt/8 failed; retrying."; sleep $((attempt*2))
done
if [[ "$DOWNLOADED" -ne 1 ]]; then echo "STOP: unable to download a verified optimizer; no training started."; exit 1; fi

"$PY" -u "$SCRIPT" \
  --development-package "$DEV" \
  --historical-holdout-package "$OLD" \
  --output-dir "$OUT" \
  --seed 42

echo "=== SELECTED DEVELOPMENT MODELS ==="
"$PY" - "$OUT/development_groupcv_report.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
for level in ("packet","flow"):
  z=r["levels"][level];m=z["candidate_oof_run_metrics"][z["selected_candidate"]]["oof_run_metrics"]
  print(f"{level}: selected={z['selected_candidate']}; grouped OOF accuracy={m['accuracy']:.4f}; grouped OOF macro-F1={m['macro_f1']:.4f}")
  print("  confusion:",m["confusion_matrix"])
print("These are model-selection CV results, not an independent final-test score.")
print("Fresh unseen runs are required before claiming final accuracy.")
PY
echo "Report: $OUT/development_groupcv_report.json"
echo "Models: $OUT/models"
echo "Log: $LOG"
