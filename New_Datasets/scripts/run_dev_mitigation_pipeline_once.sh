#!/usr/bin/env bash
# One-shot development-only diagnostics. Does not collect traffic or touch final-test files/models.
set -Eeuo pipefail
ROOT="${PROJECT_ROOT:-$PWD}"
cd "$ROOT"
PY="$ROOT/dataset_env/bin/python"
DEV="$ROOT/New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026"
SCRIPT="$ROOT/New_Datasets/scripts/dev_mitigation_pipeline_once.py"
REPORT="$ROOT/New_Datasets/reports/dev_mitigation_pipeline_once_20261026.json"
LOG="$ROOT/New_Datasets/reports/dev_mitigation_pipeline_once_20261026.log"
PIDFILE="$ROOT/New_Datasets/reports/dev_mitigation_pipeline_once_20261026.pid"
URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/hOTieFtyeMBsQeTi.py"

[[ -x "$PY" ]] || { echo "STOP: expected executable $PY"; exit 1; }
[[ -d "$DEV" ]] || { echo "STOP: development package missing: $DEV"; exit 1; }
[[ -s "$DEV/SHA256SUMS.txt" ]] || { echo "STOP: development package checksum manifest missing"; exit 1; }
[[ ! -e "$ROOT/New_Datasets/experiments/run_manifest.csv.in_flight.json" ]] || { echo "STOP: active collection latch exists"; exit 1; }
for f in "$REPORT" "$LOG" "$PIDFILE"; do
  [[ ! -e "$f" ]] || { echo "STOP: output already exists; refusing overwrite: $f"; exit 1; }
done
mkdir -p "$ROOT/New_Datasets/scripts" "$ROOT/New_Datasets/reports"
TMP="$SCRIPT.download.$$"
trap 'rm -f "$TMP"' EXIT
DOWNLOADED=0
for attempt in {1..6}; do
  rm -f "$TMP"
  if wget --timeout=20 --tries=1 -O "$TMP" "$URL" \
    && [[ -s "$TMP" ]] \
    && "$PY" -c 'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))' "$TMP"; then
    mv "$TMP" "$SCRIPT"
    DOWNLOADED=1
    break
  fi
  rm -f "$TMP"
  echo "Download attempt $attempt/6 failed; retrying."
  sleep $((attempt*2))
done
[[ "$DOWNLOADED" -eq 1 ]] || { echo "STOP: could not download/validate script; no model fitting started."; exit 1; }
"$PY" -c 'import numpy,pandas,sklearn,xgboost; print("PASS: required ML dependencies available")'
nohup "$PY" -u "$SCRIPT" --project-root "$ROOT" --output "$REPORT" > "$LOG" 2>&1 < /dev/null &
PID=$!
printf '%s\n' "$PID" > "$PIDFILE"
echo "Started development-only mitigation diagnostics."
echo "PID: $PID"
echo "Log: $LOG"
echo "Report (created on success): $REPORT"
echo "No new traffic collected; no final-test data or frozen models will be changed."
