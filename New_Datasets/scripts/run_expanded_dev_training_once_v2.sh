#!/usr/bin/env bash
set -euo pipefail
cd "$HOME/Graduation_Project/IoT-devices"

SCRIPT="New_Datasets/scripts/build_train_expanded_dev_once_v2.py"
PLAN="New_Datasets/scripts/collection_plan_expanded_development_160_20261025.csv"
REPLACEMENT="New_Datasets/scripts/collection_plan_replace_failed_expanded_dev_6runs.csv"
LOG="New_Datasets/reports/build_train_expanded_dev_20261026_v2.log"
SCRIPT_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/RcJtRusIhdmnwaDx.py"
PLAN_URL="https://files.manuscdn.com/user_upload_by_module/session_file/310519663095315619/IIUOOiDNmPYtgnTU.csv"

# Do not race an active capture or overwrite logs/artifacts.
if pgrep -af '[R]eal_network_topology_packet_flow_final_v3.py'; then
  echo "STOP: topology capture is still running. Wait for it to finish before building."
  exit 1
fi
if [ -e New_Datasets/experiments/run_manifest.csv.in_flight.json ]; then
  echo "STOP: an in-flight collector latch exists; resolve it before building."
  exit 1
fi
for f in "$REPLACEMENT" "$LOG"; do
  if [ ! -s "$f" ] && [ -e "$f" ]; then
    echo "STOP: empty file already exists; inspect it before continuing: $f"
    exit 1
  fi
done
if [ -e "$LOG" ]; then
  echo "STOP: log already exists; refusing a second run: $LOG"
  exit 1
fi

# Download missing inputs through temporary files, preserving any existing copy.
download_atomic() {
  local dest="$1" url="$2" tmp="${1}.download.$$"
  if [ -s "$dest" ]; then
    echo "Using existing file: $dest"
    return
  fi
  if [ -e "$dest" ]; then
    echo "STOP: destination exists but is empty: $dest"
    exit 1
  fi
  wget --tries=5 --waitretry=2 -O "$tmp" "$url"
  test -s "$tmp" || { echo "STOP: downloaded file is empty: $dest"; exit 1; }
  mv "$tmp" "$dest"
  echo "Downloaded: $dest"
}

download_atomic "$SCRIPT" "$SCRIPT_URL"
download_atomic "$PLAN" "$PLAN_URL"
test -s "$REPLACEMENT" || { echo "STOP: replacement plan missing/empty: $REPLACEMENT"; exit 1; }
test -x ./dataset_env/bin/python || { echo "STOP: dataset_env Python is missing."; exit 1; }

mkdir -p New_Datasets/reports
./dataset_env/bin/python -m py_compile "$SCRIPT"

echo "Expanded development-only build and training starting." 
echo "Input: repaired V2 train/validation (80 runs) + expanded development (160 valid runs)."
echo "Expected output: 240 runs total; 48 train/class and 12 validation/class."
echo "Final-test data will not be opened, scored, or used."

set -o pipefail
PYTHONUNBUFFERED=1 ./dataset_env/bin/python -u "$SCRIPT" \
  --project-root "$PWD" 2>&1 | tee "$LOG"

PKG="New_Datasets/AI_OFFLINE_LEARNING_EXPANDED_DEV_V1_20261026"
(cd "$PKG" && sha256sum -c SHA256SUMS.txt)
echo
echo "=== Training summary ==="
./dataset_env/bin/python - "$PKG/models/final_trainval_20261026/training_summary.json" <<'PY'
import json,sys
p=sys.argv[1]
d=json.load(open(p))
print(d["purpose"])
for level,section in d["levels"].items():
    print("\n"+level.upper())
    for name,m in section["models"].items():
        tr=m["train"]["run_level"];va=m["validation"]["run_level"]
        print(f"{name}: train acc/F1={tr['accuracy']:.4f}/{tr['f1_macro']:.4f}; validation acc/F1={va['accuracy']:.4f}/{va['f1_macro']:.4f}")
PY

echo "PIPELINE COMPLETE. Log: $LOG"
echo "Development package: $PKG"
