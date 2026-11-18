#!/usr/bin/env bash
set -euo pipefail

PROJECT="${TRUSTFLOW_PROJECT:-$HOME/Graduation_Project/IoT-devices}"
BRANCH_WT="${TRUSTFLOW_BRANCH_WT:-/tmp/Final_OFFLINE_CSV-worktree}"
DATA="$PROJECT/New_Datasets/AI_OFFLINE_LEARNING_V3"
SOURCE="$BRANCH_WT/New_Datasets"
DEST="${1:-$HOME/Downloads/AI_OFFLINE_LEARNING_V3_AItrack_20261118.tar.gz}"

CSV="$DATA/packetin_window_4class_22features.csv"
SPLITS="$DATA/packet_splits"
CONFIG="$SOURCE/config/model_features_packetin_22_v1.json"
MANIFEST="$PROJECT/New_Datasets/experiments/run_manifest.csv"

required_files=(
  "$CSV"
  "$SPLITS/train.csv"
  "$SPLITS/validation.csv"
  "$SPLITS/test.csv"
  "$CONFIG"
  "$MANIFEST"
  "$SOURCE/reports/AI_OFFLINE_LEARNING_V3_MODEL_COMPARISON.md"
  "$DATA/validation_rf_xgb_et_22_v1.json"
  "$DATA/validation_hgb_22_v1.json"
  "$DATA/validation_ensemble_22_v1.json"
  "$SOURCE/scripts/build_packetin_window_22features_v1.py"
  "$SOURCE/scripts/split_by_run.py"
  "$SOURCE/scripts/compare_rf_xgb_extratrees_packetin22_validation_only.py"
  "$SOURCE/scripts/tune_histgradientboosting_packetin22_validation_only.py"
  "$SOURCE/scripts/compare_four_model_ensemble_packetin22_validation_only.py"
)

for f in "${required_files[@]}"; do
  if [[ ! -f "$f" ]]; then
    echo "STOP: required delivery file is missing: $f" >&2
    exit 1
  fi
done
if [[ -e "$DEST" ]]; then
  echo "STOP: refusing to overwrite existing archive: $DEST" >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/TrustFlow_AI_OFFLINE_LEARNING_V3"
mkdir -p "$ROOT/dataset/splits" "$ROOT/config" "$ROOT/docs" "$ROOT/reports" "$ROOT/scripts"

cp "$CSV" "$ROOT/dataset/"
cp "$SPLITS/train.csv" "$SPLITS/validation.csv" "$SPLITS/test.csv" "$ROOT/dataset/splits/"
cp "$CONFIG" "$ROOT/config/"
cp "$SOURCE/reports/AI_OFFLINE_LEARNING_V3_MODEL_COMPARISON.md" "$ROOT/docs/"
cp "$DATA/validation_rf_xgb_et_22_v1.json" \
   "$DATA/validation_hgb_22_v1.json" \
   "$DATA/validation_ensemble_22_v1.json" "$ROOT/reports/"
cp "$SOURCE/scripts/build_packetin_window_22features_v1.py" \
   "$SOURCE/scripts/split_by_run.py" \
   "$SOURCE/scripts/compare_rf_xgb_extratrees_packetin22_validation_only.py" \
   "$SOURCE/scripts/tune_histgradientboosting_packetin22_validation_only.py" \
   "$SOURCE/scripts/compare_four_model_ensemble_packetin22_validation_only.py" \
   "$ROOT/scripts/"

cat > "$ROOT/README.txt" <<'EOF'
TrustFlow AI Offline Learning V3 — AI Track delivery

Contents
- dataset/packetin_window_4class_22features.csv: full 4-class dataset
- dataset/splits/: run-disjoint train, validation, and test CSVs
- config/: exact 22-feature Ryu packetin_window contract
- docs/: detailed model comparison and reproduction notes
- reports/: Validation-only comparisons for RF/XGBoost/ExtraTrees, HGB, and ensembles
- scripts/: dataset builder, run splitter, and validation-only model scripts
- SHA256SUMS: integrity hashes for the delivered files

Target: label. Keep run_id for grouping/aggregation; do not use run_id or
observation_id as model features. The model input must use exactly the 22 fields
in config/model_features_packetin_22_v1.json, with the categorical encodings
and run-based weighting described in the model comparison report.

Important evaluation note: run-level splits prevent run_id leakage. The current
V3 model scripts did not read/score test.csv. The Test split was evaluated in
older 20-feature development experiments, so it is not a pristine final holdout.
Generations 550-709 are excluded from this dataset. Treat reported Validation
scores as development results, not guaranteed deployment performance.

The model-comparison scripts save metrics, not fitted models. Fitting a final
model and saving deployable artifacts must be performed and documented separately.
EOF

python3 - "$ROOT" "$CONFIG" "$MANIFEST" <<'PY'
import csv
import json
import sys
from pathlib import Path

root, config_path, manifest_path = map(Path, sys.argv[1:])
config = json.loads(config_path.read_text(encoding="utf-8"))
features = config["flow_features"]
expected = ["run_id", "observation_id", *features, "label"]

with manifest_path.open(newline="", encoding="utf-8-sig") as f:
    generations = {r["run_id"].strip(): int(r["generation"]) for r in csv.DictReader(f)}

full_path = root / "dataset/packetin_window_4class_22features.csv"
full_ids, full_runs, full_labels = set(), set(), set()
full_rows = 0
with full_path.open(newline="", encoding="utf-8-sig") as f:
    reader = csv.DictReader(f)
    if reader.fieldnames != expected:
        raise SystemExit("STOP: full CSV header/order differs from the exact 22-feature contract")
    for row in reader:
        full_rows += 1
        oid, rid = row["observation_id"].strip(), row["run_id"].strip()
        if not oid or oid in full_ids:
            raise SystemExit("STOP: blank or duplicate observation_id in full CSV")
        if not rid or not row["label"].strip():
            raise SystemExit("STOP: blank run_id or label in full CSV")
        if any(not (row.get(col) or "").strip() for col in features):
            raise SystemExit(f"STOP: blank feature in observation {oid}")
        if row["source"] != "packetin_window":
            raise SystemExit(f"STOP: unexpected source for observation {oid}")
        if rid not in generations:
            raise SystemExit(f"STOP: run_id missing from manifest: {rid}")
        if 550 <= generations[rid] <= 709:
            raise SystemExit(f"STOP: holdout-generation row found in full CSV: {rid}")
        full_ids.add(oid); full_runs.add(rid); full_labels.add(row["label"].strip())
if full_rows < 100_000 or len(features) != 22:
    raise SystemExit("STOP: full dataset row/feature minimum was not met")
if full_labels != set(config["labels"]):
    raise SystemExit(f"STOP: unexpected class set: {sorted(full_labels)}")

split_ids, split_runs = {}, {}
for name in ("train", "validation", "test"):
    path = root / "dataset/splits" / f"{name}.csv"
    ids, runs, seen_labels = set(), set(), {}
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != expected:
            raise SystemExit(f"STOP: {name} CSV header/order differs from contract")
        for row in reader:
            oid, rid = row["observation_id"].strip(), row["run_id"].strip()
            if not oid or oid in ids:
                raise SystemExit(f"STOP: blank/duplicate observation_id in {name}")
            if any(not (row.get(col) or "").strip() for col in features):
                raise SystemExit(f"STOP: blank feature in {name} row {oid}")
            if row["source"] != "packetin_window":
                raise SystemExit(f"STOP: unexpected source in {name}")
            if rid in seen_labels and seen_labels[rid] != row["label"]:
                raise SystemExit(f"STOP: conflicting labels for run {rid} in {name}")
            seen_labels[rid] = row["label"]
            if rid not in generations or 550 <= generations[rid] <= 709:
                raise SystemExit(f"STOP: unknown/holdout generation run in {name}: {rid}")
            ids.add(oid); runs.add(rid)
    split_ids[name], split_runs[name] = ids, runs

if split_ids["train"] & split_ids["validation"] or split_ids["train"] & split_ids["test"] or split_ids["validation"] & split_ids["test"]:
    raise SystemExit("STOP: observation_id overlap across splits")
if split_runs["train"] & split_runs["validation"] or split_runs["train"] & split_runs["test"] or split_runs["validation"] & split_runs["test"]:
    raise SystemExit("STOP: run_id leakage across splits")
if set().union(*split_ids.values()) != full_ids:
    raise SystemExit("STOP: split IDs do not exactly cover the full CSV")
if sum(map(len, split_ids.values())) != full_rows:
    raise SystemExit("STOP: split row counts do not sum to the full dataset")

for name in ("validation_rf_xgb_et_22_v1.json", "validation_hgb_22_v1.json", "validation_ensemble_22_v1.json"):
    report = json.loads((root / "reports" / name).read_text(encoding="utf-8"))
    if report.get("test_used") is not False:
        raise SystemExit(f"STOP: report does not confirm test_used=false: {name}")

print(f"PACKAGE DATA QA PASS: rows={full_rows}; features={len(features)}; unique IDs={len(full_ids)}; runs={len(full_runs)}")
print("Train/validation/test are run-disjoint, cover all rows, and exclude generations 550-709.")
PY

(
  cd "$STAGE"
  find TrustFlow_AI_OFFLINE_LEARNING_V3 -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum > TrustFlow_AI_OFFLINE_LEARNING_V3/SHA256SUMS
  sha256sum -c TrustFlow_AI_OFFLINE_LEARNING_V3/SHA256SUMS >/dev/null
)

tar -czf "$DEST" -C "$STAGE" TrustFlow_AI_OFFLINE_LEARNING_V3

tar -tzf "$DEST" >/dev/null
printf 'DELIVERY ARCHIVE CREATED\nfile=%s\n' "$DEST"
du -h "$DEST"
sha256sum "$DEST"
