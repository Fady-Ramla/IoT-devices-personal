# Offline Training Workflow

This workflow is independent of the Ryu controller and does not call the AI API or the Security API.

## 1. Register completed runs

Register every experiment in `experiments/run_manifest.csv`. The label is ground truth metadata and is never inferred from traffic values.

```bash
cd /home/ubuntu/secureiot_final/New_Datasets
python3 scripts/register_run.py \
  --run-id normal_0001 --run-type normal \
  --start-time 2026-10-18T21:30:00+00:00 \
  --end-time 2026-10-18T21:31:00+00:00 \
  --status completed
```

For an attack, include `--label` and the experiment metadata. Use one independent run per scenario.

## 2. Store raw files per run

Rename or copy each raw output so the filename stem is the registered `run_id`:

```text
raw/flow/normal_0001.csv
raw/flow/syn_0001.csv
raw/packet/normal_0001.csv
raw/packet/syn_0001.csv
```

Do not combine runs before the build step.

## 3. Build the labeled offline dataset

```bash
python3 scripts/build_dataset.py \
  --level flow \
  --input-dir raw/flow \
  --output processed/flow_dataset.csv

python3 scripts/build_dataset.py \
  --level packet \
  --input-dir raw/packet \
  --output processed/packet_dataset.csv
```

The script adds `run_id`, `observation_id`, `label`, and `label_status`. These are metadata/targets, not model features.

## 4. Split by run, never by row

```bash
python3 scripts/split_by_run.py \
  --input processed/flow_dataset.csv \
  --output-dir splits/flow
```

The same command can be used for `packet_dataset.csv`. A run cannot appear in more than one split.

## 5. Train offline models

Install dependencies in the training environment, not in the Ryu runtime:

```bash
python3 -m pip install pandas numpy scikit-learn joblib xgboost
```

Then:

```bash
python3 scripts/train_models.py \
  --level flow \
  --split-dir splits/flow \
  --output-dir models/flow
```

Random Forest is mandatory. XGBoost is trained when installed. Metrics and confusion matrices are written to the model directory.

## Leakage rules

Do not train on `run_id`, timestamps, IPs, MACs, switch IDs, input ports, labels, trust scores, decisions, blocking results, firewall outcomes, or reroute outcomes. The authoritative list is `config/model_features.json`.

## Important limitation in v1

FlowStats alone does not contain TCP flags. Therefore the first flow build sets `syn_count`, `ack_count`, `rst_count`, `fin_count`, and related flow-window features to zero. These fields must be populated by a separately validated packet-window aggregation before the final model comparison. Do not pretend that zero means “no SYN” without checking the capture source.
