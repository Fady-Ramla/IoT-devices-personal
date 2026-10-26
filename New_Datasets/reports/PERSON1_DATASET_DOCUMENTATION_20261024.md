# TrustFlow — Person 1 Dataset Pipeline Documentation

**Date:** 2026-10-24  
**Scope:** Fresh IoT traffic collection, data quality, canonical assembly, run-grouped offline splits, and RF/XGBoost baselines.  
**Environment:** User's VirtualBox VM, Mininet/Ryu 38-host topology; all collection and model execution were performed on that VM.  
**Status:** Dataset assembly and split audit PASS. Baselines are exploratory, not production validation.

## 1. Executive summary

A fresh, run-scoped dataset was assembled from the 38-host, five-VLAN Mininet/Ryu environment. The collection manifest contains 15 usable runs for each of four labels: `Normal`, `Malicious_POST`, `Port_Scan`, and `SYN_Flood`. Two completed-but-invalid runs were explicitly excluded; failed runs were skipped by the builder. Canonical packet and flow datasets were built from the per-run raw CSVs, then split by `run_id` to prevent run-level leakage.

Final candidate sizes:

| Level | Canonical observations | Usable runs | Runs per label |
|---|---:|---:|---:|
| Packet | 13,968 | 60 | 15 |
| Flow | 86 | 60 | 15 |

Both Random Forest and XGBoost were trained for flow and packet baselines. Packet training used equal total sample weight per training run so a high-volume run would not dominate solely because it generated more packets.

## 2. Scope and operating requirements

- Fresh collection data only; archived/legacy data is not mixed into the assembled dataset.
- The dataset is scoped to the 38-host, five-VLAN lab topology.
- Network enforcement remains fail-closed and device response scope is `BLOCK_DEVICE`; quarantine is out of scope.
- Raw per-run CSVs and the manifest remain the source of truth. Candidate/final files are derived artifacts.
- Offline model features must match what the online inference path can actually provide. Do not add a feature offline unless the same feature is available at inference time.

## 3. Collection and manifest accounting

The final candidate builder assembled **60 usable runs** with **15 runs per label**. The manifest also includes unsuccessful/invalid history that was not used as training data. In particular:

1. Failed runs are skipped based on manifest status.
2. `e4461f40-2bf3-4153-b8da-9c11ba098b1b` was excluded because both raw files were empty and the manifest notes a curl connection timeout.
3. `3a761d08-16fd-431e-ba5b-38a21e725dab` was excluded because its raw endpoint pair did not match the manifest source/target; the recorded hping output reported 347 packets sent and 0 received.

The exclusion list is recorded in `dataset_quality_exclusions_20261024.csv`; do not delete or rewrite it. Three failed runs were observed in the manifest during QA; they were not included in the candidate datasets.

## 4. Canonical assembly and quality checks

The candidate builder:

- reads per-run CSVs and the run manifest;
- skips non-completed runs and explicit quality exclusions;
- requires fresh run identity and unique `observation_id` values;
- filters observations to the registered run time window;
- keeps packet observations only for the manifest source-to-target direction at the source host's access switch;
- keeps flow observations only from the collector's `packetin_window` source at the source access switch, excluding per-switch operational flow counters as duplicate model examples;
- normalizes protocol values and applies labels from the manifest;
- preserves `run_id` and `observation_id` in each derived row.

Assembly outputs:

- `balanced_candidate_packet_qc_v2.csv`: 13,968 canonical packet rows.
- `balanced_candidate_flow_qc_v2.csv`: 86 canonical flow rows.

Final candidate audit passed:

- 60 distinct usable runs per level; 15 distinct runs per label;
- identical run-ID sets in packet and flow datasets;
- no duplicate observation IDs;
- no run assigned multiple labels;
- no missing identity/label values;
- all `label_status` values matched.

**Balance definition:** the collection is balanced by number of runs per label, not by number of packet rows. Packet row counts are Normal 1,733; Malicious_POST 2,143; Port_Scan 2,632; SYN_Flood 7,460. These differences are expected from different traffic volumes and are why the packet trainer weights each run equally.

## 5. Run-grouped split

The split script `split_by_run.py` was used with seed 42 and proportions 70%/15%/15%. It assigns complete runs to one partition and never splits individual observations from the same run across partitions.

Artifacts live at:

`New_Datasets/final/splits_20261024_v1/{packet,flow}/{train,validation,test}.csv`

Each label has 10 train runs, 2 validation runs, and 3 test runs:

| Split | Runs | Runs per label | Packet rows | Flow rows |
|---|---:|---:|---:|---:|
| Train | 40 | 10 | 10,197 | 57 |
| Validation | 8 | 2 | 1,763 | 13 |
| Test | 12 | 3 | 2,008 | 16 |

Split audit passed: no `run_id` overlap between train/validation/test, the same run IDs are used in packet and flow for each partition, and all labels are represented in every split.

## 6. Final dataset artifacts

Final files, checksummed on the VM:

- `New_Datasets/final/packet_dataset_20261024_v1.csv`
- `New_Datasets/final/flow_dataset_20261024_v1.csv`
- `New_Datasets/final/run_manifest_snapshot_20261024.csv`
- `New_Datasets/final/dataset_quality_exclusions_20261024.csv`
- `New_Datasets/final/build_dataset_candidate.py`
- `New_Datasets/final/SHA256SUMS_20261024_v1.txt`

All recorded checksum validations returned `OK`. Treat these as immutable versioned artifacts. If the dataset changes, create a new version and new checksums instead of overwriting v1.

## 7. Offline model baselines

### 7.1 Flow baseline

Saved under `New_Datasets/final/models/flow_baseline_20261024_v2/` with Random Forest and XGBoost model artifacts and `training_metrics.json`.

Row-level results:

| Model | Validation accuracy | Validation macro-F1 | Test accuracy | Test macro-F1 |
|---|---:|---:|---:|---:|
| Random Forest | 0.8462 | 0.8333 | 0.8750 | 0.8875 |
| XGBoost | 0.9231 | 0.9143 | 0.8750 | 0.8875 |

A separate run-level evaluation aggregates mean class probabilities across observations per run. Both models classified 8/8 validation runs and 12/12 test runs correctly. These estimates are very uncertain because validation/test contain only 8/12 runs total.

### 7.2 Packet baseline with equal run contribution

Saved under `New_Datasets/final/models/packet_run_balanced_20261024_v1/` with Random Forest and XGBoost model artifacts and row/run-level metrics.

| Model | Validation run macro-F1 | Test row macro-F1 | Test run accuracy | Test run macro-F1 |
|---|---:|---:|---:|---:|
| Random Forest | 0.6000 | 0.8046 | 0.7500 | 0.7429 |
| XGBoost | 0.6000 | 0.8381 | 0.8333 | 0.8333 |

Validation errors for both packet models were confined to confusion between `Normal` and `Malicious_POST`; `Port_Scan` and `SYN_Flood` validation runs were classified correctly. The test split is small (12 runs), so do not select or tune a model solely on test results. The packet values are baselines for this split, not a generalization guarantee.

## 8. Feature limitation and AI-track handoff

The current packet feature set contains protocol, ports, packet length, TCP flags, ICMP type, and ARP operation. It does **not** encode HTTP method, route, or application semantics. On the validation data, Normal and Malicious_POST traffic both used TCP destination port 5000 and had nearly identical median packet length and SYN/ACK fractions. Thus packet headers alone do not reliably distinguish these application-level classes in this dataset.

Before online inference, Person 1 and the AI/online track must agree on feature parity and definitions:

1. Confirm protocol normalization (e.g., TCP/UDP/ICMP numeric-to-name mapping) is identical offline and online.
2. Define `syn_ack_ratio` precisely, including denominator, zero-denominator behavior, and aggregation window.
3. Decide whether an HTTP-aware feature (e.g., method class or endpoint category) is available at the online inference point. If TLS is terminated before the telemetry source, packet headers alone cannot reveal method/path; instrument only the authorized API/TLS termination layer and avoid storing sensitive request bodies.
4. Freeze a shared feature schema/version between dataset, offline model, and online API before deployment.

No production/online model should be enabled based only on these small baselines. Do not train with fields unavailable to online inference, and do not use test data to tune model parameters.

## 9. Recommended next steps

1. Share this documentation, `model_features.json`, and the saved model metrics with the AI/online inference teammate.
2. Agree and document protocol normalization and the exact `syn_ack_ratio` formula; decide whether application-level HTTP telemetry is in scope and available at inference.
3. Update and version a single feature contract only after the online source is confirmed. If features change, rebuild the dataset/model as a new version and keep v1 intact.
4. For a stronger generalization estimate, collect additional independent runs (especially Normal and Malicious_POST under varied legitimate services/traffic patterns) and preserve the run-grouped split discipline. Do not manufacture rows or randomly re-split rows.
5. After the feature contract is frozen, run a new group-aware evaluation and report per-run metrics and confusion matrices; keep test data untouched until final evaluation.

## 10. Reproducibility notes

- Final builder command and QA inputs are recorded in the VM's project tree; the versioned candidates, manifest snapshot, exclusions, and checksum file identify the exact dataset release.
- Split seed: 42; train/validation/test: 0.70/0.15/0.15 by `run_id` within each label.
- Model seeds: 42.
- Flow baseline used the dual-model trainer available at its run time. Packet v1 used the later trainer with equal total sample weight per training `run_id` and saved row-level and run-level metrics.
- Keep archived/legacy raw files separate; do not point the candidate builder at them.
