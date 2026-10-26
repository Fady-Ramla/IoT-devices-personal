# AI Offline Learning V2 — Final package

This package preserves the verified, existing train/validation/test splits without reshuffling. Packet and flow use the same run_id assignment. All observations from the balanced QC candidate CSVs are included exactly once.

## Contents
- `packet_splits/{train,validation,test}.csv`
- `flow_splits/{train,validation,test}.csv`
- `config/model_features.json`
- `run_split_manifest.csv`
- `qc_report.json`
- `SHA256SUMS.txt`

## Important limits
No exact duplicate rows or observation IDs were found in the source candidates, and run IDs do not cross train/validation/test. Similar feature vectors are retained: different real observations can share the same selected features. This is not proof of zero bias. Packet rows are imbalanced even though each label has 15 runs; report macro-F1, balanced accuracy, per-class precision/recall, and confusion matrix. The flow data has only 86 rows, so treat its metrics as exploratory.

The 55-run collection report does not match these 60-run balanced candidates and was not merged. Existing model metrics were not copied; retrain and report metrics for the exact splits if needed.
