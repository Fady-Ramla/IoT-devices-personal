# Final offline Packet/Flow datasets (V3)

Generated from 160 completed independent Mininet runs: 40 per class. Train/validation/final-test are split by run/profile (16/4/20 per class), so no run or profile crosses splits. Packet and flow records share the same run-level split.

Three manifest-failed captures are preserved in the source raw folders and listed in `excluded_failed_runs.csv`; they are excluded from every split. No oversampling, synthetic rows, or exact-row duplication was used. Naturally repeated feature vectors in packet telemetry are retained.

Use `packet_splits/` or `flow_splits/` with the existing `train_models.py`. Keep `test.csv` untouched until final evaluation; do not use it for feature or model selection.
