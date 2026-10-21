PLAN ONLY — this script did not start Mininet, Ryu, or any traffic.
Seed: 20261019
Runs per class: 20
Total planned runs: 60
Excluded already completed pilot commands: 3

This plan is for the current run_id-enabled capture code. It contains unique commands and excludes the exact pilot configurations.
Start Ryu from a NEW, empty raw-data directory with the current packet/flow CSV schema; keep the six-switch topology connected.
SYN PPS and scan completion are bounded requests/caps; actual timing/rates may differ. Port scans have a 20-second maximum wall-clock cap.
Normal traffic is approximately one HTTP(S) request per second; this plan varies client/service/target/duration, not its request rate.
The plan balances run configurations, not row counts. Do not oversample or edit raw CSVs; Person 3 should review run-level distribution before any split.
After collection, run build_failed_runs_report.py to fill failed_runs_report.csv from failed entries in the manifest.
