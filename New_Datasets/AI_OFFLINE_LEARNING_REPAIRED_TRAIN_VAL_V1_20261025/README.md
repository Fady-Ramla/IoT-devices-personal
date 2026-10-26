# Repaired Packet/Flow development candidate

This is a train/validation-only candidate (16 train + 4 validation runs per class). It excludes five original Malicious_POST runs with no observed application POST and keeps verified replacements MP041–MP044 and MP046 exactly once. Accidental second-batch duplicate profiles and failed MP045 attempts are listed in `excluded_runs.csv`.

No test split is included or read. Do not treat validation results from this small split as final test performance. The original V3 package and all source raw files remain untouched.
