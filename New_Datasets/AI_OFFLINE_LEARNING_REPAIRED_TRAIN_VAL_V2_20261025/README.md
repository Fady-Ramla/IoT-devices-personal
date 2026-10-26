# Repaired Packet/Flow development candidate V2

Train/validation only: 16 train and 4 validation runs per class. This build excludes five Malicious_POST captures without observed POST telemetry and eight Normal HTTP captures whose client commands timed out. It includes five previously verified Malicious_POST replacements and eight new Normal replacements with matching application telemetry. Duplicate replacement attempts are excluded.

No final_test files were included or read. Original dataset packages and raw source files remain untouched. Validation is for model development only, not final performance claims.
