# IOT-API-Merge coverage and conflict policy

`IOT-API-Merge` has both source tips as parents. The API branch is the active
runtime baseline because it contains the newer runtime API, forwarding-flow
lifecycle, firewall/SSH state, and service failover reporting.

All IoT-only files are retained in their original paths. Where both branches
changed the same path and a safe semantic combination could not be proven from
static inspection, the active API file is retained and the exact IoT and API
versions are preserved under `source_snapshots/`. `merge_manifest.json` records
both source commits and every source-tree blob. `tests/test_merge_branch_coverage.py`
prevents deletion or mutation of those preserved implementations.

This is intentionally an auditable merge, not a claim that every conflicting
runtime implementation is simultaneously wired into one process. The review
must still validate service failover, Shadow verdict enforcement, and link
failure behavior end-to-end on the Mininet/Ryu VM.
