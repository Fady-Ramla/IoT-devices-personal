# IOT-API-Merge review

## Source branches and merge identity

- API source: `api-runtime-latest-20261111`
- IoT source: `iot-simulator-integration`
- Merge commit: `64bd5d96cd71cdb1ef5be9fe83ff581ec3a379a4`
- Parents: `c9e2452ff7f86becaf356b55d25b05c59f696124` and `abf2836f4a053b3b8dc772463505f07b190376d9`

## Preservation result

The branch is a real two-parent merge. API-latest is the active runtime baseline because it has the newer runtime API, forwarding-flow lifecycle, firewall/SSH state, and service failover reporting. IoT-only modules, tests, scripts, documentation, and data metadata remain in the merged tree. The 17 shared conflict paths were not silently discarded: exact API and IoT source versions are preserved under `source_snapshots/`, with Git-blob hashes recorded in `merge_manifest.json`.

## Automated checks

- `python3 -m py_compile` passed for the active controller, telemetry, API, Shadow, Mininet, service, and merge-test files.
- All four functions in `tests/test_merge_branch_coverage.py` passed when executed directly. The sandbox did not have `pytest` installed, so a pytest runner result is not claimed.
- The coverage checks verify both source tips, every source-tree path, every preserved conflict blob, and required blocking, unblocking, rerouting, load-balancer, Shadow, health, and telemetry markers.
- No unresolved Git paths remained before commit, and the final published tree has no uncommitted changes.

## Important review limitation

This merge is an auditable preservation merge, not proof of end-to-end Mininet/Ryu interoperability. Shared runtime conflicts use API-latest actively while the exact IoT alternatives remain available as compatibility snapshots. Before production/demo use on the VM, run the existing VLAN, forwarding, Shadow enforcement, load-balancer failover, SSH, and link-isolation tests. In particular, verify the Ryu `POST /shadow/verdict` response body, backend failover for new connections, and load-balancer-process failure redirection.
