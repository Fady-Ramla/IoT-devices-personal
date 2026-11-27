# TrustFlow HTTPS-balanced collection v2

## Scope and validation

This package contains a candidate Mininet launcher, a one-run HTTPS canary, and a 41-run follow-up plan. The launcher was syntax-compiled and its attack builders, normal HTTPS command, plan grammar, run bounds, and target class totals were checked in the sandbox. It has **not** been run on the user's VirtualBox VM; VM verification is still required.

The manifest snapshot provided by the user had 18 completed rows: Normal 6, SYN_Flood 4, Port_Scan 4, Malicious_POST 4. The previous 55-row batch stopped at row 14; do not rerun that plan. The failed run must remain failed and excluded.

After the one-run HTTPS canary succeeds, the 41-row plan adds Normal 8 and 11 runs for each attack label, reaching 15 completed runs per label. Normal, SYN_Flood, and Port_Scan additions cover `h2:5000` and `h3:443` in an 8/7 split when combined with existing runs. Malicious_POST remains on the real `/login` API at `h2:5000`. Rate units are class-specific (requests/sec vs packets/sec vs scan packet ceiling) and should not be compared as one common scale.

## Install on the VM

1. Leave Ryu running. At the current `mininet>` prompt, type `exit` to stop the manual HTTPS smoke-test topology. Do not start another collection while installing.
2. Download the files and place them in the indicated project locations. Back up the active launcher before replacement:

```bash
cd ~/Graduation_Project/IoT-devices
cp -a mininet/Real_network_topology.py \
  "mininet/Real_network_topology.py.before_https_balance_$(date +%Y%m%d_%H%M%S)"
cp ~/Downloads/Real_network_topology_balanced_candidate.py mininet/Real_network_topology.py
cp ~/Downloads/collection_plan_https_canary.csv New_Datasets/scripts/
cp ~/Downloads/collection_plan_balanced_services_20261024_v2.csv New_Datasets/scripts/
python3 -m py_compile mininet/Real_network_topology.py
```

## Canary first

Confirm there is no in-flight latch, then execute only the HTTPS canary:

```bash
cd ~/Graduation_Project/IoT-devices
if [ -e New_Datasets/experiments/run_manifest.csv.in_flight.json ]; then
  echo "STOP: in-flight latch exists"
else
  unset START_DEMO_SERVICES START_IOT_SIMULATORS
  sudo -E env SECUREIOT_BATCH_PLAN="$PWD/New_Datasets/scripts/collection_plan_https_canary.csv" \
    python3 mininet/Real_network_topology.py
fi
```

Proceed only if the launcher reports run status `completed` and logs that the real HTTPS service is ready from h5. If it fails, stop and inspect; do not start the 41-row plan.

## Follow-up plan

After canary success, stop Ryu with Ctrl-C and restart it in `ryu_env` because a completed run leaves the collector state as `drained`, while a new launcher startup checks for `idle`. Verify the in-flight latch is absent. Then run:

```bash
cd ~/Graduation_Project/IoT-devices
unset START_DEMO_SERVICES START_IOT_SIMULATORS
sudo -E env SECUREIOT_BATCH_PLAN="$PWD/New_Datasets/scripts/collection_plan_balanced_services_20261024_v2.csv" \
  python3 mininet/Real_network_topology.py
```

This plan is fail-closed: a run failure stops the batch. Do not clear a latch manually. After the batch, audit manifest statuses, raw packet/flow identity, labels, and per-run quality before dataset assembly.
