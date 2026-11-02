# SecureIoT Mininet–Ryu–Dashboard Integration

## What the integration does

In interactive demo mode, the IoT simulator processes on Mininet hosts `h5`–`h16` send their existing JSON envelopes to the real Flask Web/API on `h2:5000`. The receiver requires a per-launch random bearer token and a matching source address in `10.10.10.5`–`10.10.10.16`, validates and stores each reading in a shared SQLite database, and returns HTTP 202. The token is generated in memory by the topology launcher and is not printed or written to source files. The Ryu runtime API reads that same database for `/api/iot/devices`, `/api/iot/sensors`, and `/api/iot/telemetry`. The database is shared on the VM filesystem; no second Ryu listener is opened inside Mininet and no dataset collector is involved.

The Ryu dashboard API derives host/switch/VLAN/link inventory from the branch’s active `mininet/vlan_config_38host.py`. Its “traffic active” calculation now reads the actual inter-switch PortStats samples held by `TopologyMonitor` rather than a nonexistent `host_port_stats_previous` field. Operational endpoints require a bearer token. CORS is disabled unless one exact `SECUREIOT_ALLOWED_ORIGIN` is configured; wildcard CORS is not used.

## Start the Ryu controller/API

From the project root, create a strong token in a private terminal and keep it out of source control and screenshots. Use the same token for the dashboard’s server-side API client; do not put a long-lived secret in browser JavaScript.

```bash
cd ~/Graduation_Project/IoT-devices
umask 077
printf 'export SECUREIOT_API_TOKEN=%q\n' "$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')" > ~/.secureiot_api_token
chmod 600 ~/.secureiot_api_token
source ~/.secureiot_api_token
export SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3
# Set this to the exact browser origin only when it is known, e.g. the dashboard URL.
export SECUREIOT_ALLOWED_ORIGIN="https://YOUR-DASHBOARD-ORIGIN"
sudo --preserve-env=SECUREIOT_API_TOKEN,SECUREIOT_IOT_DB,SECUREIOT_ALLOWED_ORIGIN \
  ./ryu_env/bin/ryu-manager --wsapi-host 127.0.0.1 --wsapi-port 8080 \
  topology_monitor.py traffic_monitor_merged.py resilience_engine.py runtime_network_api.py
```

If the API is started by a service manager, define these three variables in that service’s protected environment instead. Keep Ryu bound to loopback; a dashboard tunnel should target `127.0.0.1:8080`, not bind the controller to every network interface.

## Start the interactive Mininet demo

In a second terminal, using the same VM and project root:

```bash
cd ~/Graduation_Project/IoT-devices
source ~/.secureiot_api_token
export SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3
export START_DEMO_SERVICES=1
export START_IOT_SIMULATORS=1
sudo --preserve-env=SECUREIOT_API_TOKEN,SECUREIOT_IOT_DB,START_DEMO_SERVICES,START_IOT_SIMULATORS \
  python3 mininet/Real_network_topology.py
```

This is the interactive demo topology, not the dataset batch collector. Do not set `SECUREIOT_BATCH_PLAN` for this test. The real Flask API runs on `h2:5000`; `h18` remains a demo backup stub. The simulated devices send periodically, and their per-host logs are `/tmp/secureiot-h5-iot.log` through `/tmp/secureiot-h16-iot.log`.

At the `mininet>` prompt, run:

```text
iot_test
```

A passing result is printed only after a unique probe originates at `h5`, receives HTTP 202 from `h2:5000`, and is then found by an authenticated read from the local Ryu endpoint. The test adds one clearly marked probe reading to the live demo database; it does not touch any training or final-test data.

## Dashboard access and API contract

Operational API calls use `Authorization: Bearer <SECUREIOT_API_TOKEN>`. `/health` and its legacy alias `/runtime/health` are unauthenticated liveness endpoints; operational/data routes require the token. Use the exact dashboard origin in `SECUREIOT_ALLOWED_ORIGIN`; restart Ryu after changing it. Example authenticated read:

```bash
curl -H "Authorization: Bearer $SECUREIOT_API_TOKEN" \
  http://127.0.0.1:8080/api/iot/telemetry?device_id=h5&limit=10
```

The checked-out `IoT-devices-personal` repository currently contains the network/controller and Mininet components but no discoverable frontend package or dashboard-origin configuration. Therefore, this integration supplies and tests the network-side API contract; a separate dashboard repository or its server-side proxy configuration is still needed to wire the user-facing WebTrack dashboard without exposing the bearer token in the browser bundle. Do not open a public tunnel until authentication is enabled and the tunnel is protected; keep internal controller action and dataset routes private.

The read-only API smoke test is `test_network_api.sh`. It accepts `API_TOKEN` and `BASE_URL`; it derives `EXPECTED_LINKS` from the checked-out topology configuration (12 on `iot-simulator-integration`, 11 on `core-s3-trunk-test`). It does not POST telemetry through a public tunnel. The end-to-end write test is the Mininet `iot_test` command above.

## Data boundaries and known limitations

The live demo bridge uses `/var/lib/secureiot/iot-telemetry.sqlite3` and does not read from or write to `New_Datasets`, training/validation splits, model artifacts, or the sealed 160-run final holdout. The `iot_test` probe creates one clearly marked row only in the live telemetry database. Do not merge demo probes into model datasets or count them as evaluation runs.

Some prior replacement-run profiles reused `h5` as a shared attacker/source host. Those observations are not independent host coverage; when analyzing or reporting the replacement runs, group by run/profile and state this shared-host limitation rather than treating the reused `h5` identity as additional source-host diversity. This API integration does not modify those records or remedy that dataset limitation.
