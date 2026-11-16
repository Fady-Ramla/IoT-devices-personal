# SecureIoT IoT telemetry and WebTrack contract GET access

This runbook follows `SECUREIOT_NETWORK_API_CONTRACT_FINAL` and uses its individual accepted endpoints. `/dashboard/snapshot` is not in that contract and is not exposed. In the current IoT integration branch, simulators on h5-h16 send authenticated POSTs to the private Web/API on h2:5000; Flask stores accepted samples in shared SQLite; Ryu exposes that data through contract GET endpoints. WebTrack uses public GET only. A dashboard GET reads the latest stored samples but does not itself generate or ingest telemetry.

## Data flow

```text
IoT hosts h5-h16
  authenticated POST /api/iot/telemetry (private Mininet path)
              |
              v
Web/API server h2:5000
  validates and accepts simulator readings (HTTP 202)
              |
              | SQLite write
              v
/var/lib/secureiot/iot-telemetry.sqlite3
              ^
              | same shared DB file
Ryu runtime API :8080 (accepted contract GET routes)
              ^
              | explicit contract GET allowlist; private API token upstream
Read-only WebTrack gateway :8090 <- ngrok tunnel
              ^
              | public HTTPS GET (no client token)
WebTrack backend
```

SQLite is shared because Flask in Mininet's `h2` namespace and Ryu run on the same VM filesystem. SQLite WAL and transactions allow both processes to read/write the same database without exposing another database port. Data persists across dashboard requests; the dashboard calls the contract's individual GET routes. No aggregate snapshot route is part of the contract.

## Start configuration

Use the IoT branch's demo flags and leave external telemetry delivery URLs unset. Simulator ingestion must stay on the private h2:5000 endpoint; never point it at ngrok.

```bash
export START_DEMO_SERVICES=1
export START_IOT_SIMULATORS=1
export IOT_POLLING_ENABLED=0
export SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3
unset IOT_TELEMETRY_GET_URL IOT_TELEMETRY_POST_URL
```

Start Ryu and the read-only gateway/ngrok services, then start Mininet from the intended branch. Do not run the known-broken `iot_test` CLI command; it can tear down Mininet before completing its check.

## Verify simulator ingestion and local persistence

From the Mininet prompt, check the private Web/API health and inspect the h16 simulator and Web/API logs:

```text
h2 curl --noproxy '*' -fsS http://127.0.0.1:5000/health
h16 tail -n 15 /tmp/secureiot-h16-iot.log
h2 tail -n 30 /tmp/web_api_h2_iot_live.log
```

The simulator log should report `telemetry sent ... http_status=202`; Flask persists accepted samples. On the VM, inspect SQLite without changing it:

```bash
sqlite3 /var/lib/secureiot/iot-telemetry.sqlite3 \
  'SELECT device_id, device_role, timestamp, sequence, readings_json FROM iot_telemetry ORDER BY id DESC LIMIT 5;'
```

For local Ryu checks, use the VM's existing API token without printing it:

```bash
source ~/.secureiot_api_token
curl -fsS -H "Authorization: Bearer $SECUREIOT_API_TOKEN" \
  'http://127.0.0.1:8080/runtime/health'
curl -fsS -H "Authorization: Bearer $SECUREIOT_API_TOKEN" \
  'http://127.0.0.1:8080/api/iot/devices'
curl -fsS -H "Authorization: Bearer $SECUREIOT_API_TOKEN" \
  'http://127.0.0.1:8080/api/iot/sensors'
curl -fsS -H "Authorization: Bearer $SECUREIOT_API_TOKEN" \
  'http://127.0.0.1:8080/api/iot/telemetry?device_id=h16&limit=5'
```

## Verify public contract routes through ngrok

Ngrok must forward to the **read-only gateway** at `127.0.0.1:8090`, never directly to Ryu `:8080` or Flask `h2:5000`. Public callers send no bearer token; the gateway adds the private Ryu token upstream. It forwards the accepted contract GET routes individually, preserves OpenFlow stats' `202 pending` status, and rejects public POST/PUT/PATCH/DELETE. The contract lists a telemetry POST operation for local ingestion, but the live demo does not use it and the public tunnel does not expose it.

Run the contract checker from the branch worktree. It tests each documented GET path without a client token, plus the public write/control boundary:

```bash
BASE_URL='https://<your-current-ngrok-host>'
bash webtrack_gateway/check_public_contract_endpoints.sh "$BASE_URL"
```

The checker expects `/dashboard/snapshot` to return 404 because that path is not in the accepted contract. It checks `/api/iot/telemetry` as GET; it never POSTs telemetry.

## Verify changing telemetry

Run the following twice at least eleven seconds apart (h16's default simulator interval is about nine seconds):

```bash
BASE_URL='https://<your-current-ngrok-host>'
curl -fsS "$BASE_URL/api/iot/telemetry?device_id=h16&limit=1"
sleep 11
curl -fsS "$BASE_URL/api/iot/telemetry?device_id=h16&limit=1"
```

The second response should show a newer sequence or timestamp and the latest sensor readings. This request only reads the database; the simulator independently generates and submits the next sample. The dashboard may also call `GET /api/iot/devices` and `GET /api/iot/sensors` for inventory.

## Verify host activity, flow counters, and observed path without VLAN changes

The current map puts h27 on s5 and h28 on s6 in the same employee VLAN. From the Mininet prompt, launch a short ping in the background:

```text
h27 sh -c 'ping -n -i 0.5 -c 60 10.10.50.28 >/tmp/h27_to_h28_ping.log 2>&1 &'
```

While the ping is running, from a normal VM terminal run:

```bash
python3 webtrack_gateway/check_dynamic_endpoints.py 'https://<your-current-ngrok-host>'
```

This issues only contract GETs. It samples h27/h28 host activity, switch activity, `/stats/flow/5` and `/stats/flow/6`, port counters, both path routes, telemetry, events, resilience, and load-balancer counters twice eleven seconds apart. Look for increasing matching ICMP flow counters, `traffic_active: true` on h27/h28 and path switches, `path_source: installed_flow`, and an h16 telemetry sequence that advances. After the bounded ping finishes, wait about 10 seconds and re-read `/topology/hosts`; activity should expire. No VLAN, port assignment, or link is changed. Empty event lists are normal absent a real failure or security action; load-balancer counters move only after traffic uses its VIP.

## Security and troubleshooting

- Sensor hosts do not access ngrok. Their authenticated POST stays inside Mininet and targets only the private Web/API on h2:5000.
- Flask writes accepted samples to shared SQLite; the read-only public gateway exposes contract GETs only. Public telemetry POST and tunnel-side database writes are blocked.
- Anyone with the public ngrok URL can read the allowlisted contract data; this is intentional. Do not share the internal Ryu API token.
- If `/dashboard/snapshot` returns 404, that is expected; use individual routes from the contract.
- If a contract GET returns 404, verify the running gateway was updated from the intended branch and that the path and method are in the PDF contract.
- If device records are empty, check `/tmp/secureiot-h5-iot.log` through `/tmp/secureiot-h16-iot.log`, the Web/API log, the private ingestion token, and the SQLite database.
- If local Ryu GETs work but public contract GETs fail, inspect the gateway/ngrok service, the allowlist, and its private upstream Ryu token. Do not expose Ryu directly or enable public telemetry POST.
- If an external telemetry delivery URL is ignored, remove old `IOT_TELEMETRY_GET_URL`/`IOT_TELEMETRY_POST_URL` exports; the intended flow uses shared SQLite.
