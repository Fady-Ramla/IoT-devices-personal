# SecureIoT IoT Simulation Integration Guide

## 1. Purpose

This document describes the IoT telemetry and dashboard API path for the SecureIoT graduation project. Keep the API/gateway worktree separate from the IoT topology worktree; the latter's VLAN and link configuration is not changed by the API update.

The currently verified IoT integration branch runs benign simulators on h5-h16. Each simulator sends authenticated telemetry to the private Flask Web/API on h2:5000. Flask stores accepted readings in SQLite shared with Ryu. WebTrack calls individual contract GET routes through the public read-only gateway; no simulator POST passes through ngrok and the gateway blocks public POST/control requests.

```text
IoT simulators h5-h16
        |
        | private authenticated POST :5000
        v
Flask Web/API h2 (Services VLAN 20)
        |
        | write sample to shared SQLite
        v
Ryu API :8080 <- private bearer token <- read-only gateway :8090 <- ngrok
        ^                                                        |
        |                                                        | public GET only
        +---------------------------------------------------- WebTrack
```

## 2. Repository and branch

The read-only API and gateway implementation is on:

```text
Branch: api-runtime-latest-20261111
Latest relevant commit: 383d760 Align public gateway with API contract
```

The Mininet IoT topology is kept in a separate worktree based on:

```text
Branch: iot-simulator-integration (VM worktree base: 905b454; remote inspected: ed69ca6)
```

The API branch may contain an optional GET-based sensor poller, but the verified
simulator on the IoT topology branch is a POST client and does not serve a
sensor endpoint on TCP/8081. For this topology, keep the optional poller
disabled unless such a sensor service is separately installed.

Important commits:

| Commit | Change |
|---|---|
| `4474b30` | Latest API/path dynamic activity fixes reviewed before the gateway update |
| `383d760` | Contract GET-only public gateway and dynamic endpoint checker |
| `905b454` | Existing VM IoT topology worktree base (topology configuration unchanged) |

## 3. VLAN layout

The relevant VLANs are:

| VLAN | Network | Gateway | Purpose |
|---:|---|---|---|
| 10 | `10.10.10.0/24` | `10.10.10.1` | IoT sensors h5-h16 |
| 20 | `10.10.20.0/24` | `10.10.20.1` | Services, including Web/API h2 |
| 30 | `10.10.30.0/24` | `10.10.30.1` | DNS |
| 40 | `10.10.40.0/24` | `10.10.40.1` | IT/management |
| 50 | `10.10.50.0/24` | `10.10.50.1` | Employees |

The primary Web/API host is:

```text
h2 = 10.10.20.2
```

The IoT hosts are:

```text
h5  = 10.10.10.5
h6  = 10.10.10.6
...
h16 = 10.10.10.16
```

All h5-h16 devices are in the same IoT VLAN 10. They are not in separate VLANs.

## 4. Simulator ingestion and shared persistence

On the inspected IoT integration branch, `mininet/iot_device_simulator.py`
generates benign, role-specific values on h5-h16 and sends an authenticated
HTTP POST to `http://10.10.20.2:5000/api/iot/telemetry`. The topology starts
the Flask Web/API on h2:5000 with a temporary ingest token and configures each
simulator with that token. The request is private to Mininet; it is not sent to
ngrok. The Web/API returns HTTP 202 for an accepted reading and stores it in
`/var/lib/secureiot/iot-telemetry.sqlite3`.

The SQLite file is shared by Flask inside the h2 network namespace and the
Ryu API on the VM filesystem. Ryu's accepted GET routes read the same store;
the public gateway attaches its private Ryu bearer token upstream. WebTrack
needs no public client token and can call only the contract's GET routes.

The API worktree also contains an optional `mininet/servers/iot_poller.py`
that expects each h5-h16 host to serve GET `/sensor/readings` on TCP/8081.
That service is **not** provided by the verified simulator on the IoT topology
branch. Keep `IOT_POLLING_ENABLED=0` for this demo unless a separate GET sensor
service is installed and verified. The working simulator POST + Flask storage
path is sufficient for fresh dashboard GET responses.

## 6. WAN, NAT, and ngrok

The gateway receives a host-backed veth pair:

```text
Host:    sio-wan-host = 172.31.255.1/30
Gateway: sio-wan-gw   = 172.31.255.2/30
```

The gateway default route is:

```text
default via 172.31.255.1 dev sio-wan-gw
```

The Ubuntu host routes the Mininet networks through the gateway and applies MASQUERADE on the external interface, normally `enp0s3` in VirtualBox.

IoT simulator ingestion does not require WAN egress from Mininet. The IoT VLAN
remains private; simulators send authenticated POSTs only to the private Web/API
on h2:5000. The VM's separately installed read-only gateway is the only service
exposed through ngrok.

The WAN setup is implemented in:

```text
mininet/configure_gateway.py
```

The external interface is detected automatically. It can be overridden when necessary:

```bash
export SECUREIOT_WAN_INTERFACE=enp0s3
```

The veth interface names are intentionally short because Linux limits interface names to 15 characters.

## 7. Required environment variables

Before starting the topology:

```bash
export RYU_IP=127.0.0.1
export RYU_PORT=6633
export START_DEMO_SERVICES=1
export START_IOT_SIMULATORS=1
export IOT_POLLING_ENABLED=0
export SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3
unset IOT_TELEMETRY_GET_URL IOT_TELEMETRY_POST_URL
```

The IoT simulators POST to the local Web/API; Flask persists accepted readings
to SQLite, which Ryu reads for the contract GETs. Do not set an external
telemetry URL or enable the optional sensor GET poller unless h5-h16 actually
serve `/sensor/readings` on port 8081.

## 8. Startup sequence

### 8.1 Start Ryu first

```bash
cd ~/Graduation_Project/IoT-devices

source ~/.secureiot_api_token
sudo --preserve-env=SECUREIOT_API_TOKEN env \
  SECUREIOT_API_TOKEN="$SECUREIOT_API_TOKEN" \
  SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3 \
  SECUREIOT_LB_STATS_FILE=/var/tmp/secureiot-lb-stats.json \
  "$PWD/ryu_env/bin/ryu-manager" \
  --observe-links \
  --ofp-tcp-listen-port 6633 \
  --wsapi-host 127.0.0.1 \
  --wsapi-port 8080 \
  topology_monitor.py \
  traffic_monitor_merged.py \
  resilience_engine.py \
  runtime_network_api.py
```

The important option is:

```text
--observe-links
```

It allows Ryu to discover the inter-switch links and install the required forwarding behavior.

### 8.2 Start ngrok

Keep Ryu authentication enabled. Do not set `SECUREIOT_DISABLE_API_AUTH=1` or use a hard-coded token. The ngrok tunnel should forward only to the installed read-only gateway:

```text
https://<your-ngrok-host> -> http://127.0.0.1:8090
```

Do not point ngrok directly at Ryu `:8080` or Flask `h2:5000`. The gateway
allows only contract GET routes. The IoT simulator's private POST to h2:5000
never uses the tunnel.

### 8.3 Start Mininet

```bash
cd ~/Graduation_Project/IoT-devices_GITHUB_iot_20261103
sudo -E python3 mininet/Real_network_topology.py
```

Use the API worktree for Ryu and gateway code; keep Mininet on the existing
IoT integration worktree so this test does not change the topology. Do not run
the known-broken `iot_test` CLI command; use the GET and log checks below.

The topology should print a WAN setup message similar to:

```text
[gateway] WAN/NAT configured via enp0s3 (Services VLAN egress only)
```

## 9. Verification checklist

### 9.1 Verify VLAN gateway connectivity

```text
mininet> h2 ping -c 2 10.10.20.1
```

### 9.2 Verify private simulator ingestion

```text
mininet> h2 curl --noproxy '*' -sS http://127.0.0.1:5000/health
mininet> h16 tail -n 15 /tmp/secureiot-h16-iot.log
mininet> h2 tail -n 20 /tmp/web_api_h2_iot_live.log
```

The h16 log should show `telemetry sent ... http_status=202` roughly every
nine seconds by default. Flask accepts the authenticated internal POST and
writes the sample to shared SQLite.

### 9.3 Verify WAN interface and default route

```text
mininet> gw ip addr show sio-wan-gw
mininet> gw ip route
```

Expected gateway address and route:

```text
172.31.255.2/30
 default via 172.31.255.1 dev sio-wan-gw
```

### 9.4 Verify the WebTrack read-only tunnel

From a normal VM terminal, call individual contract read endpoints through the public gateway without a client token. The accepted contract has no aggregate `/dashboard/snapshot` route:

```bash
BASE_URL='https://<your-ngrok-host>'
curl -fsS "$BASE_URL/runtime/health"
curl -fsS "$BASE_URL/topology/hosts"
curl -fsS "$BASE_URL/topology/switches"
curl -fsS "$BASE_URL/api/iot/telemetry?device_id=h16&limit=5"
```

This GET reads the stored database row; it does not trigger sample generation
or ingestion.

### 9.5 Verify the Web/API process

```text
mininet> h2 ps -ef | grep '[w]eb_api_server.py'
mininet> h2 head -n 15 /tmp/web_api_h2_iot_live.log
```

The Web/API access log should show private telemetry POSTs from IoT simulator
hosts. The simulator POST must never go through ngrok.

### 9.6 Verify SQLite and the authenticated GET reads

The database should receive a new row after each successful simulator POST:

```bash
sqlite3 /var/lib/secureiot/iot-telemetry.sqlite3 \
  'SELECT device_id, timestamp, sequence, readings_json FROM iot_telemetry ORDER BY id DESC LIMIT 5;'
```

The ngrok inspector should show contract GET requests such as
`GET /api/iot/telemetry?device_id=h16&limit=5`. Private simulator POSTs to h2
must not appear in the public ngrok inspector.

### 9.7 Verify the public API data

Use the ngrok URL for individual public contract GETs; no client bearer token is required:

```bash
BASE_URL='https://<your-ngrok-host>'
curl -sS "$BASE_URL/api/iot/devices"
curl -sS "$BASE_URL/api/iot/sensors"
curl -sS "$BASE_URL/api/iot/telemetry?device_id=h16&limit=1"
```

The result should contain h5-h16 with increasing `sample_count`, recent `last_seen` timestamps, and `status: online`.

## 10. Proving that values are dynamic

Run the telemetry GET twice at least eleven seconds apart (h16's default
simulator interval is about nine seconds). The GETs only read the store:

```bash
BASE_URL='https://<your-ngrok-host>'
curl -sS "$BASE_URL/api/iot/telemetry?device_id=h16&limit=1"
sleep 11
curl -sS "$BASE_URL/api/iot/telemetry?device_id=h16&limit=1"
```

The two responses should show newer:

- telemetry `id`;
- timestamp;
- sequence number; and usually
- sensor values such as `vibration_rms`.

The observed data already demonstrated sequences 38, 39, 40, 41, 42, 43, 44, and 45, with changing values for h6, h16, and the other devices.

## 11. Authentication behavior

There are two API surfaces:

### Public ngrok/read-only gateway

The tunnel must terminate at the read-only proxy, not at Ryu directly. Public
clients need no bearer token. The gateway supplies its private Ryu API token
upstream and exposes only allowlisted GET routes; mutating methods and
ingestion routes are not exposed. Anyone with the public URL can read those
allowlisted network and telemetry fields.

WebTrack uses GET requests without a client token. Each GET reads the current
API/database state; it does not trigger sample generation or change database
state.

### Local Flask Web/API on h2:5000

The local Flask Web/API is not the public dashboard endpoint. Its telemetry
ingestion route accepts the private token injected for the simulator by the
topology startup; the public gateway does not forward any client POST.

```text
http://10.10.20.2:5000/api/iot/devices
http://10.10.20.2:5000/api/iot/sensors
http://10.10.20.2:5000/api/iot/telemetry
```

The dashboard should use the public read-only gateway URL; Ryu's internal
token stays on the VM. Do not place either private ingestion or Ryu tokens in
browser JavaScript.

## 12. Troubleshooting

### IoT simulator POST does not return HTTP 202

Check that Mininet is connected to Ryu and that h2's private Web/API is healthy:

```text
h2 ping -c 2 10.10.20.1
h2 curl --noproxy '*' -fsS http://127.0.0.1:5000/health
h16 tail -n 20 /tmp/secureiot-h16-iot.log
h2 tail -n 30 /tmp/web_api_h2_iot_live.log
```

Verify the h16 log reports HTTP 202 and the Web/API uses
`SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3`.

### Dashboard GET is empty or its sequence does not advance

Check that the IoT simulators are running on h5-h16, inspect their
`/tmp/secureiot-h*-iot.log` output, verify the private ingestion token is
accepted by h2, and query the shared SQLite file. A public GET cannot create a
missing sample.

### ngrok hostname resolution timeout

The ngrok tunnel runs on the VM host, not inside the Mininet gateway. Check the host-side services:

```bash
systemctl is-active secureiot-webtrack-readonly.service ngrok-webtrack-readonly.service
curl -fsS http://127.0.0.1:8090/health
```

Check the VM's Internet connection and the ngrok service logs. This is separate from private simulator-to-Web/API ingestion.

### `/tmp/web_api_h2_iot_live.log` does not exist

Check that the Web/API process started:

```text
h2 ps -ef | grep web_api_server | grep -v grep
```

Ensure `START_DEMO_SERVICES=1` was exported before running:

```bash
sudo -E python3 mininet/Real_network_topology.py
```

### IoT telemetry is absent from the Flask log

Check the simulator logs for `telemetry sent ... http_status=202`, the Web/API
log for the private POST, and confirm Web/API and Ryu share the same
`SECUREIOT_IOT_DB` path. Telemetry is stored locally; it is not sent through ngrok.

## 13. Security note

Keep authentication enabled on the Ryu runtime API and read-only gateway. For production or public deployment:

- do not expose Ryu directly through ngrok;
- configure a strong runtime token and JWT secret;
- keep IoT VLAN Internet egress disabled;
- keep the IoT VLAN private and allow only the required IoT-to-Web/API service path;
- protect the ngrok hostname and avoid exposing administrative routes.
