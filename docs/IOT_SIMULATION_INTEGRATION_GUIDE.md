# SecureIoT IoT Simulation Integration Guide

## 1. Purpose

This document describes the final IoT simulation and telemetry integration used by the SecureIoT graduation project.

The final design keeps IoT sensors inside the Mininet private network. The Web/API server on the Services VLAN polls the sensors every five seconds, receives fresh readings, and posts each reading through the configured ngrok URL to the Ryu runtime API. The WebTrack/dashboard reads the changing data through the public ngrok API.

The IoT devices do **not** post directly to ngrok.

```text
IoT sensor h5-h16
        |
        | private HTTP GET :8081
        v
Web/API server h2 (Services VLAN 20)
        |
        | HTTPS POST through WAN/NAT and ngrok
        v
ngrok public URL -> Ryu runtime API :8080
        |
        | dashboard GET requests
        v
WebTrack / dashboard
```

## 2. Repository and branch

The implementation is on:

```text
Branch: api-runtime-latest-20261111
Latest commit: e25331d Match WAN forwarding rule to veth name
```

The earlier reusable network implementation was found on:

```text
iot-simulator-integration
```

The current branch contains the required polling implementation plus the ported WAN/NAT setup.

Important commits:

| Commit | Change |
|---|---|
| `bd2a0fd` | Implement contract-preserving IoT server polling |
| `428425e` | Post polled IoT readings through ngrok |
| `e92743a` | Bypass host proxy behavior for private sensor polling |
| `5a51833` | Use direct sockets for Mininet sensor reads |
| `7d170be` | Start sensors before the IoT poller and wait for readiness |
| `cbc0b89` | Add Services VLAN WAN/NAT connectivity |
| `f0f9076` | Use Linux-compatible WAN interface names |
| `e25331d` | Match the WAN firewall rule to the actual veth name |

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

## 4. Sensor services

Each IoT host runs a private HTTP sensor service on TCP port `8081`:

```text
http://10.10.10.X:8081/health
http://10.10.10.X:8081/sensor/readings
```

Example:

```bash
h2 curl --noproxy '*' -sS http://10.10.10.16:8081/health
```

Expected response:

```json
{"status":"healthy","device_id":"h16","service":"iot-sensor"}
```

The readings endpoint returns changing simulated values, a sequence number, timestamp, device ID, and device role. Example fields include:

```json
{
  "device_id": "h16",
  "device_role": "vibration_sensor",
  "readings": {
    "vibration_mm_s": 1.807,
    "machine_status": "normal"
  },
  "sequence": 44,
  "status": "online",
  "simulation": true,
  "source": "mininet"
}
```

The gateway allows only the Web/API Services VLAN to access IoT TCP/8081. IoT devices do not initiate telemetry POSTs.

## 5. Polling flow

The poller is implemented in:

```text
mininet/servers/iot_poller.py
```

It runs inside the Web/API process:

```text
mininet/servers/web_api_server.py
```

The poller performs the following loop:

1. Connect to each sensor privately over TCP/8081.
2. GET `/sensor/readings`.
3. Validate the response and preserve the fresh reading.
4. Write the reading to the local telemetry store.
5. POST the same fresh payload to `IOT_TELEMETRY_POST_URL`.
6. Repeat according to `IOT_POLL_INTERVAL`.

Private sensor reads use a direct `http.client.HTTPConnection`. This intentionally bypasses inherited HTTP proxy settings and avoids proxy DNS resolution for Mininet IP addresses.

The final topology starts sensors first, waits for every `/health` endpoint to become ready, and only then starts the Web/API poller. This prevents startup `Connection refused` races.

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

Only Services VLAN 20 is allowed to use this WAN egress for the server-side ngrok POST. The IoT VLAN remains private.

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
export IOT_POLLING_ENABLED=1
export IOT_POLL_INTERVAL=5
export IOT_SENSOR_PORT=8081
export IOT_TELEMETRY_POST_URL='https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/telemetry'
export IOT_TELEMETRY_POST_TOKEN=''
```

The ngrok hostname is dynamic. If ngrok gives a new hostname, update only `IOT_TELEMETRY_POST_URL` before starting the topology.

## 8. Startup sequence

### 8.1 Start Ryu first

```bash
cd ~/Graduation_Project/IoT-devices

sudo env \
  SECUREIOT_DISABLE_API_AUTH=1 \
  SECUREIOT_API_TOKEN='secureiot-local-demo-token-2026-abcdef' \
  SECUREIOT_CONTROL_TOKEN='secureiot-local-demo-token-2026-abcdef' \
  SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3 \
  SECUREIOT_LB_STATS_FILE=/var/tmp/secureiot-lb-stats.json \
  SECUREIOT_ALLOWED_ORIGIN='https://uneasy-cobweb-headdress.ngrok-free.dev' \
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

The ngrok tunnel should forward to the Ryu runtime API:

```text
https://uneasy-cobweb-headdress.ngrok-free.dev -> http://127.0.0.1:8080
```

Do not point this telemetry tunnel at `h2:5000`. The final poller posts to the Ryu runtime endpoint on port 8080 through the host WAN/NAT path.

### 8.3 Start Mininet

```bash
cd ~/Graduation_Project/IoT-devices
git pull --ff-only origin api-runtime-latest-20261111
sudo mn -c
sudo -E python3 mininet/Real_network_topology.py
```

The topology should print a WAN setup message similar to:

```text
[gateway] WAN/NAT configured via enp0s3 (Services VLAN egress only)
```

## 9. Verification checklist

### 9.1 Verify VLAN gateway connectivity

```text
mininet> h2 ping -c 2 10.10.20.1
```

### 9.2 Verify the private sensor path

```text
mininet> h2 curl --noproxy '*' -sS http://10.10.10.16:8081/health
```

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

### 9.4 Verify public HTTPS access

```text
mininet> h2 curl --noproxy '*' -v --max-time 10 https://uneasy-cobweb-headdress.ngrok-free.dev/health
```

A DNS timeout means the WAN path is not ready. Do not troubleshoot the sensor VLAN in that case.

### 9.5 Verify the Web/API process

```text
mininet> h2 ps -ef | grep -E 'web_api_server|iot_poller' | grep -v grep
mininet> h2 head -n 15 /tmp/web_api_h2_iot_live.log
```

The poller is inside `web_api_server.py`; it is not a separate process named `iot_poller`.

### 9.6 Verify ngrok POST traffic

The ngrok inspector should show repeated requests:

```text
POST /api/iot/telemetry 201
```

The `201 Created` response is a success response from the Ryu runtime API.

### 9.7 Verify the public API data

Use the ngrok URL for the no-token lab runtime API:

```bash
curl -sS https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/devices
curl -sS https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/sensors
curl -sS https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/telemetry
```

The result should contain h5-h16 with increasing `sample_count`, recent `last_seen` timestamps, and `status: online`.

## 10. Proving that values are dynamic

Run the following twice, at least six seconds apart:

```bash
curl -sS 'https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/telemetry?device_id=h16&limit=1'
sleep 6
curl -sS 'https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/telemetry?device_id=h16&limit=1'
```

The two responses should show newer:

- telemetry `id`;
- timestamp;
- sequence number; and usually
- sensor values such as `vibration_mm_s`.

The observed data already demonstrated sequences 38, 39, 40, 41, 42, 43, 44, and 45, with changing values for h6, h16, and the other devices.

## 11. Authentication behavior

There are two API surfaces:

### Public ngrok/Ryu runtime API

The lab Ryu process is started with:

```text
SECUREIOT_DISABLE_API_AUTH=1
```

Therefore the runtime GET routes used by the dashboard can be called without a Bearer token during this lab run. The telemetry POST returns `201` when accepted.

### Local Flask Web/API on h2:5000

The Flask routes are separately protected by the Web/API authentication decorator. Therefore these requests return `Valid Bearer token required` unless a valid token is supplied:

```text
http://10.10.20.2:5000/api/iot/devices
http://10.10.20.2:5000/api/iot/sensors
http://10.10.20.2:5000/api/iot/telemetry
```

This is expected and does not mean that polling or ngrok ingestion failed. The dashboard should use the public runtime API URL in this lab configuration.

## 12. Troubleshooting

### `No route to host` for `10.10.10.X:8081`

Check that Ryu is running and that Mininet was started after Ryu. Confirm:

```text
h2 ping -c 2 10.10.20.1
h2 curl --noproxy '*' http://10.10.10.16:8081/health
```

### `Connection refused` on sensor port 8081

This is normally a startup race. Restart from the latest branch. The final topology starts h5-h16 first and waits for their health endpoints before starting Web/API.

### `Temporary failure in name resolution` for the sensor IP URLs

The old urllib/proxy path was removed. Pull the latest commit and restart the Web/API process; a running Python process does not reload changed files.

### ngrok hostname resolution timeout

Check:

```text
gw ip addr show sio-wan-gw
gw ip route
```

Then check host forwarding/NAT:

```bash
sudo iptables -L FORWARD -n -v --line-numbers
sudo iptables -t nat -L POSTROUTING -n -v --line-numbers
```

The counters for `sio-wan-host -> enp0s3` and `MASQUERADE` should increase while testing from h2.

### `/tmp/web_api_h2_iot_live.log` does not exist

Check that the Web/API process started:

```text
h2 ps -ef | grep web_api_server | grep -v grep
```

Ensure `START_DEMO_SERVICES=1` was exported before running:

```bash
sudo -E python3 mininet/Real_network_topology.py
```

### `telemetry POST accepted` is absent from the Flask log

The final POST goes to ngrok and then Ryu on port 8080, not to the Flask service on h2:5000. Verify the ngrok inspector and query the public runtime API instead.

## 13. Security note

The no-token runtime mode is intended for this local graduation-project lab demonstration. For production or public deployment:

- do not disable API authentication;
- configure a strong runtime token and JWT secret;
- keep IoT VLAN Internet egress disabled;
- allow only the required Services-to-IoT TCP/8081 path;
- protect the ngrok hostname and avoid exposing administrative routes.
