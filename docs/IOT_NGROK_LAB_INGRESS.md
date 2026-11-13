# SecureIoT IoT telemetry and read-only WebTrack access

This runbook describes the GET-only telemetry read path. IoT sensors are polled privately by the Web/API server; their fresh readings are written directly to the shared SQLite database. Ryu and the read-only WebTrack gateway read that same database. No sensor or poller sends telemetry through ngrok, and no public GET endpoint mutates telemetry state.

## Data flow

```text
IoT hosts h5-h16
  GET /sensor/readings :8081 (private Mininet path)
              |
              v
Web/API server h2:5000
  background IoTPoller (IOT_POLL_INTERVAL, default 5 seconds)
              |
              | local SQLite write (no HTTP ingest request)
              v
/var/lib/secureiot/iot-telemetry.sqlite3
              ^
              | same shared DB file
Ryu runtime API :8080 (authenticated GET read routes)
              ^
              | allowlisted GET only
Read-only WebTrack gateway :8090 <- ngrok tunnel
              ^
              | public HTTPS GET (no client token)
WebTrack backend
```

SQLite is shared because the Flask service in Mininet's `h2` namespace and Ryu run on the same VM filesystem. SQLite WAL and transactional writes allow both processes to read/write the same database without exposing an additional database/network port. The database is persistent; the dashboard snapshot is generated from current database/API state when requested, not a one-time snapshot.

## Start configuration

Use the normal branch's demo flags and leave telemetry delivery URLs unset. Do not point the poller at the public ngrok hostname.

```bash
export START_DEMO_SERVICES=1
export START_IOT_SIMULATORS=1
export IOT_POLLING_ENABLED=1
export IOT_POLL_INTERVAL=5
export IOT_SENSOR_PORT=8081
export SECUREIOT_IOT_DB=/var/lib/secureiot/iot-telemetry.sqlite3
unset IOT_TELEMETRY_GET_URL IOT_TELEMETRY_POST_URL
```

Start Ryu and the read-only gateway/ngrok services as configured on the VM, then start the Mininet topology from the intended GitHub branch. Do not run the known-broken `iot_test` CLI command; it can tear down Mininet before completing its check.

## Verify sensor polling and local persistence

From the Mininet prompt, read one sensor with GET and inspect the poller log:

```text
h2 curl --noproxy '*' -fsS http://10.10.10.16:8081/sensor/readings
h2 tail -n 30 /tmp/web_api_h2_iot_live.log
```

The service log should report the poller enabled and fresh samples stored. On the VM (outside Mininet), check SQLite without changing it:

```bash
sqlite3 /var/lib/secureiot/iot-telemetry.sqlite3 \
  'SELECT device_id, device_role, timestamp, sequence, readings_json FROM iot_telemetry ORDER BY id DESC LIMIT 5;'
```

Verify authenticated local Ryu GETs using the existing API token without printing it:

```bash
source ~/.secureiot_api_token
curl -fsS -H "Authorization: Bearer $SECUREIOT_API_TOKEN" \
  'http://127.0.0.1:8080/api/iot/devices'
curl -fsS -H "Authorization: Bearer $SECUREIOT_API_TOKEN" \
  'http://127.0.0.1:8080/api/iot/sensors'
curl -fsS -H "Authorization: Bearer $SECUREIOT_API_TOKEN" \
  'http://127.0.0.1:8080/api/iot/telemetry?device_id=h16&limit=5'
```

## Verify WebTrack/ngrok GET access

The ngrok tunnel must point to the **read-only gateway** on `127.0.0.1:8090`, not directly to Ryu `:8080` or Flask `h2:5000`. Public clients do not send a bearer token. The gateway must allow only the documented GET routes, reject POST/PUT/PATCH/DELETE, and attach its private Ryu API token upstream; never expose that internal token. Anyone who obtains the public URL can read the allowlisted telemetry and network status.

```bash
BASE_URL='https://<your-ngrok-host>'
curl -fsS "$BASE_URL/dashboard/snapshot" \
  -o /tmp/webtrack_snapshot.json
python3 - <<'PY'
import json
p = json.load(open('/tmp/webtrack_snapshot.json', encoding='utf-8'))
print('status:', p.get('status'))
print('errors:', p.get('errors', {}))
print('sections:', ', '.join(p.get('data', {})))
print('IoT devices:', len(p.get('data', {}).get('iot_devices', [])))
print('IoT sensors:', len(p.get('data', {}).get('iot_sensors', [])))
print('IoT telemetry rows:', len(p.get('data', {}).get('iot_telemetry', [])))
PY
```

After at least one poll interval, repeat the GET and confirm that `last_seen`, timestamp, sequence, or sensor readings advance. The public request is a read: it does not trigger a sensor poll or write to SQLite. The background poller keeps the store current independently of dashboard polling.

## Security and troubleshooting

- Sensor hosts do not access ngrok. Only the server-side poller reads their private GET endpoints.
- Telemetry ingestion is an in-process store write, not a public API route. IoT read endpoints are GET-only and protected by the runtime bearer token behind the read-only gateway.
- DNS resolves names to addresses; it is not a telemetry data endpoint. The existing private sensor URLs use the topology's configured addresses and require no DNS POST/GET data exchange.
- If device records are empty, check the sensor `/health` endpoint, `/tmp/secureiot-h5-iot.log` through `/tmp/secureiot-h16-iot.log`, and `/tmp/web_api_h2_iot_live.log`.
- If the local Ryu GETs work but the public snapshot fails, inspect the read-only gateway/ngrok service, its GET allowlist, and its private upstream Ryu token. Do not solve this by exposing Ryu directly or enabling a public ingestion route.
- If you see a warning that an external telemetry delivery URL is ignored, remove old `IOT_TELEMETRY_GET_URL`/`IOT_TELEMETRY_POST_URL` exports; the intended flow uses shared SQLite.
