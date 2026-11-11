# SecureIoT IoT telemetry: server polling and dashboard ingress

The final architecture preserves the existing SecureIoT Network API Contract. The
browser/dashboard continues to call the documented runtime endpoints; no public
poller endpoint is added.

```text
Mininet h5-h16
  GET /sensor/readings :8081 (private IoT VLAN endpoint)
          |
          | Services -> IoT, TCP/8081 only
          v
Web/API server h2:5000
  internal background poller every IOT_POLL_INTERVAL seconds
          |
          +--> POST /api/iot/telemetry via ngrok (fresh JSON each cycle)
          |             |
          |             v
          |       Ryu contract API :8080
          |             |
          +--------> shared SQLite IoTTelemetryStore
          |
          +--> Ryu contract API :8080
          |      GET /api/iot/devices
          |      GET /api/iot/sensors
          |      GET /api/iot/telemetry
          |
          +--> dashboard/WebTrack GET requests see new values

ngrok carries the server-side telemetry POST and dashboard GET requests; IoT
devices themselves never use ngrok.
```

## Run configuration

```bash
export START_DEMO_SERVICES=1
export START_IOT_SIMULATORS=1
export IOT_POLLING_ENABLED=1
export IOT_POLL_INTERVAL=5
export IOT_SENSOR_PORT=8081
export IOT_TELEMETRY_POST_URL="https://<your-ngrok-host>/api/iot/telemetry"
export IOT_TELEMETRY_POST_TOKEN="<optional-ingest-token>"
```

Start Ryu first, then start the Mininet topology. The device logs should show
`IOT_SENSOR_READY`, while `/tmp/web_api_h2_iot_live.log` should show that the
poller is enabled. The first successful polling cycle creates a fresh POST, and
the contract API persists it in the shared store. A new POST is sent after
every successful private sensor GET.

## Contract behavior

The existing contract routes and payload shapes remain unchanged:

- `GET /api/iot/devices` returns live device status and `last_seen`.
- `GET /api/iot/sensors` returns the latest value for every discovered sensor.
- `GET /api/iot/telemetry` returns the changing stored samples and preserves
  `device_id`, `sensor_id`, and `limit` filtering.
- `POST /api/iot/telemetry` receives the normalized, changing reading from the
  server-side poller. It is not a device push: the poller first performs a
  private GET, then POSTs that exact fresh payload through ngrok.

OpenFlow, topology, VLAN, load-balancer, firewall, and runtime endpoints keep
using their existing provider-backed responses. A dashboard should poll those
GET routes at the intervals described in the API contract and render the latest
response rather than caching a static snapshot.

## Troubleshooting

```bash
# From h2, verify one private sensor endpoint.
curl -s http://10.10.10.16:8081/health
curl -s http://10.10.10.16:8081/sensor/readings

# Verify the contract API through the runtime/dashboard ingress.
curl -s http://<controller-host>:8080/api/iot/devices
curl -s http://<controller-host>:8080/api/iot/sensors
curl -s 'http://<controller-host>:8080/api/iot/telemetry?device_id=h16&limit=5'
```

The ngrok inspector should show one `POST /api/iot/telemetry` approximately
every `IOT_POLL_INTERVAL` seconds, with changing `sequence`, `timestamp`, and
sensor values. Dashboard GET requests are separate and can use their own
refresh interval.

If a device becomes unreachable, its last stored sample remains available but
its contract inventory status becomes `stale` after the store freshness window.
The next polling cycle retries automatically.
