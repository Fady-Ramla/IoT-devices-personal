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
          v
shared SQLite IoTTelemetryStore
          |
          +--> Ryu contract API :8080
          |      GET /api/iot/devices
          |      GET /api/iot/sensors
          |      GET /api/iot/telemetry
          |
          +--> dashboard/WebTrack GET requests see new values

ngrok exposes the dashboard/Web/API ingress only; IoT devices never use ngrok.
```

## Run configuration

```bash
export START_DEMO_SERVICES=1
export START_IOT_SIMULATORS=1
export IOT_POLLING_ENABLED=1
export IOT_POLL_INTERVAL=5
export IOT_SENSOR_PORT=8081
```

Start Ryu first, then start the Mininet topology. The device logs should show
`IOT_SENSOR_READY`, while `/tmp/web_api_h2_iot_live.log` should show that the
poller is enabled. The first successful polling cycle creates live records in
the shared store.

## Contract behavior

The existing contract routes and payload shapes remain unchanged:

- `GET /api/iot/devices` returns live device status and `last_seen`.
- `GET /api/iot/sensors` returns the latest value for every discovered sensor.
- `GET /api/iot/telemetry` returns the changing stored samples and preserves
  `device_id`, `sensor_id`, and `limit` filtering.
- `POST /api/iot/telemetry` remains available for contract compatibility and
  validation, but the normal Mininet flow no longer depends on device push.

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

If a device becomes unreachable, its last stored sample remains available but
its contract inventory status becomes `stale` after the store freshness window.
The next polling cycle retries automatically.
