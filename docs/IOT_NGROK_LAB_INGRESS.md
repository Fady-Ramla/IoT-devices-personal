# Mininet-to-ngrok IoT telemetry (lab mode)

In lab mode, each Mininet IoT host (`h5`–`h16`) sends its generated sensor reading directly with `POST` to the configured ngrok endpoint:

```text
Mininet h16
  -> POST https://<ngrok-host>/api/iot/telemetry
  -> Ryu runtime API :8080
  -> shared IoT SQLite store
```

The runtime `POST /api/iot/telemetry` route is intentionally public for this lab flow. Telemetry `GET` routes and the other runtime APIs remain protected by the normal integration bearer token.

The default endpoint is:

```text
https://uneasy-cobweb-headdress.ngrok-free.dev/api/iot/telemetry
```

If the ngrok hostname changes, set the endpoint before starting Mininet:

```bash
export IOT_TELEMETRY_ENDPOINT="https://YOUR-NGROK-HOST.ngrok-free.dev/api/iot/telemetry"
```

The simulator also supports an explicit endpoint:

```bash
python3 mininet/iot_device_simulator.py \
  --device-id h16 \
  --role vibration_sensor \
  --endpoint "$IOT_TELEMETRY_ENDPOINT" \
  --interval 10
```

After pulling the branch, restart the Ryu runtime API and restart the Mininet topology so the changed route and simulator destination are loaded. The simulator log should show the ngrok URL in `IOT_SIMULATOR_READY`, followed by `IOT_TELEMETRY_SENT` entries. A `201` response is expected from the runtime API; `202` is expected only from the internal Flask ingest route.
