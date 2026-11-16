# Public GET-only gateway for the SecureIoT Network API Contract

This bundle installs a local reverse proxy on `127.0.0.1:8090`, with ngrok forwarding to that port. WebTrack clients need no bearer token. The proxy attaches the VM's private `SECUREIOT_API_TOKEN` only when it calls Ryu at `127.0.0.1:8080`; that credential is never returned to or required from the client.

The public gateway exposes only the **GET routes listed in `SECUREIOT_NETWORK_API_CONTRACT_FINAL`**. It does not add an aggregate endpoint: **`/dashboard/snapshot` is not in the contract and returns 404**. Stats responses preserve the contract's `202 pending` and `200 ready` HTTP statuses. CORS is enabled for allowed contract paths.

The IoT demo data path is GET-based: the Web/API poller privately GETs sensor readings from h5-h16 and writes the samples directly to shared SQLite; WebTrack reads them with `GET /api/iot/devices`, `GET /api/iot/sensors`, or `GET /api/iot/telemetry`. The contract's `POST /api/iot/telemetry` is **not used by this demo and is blocked through the public tunnel**. No sensor or poller sends a POST to ngrok. Mininet and Ryu remain independently managed; when Ryu is stopped, the gateway can return HTTP 502.

## Contract GET routes available through the public gateway

- Runtime: `/runtime/health`.
- Topology: `/topology/switches`, `/topology/hosts`, `/topology/links`, `/topology/paths`, and `/topology/hosts/{host_id}/path`.
- VLANs: `/network/vlans`, `/network/vlan-ports`.
- OpenFlow: `/stats/desc/{dpid}`, `/stats/port/{dpid}`, `/stats/flow/{dpid}`.
- Load balancer: `/network/load-balancer`, `/network/load-balancer/status`, `/network/load-balancer/backends`, `/network/load-balancer/stats`.
- IoT: `/api/iot/devices`, `/api/iot/sensors`, `/api/iot/telemetry` (GET only).
- Firewall: `/firewall/status`, `/firewall/rules`, `/firewall/events`.
- Runtime events: `/network/events`, `/controller/clff`, `/controller/resilience`.

Allowed query parameters follow the contract: paths use source/destination selectors; IoT telemetry accepts `device_id`, `sensor_id`, and `limit` (1–1000); event endpoints accept `limit`. Control/action paths are not allowlisted. Public POST/PUT/PATCH/DELETE methods are rejected with 405. `OPTIONS` is supported only as a CORS preflight for an allowed contract GET route.

## Existing gateway installation

The branch should be in a dedicated worktree so it does not change the iot-simulator/core topology worktrees. The current VM already has `~/Graduation_Project/IoT-devices` checked out on `api-runtime-latest-20261111`; after fetching, use that checkout only if it remains on that branch and clean, or use its existing branch worktree:

```bash
git -C ~/Graduation_Project/IoT-devices fetch origin
git -C ~/Graduation_Project/IoT-devices status --short --branch
```

Fast-forward the target branch to the latest pushed commit, then run the rollback-capable updater from that branch directory:

```bash
cd ~/Graduation_Project/IoT-devices
git merge --ff-only origin/api-runtime-latest-20261111
git rev-parse --short HEAD  # verify the expected commit from the update message
sudo bash webtrack_gateway/update_readonly_webtrack_gateway_public_get.sh
```

The updater backs up the installed proxy and its environment file, installs the contract GET allowlist, keeps only the private Ryu token in the service environment, restarts only the read-only gateway, and verifies: contract `GET /runtime/health` and `GET /api/iot/telemetry` are reachable when Ryu is up; `GET /dashboard/snapshot` is 404; public telemetry POST is 405; control paths are not allowlisted; and CORS preflight is accepted for a contract path. It does not restart ngrok, Ryu, or Mininet and does not touch SQLite or datasets. If a check differs, it restores both backups. An old `~/.config/secureiot/webtrack_readonly_token` file, if present, is left untouched for rollback but is not read; do not send that old token to WebTrack.

## Verify the public contract routes

After the updater succeeds, obtain the current ngrok URL and run the checker with no client token:

```bash
BASE_URL='https://<your-current-ngrok-host>'
bash webtrack_gateway/check_public_contract_endpoints.sh "$BASE_URL"
```

A successful checker run confirms the individual contract paths (including telemetry GET) and confirms that the undocumented snapshot, public telemetry POST, and control route are rejected. For example:

```bash
curl -i "$BASE_URL/runtime/health"
curl -i "$BASE_URL/api/iot/telemetry?device_id=h16&limit=5"
curl -i "$BASE_URL/stats/flow/1"
```

The OpenFlow stats endpoints may return HTTP 202 `pending` on their first request, then HTTP 200 `ready`; both are contract-valid. Do not tell WebTrack to call `/dashboard/snapshot`.

## Test changing host/path/counter fields without changing VLANs

The latest topology maps h27 to s5 and h28 to s6 on the same employee VLAN. Start a bounded ping from h27 to h28 inside the Mininet prompt:

```text
h27 sh -c 'ping -n -i 0.5 -c 40 10.10.50.28 >/tmp/h27_to_h28_ping.log 2>&1 &'
```

While it runs, use a regular VM terminal:

```bash
python3 webtrack_gateway/check_dynamic_endpoints.py 'https://<your-current-ngrok-host>'
```

The read-only script samples contract host/switch inventory, flow and port statistics, both path routes, IoT telemetry, load-balancer counters, event history, and resilience twice six seconds apart. During the ping, expect h27/h28 and switches on the installed path to become `traffic_active: true`; the host-pair path should report `path_source: installed_flow` and traverse DPID 5 to DPID 6. The relevant ICMP counters should increase. After ping ends, the two host activity flags should expire after the controller's activity window. Empty event arrays are normal without a failure/action; load-balancer counters change only after requests reach its VIP. This test sends GETs only and does not alter VLANs or links.

## Fresh gateway installation

For a VM without the gateway services, use the installer instead:

```bash
cd ~/Graduation_Project/IoT-devices
sudo bash webtrack_gateway/install_readonly_webtrack_gateway.sh "$PWD"
```

Do not run the fresh installer on top of existing gateway services; it intentionally stops rather than overwrite existing paths. For an existing installation, use the updater above. Do not point ngrok directly to Ryu `:8080` or Flask `h2:5000`.

WebTrack should poll only the individual contract GETs it needs, at the contract's suggested intervals (topology/firewall 5–30 seconds, port stats about 3 seconds, flow stats about 5 seconds) to manage the free-plan limits (20,000 HTTP requests and 1 GB transfer per month). Avoid polling endpoints the dashboard does not use.
