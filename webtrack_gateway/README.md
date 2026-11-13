# Public GET-only WebTrack gateway for TrustFlow

This bundle installs a local reverse proxy on `127.0.0.1:8090`, with ngrok forwarding to that local port. WebTrack clients need no bearer token. The proxy attaches the VM's private `SECUREIOT_API_TOKEN` only when it calls Ryu at `127.0.0.1:8080`; that credential is never returned to or required from the client.

The public allowlist contains only documented read endpoints: health, controller/topology inventory, VLANs, load-balancer status, firewall status/rules/events, network events, selected OpenFlow stats, and IoT devices/sensors/telemetry. `GET /dashboard/snapshot` aggregates those fields. Paths and query parameters are validated. All POST/PUT/PATCH/DELETE/OPTIONS/HEAD methods return 405, and control/action and dataset-lifecycle paths are not allowlisted. Anyone who obtains the public ngrok URL can read the allowlisted status and telemetry; this is an intentional public-read configuration.

The poller GETs sensor readings privately from h5-h16 and writes them directly to the shared SQLite database. Ryu reads the same database. Dashboard GETs do not trigger polling and do not write to SQLite. Mininet and Ryu remain independently managed; when Ryu is stopped, the gateway can return HTTP 502.

## Existing gateway installation

On the VM, keep this work separate from the iot-simulator/core topology worktrees. If this branch does not already have its own worktree, create one from the repository checkout:

```bash
git -C ~/Graduation_Project/IoT-devices fetch origin
git -C ~/Graduation_Project/IoT-devices worktree add --track -b api-runtime-latest-20261111 \
  ~/Graduation_Project/IoT-devices_GITHUB_api-runtime_20261113 \
  origin/api-runtime-latest-20261111
```

If that local branch or worktree already exists, do not run `worktree add` again; use the existing branch worktree and verify its branch and clean status. Then fast-forward it and run the rollback-capable updater:

```bash
cd ~/Graduation_Project/IoT-devices_GITHUB_api-runtime_20261113
git status --short --branch
git pull --ff-only
sudo bash webtrack_gateway/update_readonly_webtrack_gateway_public_get.sh
```

The updater backs up the installed proxy and its environment file, removes the public-client token requirement, retains only the private Ryu token in the service environment, restarts only the read-only gateway, then checks that a no-token GET is accepted, POST returns 405, and a control route is not allowlisted. It does not restart ngrok, Ryu, or Mininet and does not touch SQLite or datasets. If the public GET check is not 200 or 502, or method/path checks differ, the updater restores both backups. If the old `~/.config/secureiot/webtrack_readonly_token` file exists, the updater leaves it untouched for rollback but the gateway no longer reads it; do not send that old token to WebTrack.

## Fresh gateway installation

For a VM without the gateway services, use the installer instead:

```bash
cd ~/Graduation_Project/IoT-devices_GITHUB_api-runtime_20261113
sudo bash webtrack_gateway/install_readonly_webtrack_gateway.sh "$PWD"
```

Do not run the fresh installer on top of an existing service; it intentionally stops rather than overwrite existing paths. For an existing installation, use the updater above.

ngrok uses the account's free dev domain and forwards to the read-only gateway. The WebTrack backend should poll only `/dashboard/snapshot` at a modest interval to manage the free-plan limits (20,000 HTTP requests and 1 GB transfer per month). Faster refresh or push requires a different quota/architecture. Do not point ngrok directly at Ryu `:8080` or Flask `h2:5000`.
