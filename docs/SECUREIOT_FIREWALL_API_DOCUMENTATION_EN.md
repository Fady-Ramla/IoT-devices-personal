# SecureIoT Firewall API Documentation

**Project:** SecureIoT SDN and IoT Network Security Platform  
**API branch:** `api-runtime-latest-20261111`  
**Implementation commit:** `d054928` — *Keep firewall host_count contract*  
**Document status:** Final implementation and verification reference

---

## 1. Overview

The SecureIoT Firewall API exposes the current firewall policy, installed security rules, and firewall event history through the existing runtime API. It also uses the existing `/network/action` endpoint to execute host block and unblock operations.

This implementation preserves the existing API contract. No new endpoint was introduced, and unrelated network, topology, telemetry, controller, and load-balancer APIs were not changed.

The firewall implementation supports the following requirements:

1. The configured inventory contains **38 hosts**.
2. The existing `topology_status.host_count` field represents the number of currently active hosts in that configured inventory.
3. Blocking one host decreases `host_count` from `38` to `37`; unblocking it restores the value to `38`.
4. `blocked_flows` counts host-block actions and SSH-denial events.
5. Firewall events expose distinct reasons for host quarantine, backend SSH denial, and frontend SSH denial.
6. Mirrored internal records for the same block request are deduplicated.

---

## 2. Firewall Endpoint Summary

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/firewall/status` | Returns the active firewall state and counters. |
| `GET` | `/firewall/rules` | Returns the currently installed firewall rules. |
| `GET` | `/firewall/events` | Returns the normalized firewall event history. |
| `POST` | `/network/action` | Executes an existing block or unblock action. |

No additional firewall endpoint was added.

---

## 3. `GET /firewall/status`

### Purpose

Returns the current firewall state, default policy, active host count, blocked-flow count, controller connectivity, and topology information.

### Example response after one host is blocked

```json
{
  "status": "active",
  "default_policy": "DROP",
  "protected_vlans": [10, 20, 30, 40, 50],
  "blocked_flows": 4,
  "controller_connected": true,
  "topology_status": {
    "topology_ready": true,
    "full_topology_discovered": true,
    "switch_count": 6,
    "link_count": 12,
    "host_count": 37,
    "blocked_device_count": 1,
    "blocked_macs": [
      "00:00:00:00:00:16"
    ]
  },
  "source": "topology-monitor-and-traffic-monitor"
}
```

### Important fields

| Field | Description |
|---|---|
| `status` | Firewall availability. Expected value is `active` when the TopologyMonitor is connected. |
| `default_policy` | Default firewall policy. The SecureIoT default is `DROP`. |
| `protected_vlans` | VLANs protected by the firewall. |
| `topology_status.host_count` | Active host count based on the configured 38-host inventory. This is the existing host-count field used by the dashboard. |
| `blocked_flows` | Number of normalized blocking events, including host blocks and SSH denials. |
| `topology_status.blocked_device_count` | Number of currently blocked devices. |
| `topology_status.blocked_macs` | MAC addresses of currently blocked devices. |
| `controller_connected` | Indicates whether the Ryu TopologyMonitor is available. |

### Host-count behavior

The active host count is calculated as:

```text
active host_count = configured hosts - currently blocked devices
```

For the current SecureIoT inventory:

```text
No blocked host:       host_count = 38
One blocked host:      host_count = 37
Two blocked hosts:     host_count = 36
After unblock:         host_count returns to 38
```

`topology_status.host_count` is intentionally based on the configured inventory, not on the number of hosts discovered at a particular moment by runtime learning. Therefore, a runtime discovery value lower than 38 does not incorrectly reduce the dashboard inventory count.

The response does **not** introduce a separate top-level `hosts_count` field. The existing `topology_status.host_count` field remains the single host-count field.

### Blocked-flow behavior

`blocked_flows` counts the following scenarios:

1. A host is blocked through `BLOCK_DEVICE`.
2. An unauthorized host attempts SSH access to a backend host on TCP port `22`.
3. A non-management host attempts SSH access to the frontend on TCP port `2222`.

For the verified test run:

```text
1 host-block event
+ 2 backend SSH-denial events
+ 1 frontend SSH-denial event
= 4 blocked flows
```

The active blocked-device state is also counted if the provider exposes the blocked device but the corresponding action event is not present in the event history. Mirrored records are counted only once.

---

## 4. `GET /firewall/rules`

### Purpose

Returns the firewall rules currently installed by the TopologyMonitor and traffic-monitor components.

### Representative response

```json
[
  {
    "rule_id": "default-deny",
    "priority": 1000,
    "action": "DROP",
    "direction": "both",
    "source": "any",
    "destination": "any",
    "enabled": true,
    "status": "installed"
  },
  {
    "rule_id": "ssh-management-frontend-allow",
    "priority": 49999,
    "action": "ALLOW",
    "direction": "ingress",
    "source": "Allow-list: h36,h37 (10.10.40.36, 10.10.40.37)",
    "destination": "10.10.20.100",
    "destination_port": 2222,
    "status": "installed"
  },
  {
    "rule_id": "ssh-frontend-nonmanagement-drop-h38",
    "priority": 49999,
    "action": "DROP",
    "direction": "ingress",
    "source": "All hosts except h36,h37",
    "destination": "10.10.20.100",
    "destination_port": 2222,
    "status": "installed"
  },
  {
    "rule_id": "device-block-000000000016",
    "priority": 50000,
    "action": "DROP",
    "direction": "ingress",
    "source": "00:00:00:00:00:16",
    "destination": "any",
    "ip": "10.10.50.21",
    "status": "installed",
    "reason": "host block firewall test"
  }
]
```

### Main rule categories

- `default-deny`: Drops traffic that is not explicitly allowed.
- `ssh-management-frontend-allow`: Allows frontend SSH only from `h36` and `h37`.
- `ssh-frontend-nonmanagement-drop-*`: Drops frontend SSH from non-management hosts.
- `ssh-backend-load-balancer-allow-*`: Allows backend SSH from the SSH load balancer.
- `ssh-backend-not-load-balancer-drop-*`: Drops backend SSH from any other source.
- `ssh-ipv6-drop`: Drops IPv6 SSH traffic.
- `device-block-*`: Drops traffic from a quarantined device MAC address.

An active device-block rule uses priority `50000`, action `DROP`, and status `installed`.

After an `UNBLOCK_DEVICE` action, the active `device-block-*` rule is removed, while the historical block and unblock events remain available through `/firewall/events`.

---

## 5. `GET /firewall/events`

### Purpose

Returns normalized firewall events from the topology provider, network event store, and traffic monitor. Duplicate records representing the same block request are removed.

### Verified response examples

#### Host quarantine

```json
{
  "event_type": "firewall_action",
  "action": "BLOCK_DEVICE",
  "mac": "00:00:00:00:00:16",
  "ip": "10.10.50.21",
  "request_id": "block-h21-clean-test-20261126",
  "reason": "host block firewall test"
}
```

#### Unauthorized backend SSH access

```json
{
  "event_type": "ssh_access_denied",
  "action": "DROP",
  "rule_id": "ssh-backend-not-load-balancer-drop-h4",
  "source_host_id": "h22",
  "source_ip": "10.10.50.22",
  "destination_host_id": "h4",
  "destination_ip": "10.10.20.4",
  "destination_port": 22,
  "reason": "backend SSH is allowed only from the SSH load balancer"
}
```

#### Unauthorized frontend SSH access

```json
{
  "event_type": "ssh_access_denied",
  "action": "DROP",
  "rule_id": "ssh-frontend-nonmanagement-drop-h38",
  "source_host_id": "h22",
  "source_ip": "10.10.50.22",
  "destination_host_id": "h38",
  "destination_ip": "10.10.20.100",
  "destination_port": 2222,
  "reason": "source host is not in the SSH frontend allow-list"
}
```

### Scenario-to-reason mapping

| Scenario | Event type | Action | Reason |
|---|---|---|---|
| Host blocking | `firewall_action` | `BLOCK_DEVICE` | Host-specific quarantine reason, such as `host block firewall test` |
| Unauthorized backend SSH | `ssh_access_denied` | `DROP` | `backend SSH is allowed only from the SSH load balancer` |
| Unauthorized frontend SSH | `ssh_access_denied` | `DROP` | `source host is not in the SSH frontend allow-list` |

The reasons are intentionally distinct so that the dashboard and evaluation tests can identify the cause of each blocked flow.

---

## 6. `POST /network/action`

### Purpose

Executes the existing network action used to block or unblock a device. This endpoint was not added as part of the firewall change; it is the existing control endpoint.

### Block request

```json
{
  "action": "BLOCK_DEVICE",
  "ip": "10.10.50.21",
  "mac": "00:00:00:00:00:16",
  "reason": "host block firewall test",
  "request_id": "block-h21-clean-test-20261126"
}
```

### Example response

```json
{
  "success": true,
  "status": "executed",
  "action": "BLOCK_DEVICE",
  "mac": "00:00:00:00:00:16",
  "ip": "10.10.50.21",
  "switches": [5, 2, 6, 1, 3, 4],
  "failed_switches": [],
  "request_id": "block-h21-clean-test-20261126",
  "trust_state_unchanged": true,
  "trust_score_unchanged": true
}
```

### Unblock request

```json
{
  "action": "UNBLOCK_DEVICE",
  "ip": "10.10.50.21",
  "mac": "00:00:00:00:00:16",
  "reason": "host unblock firewall test",
  "request_id": "unblock-h21-clean-test-20261126"
}
```

Control requests must use the configured SecureIoT control-token header in the local lab deployment:

```http
X-SecureIoT-Token: <SECUREIOT_API_TOKEN>
```

Do not place the token in the request body or in source-controlled documentation.

---

## 7. Verification Procedure

### 7.1 Update the API branch

```bash
cd ~/Graduation_Project/IoT-devices

git fetch origin
git switch api-runtime-latest-20261111
git pull --ff-only origin api-runtime-latest-20261111
```

### 7.2 Run the regression test

```bash
python3 test_firewall_dashboard_contract.py
```

Expected output:

```text
PASS: firewall dashboard counters and reasons
```

### 7.3 Restart the Ryu API process

A Git pull does not reload a running Python process. Stop the old Ryu process with `Ctrl+C`, then start it again using the project’s documented Ryu command.

### 7.4 Verify the status contract

```bash
export API="http://127.0.0.1:8080"

curl -fsS "$API/firewall/status" | python3 -c '
import json, sys
x = json.load(sys.stdin)
t = x.get("topology_status", {})
print({
    "top_level_hosts_count_exists": "hosts_count" in x,
    "host_count": t.get("host_count"),
    "blocked_flows": x.get("blocked_flows"),
    "blocked_device_count": t.get("blocked_device_count"),
    "event_count": x.get("event_count")
})
'
```

With one host currently blocked, the expected contract is:

```text
 top_level_hosts_count_exists = False
 host_count                   = 37
 blocked_device_count         = 1
```

The exact `blocked_flows` and `event_count` values depend on the events generated during the current controller session.

### 7.5 Verify unauthorized SSH denial

From Mininet, use a non-management host such as `h3` or `h22`:

```text
h3 nc -vz -w 2 10.10.20.4 22
h3 nc -vz -w 2 10.10.20.20 22
h3 nc -vz -w 2 10.10.20.100 2222
```

The connection attempts should fail or time out. The expected policy is:

- Backend SSH on TCP/22 is allowed only from the SSH load balancer.
- Frontend SSH on TCP/2222 is allowed only from `h36` and `h37`.

Then inspect the events:

```bash
curl -fsS "$API/firewall/events" | python3 -c '
import json, sys
for event in json.load(sys.stdin):
    if event.get("event_type") == "ssh_access_denied":
        print({
            "source_host_id": event.get("source_host_id"),
            "destination_host_id": event.get("destination_host_id"),
            "destination_port": event.get("destination_port"),
            "rule_id": event.get("rule_id"),
            "reason": event.get("reason")
        })
'
```

### 7.6 Verify host blocking

After a successful `BLOCK_DEVICE` request:

```text
 topology_status.host_count = 37
 topology_status.blocked_device_count = 1
 blocked_flows increases by one
```

After the matching `UNBLOCK_DEVICE` request:

```text
 topology_status.host_count = 38
 topology_status.blocked_device_count = 0
```

Use baseline/delta comparisons when historical events already exist in the controller’s in-memory stores.

---

## 8. Verified Implementation Result

The final verification run produced the following result:

```text
host_count            = 37
blocked_flows         = 4
blocked_device_count  = 1
event_count            = 4
```

The four blocked flows consisted of:

```text
1 host-block event
2 unauthorized backend SSH events
1 unauthorized frontend SSH event
```

The API therefore satisfies the requested firewall contract while preserving the original endpoint names and the original `topology_status.host_count` field.

---

## 9. Change Scope

### Changed

- `/firewall/status` now reports the active configured inventory through the existing `topology_status.host_count` field.
- `blocked_flows` counts host blocking and SSH-denial scenarios.
- `/firewall/events` returns distinct, scenario-specific reasons.
- Mirrored block records are deduplicated.
- A focused regression test validates the firewall dashboard contract.

### Not changed

- No new endpoint was introduced.
- `/firewall/rules` endpoint name and purpose were preserved.
- `/network/action` endpoint name and purpose were preserved.
- Unrelated APIs were not modified.
- The top-level `hosts_count` field is not part of the final contract.
