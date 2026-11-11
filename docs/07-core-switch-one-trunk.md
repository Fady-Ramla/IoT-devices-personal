# Core L2 and single-trunk gateway topology

## Proposed switch inventory

The design contains six OpenFlow switches: access switches `s1`, `s2`, `s4`, `s5`, `s6`, plus Core `s3`. The old IoT-access role of `s3` is removed, and the name `s3` is reused for the Core; it has no hosts. The current server-bearing switches are retained: `s1` (primary DNS and API), `s2` (HTTPS, SSH and load balancer), and `s5` (backup DNS/services and employees). Hosts `h5` through `h10` move to `s4`, alongside `h11` through `h16`.

The Linux node `gw` remains the Layer-3 gateway/firewall. Core `s3` is Layer 2 only. One physical Mininet link connects `gw-eth0` to `s3` as an 802.1Q trunk carrying VLANs 10, 20, 30, 40 and 50. The gateway creates Linux VLAN subinterfaces `gw-eth0.10` through `gw-eth0.50` and retains the current `.1/24` gateway address in each VLAN. Each subinterface is assigned a unique locally administered MAC address; this is required because TopologyMonitor currently treats a learned MAC as belonging to one VLAN.

## Switch links

The design keeps seven existing mesh links among the retained access switches:

- `s1-s2`, `s1-s5`, `s2-s4`, `s2-s5`, `s4-s5`, `s4-s6`, `s5-s6`

It adds five trunks from Core `s3` to `s1`, `s2`, `s4`, `s5` and `s6`, for twelve inter-switch links total. The single `gw-s3` trunk is a separate host-to-switch link and is not included in the inter-switch-link count.

Every switch has at least three incident links in the switch graph. The static test verifies that removing any one inter-switch link leaves all six switches connected. This does not protect against failure of Core `s3` itself: the Gateway has one physical uplink and becomes unreachable if the Core fails.

## Ryu and VLAN-map requirements

Ryu expects six switches named exactly `s1`, `s2`, `s3`, `s4`, `s5`, `s6`, and twelve inter-switch links. The VLAN port map contains 38 host access ports, 24 inter-switch trunk endpoints and one gateway trunk endpoint. The gateway trunk role must be preserved in the map so Ryu accepts tagged frames from the Linux VLAN subinterfaces and applies the same VLAN allowlist.

CLFF is used to keep broadcast forwarding loop-free over the physical mesh. It does not remove the redundant physical links. Ryu's topology discovery, VLAN-map validation, flow forwarding and reroute behavior must be exercised in the target Mininet/Ryu VM before treating this proposal as operational.

## Validation

Run the repository-level static checks with:

```bash
python3 mininet/test_core_switch_trunk.py
```

The test does not start Mininet or Ryu and does not change a real network namespace. Full validation still needs a target-VM test: start Ryu, start Mininet, confirm six switch connections and a ready VLAN map, test allowed/denied inter-VLAN paths, then disable one mesh link and confirm recovery. Do not test by removing Core `s3`; it currently is a single point for Gateway reachability.
