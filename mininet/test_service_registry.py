#!/usr/bin/env python3
"""Smoke test: service registry <-> canonical VLAN config (no Mininet/Ryu)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vlan_config_38host as cfg
from service_registry import ServiceRegistry

reg = ServiceRegistry()
assert set(reg.status()["active"]) == {"dns", "http_api", "https", "ssh"}

for service, pair in cfg.SERVICE_PAIRS.items():
    active = reg.active_backend(service)
    assert active["host"] == pair["primary"] and active["endpoint"] == "primary"
    reg.set_health(service, "primary", False)
    active = reg.active_backend(service)
    assert active["host"] == pair["backup"] and active["ip"] == cfg.host_ip(pair["backup"])
    assert active["vlan"] == pair["vlan"]
    reg.set_health(service, "backup", False)
    assert reg.active_backend(service) is None

reg = ServiceRegistry()
reg.set_health("http_api", "primary", False)
assert [b["ip"] for b in reg.load_balancer_backends(5000)] == ["10.10.20.8"]
assert [b["host"] for b in reg.load_balancer_backends(443)] == ["h3"]
assert reg.load_balancer_backends(53) == []        # DNS is not behind the LB

roles = {spec["role"] for h, spec in cfg.HOSTS.items() if spec["vlan"] == 10}
import iot_device_simulator as sim
assert roles <= set(sim.ROLE_INTERVAL_MULTIPLIER), roles - set(sim.ROLE_INTERVAL_MULTIPLIER)
print("SERVICE REGISTRY / ROLE CONTRACT TESTS: PASS")
