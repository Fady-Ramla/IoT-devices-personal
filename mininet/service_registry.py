#!/usr/bin/env python3
"""Primary/backup service registry for the SecureIoT target topology."""

from copy import deepcopy
from threading import RLock

from vlan_config_38host import HOSTS, LOAD_BALANCER, SERVICE_PAIRS, host_ip


class ServiceRegistry:
    """Track service health without making security decisions."""

    def __init__(self):
        self._lock = RLock()
        self._health = {
            service: {"primary": True, "backup": True}
            for service in SERVICE_PAIRS
        }

    def set_health(self, service, endpoint, healthy):
        if service not in SERVICE_PAIRS:
            raise KeyError(f"Unknown service: {service}")
        if endpoint not in ("primary", "backup"):
            raise ValueError("endpoint must be primary or backup")
        with self._lock:
            self._health[service][endpoint] = bool(healthy)

    def active_backend(self, service):
        with self._lock:
            pair = SERVICE_PAIRS[service]
            health = self._health[service]
            if health["primary"]:
                host = pair["primary"]
            elif health["backup"]:
                host = pair["backup"]
            else:
                return None
            return {
                "service": service,
                "host": host,
                "ip": host_ip(host),
                "port": pair["port"],
                "vlan": pair["vlan"],
                "endpoint": "primary" if host == pair["primary"] else "backup",
            }

    def load_balancer_backends(self, frontend_port):
        for service, pair in SERVICE_PAIRS.items():
            if pair["port"] == frontend_port and frontend_port in LOAD_BALANCER["frontends"]:
                active = self.active_backend(service)
                return [active] if active else []
        return []

    def status(self):
        with self._lock:
            result = deepcopy(self._health)
            result["active"] = {
                service: self.active_backend(service)
                for service in SERVICE_PAIRS
            }
            result["load_balancer"] = {
                "host": LOAD_BALANCER["host"],
                "frontends": deepcopy(LOAD_BALANCER["frontends"]),
            }
            return result


registry = ServiceRegistry()


if __name__ == "__main__":
    import json
    print(json.dumps(registry.status(), indent=2))
