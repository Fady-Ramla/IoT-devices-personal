#!/usr/bin/env python3
"""SecureIoT 38-host target topology.

This file is the Mininet implementation of
SECUREIOT_TARGET_DESIGN_38HOSTS_FINAL.md.

Run Ryu first with EXPECTED_SWITCHES=6 and EXPECTED_PHYSICAL_LINKS=11.
The topology creates a Linux gateway node with five zone interfaces and
installs a conservative inter-zone iptables policy. VLAN access/trunk
programming is kept explicit in configure_ovs_zones so it can be audited
against the VLAN-aware Ryu forwarding implementation before production tests.
"""

import os
import sys
import time
import csv
import json
import math
import re
import shlex
import uuid
import urllib.request
from types import SimpleNamespace
from attack_manager import (
    run_attack, run_experiment, validate_duration, validate_syn_parameters,
    validate_ipv4, build_syn_command, MAX_RATE_PPS, MAX_DURATION_SEC,
    MAX_NORMAL_DURATION_SEC,
)

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import info, setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.topo import Topo

from configure_gateway import configure_gateway
from vlan_config_38host import HOSTS, INTER_SWITCH_LINKS, NETWORKS, host_cidr, gateway_for


RYU_IP = os.getenv("RYU_IP", "127.0.0.1")
RYU_PORT = int(os.getenv("RYU_PORT", "6633"))
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VLAN_PORT_MAP_FILE = os.getenv(
    "SECUREIOT_VLAN_PORT_MAP",
    os.path.join(PROJECT_ROOT, "New_Datasets", "config", "vlan_port_map.json"),
)


class SecureIoT38Topo(Topo):
    def build(self):
        switches = {name: self.addSwitch(name, cls=OVSSwitch)
                    for name in ("s1", "s2", "s3", "s4", "s5", "s6")}
        gateway = self.addHost("gw", ip=None)

        for host_id, spec in HOSTS.items():
            host = self.addHost(
                host_id,
                ip=host_cidr(host_id),
                defaultRoute=f"via {gateway_for(host_id)}",
            )
            self.addLink(host, switches[spec["switch"]])

        # Five routed zone interfaces. Interface order is stable because these
        # links are created in this order: IoT, services, DNS, management, employees.
        for zone_switch in ("s3", "s2", "s2", "s6", "s5"):
            self.addLink(gateway, switches[zone_switch])

        for left, right in INTER_SWITCH_LINKS:
            self.addLink(switches[left], switches[right])


def clear_vlan_port_map():
    try:
        os.unlink(VLAN_PORT_MAP_FILE)
    except FileNotFoundError:
        pass


def _switch_port_for_node(switch, node, node_intf_name=None):
    connections = switch.connectionsTo(node)
    if not connections:
        raise RuntimeError("no link between %s and %s" % (switch.name, node.name))
    for pair in connections:
        if node_intf_name is not None and not any(
            getattr(intf, "node", None) is node and intf.name == node_intf_name
            for intf in pair
        ):
            continue
        for intf in pair:
            if getattr(intf, "node", None) is switch:
                port_no = switch.ports.get(intf)
                if port_no is not None:
                    return int(port_no)
    raise RuntimeError("cannot resolve OVS port for %s -> %s" % (switch.name, node.name))


def _switch_interface_for_node_interface(switch, node, node_intf_name):
    """Return the OVS interface paired with one exact node-side interface."""
    for pair in switch.connectionsTo(node):
        node_side = next(
            (intf for intf in pair
             if getattr(intf, "node", None) is node
             and intf.name == node_intf_name),
            None,
        )
        if node_side is None:
            continue
        switch_side = next(
            (intf for intf in pair if getattr(intf, "node", None) is switch),
            None,
        )
        if switch_side is not None:
            return switch_side
    raise RuntimeError(
        "cannot resolve OVS interface for %s -> %s:%s"
        % (switch.name, node.name, node_intf_name)
    )


def _switch_dpid(switch):
    value = switch.dpid
    return int(value, 16) if isinstance(value, str) else int(value)


def _write_vlan_port_map(net):
    """Publish configured access/trunk VLAN membership for Ryu fail-closed."""
    allowed_vlans = sorted(int(vlan_id) for vlan_id in NETWORKS)
    records = []

    def add_record(switch, node, kind, vlan_id=None, role="endpoint", node_intf_name=None):
        record = {
            "dpid": _switch_dpid(switch),
            "switch": switch.name,
            "port_no": _switch_port_for_node(switch, node, node_intf_name),
            "kind": kind,
            "role": role,
            "vlan_id": int(vlan_id) if vlan_id is not None else None,
            "allowed_vlans": allowed_vlans if kind == "trunk" else [],
        }
        records.append(record)

    for host_id, spec in HOSTS.items():
        add_record(net.get(spec["switch"]), net.get(host_id), "access", spec["vlan"])

    gateway_zones = (
        ("gw-eth0", "s3", 10),
        ("gw-eth1", "s2", 20),
        ("gw-eth2", "s2", 30),
        ("gw-eth3", "s6", 40),
        ("gw-eth4", "s5", 50),
    )
    gateway = net.get("gw")
    for gateway_intf, switch_name, vlan_id in gateway_zones:
        switch = net.get(switch_name)
        add_record(
            switch, gateway, "access", vlan_id,
            role="gateway", node_intf_name=gateway_intf)

    for left_name, right_name in INTER_SWITCH_LINKS:
        left, right = net.get(left_name), net.get(right_name)
        for switch, neighbor in ((left, right), (right, left)):
            add_record(switch, neighbor, "trunk")

    identities = [(row["dpid"], row["port_no"]) for row in records]
    if len(identities) != len(set(identities)):
        raise RuntimeError("duplicate switch/port in VLAN map")
    access_count = sum(row["kind"] == "access" for row in records)
    trunk_count = sum(row["kind"] == "trunk" for row in records)
    if (len(HOSTS) != 38 or access_count != 43 or trunk_count != 22
            or len(records) != 65 or len(allowed_vlans) != 5):
        raise RuntimeError(
            "unexpected VLAN map size: hosts=%d access=%d trunks=%d vlans=%d"
            % (len(HOSTS), access_count, trunk_count, len(allowed_vlans))
        )

    payload = {
        "schema_version": 2,
        "topology_id": uuid.uuid4().hex,
        "expected_switches": 6,
        "expected_inter_switch_links": 11,
        "host_count": len(HOSTS),
        "allowed_vlans": allowed_vlans,
        "networks": {str(key): value for key, value in NETWORKS.items()},
        "ports": records,
    }
    os.makedirs(os.path.dirname(VLAN_PORT_MAP_FILE), exist_ok=True)
    temp_path = VLAN_PORT_MAP_FILE + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp_path, VLAN_PORT_MAP_FILE)
    info("*** VLAN port map published: %d access, %d trunk ports\n", access_count, trunk_count)


def configure_ovs_zones(net):
    """Apply access VLAN tags to host ports and gateway zone ports.

    Ryu must preserve VLAN tags when forwarding trunks. This function is kept
    separate so VLAN-aware controller enforcement can be verified before the
    final integration run.
    """
    # Mininet assigns host links before gateway links and inter-switch links.
    # We discover host-facing ports from OVS interface names instead of assuming
    # numeric port values in the documentation.
    for host_id, spec in HOSTS.items():
        switch = net.get(spec["switch"])
        host = net.get(host_id)
        connections = switch.connectionsTo(host)
        if not connections:
            raise RuntimeError(f"No link found for {host_id} on {switch.name}")
        switch_intf, _ = connections[0]
        result = switch.cmd(
            f"ovs-vsctl set Port {switch_intf.name} tag={spec['vlan']}"
        )
        if result.strip():
            info("[vlan] %s", result)

    # Configure each gateway-facing link as an access port for its zone.
    # The gateway uses one untagged Linux interface per VLAN, so these OVS
    # ports must add/remove the VLAN tag at the switch boundary.
    gateway_zones = (
        ("gw-eth0", "s3", 10),  # IoT
        ("gw-eth1", "s2", 20),  # Services
        ("gw-eth2", "s2", 30),  # DNS
        ("gw-eth3", "s6", 40),  # IT management
        ("gw-eth4", "s5", 50),  # Employees
    )
    gateway = net.get("gw")
    for gateway_intf_name, switch_name, vlan in gateway_zones:
        switch = net.get(switch_name)
        switch_intf = _switch_interface_for_node_interface(
            switch, gateway, gateway_intf_name)
        result = switch.cmd(
            f"ovs-vsctl set Port {switch_intf.name} tag={vlan} trunks=[]"
        )
        if result.strip():
            info("[vlan] %s", result)

    # Configure every inter-switch link as an 802.1Q trunk. Without this,
    # access VLANs remain local to a switch and same-VLAN hosts on different
    # switches cannot communicate.
    trunk_vlans = ",".join(str(vlan) for vlan in sorted(NETWORKS))
    for left_name, right_name in INTER_SWITCH_LINKS:
        left = net.get(left_name)
        right = net.get(right_name)
        connections = left.connectionsTo(right)
        if not connections:
            raise RuntimeError(
                f"No inter-switch link found between {left_name} and {right_name}"
            )
        for left_intf, right_intf in connections:
            for switch, switch_intf in (
                (left, left_intf),
                (right, right_intf),
            ):
                result = switch.cmd(
                    f"ovs-vsctl set Port {switch_intf.name} tag=[] "
                    f"trunks={trunk_vlans}"
                )
                if result.strip():
                    info("[trunk] %s", result)

    _write_vlan_port_map(net)


def start_iot_simulators(net):
    """Start one synthetic telemetry process on each IoT host h5-h16."""
    project_dir = os.path.dirname(os.path.abspath(__file__))
    simulator = os.path.join(project_dir, "iot_device_simulator.py")
    interval = float(os.getenv("IOT_TELEMETRY_INTERVAL", "10"))
    target = os.getenv("IOT_TELEMETRY_SERVER", "10.10.20.2")
    port = int(os.getenv("IOT_TELEMETRY_PORT", "5000"))

    for host_id in (f"h{i}" for i in range(5, 17)):
        spec = HOSTS[host_id]
        host = net.get(host_id)
        log_path = f"/tmp/secureiot-{host_id}-iot.log"
        command = (
            f"python3 {simulator} --device-id {host_id} --role {spec['role']} "
            f"--server {target} --port {port} --interval {interval} "
            f"> {log_path} 2>&1 &"
        )
        host.cmd(command)
    info("*** IoT simulators started for h5-h16; target=%s:%s interval=%ss\n", target, port, interval)
    info("*** Per-device logs: /tmp/secureiot-h5-iot.log through /tmp/secureiot-h16-iot.log\n")


def print_inventory():
    info("\n=== SecureIoT 38-host topology ===\n")
    info("Switches: s1-s6 | inter-switch links: 11\n")
    info("VLAN 10 IoT:          10.10.10.0/24\n")
    info("VLAN 20 Services:     10.10.20.0/24\n")
    info("VLAN 30 DNS:          10.10.30.0/24\n")
    info("VLAN 40 IT Management:10.10.40.0/24\n")
    info("VLAN 50 Employees:    10.10.50.0/24\n")
    info("Primary: h1-h4 | IoT: h5-h16 | Backup: h17-h20\n")
    info("Employees: h21-h35 | IT Admin: h36-h37 | LB: h38\n")
    info("Load balancer: h38:5000 -> h2/h18, h38:443 -> h3/h19\n")
    info("\nUseful checks: pingall, net, links, nodes, gw iptables -L -n -v\n\n")


def start_demo_services(net):
    """Start HTTP backends and TCP load-balancer listeners for local tests."""
    project_dir = os.path.dirname(os.path.abspath(__file__))
    service_stub = os.path.join(project_dir, "service_stub.py")
    load_balancer = os.path.join(project_dir, "load_balancer.py")

    for host_id, port, name in (
        ("h2", 5000, "primary-web-api"),
        ("h18", 5000, "backup-web-api"),
    ):
        net.get(host_id).cmd(
            f"python3 {service_stub} --host 0.0.0.0 --port {port} --name {name} "
            f"> /tmp/{name}.log 2>&1 &"
        )

    lb = net.get("h38")
    lb.cmd(
        f"python3 {load_balancer} --listen-port 5000 "
        "--backends 10.10.20.2:5000,10.10.20.8:5000 "
        "> /tmp/lb-5000.log 2>&1 &"
    )
    info("*** Demo Web/API backends and h38:5000 load balancer started.\n")


def wait_for_controller_ready(timeout_sec=60):
    """Wait until the telemetry collector sees all six OpenFlow switches."""
    url = "http://127.0.0.1:8080/dataset/run/status"
    deadline = time.monotonic() + timeout_sec
    last_error = "no status received"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                status = json.loads(response.read().decode("utf-8"))
            state = status.get("state")
            prior_run_drained = (
                state == "drained"
                and status.get("durable") is True
                and not status.get("pending_final_switches")
                and not status.get("drain_errors")
                and not status.get("error")
                and not status.get("closed")
            )
            if (status.get("success")
                    and int(status.get("connected_switches", 0)) == 6
                    and (state == "idle" or prior_run_drained)):
                info("*** Collector ready: six switches connected; run state=%s.\n" % state)
                return
            last_error = "collector status=" + json.dumps(status, sort_keys=True)
        except Exception as exc:
            last_error = str(exc)
        time.sleep(1)
    raise RuntimeError(
        "Ryu collector did not become ready within %s seconds: %s"
        % (timeout_sec, last_error)
    )


def start_project_web_api(net):
    """Start the Flask API with ephemeral demo auth and an isolated v2 event sink."""
    host = net.get("h2")
    project_dir = os.path.dirname(os.path.abspath(__file__))
    server = os.path.join(project_dir, "servers", "web_api_server.py")
    prepare_auth = os.path.join(project_dir, "servers", "prepare_demo_auth.py")
    auth_env = "/tmp/trustflow_demo_auth.env"
    application_dir = os.path.abspath(os.path.join(
        project_dir, "..", "New_Datasets", "raw", "application_v2"
    ))
    health_url = "http://127.0.0.1:5000/health"

    def healthy_response():
        return host.cmd(
            "curl -fsS --max-time 1 %s 2>/dev/null" % shlex.quote(health_url)
        )

    prepared = host.cmd(
        "python3 %s --output %s 2>&1"
        % (shlex.quote(prepare_auth), shlex.quote(auth_env))
    )
    if "credentials prepared" not in prepared:
        raise RuntimeError("could not prepare ephemeral demo auth: " + prepared.strip())

    response = healthy_response()
    if '"IoT Web/API Server"' in response and '"healthy"' in response:
        # h2 is the dedicated lab Web/API host. Restart only this project app so
        # it cannot keep stale auth settings or write into the app-v1 directory.
        host.cmd("pkill -f '[w]eb_api_server.py' >/dev/null 2>&1 || true")
        time.sleep(0.5)

    launch = (
        "set -a; . %s; export SECUREIOT_APPLICATION_DATA_DIR=%s; set +a; "
        "python3 %s > /tmp/web_api_h2_appv2.log 2>&1 &"
        % (shlex.quote(auth_env), shlex.quote(application_dir), shlex.quote(server))
    )
    host.cmd(launch)
    deadline = time.monotonic() + 20
    healthy = False
    while time.monotonic() < deadline:
        response = healthy_response()
        if '"IoT Web/API Server"' in response and '"healthy"' in response:
            healthy = True
            break
        time.sleep(0.5)
    if not healthy:
        tail = host.cmd("tail -n 20 /tmp/web_api_h2_appv2.log 2>/dev/null")
        raise RuntimeError(
            "project Flask Web/API did not become healthy on h2:5000; "
            "log tail: " + tail.strip()
        )

    # Prove the configured demo credential succeeds and a wrong password fails.
    # The probe runs before any collection latch is active, so it is not dataset data.
    valid_payload = r'{\"username\":\"${ADMIN_USERNAME}\",\"password\":\"${TRUSTFLOW_DEMO_PASSWORD}\"}'
    valid_url = "http://127.0.0.1:5000/login"
    invalid_payload = '{"username":"invalid_probe","password":"invalid"}'
    auth_probe = (
        "set -a; . %s; set +a; "
        "valid=$(curl -4 -sS --connect-timeout 1 --max-time 2 -o /dev/null "
        "-w '%%{http_code}' -H 'Content-Type: application/json' "
        "--data-binary \"%s\" %s) && "
        "invalid=$(curl -4 -sS --connect-timeout 1 --max-time 2 -o /dev/null "
        "-w '%%{http_code}' -H 'Content-Type: application/json' "
        "--data-binary %s %s) && "
        "test \"$valid\" = 200 && test \"$invalid\" = 401 && echo AUTH_READY"
        % (shlex.quote(auth_env), valid_payload, shlex.quote(valid_url),
           shlex.quote(invalid_payload), shlex.quote(valid_url))
    )
    probe_result = host.cmd(auth_probe)
    if "AUTH_READY" not in probe_result:
        tail = host.cmd("tail -n 20 /tmp/web_api_h2_appv2.log 2>/dev/null")
        raise RuntimeError(
            "demo login controls failed: expected valid=200 and invalid=401; "
            "auth probe=%r; log tail: %s" % (probe_result.strip(), tail.strip())
        )
    info("*** Project Web/API ready: demo auth verified; app-v2 telemetry isolated.\n")
    return


def start_project_https(net):
    """Start and verify the real HTTPS server on h3:443 with a lab-local cert."""
    server_host = net.get("h3")
    client_host = net.get("h5")
    project_dir = os.path.dirname(os.path.abspath(__file__))
    server = os.path.join(project_dir, "servers", "https_server.py")
    cert_dir = "/tmp/https_server"
    cert = cert_dir + "/cert.pem"
    key = cert_dir + "/key.pem"
    make_cert = server_host.cmd(
        "mkdir -p %s && openssl req -x509 -nodes -days 2 -newkey rsa:2048 "
        "-subj '/CN=10.10.20.3' -keyout %s -out %s "
        ">/tmp/https_cert.log 2>&1 && test -s %s && test -s %s && echo CERT_READY"
        % (shlex.quote(cert_dir), shlex.quote(key), shlex.quote(cert),
           shlex.quote(key), shlex.quote(cert))
    )
    if "CERT_READY" not in make_cert:
        raise RuntimeError("could not prepare lab HTTPS certificate: " + make_cert.strip())

    server_host.cmd(
        "env HTTPS_SERVER_IP=10.10.20.3 HTTPS_SERVER_PORT=443 "
        "HTTPS_CERT_FILE=%s HTTPS_KEY_FILE=%s python3 %s "
        "> /tmp/https_h3.log 2>&1 &"
        % (shlex.quote(cert), shlex.quote(key), shlex.quote(server))
    )
    deadline = time.monotonic() + 20
    last_response = ""
    while time.monotonic() < deadline:
        last_response = client_host.cmd(
            "curl -4 -k -sS --connect-timeout 1 --max-time 2 "
            "-o /dev/null -w '%{http_code}' https://10.10.20.3/ 2>/dev/null"
        ).strip()
        if last_response == "200":
            info("*** Project HTTPS ready on h3:443; reachable from h5.\n")
            return
        time.sleep(0.5)
    tail = server_host.cmd("tail -n 20 /tmp/https_h3.log /tmp/https_cert.log 2>/dev/null")
    raise RuntimeError(
        "project HTTPS did not become healthy from h5 (last HTTP status=%r): %s"
        % (last_response, tail.strip())
    )


def service_name_for_target(target_name, attack_type, dst_port):
    """Record the known service at the target, not the attack mechanism."""
    if target_name == 'h18':
        if attack_type == 'port_scan':
            try:
                low, high = map(int, str(dst_port).split('-', 1))
                midpoint = (low + high) / 2.0
                return 'https_backup' if abs(midpoint - 443) < abs(midpoint - 5000) else 'http_api_backup'
            except (TypeError, ValueError):
                return 'backup_service'
        return 'https_backup' if str(dst_port) == '443' else 'http_api_backup'
    if target_name == 'h38':
        return 'load_balancer'
    return {
        'h1': 'dns',
        'h2': 'http_api',
        'h3': 'https',
        'h4': 'ssh',
        'h17': 'dns_backup',
        'h19': 'https_backup',
        'h20': 'ssh_backup',
    }.get(target_name, 'unknown_service')


def build_attack_spec(attack_type, dst_ip, parameters):
    """Pure command builder: validate first, never send traffic or change plans.

    SYN is 10..200 pps and 5..20 seconds. Scan/POST use an explicit
    5..20-second wall-clock cap; a timed-out bounded slice is not a complete
    scan or evidence that all requested POSTs finished.
    """
    dst_ip = validate_ipv4(dst_ip)
    parameters = list(parameters)
    notes = {}
    duration = MAX_DURATION_SEC
    if attack_type == 'syn_flood':
        if len(parameters) > 3:
            raise ValueError('syn_flood syntax: [dst_port] [rate_pps] [duration_sec]')
        port = int(parameters[0]) if parameters else 5000
        if not 1 <= port <= 65535:
            raise ValueError('destination port must be 1..65535')
        rate = int(parameters[1]) if len(parameters) >= 2 else 100
        duration = int(parameters[2]) if len(parameters) >= 3 else 10
        rate, duration, interval_us = validate_syn_parameters(rate, duration)
        command = build_syn_command(dst_ip, port, rate, duration)
        service = {5000: 'http_api', 443: 'https', 22: 'ssh', 53: 'dns'}.get(port, 'tcp')
        notes = {'rate_unit': 'pps', 'interval_us': interval_us,
                 'max_packets': rate * duration, 'duration_is_cap': True}
    elif attack_type == 'port_scan':
        if len(parameters) > 3:
            raise ValueError('port_scan syntax: [port_range] [delay_ms] [duration_sec]')
        port = parameters[0] if parameters else '1-1000'
        delay_ms = int(parameters[1]) if len(parameters) >= 2 else 100
        duration = int(parameters[2]) if len(parameters) >= 3 else MAX_DURATION_SEC
        validate_duration(duration)
        if not re.fullmatch(r'\d{1,5}-\d{1,5}', port):
            raise ValueError('port_scan range must be N-M')
        low, high = map(int, port.split('-'))
        if not (1 <= low <= high <= 65535 and 0 <= delay_ms <= 5000):
            raise ValueError('invalid scan ports/delay: 1..65535, 0..5000ms')
        rate = min(MAX_RATE_PPS, 1000.0 / delay_ms) if delay_ms else MAX_RATE_PPS
        command = ('timeout --signal=TERM --kill-after=1s %ds '
                   'nmap -n -Pn -sS -p %s --scan-delay %dms --max-rate %d '
                   '--max-retries 1 %s' % (duration, port, delay_ms, MAX_RATE_PPS, dst_ip))
        service = 'port_scan'
        notes = {'rate_unit': 'pps_ceiling', 'scan_delay_ms': delay_ms,
                 'duration_is_cap': True, 'full_scan_guaranteed': False}
    elif attack_type == 'malicious_post':
        if not 1 <= len(parameters) <= 5:
            raise ValueError('malicious_post syntax: <endpoint> [count] [delay_ms] [workers] [duration_sec]')
        endpoint = parameters[0]
        count = int(parameters[1]) if len(parameters) >= 2 else 100
        delay_ms = int(parameters[2]) if len(parameters) >= 3 else 100
        workers = int(parameters[3]) if len(parameters) >= 4 else 1
        duration = int(parameters[4]) if len(parameters) >= 5 else MAX_DURATION_SEC
        validate_duration(duration)
        if (not endpoint.startswith('/') or len(endpoint) > 2048
                or any(char in endpoint for char in '\r\n')
                or not (1 <= count <= MAX_RATE_PPS * MAX_DURATION_SEC)
                or not (1 <= workers <= 50) or not (1 <= delay_ms <= 60000)):
            raise ValueError('POST requires /path, count 1..4000, delay 1..60000ms, workers 1..50')
        # There is one sleep after EACH launch; workers only cap concurrency,
        # not the launch rate. Waiting at batch boundaries reduces this ceiling.
        rate = 1000.0 / delay_ms
        if rate > MAX_RATE_PPS:
            raise ValueError('POST launch rate must be <=200 requests/sec (delay >=5ms)')
        if count > int(rate * duration):
            raise ValueError('POST count exceeds rate × duration; lower count or raise duration')
        url = shlex.quote('http://' + dst_ip + ':5000' + endpoint)
        request = (
            "status=$(curl -4 -sS --connect-timeout 1 --max-time 2 -o /dev/null "
            "-w '%{http_code}' --http1.1 -X POST "
            "-H 'Content-Type: application/json' "
            "-d '{\"username\":\"attack_probe\",\"password\":\"invalid\"}' "
            + url + ") && test \"$status\" = 401"
        )
        # Wait for EVERY child at each batch boundary and preserve transport
        # failures. The outer timeout kills the whole shell process group.
        loop = ('failed=0; pids=""; for i in $(seq 1 %d); do %s & '
                'pids="$pids $!"; sleep %.6f; '
                'if [ $((i %% %d)) -eq 0 ]; then '
                'for pid in $pids; do wait "$pid" || failed=1; done; pids=""; fi; '
                'done; for pid in $pids; do wait "$pid" || failed=1; done; exit "$failed"' %
                (count, request, delay_ms / 1000.0, workers))
        command = 'timeout --signal=TERM --kill-after=1s %ds sh -c %s' % (duration, shlex.quote(loop))
        port, service = 5000, 'http_api'
        notes = {'rate_unit': 'requests_per_second_ceiling', 'count': count,
                 'delay_ms': delay_ms, 'workers': workers, 'endpoint': endpoint,
                 'duration_is_cap': True, 'requested_count_guaranteed': False}
    else:
        raise ValueError('unknown attack type: ' + attack_type)
    return dict(command=command, dst_port=str(port), src_port='*', protocol='TCP',
                service_name=service, rate_value=rate, duration_sec=duration,
                accepted_returncodes=(0, 124), notes=json.dumps(notes, sort_keys=True))


class AttackCLI(CLI):

    def do_attack(self, line):
        # cmd.Cmd treats any truthy handler return as a request to exit.
        self._last_run_error = None
        try:
            args = shlex.split(line)
            if len(args) < 3:
                print('Usage: attack <attacker> <syn_flood|port_scan|malicious_post> <target> [parameters]')
                return False
            attacker_name, attack_type, target_name = args[:3]
            attacker, target = self.mn.get(attacker_name), self.mn.get(target_name)
            dst_ip = validate_ipv4(target.IP())
            specification = build_attack_spec(attack_type, dst_ip, args[3:])
            specification['service_name'] = service_name_for_target(
                target.name, attack_type, specification['dst_port'])
            row = run_attack(attacker=attacker, attack_type=attack_type, dst_ip=dst_ip,
                             target_host=target.name, **specification)
            print('Run finished: run_id=%s status=%s' % (row.get('run_id'), row.get('status')))
        except Exception as exc:
            self._last_run_error = exc
            print('Run failed; no next run was started: %s' % exc)
        return False

    def do_normal(self, line):
        self._last_run_error = None
        try:
            row = run_normal_plan(self.mn, line)
            print('Run finished: run_id=%s status=%s' % (row.get('run_id'), row.get('status')))
        except Exception as exc:
            self._last_run_error = exc
            print('Run failed; no next run was started: %s' % exc)
        return False


def run_batch_plan(net, plan_path):
    """Run one command per CSV row through the existing AttackCLI logic."""
    if not os.path.exists(plan_path):
        raise RuntimeError('batch plan not found: ' + plan_path)
    with open(plan_path, newline='', encoding='utf-8') as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise RuntimeError('batch plan is empty: ' + plan_path)
    runner = SimpleNamespace(mn=net)
    # Validate all pauses before any run. No CSV plan is rewritten.
    pauses = [float(row.get('pause_after_sec') or 5) for row in rows]
    if any(not math.isfinite(pause) or not 0 <= pause <= 60 for pause in pauses):
        raise ValueError('batch pauses must be finite in 0..60 seconds')
    info('\n*** Starting automated collection batch: %s\n' % plan_path)
    for index, row in enumerate(rows, 1):
        command = (row.get('command') or '').strip()
        if not (command.startswith('attack ') or command.startswith('normal ')):
            raise RuntimeError('plan row %d must start with attack or normal: %s' % (index, command))
        info('*** Batch run %d/%d: %s\n' % (index, len(rows), command))
        if command.startswith('attack '):
            AttackCLI.do_attack(runner, command[len('attack '):])
            if runner._last_run_error is not None:
                raise runner._last_run_error
        else:
            result = run_normal_plan(net, command[len('normal '):])
            info('*** Run finished: run_id=%s status=%s\n' %
                 (result.get('run_id'), result.get('status')))
        # Both functions return only after the SAME run is drained and committed.
        time.sleep(pauses[index - 1])
    info('*** Automated collection batch completed.\n')


def run_normal_plan(net, specification, *, controller=None, manifest_path=None, executor=None):
    """Run bounded normal HTTP/HTTPS requests and isolated auth controls."""
    args = shlex.split(specification)
    if len(args) not in (4, 5):
        raise RuntimeError('normal syntax: <client> <service> <target> <duration_sec> [rate_rps]')
    client_name, service, target_name, duration_text = args[:4]
    duration = int(duration_text)
    validate_duration(duration, MAX_NORMAL_DURATION_SEC)
    rate = float(args[4]) if len(args) == 5 else 1.0
    if not math.isfinite(rate) or not 0.5 <= rate <= 5.0:
        raise ValueError('normal request-rate ceiling must be 0.5..5 requests/sec')
    target = net.get(target_name)
    client = net.get(client_name)
    target_ip = validate_ipv4(target.IP())
    if service in {'http_api', 'load_balancer'}:
        port, url, extra = 5000, 'http://%s:5000/health' % target_ip, ''
    elif service == 'http_api_telemetry':
        port = 5000
        url = 'http://%s:5000/api/iot/telemetry' % target_ip
        extra = ("--header 'Content-Type: application/json' "
                 "--data-binary '{\"device_id\":\"normal-telemetry-probe\","
                 "\"device_role\":\"telemetry_probe\","
                 "\"telemetry\":{\"status\":\"ok\"}}' ")
    elif service == 'http_api_login_read':
        port, url, extra = 5000, 'http://%s:5000/login' % target_ip, ''
    elif service in {'http_api_login_success', 'http_api_login_invalid_once'}:
        port, url, extra = 5000, 'http://%s:5000/login' % target_ip, ''
    elif service == 'https':
        port, url, extra = 443, 'https://%s/' % target_ip, '-k '
    else:
        raise RuntimeError('unsupported normal service: ' + service)
    single_login_control = service in {
        'http_api_login_success', 'http_api_login_invalid_once'
    }
    request_count = 1 if single_login_control else max(1, int(math.floor(rate * duration)))
    interval = 1.0 / rate
    # Sleep before each request after the first. The timeout remains a hard cap;
    # requests/sec is a ceiling, and the actual observed rate may be lower.
    if service == 'http_api_login_success':
        auth_env = '/tmp/trustflow_demo_auth.env'
        payload = r'{\"username\":\"${ADMIN_USERNAME}\",\"password\":\"${TRUSTFLOW_DEMO_PASSWORD}\"}'
        request = (
            'set -a; . %s; set +a; '
            'status=$(curl -4 -sS --connect-timeout 1 --max-time 2 -o /dev/null '
            "-w '%%{http_code}' -H 'Content-Type: application/json' "
            '--data-binary "%s" %s) && test "$status" = 200'
            % (shlex.quote(auth_env), payload, shlex.quote(url))
        )
    elif service == 'http_api_login_invalid_once':
        request = (
            'status=$(curl -4 -sS --connect-timeout 1 --max-time 2 -o /dev/null '
            "-w '%%{http_code}' -H 'Content-Type: application/json' "
            "--data-binary '{\"username\":\"normal_typo_probe\",\"password\":\"wrong\"}' "
            '%s) && test "$status" = 401' % shlex.quote(url)
        )
    else:
        request = ('curl -4 %s-sS --fail --connect-timeout 1 --max-time 2 '
                   '-o /dev/null %s' % (extra, shlex.quote(url)))
    loop = ('i=0; for _ in $(seq 1 %d); do '
            'if [ "$i" -gt 0 ]; then sleep %.6f; fi; '
            '%s || exit $?; i=$((i+1)); done' %
            (request_count, interval, request))
    command = 'timeout --signal=TERM --kill-after=1s %ds sh -c %s' % (
        duration, shlex.quote(loop))
    return run_experiment(
        client, command, run_type='normal', label='Normal',
        target_host=target.name, target_ip=target_ip,
        service_name=service, protocol='TCP', dst_port=str(port), src_port='*',
        rate_value=rate, duration_sec=duration, experiment_category='normal_baseline',
        accepted_returncodes=(0, 124),
        notes=json.dumps({'rate_unit': 'requests_per_second_ceiling',
                          'request_count_cap': request_count,
                          'duration_is_cap': True,
                          'auth_control': service if single_login_control else None}),
        controller=controller, manifest_path=manifest_path, executor=executor,
    )


def run():
    net = Mininet(
        topo=SecureIoT38Topo(),
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
    )
    net.addController("c0", controller=RemoteController, ip=RYU_IP, port=RYU_PORT)

    info("*** Starting 38-host SecureIoT topology\n")
    clear_vlan_port_map()
    started = False
    try:
        net.start()
        started = True
        time.sleep(5)

        configure_gateway(net.get("gw"))
        configure_ovs_zones(net)
        batch_path = os.getenv("SECUREIOT_BATCH_PLAN", "").strip()
        if batch_path and os.getenv("START_DEMO_SERVICES", "0") == "1":
            raise RuntimeError(
                "dataset batch cannot use demo service stubs; unset START_DEMO_SERVICES"
            )
        if batch_path and os.getenv("START_IOT_SIMULATORS", "0") == "1":
            raise RuntimeError(
                "dataset batch cannot include background IoT simulators"
            )
        if not batch_path and os.getenv("START_DEMO_SERVICES", "0") == "1":
            start_demo_services(net)
        if not batch_path and os.getenv("START_IOT_SIMULATORS", "0") == "1":
            if os.getenv("START_DEMO_SERVICES", "0") != "1":
                info("*** WARNING: IoT simulators need the demo Web/API service; set START_DEMO_SERVICES=1\n")
            start_iot_simulators(net)
        print_inventory()
        if batch_path:
            wait_for_controller_ready()
            start_project_web_api(net)
            start_project_https(net)
            run_batch_plan(net, batch_path)
        else:
            AttackCLI(net)
    finally:
        info("*** Stopping topology\n")
        clear_vlan_port_map()
        if started:
            net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
