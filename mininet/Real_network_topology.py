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

from vlan_config import HOSTS, INTER_SWITCH_LINKS, NETWORKS, host_cidr, gateway_for


RYU_IP = os.getenv("RYU_IP", "127.0.0.1")
RYU_PORT = int(os.getenv("RYU_PORT", "6633"))


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


def configure_gateway(gateway):
    """Configure five routed interfaces and default-deny forwarding."""
    commands = [
        "sysctl -w net.ipv4.ip_forward=1",
        "iptables -F",
        "iptables -t nat -F",
        "iptables -P FORWARD DROP",
        "iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
        # IoT to registered services and DNS.
        "iptables -A FORWARD -i gw-eth0 -o gw-eth1 -p tcp -m multiport --dports 5000,443 -j ACCEPT",
        "iptables -A FORWARD -i gw-eth0 -o gw-eth2 -p udp --dport 53 -j ACCEPT",
        "iptables -A FORWARD -i gw-eth0 -o gw-eth2 -p tcp --dport 53 -j ACCEPT",
        # Employees to load-balanced application frontends and DNS.
        "iptables -A FORWARD -i gw-eth4 -o gw-eth1 -p tcp -m multiport --dports 5000,443 -j ACCEPT",
        "iptables -A FORWARD -i gw-eth4 -o gw-eth2 -p udp --dport 53 -j ACCEPT",
        "iptables -A FORWARD -i gw-eth4 -o gw-eth2 -p tcp --dport 53 -j ACCEPT",
        # IT admins to approved service and management ports.
        "iptables -A FORWARD -i gw-eth3 -o gw-eth1 -p tcp -m multiport --dports 22,443,5000 -j ACCEPT",
        "iptables -A FORWARD -i gw-eth3 -o gw-eth0 -p tcp --dport 5000 -j ACCEPT",
        # Explicitly deny protected-to-IoT and all remaining directions.
        "iptables -A FORWARD -i gw-eth1 -o gw-eth0 -j DROP",
    ]
    addresses = {
        "gw-eth0": "10.10.10.1/24",  # IoT
        "gw-eth1": "10.10.20.1/24",  # services
        "gw-eth2": "10.10.30.1/24",  # DNS
        "gw-eth3": "10.10.40.1/24",  # IT management
        "gw-eth4": "10.10.50.1/24",  # employees
    }
    for interface, address in addresses.items():
        commands.extend([
            f"ip addr flush dev {interface}",
            f"ip addr add {address} dev {interface}",
            f"ip link set {interface} up",
        ])
    for command in commands:
        output = gateway.cmd(command)
        if output.strip() and "Warning" not in output:
            info("[gw] %s", output)


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
        connections = gateway.connectionsTo(switch)
        switch_intf = next(
            (left for left, right in connections
             if left.name == gateway_intf_name or right.name == gateway_intf_name),
            None,
        )
        if switch_intf is None:
            raise RuntimeError(
                f"No link found for {gateway_intf_name} on {switch.name}"
            )
        # connectionsTo() may return the switch interface first or second
        # depending on Mininet version; select the interface owned by OVS.
        if not switch_intf.name.startswith(f"{switch_name}-"):
            switch_intf = next(
                (intf for pair in connections for intf in pair
                 if intf.name.startswith(f"{switch_name}-")),
                None,
            )
        if switch_intf is None:
            raise RuntimeError(
                f"Could not identify OVS port for {gateway_intf_name}"
            )
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


def service_name_for_target(target_name, attack_type, dst_port):
    """Record the known service at the target, not the attack mechanism."""
    if target_name == 'h8':
        if attack_type == 'port_scan':
            try:
                low, high = map(int, str(dst_port).split('-', 1))
                midpoint = (low + high) / 2.0
                return 'https_backup' if abs(midpoint - 443) < abs(midpoint - 5000) else 'http_api_backup'
            except (TypeError, ValueError):
                return 'backup_service'
        return 'https_backup' if str(dst_port) == '443' else 'http_api_backup'
    if target_name == 'h11':
        return 'load_balancer'
    return {'h2': 'http_api', 'h3': 'https', 'h4': 'ssh'}.get(target_name, 'unknown_service')


def build_attack_spec(attack_type, dst_ip, parameters):
    """Pure command builder: validate first, never send traffic or change plans.

    SYN: 10..200 pps and 5..20 seconds. Scan/POST use a 20-second
    wall-clock cap; a timed-out bounded slice is not a complete port scan or
    evidence that the requested POST count finished. Notes preserve that fact.
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
        if len(parameters) > 2:
            raise ValueError('port_scan syntax: [port_range] [delay_ms]')
        port = parameters[0] if parameters else '1-1000'
        delay_ms = int(parameters[1]) if len(parameters) >= 2 else 100
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
        if not 1 <= len(parameters) <= 4:
            raise ValueError('malicious_post syntax: <endpoint> [count] [delay_ms] [workers]')
        endpoint = parameters[0]
        count = int(parameters[1]) if len(parameters) >= 2 else 100
        delay_ms = int(parameters[2]) if len(parameters) >= 3 else 100
        workers = int(parameters[3]) if len(parameters) >= 4 else 1
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
        url = shlex.quote('http://' + dst_ip + ':5000' + endpoint)
        request = ("curl -4 -sS --connect-timeout 1 --max-time 2 -o /dev/null "
                   "--http1.1 -X POST -H 'Content-Type: application/json' "
                   "-d '{\"username\":\"attack_probe\",\"password\":\"invalid\"}' " + url)
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
            run_normal_plan(net, command[len('normal '):])
        # Both functions return only after the SAME run is drained and committed.
        time.sleep(pauses[index - 1])
    info('*** Automated collection batch completed.\n')


def run_normal_plan(net, specification, *, controller=None, manifest_path=None, executor=None):
    """Normal traffic obeys the same planned/start/stop/drain state machine."""
    args = shlex.split(specification)
    if len(args) != 4:
        raise RuntimeError('normal syntax: normal <client> <service> <target> <duration_sec>')
    client_name, service, target_name, duration_text = args
    client = net.get(client_name)
    target = net.get(target_name)
    duration = int(duration_text)
    validate_duration(duration, MAX_NORMAL_DURATION_SEC)
    target_ip = validate_ipv4(target.IP())
    if service in {'http_api', 'load_balancer'}:
        port, url, extra = 5000, 'http://%s:5000/health' % target_ip, ''
    elif service == 'https':
        port, url, extra = 443, 'https://%s/' % target_ip, '-k '
    else:
        raise RuntimeError('unsupported normal service: ' + service)
    # Each failed transport exits immediately; a curl failure must not be hidden
    # by a later successful sleep. timeout's 124 is an intentional bounded end.
    loop = ('for i in $(seq 1 %d); do curl -4 %s-sS --fail --connect-timeout 1 '
            '--max-time 2 -o /dev/null %s || exit $?; sleep 1; done' %
            (duration, extra, shlex.quote(url)))
    command = 'timeout --signal=TERM --kill-after=1s %ds sh -c %s' % (duration, shlex.quote(loop))
    return run_experiment(
        client, command, run_type='normal', target_host=target.name, target_ip=target_ip,
        service_name=service, protocol='TCP', dst_port=str(port), src_port='*',
        rate_value=1, duration_sec=duration, experiment_category='normal_baseline',
        accepted_returncodes=(0, 124),
        notes=json.dumps({'rate_unit': 'requests_per_second_ceiling', 'duration_is_cap': True}),
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
    net.start()
    time.sleep(5)

    configure_gateway(net.get("gw"))
    configure_ovs_zones(net)
    if os.getenv("START_DEMO_SERVICES", "0") == "1":
        start_demo_services(net)
    if os.getenv("START_IOT_SIMULATORS", "0") == "1":
        if os.getenv("START_DEMO_SERVICES", "0") != "1":
            info("*** WARNING: IoT simulators need the demo Web/API service; set START_DEMO_SERVICES=1\n")
        start_iot_simulators(net)
    print_inventory()

    AttackCLI(net)
    info("*** Stopping topology\n")
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run()
