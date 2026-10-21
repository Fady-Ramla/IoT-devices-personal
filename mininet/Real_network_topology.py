#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.link import TCLink

import os
import re
import secrets
import shlex
import time
import csv
import json
import math
from types import SimpleNamespace

from attack_manager import (
    run_attack, run_experiment, validate_duration, validate_syn_parameters,
    validate_ipv4, build_syn_command, MAX_RATE_PPS, MAX_DURATION_SEC, MAX_NORMAL_DURATION_SEC,
)
from vlan_config import HOSTS, configure_ovs_vlans
from configure_gateway import configure_gateway


# ============================================================
# PROJECT PATHS
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SERVER_DIR = os.path.join(SCRIPT_DIR, 'servers')


# ============================================================
# TOPOLOGY
# ============================================================

class PartialMeshTopo(Topo):

    def build(self):

        # ----------------------------------------------------
        # Switches
        # ----------------------------------------------------

        s1 = self.addSwitch('s1', cls=OVSSwitch)
        s2 = self.addSwitch('s2', cls=OVSSwitch)
        s3 = self.addSwitch('s3', cls=OVSSwitch)
        s4 = self.addSwitch('s4', cls=OVSSwitch)
        s5 = self.addSwitch('s5', cls=OVSSwitch)
        s6 = self.addSwitch('s6', cls=OVSSwitch)

        # ----------------------------------------------------
        # Servers
        # ----------------------------------------------------

        h1 = self.addHost('h1', ip=HOSTS['h1'][1], defaultRoute='via ' + HOSTS['h1'][2])
        h2 = self.addHost('h2', ip=HOSTS['h2'][1], defaultRoute='via ' + HOSTS['h2'][2])
        h3 = self.addHost('h3', ip=HOSTS['h3'][1], defaultRoute='via ' + HOSTS['h3'][2])
        h4 = self.addHost('h4', ip=HOSTS['h4'][1], defaultRoute='via ' + HOSTS['h4'][2])

        # ----------------------------------------------------
        # Clients
        # ----------------------------------------------------

        h5 = self.addHost('h5', ip=HOSTS['h5'][1], defaultRoute='via ' + HOSTS['h5'][2])
        h6 = self.addHost('h6', ip=HOSTS['h6'][1], defaultRoute='via ' + HOSTS['h6'][2])
        h7 = self.addHost('h7', ip=HOSTS['h7'][1], defaultRoute='via ' + HOSTS['h7'][2])
        h8 = self.addHost('h8', ip=HOSTS['h8'][1], defaultRoute='via ' + HOSTS['h8'][2])
        h9 = self.addHost('h9', ip=HOSTS['h9'][1], defaultRoute='via ' + HOSTS['h9'][2])
        h10 = self.addHost('h10', ip=HOSTS['h10'][1], defaultRoute='via ' + HOSTS['h10'][2])
        h11 = self.addHost('h11', ip=HOSTS['h11'][1], defaultRoute='via ' + HOSTS['h11'][2])

        # ----------------------------------------------------
        # Host connections
        # Preserve existing host IPs during Phase 1. h10 moves to s6;
        # VLAN/subnet changes are intentionally deferred to later phases.
        # ----------------------------------------------------

        self.addLink(h1, s1)
        self.addLink(h2, s1)

        self.addLink(h3, s2)
        self.addLink(h4, s2)

        self.addLink(h5, s3)
        self.addLink(h6, s3)

        self.addLink(h7, s4)
        self.addLink(h8, s4)

        self.addLink(h9, s5)
        self.addLink(h10, s6)
        self.addLink(h11, s6)

        # ----------------------------------------------------
        # Main switch chain
        # Bandwidth: 10 Mbps per inter-switch link
        # ----------------------------------------------------

        self.addLink(s1, s2, cls=TCLink, bw=10)
        self.addLink(s2, s3, cls=TCLink, bw=10)
        self.addLink(s3, s4, cls=TCLink, bw=10)
        self.addLink(s4, s5, cls=TCLink, bw=10)

        # ----------------------------------------------------
        # Redundant links
        # Bandwidth: 10 Mbps per inter-switch link
        # ----------------------------------------------------

        self.addLink(s1, s3, cls=TCLink, bw=10)
        self.addLink(s2, s4, cls=TCLink, bw=10)
        self.addLink(s3, s5, cls=TCLink, bw=10)

        # ----------------------------------------------------
        # Enterprise topology expansion (Phase 1)
        # Four additional redundant links; keep 10 Mbps per link.
        # ----------------------------------------------------

        self.addLink(s4, s6, cls=TCLink, bw=10)
        self.addLink(s5, s6, cls=TCLink, bw=10)
        self.addLink(s1, s5, cls=TCLink, bw=10)
        self.addLink(s2, s5, cls=TCLink, bw=10)


# ============================================================
# SERVER SETUP
# ============================================================

def setup_servers(net):

    info('\n')
    info('============================================\n')
    info('        STARTING SERVER SERVICES\n')
    info('============================================\n')

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    h4 = net.get('h4')

    # Authentication secrets are supplied by the operator, never embedded in
    # the application source. Health checks remain available when secrets are
    # omitted, while login/admin routes stay disabled until configured.
    api_env = ['WEB_API_SERVER_IP=10.10.20.2']
    backup_api_env = ['WEB_API_SERVER_IP=10.10.20.8']
    for key in ('ADMIN_USERNAME', 'ADMIN_PASSWORD_HASH', 'JWT_SECRET',
                'JWT_TTL_SECONDS'):
        value = os.environ.get('SECUREIOT_' + key) or os.environ.get(key)
        if value:
            api_env.append(key + '=' + shlex.quote(value))
            backup_api_env.append(key + '=' + shlex.quote(value))
    api_env_prefix = ' '.join(api_env)
    backup_api_env_prefix = ' '.join(backup_api_env)

    # --------------------------------------------------------
    # DNS Server
    # --------------------------------------------------------

    info('Starting DNS server on h1...\n')

    dns_server = os.path.join(
        SERVER_DIR,
        'dns_server.py'
    )

    h1.cmd(
        'DNS_SERVER_IP=10.10.30.2 DNS_ANSWER_IP=10.10.20.2 python3 '
        + dns_server
        + ' > /tmp/dns.log 2>&1 &'
    )

    # --------------------------------------------------------
    # Flask Web/API Server
    # --------------------------------------------------------

    info('Starting Web/API server on h2...\n')

    web_api_server = os.path.join(
        SERVER_DIR,
        'web_api_server.py'
    )

    h2.cmd(
        api_env_prefix + ' python3 '
        + web_api_server
        + ' > /tmp/web_api.log 2>&1 &'
    )

    # --------------------------------------------------------
    # HTTPS Server
    # --------------------------------------------------------

    info('Starting HTTPS server on h3...\n')

    https_server = os.path.join(
        SERVER_DIR,
        'https_server.py'
    )

    h3.cmd(
        'mkdir -p /tmp/https_server'
    )

    h3.cmd(
        'echo "HTTPS Server - IoT SDN Graduation Project" '
        '> /tmp/https_server/index.html'
    )

    h3.cmd(
        'openssl req -x509 '
        '-newkey rsa:2048 '
        '-keyout /tmp/https_server/key.pem '
        '-out /tmp/https_server/cert.pem '
        '-days 365 '
        '-nodes '
        '-subj "/CN=10.10.20.3" '
        '> /dev/null 2>&1'
    )

    h3.cmd(
        'cd /tmp/https_server && '
        'python3 '
        + https_server
        + ' > /tmp/https.log 2>&1 &'
    )

    # --------------------------------------------------------
    # SSH Server
    # --------------------------------------------------------

    info('Starting SSH server on h4...\n')

    h4.cmd(
        'mkdir -p /run/sshd'
    )

    h4.cmd(
        'ssh-keygen -A '
        '> /dev/null 2>&1'
    )

    # Lab SSH service: retain TCP/22 for the VLAN policy demonstration, but
    # remove the insecure root/root account. A password can be supplied as
    # SECUREIOT_SSH_PASSWORD; otherwise an unpredictable temporary password is
    # generated inside the ephemeral Mininet namespace.
    ssh_password = (os.environ.get('SECUREIOT_SSH_PASSWORD') or
                    secrets.token_urlsafe(18))
    h4.cmd('id -u secureiot-admin >/dev/null 2>&1 || '
           'useradd -m -s /bin/bash secureiot-admin')
    h4.cmd('printf %s secureiot-admin:' + shlex.quote(ssh_password) +
           ' | chpasswd')

    h4.cmd(
        '/usr/sbin/sshd '
        '-o PermitRootLogin=no '
        '-o PasswordAuthentication=yes '
        '-o AllowUsers=secureiot-admin '
        '-o ListenAddress=10.10.20.4 '
        '> /tmp/ssh.log 2>&1 &'
    )

    h8 = net.get('h8')
    h10 = net.get('h10')
    h10.cmd('DNS_SERVER_IP=10.10.30.10 DNS_ANSWER_IP=10.10.20.100 python3 ' + dns_server + ' > /tmp/dns_backup.log 2>&1 &')
    h8.cmd(backup_api_env_prefix + ' python3 ' + web_api_server + ' > /tmp/web_api_backup.log 2>&1 &')
    h8.cmd('mkdir -p /tmp/https_server_backup')
    h8.cmd('echo "HTTPS Backup - IoT SDN Graduation Project" > /tmp/https_server_backup/index.html')
    h8.cmd('openssl req -x509 -newkey rsa:2048 -keyout /tmp/https_server_backup/key.pem -out /tmp/https_server_backup/cert.pem -days 365 -nodes -subj "/CN=10.10.20.8" > /dev/null 2>&1')
    h8.cmd('cd /tmp/https_server_backup && env HTTPS_SERVER_IP=10.10.20.8 HTTPS_CERT_FILE=/tmp/https_server_backup/cert.pem HTTPS_KEY_FILE=/tmp/https_server_backup/key.pem python3 ' + https_server + ' > /tmp/https_backup.log 2>&1 &')

    info('\nAll server services started, including h8 backups.\n')


# ============================================================
# LOAD BALANCER SETUP
# ============================================================

def setup_load_balancer(net):
    h11 = net.get('h11')
    lb = os.path.join(SERVER_DIR, '..', 'load_balancer.py')
    h11.cmd('python3 ' + lb + ' > /tmp/load_balancer.log 2>&1 &')
    info('Load Balancer h11: VIP 10.10.20.100 ports 5000 and 443\n')


# ============================================================
# CUSTOM ATTACK CLI
# ============================================================

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


# ============================================================
# SHOW NETWORK INFORMATION
# ============================================================

def show_info(net):

    info('\n')
    info('============================================\n')
    info('          NETWORK INFORMATION\n')
    info('============================================\n')

    info('Servers:\n')
    info('  h1  DNS       -> 10.10.30.2:53\n')
    info('  h2  Web/API   -> 10.10.20.2:5000 (Flask)\n')
    info('  h3  HTTPS     -> 10.10.20.3:443\n')
    info('  h4  SSH       -> 10.10.20.4:22\n')

    info('\nClients:\n')
    info('  h5\n')
    info('  h6\n')
    info('  h7\n')
    info('  h8\n')
    info('  h9\n')
    info('  h10 DNS Backup -> 10.10.30.10\n')
    info('  h11 Load Balancer VIP -> 10.10.20.100:5000,443\n')

    info('\nTraffic is MANUAL.\n')
    info('No application traffic will start automatically.\n')

    info('\nUseful commands:\n')
    info('  pingall\n')
    info('  net\n')
    info('  nodes\n')
    info('  links\n')
    info('  sh ovs-vsctl show\n')

    info('\n============================================\n')
    info('          NETWORK READY\n')
    info('============================================\n\n')


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


# ============================================================
# MAIN
# ============================================================

def run():

    topo = PartialMeshTopo()

    net = Mininet(
        topo=topo,
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    # --------------------------------------------------------
    # Ryu Controller
    # --------------------------------------------------------

    net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    # --------------------------------------------------------
    # Start Network
    # --------------------------------------------------------

    info('\n*** Starting Mininet network...\n')

    net.start()

    info('\n*** Applying VLAN access/trunk configuration...\n')
    configure_ovs_vlans(net)
    info('*** VLAN 10/20/30/40 L2 segmentation configured.\n')
    info('*** Configuring s1 VLAN gateways and Zero Trust routing policy...\n')
    configure_gateway(net.get('s1'))
    info('*** Inter-VLAN routing and initial policy are enabled.\n')


    # --------------------------------------------------------
    # No STP
    # --------------------------------------------------------
    #
    # STP is intentionally DISABLED.
    # Loop prevention is handled by Ryu CLFF.
    # --------------------------------------------------------

    info('\n*** STP is DISABLED.\n')
    info('*** All physical links remain available for Ryu.\n')

    # --------------------------------------------------------
    # Give Ryu time to discover topology
    # --------------------------------------------------------

    info('\n*** Waiting for Ryu topology discovery...\n')

    time.sleep(5)

    # --------------------------------------------------------
    # Enable LLDP rules on all switches
    # --------------------------------------------------------

    info('\n*** Enabling LLDP rules on all switches...\n')

    for switch in net.switches:

        switch.cmd(
            'ovs-ofctl add-flow %s '
            'priority=100,dl_type=0x88cc,actions=CONTROLLER:65535'
            % switch.name
        )
        switch.cmd(
            'ovs-ofctl add-flow %s '
            'priority=0,actions=CONTROLLER:65535'
            % switch.name
        )

    info('*** LLDP rules installed.\n')
    info('*** OpenFlow table-miss rules installed.\n')

    # --------------------------------------------------------
    # Start Servers
    # --------------------------------------------------------

    setup_servers(net)
    setup_load_balancer(net)

    # --------------------------------------------------------
    # Network Information
    # --------------------------------------------------------

    show_info(net)

    # --------------------------------------------------------
    # Start CLI or automated batch
    # --------------------------------------------------------

    try:
        batch_plan = os.environ.get('SECUREIOT_BATCH_PLAN', '').strip()
        if batch_plan:
            run_batch_plan(net, batch_plan)
        else:
            AttackCLI(net)
    finally:
        # Lifecycle failures abort a batch; never leave its network running.
        info('\n*** Stopping network...\n')
        net.stop()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == '__main__':

    setLogLevel('info')

    run()
