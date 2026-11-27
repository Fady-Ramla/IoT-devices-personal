#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.link import TCLink

import os
import secrets
import shlex
import time

from attack_manager import run_attack
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

class AttackCLI(CLI):

    def do_attack(self, line):

        args = line.split()

        if len(args) < 3:
            print(
                "Usage: attack <attacker> "
                "<attack_type> <target> [endpoint]"
            )
            return

        attacker_name = args[0]
        attack_type = args[1]
        target_name = args[2]

        try:
            attacker = self.mn.get(attacker_name)
        except KeyError:
            print("Unknown attacker:", attacker_name)
            return

        try:
            target = self.mn.get(target_name)
        except KeyError:
            print("Unknown target:", target_name)
            return

        dst_ip = target.IP()

        # ====================================================
        # SYN FLOOD
        # ====================================================

        if attack_type == "syn_flood":

            command = (
                "timeout 10 "
                "hping3 -S "
                "-p 5000 "
                "-i u1000 "
                "--flood "
                + dst_ip
            )

            run_attack(
                attacker=attacker,
                attack_type="syn_flood",
                dst_ip=dst_ip,
                command=command,
                src_port="*",
                dst_port="5000",
                protocol="TCP"
            )

        # ====================================================
        # PORT SCAN
        # ====================================================

        elif attack_type == "port_scan":

            command = (
                "nmap -Pn -sS -p 1-1000 --scan-delay 100ms "
                + dst_ip
            )

            run_attack(
                attacker=attacker,
                attack_type="port_scan",
                dst_ip=dst_ip,
                command=command,
                src_port="*",
                dst_port="*",
                protocol="TCP"
            )

        # ====================================================
        # MALICIOUS POST
        # ====================================================

        elif attack_type == "malicious_post":

            if len(args) < 4:
                print(
                    "Usage: attack "
                    "<attacker> malicious_post "
                    "<target> <endpoint>"
                )
                return

            endpoint = args[3]

            command = (
                "for i in $(seq 1 100); do "
                "curl -s -o /dev/null -X POST "
                "\"http://"
                + dst_ip
                + ":5000"
                + endpoint
                + "\"; "
                "done"
            )

            run_attack(
                attacker=attacker,
                attack_type="malicious_post",
                dst_ip=dst_ip,
                command=command,
                src_port="*",
                dst_port="5000",
                protocol="TCP"
            )

        # ====================================================
        # UNKNOWN ATTACK
        # ====================================================

        else:

            print("Unknown attack type:", attack_type)
            print("Available attack types:")
            print("  syn_flood")
            print("  port_scan")
            print("  malicious_post")


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

    info('*** LLDP rules installed.\n')

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
    # Start CLI
    # --------------------------------------------------------

    AttackCLI(net)

    # --------------------------------------------------------
    # Stop Network
    # --------------------------------------------------------

    info('\n*** Stopping network...\n')

    net.stop()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == '__main__':

    setLogLevel('info')

    run()
