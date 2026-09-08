#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.link import TCLink

import time

from attack_manager import run_attack


# ============================================================
# STP ENABLED SWITCH
# ============================================================

class STPSwitch(OVSSwitch):

    def start(self, controllers):

        OVSSwitch.start(
            self,
            controllers
        )

        self.cmd(
            'ovs-vsctl set Bridge %s stp_enable=true'
            % self.name
        )


# ============================================================
# TOPOLOGY
# ============================================================

class PartialMeshTopo(Topo):

    def build(self):

        # ----------------------------------------------------
        # Switches
        # ----------------------------------------------------

        s1 = self.addSwitch('s1', cls=STPSwitch)
        s2 = self.addSwitch('s2', cls=STPSwitch)
        s3 = self.addSwitch('s3', cls=STPSwitch)
        s4 = self.addSwitch('s4', cls=STPSwitch)
        s5 = self.addSwitch('s5', cls=STPSwitch)

        # ----------------------------------------------------
        # Servers
        # ----------------------------------------------------

        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')

        # ----------------------------------------------------
        # Clients
        # ----------------------------------------------------

        h5 = self.addHost('h5', ip='10.0.0.5/24')
        h6 = self.addHost('h6', ip='10.0.0.6/24')
        h7 = self.addHost('h7', ip='10.0.0.7/24')
        h8 = self.addHost('h8', ip='10.0.0.8/24')
        h9 = self.addHost('h9', ip='10.0.0.9/24')
        h10 = self.addHost('h10', ip='10.0.0.10/24')

        # ----------------------------------------------------
        # Host connections
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
        self.addLink(h10, s5)

        # ----------------------------------------------------
        # Main switch chain
        # ----------------------------------------------------

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)

        # ----------------------------------------------------
        # Redundant links
        # ----------------------------------------------------

        self.addLink(s1, s3)
        self.addLink(s2, s4)
        self.addLink(s3, s5)


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

    # --------------------------------------------------------
    # DNS Server
    # --------------------------------------------------------

    info('Starting DNS server on h1...\n')

    h1.cmd(
        'python3 '
        '/home/fady/IoT-devices/mininet/servers/dns_server.py '
        '> /tmp/dns.log 2>&1 &'
    )

    # --------------------------------------------------------
    # Flask Web/API Server
    # --------------------------------------------------------

    info('Starting Web/API server on h2...\n')

    h2.cmd(
        '/home/fady/.pyenv/versions/3.8.20/bin/python3 '
        '/home/fady/IoT-devices/mininet/servers/web_api_server.py '
        '> /tmp/web_api.log 2>&1 &'
    )

    # --------------------------------------------------------
    # HTTPS Server
    # --------------------------------------------------------

    info('Starting HTTPS server on h3...\n')

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
        '-subj "/CN=10.0.0.3" '
        '> /dev/null 2>&1'
    )

    h3.cmd(
        'cd /tmp/https_server && '
        'python3 '
        '/home/fady/IoT-devices/mininet/servers/https_server.py '
        '> /tmp/https.log 2>&1 &'
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

    h4.cmd(
        'echo "PermitRootLogin yes" '
        '>> /etc/ssh/sshd_config'
    )

    h4.cmd(
        'echo "PasswordAuthentication yes" '
        '>> /etc/ssh/sshd_config'
    )

    h4.cmd(
        'echo "root:root" | chpasswd'
    )

    h4.cmd(
        '/usr/sbin/sshd '
        '-o ListenAddress=10.0.0.4 '
        '> /tmp/ssh.log 2>&1 &'
    )

    info('\nAll server services started.\n')


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

        # ----------------------------------------------------
        # Any host can be the attacker
        # ----------------------------------------------------

        try:
            attacker = self.mn.get(attacker_name)

        except KeyError:
            print("Unknown attacker:", attacker_name)
            return

        # ----------------------------------------------------
        # Any host can be the target
        # ----------------------------------------------------

        try:
            target = self.mn.get(target_name)

        except KeyError:
            print("Unknown target:", target_name)
            return

        # ----------------------------------------------------
        # Destination IP is obtained internally
        # ----------------------------------------------------

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

                # Actual source port is NOT predetermined
                src_port="*",

                # Flask destination port
                dst_port="5000",

                protocol="TCP"
            )

        # ====================================================
        # PORT SCAN
        # ====================================================

        elif attack_type == "port_scan":

            command = (
                "nmap "
                + dst_ip
            )

            run_attack(
                attacker=attacker,
                attack_type="port_scan",
                dst_ip=dst_ip,
                command=command,

                # Actual source port is dynamic
                src_port="*",

                # Multiple destination ports
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

                # Actual source port is dynamic
                src_port="*",

                # Flask destination port
                dst_port="5000",

                protocol="TCP"
            )

        # ====================================================
        # UNKNOWN ATTACK
        # ====================================================

        else:

            print(
                "Unknown attack type:",
                attack_type
            )

            print(
                "Available attack types:"
            )

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

    info(
        '  h1  DNS       -> 10.0.0.1:53\n'
    )

    info(
        '  h2  Web/API   -> 10.0.0.2:5000 (Flask)\n'
    )

    info(
        '  h3  HTTPS     -> 10.0.0.3:443\n'
    )

    info(
        '  h4  SSH       -> 10.0.0.4:22\n'
    )

    info('\nClients:\n')

    info('  h5\n')
    info('  h6\n')
    info('  h7\n')
    info('  h8\n')
    info('  h9\n')
    info('  h10\n')

    info('\nTraffic is MANUAL.\n')

    info(
        'No application traffic will start automatically.\n'
    )

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
        switch=STPSwitch,
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

    info(
        '\n*** Starting Mininet network...\n'
    )

    net.start()

    # --------------------------------------------------------
    # Enable STP
    # --------------------------------------------------------

    info(
        '\n*** Enabling STP on all switches...\n'
    )

    for switch in net.switches:

        switch.cmd(
            'ovs-vsctl set Bridge %s stp_enable=true'
            % switch.name
        )

    # --------------------------------------------------------
    # STP Convergence
    # --------------------------------------------------------

    info(
        '\n*** Waiting for STP convergence '
        '(30 seconds)...\n'
    )

    time.sleep(30)

    # --------------------------------------------------------
    # Start Servers
    # --------------------------------------------------------

    setup_servers(net)

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

    info(
        '\n*** Stopping network...\n'
    )

    net.stop()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == '__main__':

    setLogLevel('info')

    run()
