#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.link import TCLink

import time


# ============================================================
# STP ENABLED SWITCH
# ============================================================

class STPSwitch(OVSSwitch):
    def start(self, controllers):
        OVSSwitch.start(self, controllers)
        self.cmd('ovs-vsctl set Bridge %s stp_enable=true' % self.name)


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

        h1 = self.addHost(
            'h1',
            ip='10.0.0.1/24'
        )

        h2 = self.addHost(
            'h2',
            ip='10.0.0.2/24'
        )

        h3 = self.addHost(
            'h3',
            ip='10.0.0.3/24'
        )

        h4 = self.addHost(
            'h4',
            ip='10.0.0.4/24'
        )

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
        # Server connections
        # ----------------------------------------------------

        self.addLink(h1, s1)
        self.addLink(h2, s1)

        self.addLink(h3, s2)
        self.addLink(h4, s2)

        # ----------------------------------------------------
        # Client connections
        # ----------------------------------------------------

        self.addLink(h5, s3)
        self.addLink(h6, s3)

        self.addLink(h7, s4)
        self.addLink(h8, s4)

        self.addLink(h9, s5)
        self.addLink(h10, s5)

        # ----------------------------------------------------
        # Main chain
        # ----------------------------------------------------

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s5)

        # ----------------------------------------------------
        # Redundant links
        # STP should block some of these to prevent loops
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
    # DNS
    # --------------------------------------------------------

    info('Starting DNS server on h1...\n')

    h1.cmd(
        'python3 /home/fady/IoT-devices/mininet/servers/dns_server.py '
        '> /tmp/dns.log 2>&1 &'
    )

    # --------------------------------------------------------
    # Web/API Server (Flask)
    # --------------------------------------------------------

    info('Starting Web/API server on h2...\n')
    h2.cmd('python3 /home/fady/IoT-devices/mininet/servers/web_api_server.py > /tmp/web_api.log 2>&1 &')

    # --------------------------------------------------------
    # HTTPS
    # --------------------------------------------------------

    info('Starting HTTPS server on h3...\n')

    h3.cmd(
        'mkdir -p /tmp/https_server'
    )

    h3.cmd(
        'echo "HTTPS Server - IoT SDN Graduation Project" '
        '> /tmp/https_server/index.html'
    )

    # Generate self-signed certificate
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
        'python3 /home/fady/IoT-devices/mininet/servers/https_server.py '
        '> /tmp/https.log 2>&1 &'
    )

    # --------------------------------------------------------
    # SSH
    # --------------------------------------------------------

    info('Starting SSH server on h4...\n')

    h4.cmd(
        'mkdir -p /run/sshd'
    )

    h4.cmd(
        'ssh-keygen -A '
        '> /dev/null 2>&1'
    )

    # Allow root login with password
    h4.cmd(
        'echo "PermitRootLogin yes" >> /etc/ssh/sshd_config'
    )
    h4.cmd(
        'echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config'
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
# SHOW NETWORK INFORMATION
# ============================================================

def show_info(net):

    info('\n')
    info('============================================\n')
    info('          NETWORK INFORMATION\n')
    info('============================================\n')

    info('Servers:\n')
    info('  h1  DNS    -> 10.0.0.1:53\n')
    info('  h2  Web/API -> 10.0.0.2:80 (Flask)\n')
    info('  h3  HTTPS  -> 10.0.0.3:443\n')
    info('  h4  SSH    -> 10.0.0.4:22 (root/root)\n')

    info('\nClients:\n')
    info('  h5  -> 10.0.0.5\n')
    info('  h6  -> 10.0.0.6\n')
    info('  h7  -> 10.0.0.7\n')
    info('  h8  -> 10.0.0.8\n')
    info('  h9  -> 10.0.0.9\n')
    info('  h10 -> 10.0.0.10\n')

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
        switch=STPSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    # --------------------------------------------------------
    # Ryu Controller
    # --------------------------------------------------------

    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    info('\n*** Starting Mininet network...\n')

    net.start()

    # =========================================================
    # Enable STP on all switches
    # =========================================================

    info('\n*** Enabling STP on all switches...\n')
    for switch in net.switches:
        switch.cmd('ovs-vsctl set Bridge %s stp_enable=true' % switch.name)

    info('\n*** Waiting for STP convergence (30 seconds)...\n')
    time.sleep(30)

    # --------------------------------------------------------
    # Start servers
    # --------------------------------------------------------

    setup_servers(net)

    # --------------------------------------------------------
    # Show network information
    # --------------------------------------------------------

    show_info(net)

    # --------------------------------------------------------
    # CLI
    # --------------------------------------------------------

    CLI(net)

    # --------------------------------------------------------
    # Cleanup
    # --------------------------------------------------------

    info('\n*** Stopping network...\n')

    net.stop()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == '__main__':

    setLogLevel('info')

    run()
