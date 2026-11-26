import importlib.util
import os
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE_PATH = Path(__file__).resolve().parents[1] / "mininet" / "load_balancer.py"
spec = importlib.util.spec_from_file_location("load_balancer", MODULE_PATH)
lb = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = lb
spec.loader.exec_module(lb)


def dns_reply(query):
    return query[:2] + struct.pack("!H", 0x8180) + query[4:6] + b"\x00\x00\x00\x00\x00\x00" + query[12:]


class LoadBalancerDNS(unittest.TestCase):
    def test_tcp_pool_selection_for_ssh_and_dns(self):
        ssh_backends = lb.parse_backends(lb.DEFAULT_SSH)
        tcp_dns_backends = lb.parse_backends(lb.DEFAULT_DNS)
        for backends in (ssh_backends, tcp_dns_backends):
            pool = lb.Pool(backends)
            pool.healthy.update(backends)
            self.assertEqual(pool.candidates(), backends)

    def test_udp_dns_fallback_and_payload_preservation(self):
        primary = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        backup = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            primary.bind(("127.0.0.1", 0))
            backup.bind(("127.0.0.1", 0))
            client.bind(("127.0.0.1", 0))
            primary_addr, backup_addr = primary.getsockname(), backup.getsockname()

            def answer(sock, transform):
                query, addr = sock.recvfrom(2048)
                sock.sendto(transform(query), addr)

            # Wrong transaction ID is rejected and causes backup selection.
            t1 = threading.Thread(target=answer, args=(primary, lambda q: b"\x00\x00" + dns_reply(q)[2:]), daemon=True)
            t2 = threading.Thread(target=answer, args=(backup, dns_reply), daemon=True)
            t1.start()
            t2.start()
            pool = lb.DNSPool([primary_addr, backup_addr])
            pool.healthy.update([primary_addr, backup_addr])
            query = lb.DNS_HEALTH_QUERY
            self.assertTrue(lb.forward_dns(query, client.getsockname(), client, pool, timeout=0.5))
            client.settimeout(0.5)
            response, _ = client.recvfrom(2048)
            self.assertEqual(response, dns_reply(query))
            self.assertEqual(response[:2], query[:2])
            self.assertNotIn(primary_addr, pool.candidates())
            t1.join(1)
            t2.join(1)
        finally:
            for sock in (primary, backup, client):
                sock.close()

    def test_dns_bind_address_cli_env_and_default(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(lb.dns_bind_address(), "10.10.20.100")
        with patch.dict(os.environ, {"LB_DNS_BIND_ADDRESS": "127.0.0.1"}, clear=True):
            self.assertEqual(lb.dns_bind_address(), "127.0.0.1")
            self.assertEqual(lb.dns_bind_address("127.0.0.2"), "127.0.0.2")


if __name__ == "__main__":
    unittest.main()
