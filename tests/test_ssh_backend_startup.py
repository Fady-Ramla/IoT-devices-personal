"""Focused tests for the active Mininet SSH backend startup contract."""
import ast
import pathlib
import re
import shlex
import time
import unittest
from types import SimpleNamespace

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "mininet" / "Real_network_topology.py"
TREE = ast.parse(SOURCE.read_text(encoding="utf-8"))
FUNCTION = next(
    node for node in TREE.body
    if isinstance(node, ast.FunctionDef) and node.name == "start_ssh_backends"
)
NAMESPACE = {
    "re": re,
    "shlex": shlex,
    "time": time,
    "SSH_DEMO_USERNAME": "demo",
    "SSH_DEMO_PASSWORD": "test-password",
    "HOSTS": {
        "h4": {"ip": "10.10.20.4/24"},
        "h20": {"ip": "10.10.20.20/24"},
    },
    "info": lambda *args, **kwargs: None,
}
exec(compile(ast.fix_missing_locations(ast.Module(body=[FUNCTION], type_ignores=[])),
             str(SOURCE), "exec"), NAMESPACE)


class FakeHost:
    def __init__(self, address):
        self.address = address
        self.commands = []
        self.listener_checks = 0

    def cmd(self, command):
        self.commands.append(command)
        if "ss -lntH" in command:
            self.listener_checks += 1
            # Simulate sshd becoming ready on the first post-launch probe.
            return "" if self.listener_checks == 1 else self.address + ":2222"
        if "test -x /usr/sbin/sshd" in command:
            return "available"
        return ""


class SSHBackendStartupTests(unittest.TestCase):
    def test_starts_and_probes_both_backends_on_2222(self):
        hosts = {
            "h4": FakeHost("10.10.20.4"),
            "h20": FakeHost("10.10.20.20"),
        }
        net = SimpleNamespace(get=lambda host_id: hosts[host_id])

        NAMESPACE["start_ssh_backends"](net)

        for host_id, host in hosts.items():
            commands = "\n".join(host.commands)
            self.assertIn("-o Port=2222", commands, host_id)
            self.assertIn("sport = :2222", commands, host_id)
            self.assertIn("10.10.20.%s:2222" % ("4" if host_id == "h4" else "20"),
                          commands, host_id)
            self.assertEqual(host.listener_checks, 2, host_id)


if __name__ == "__main__":
    unittest.main()
