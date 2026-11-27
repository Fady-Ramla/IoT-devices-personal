import importlib.util
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "mininet" / "service_lifecycle.py"

spec = importlib.util.spec_from_file_location(
    "secureiot_service_lifecycle_test", MODULE_PATH
)
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


class FakeHost:
    def __init__(self, listener_output="", process_command=""):
        self.listener_output = listener_output
        self.process_command = process_command
        self.commands = []

    def cmd(self, command):
        self.commands.append(command)
        if command.startswith("ss "):
            return self.listener_output
        if "/proc/" in command and "/cmdline" in command:
            return self.process_command
        return ""


class DemoServiceLifecycleTests(unittest.TestCase):

    def test_tcp_listener_is_found(self):
        host = FakeHost(
            "LISTEN 0 128 0.0.0.0:5000 0.0.0.0:* users:(("
            "python3\",pid=1234,fd=3))"
        )
        result = lifecycle.listener_line(host, "tcp", 5000)
        self.assertIn(":5000", result)
        self.assertIn("-ltnp", host.commands[0])

    def test_udp_listener_is_found(self):
        host = FakeHost(
            "UNCONN 0 0 10.10.30.2:53 0.0.0.0:* "
            "users:((\"python3\",pid=1234,fd=3))"
        )
        result = lifecycle.listener_line(host, "udp", 53)
        self.assertIn("10.10.30.2:53", result)
        self.assertIn("-lunp", host.commands[0])

    def test_unrelated_port_is_not_matched(self):
        host = FakeHost(
            "LISTEN 0 128 0.0.0.0:15000 0.0.0.0:*"
        )
        self.assertEqual(lifecycle.listener_line(host, "tcp", 5000), "")

    def test_invalid_protocol_is_rejected(self):
        with self.assertRaises(ValueError):
            lifecycle.listener_line(FakeHost(), "icmp", 53)

    def test_listener_pid_is_extracted(self):
        line = 'LISTEN users:(("python3",pid=116534,fd=4))'
        self.assertEqual(lifecycle.listener_pid(line), 116534)

    def test_listener_without_pid_returns_none(self):
        self.assertIsNone(lifecycle.listener_pid("LISTEN 0 128 *:443"))

    def test_listener_owner_is_verified(self):
        line = 'LISTEN users:(("python3",pid=1234,fd=3))'
        host = FakeHost(
            process_command="python3 service_stub.py --name primary-web-api"
        )
        self.assertTrue(
            lifecycle.listener_owned_by(
                host, line, ["service_stub.py", "--name primary-web-api"]
            )
        )

    def test_wrong_listener_owner_is_rejected(self):
        line = 'LISTEN users:(("python3",pid=1234,fd=3))'
        host = FakeHost(process_command="python3 unrelated_server.py")
        self.assertFalse(
            lifecycle.listener_owned_by(
                host, line, ["service_stub.py"]
            )
        )

    def test_http_service_identity_is_checked(self):
        response = (
            '{"service": "primary-web-api", "status": "healthy"}'
        )
        self.assertTrue(
            lifecycle.http_service_is_healthy(response, "primary-web-api")
        )
        self.assertFalse(
            lifecycle.http_service_is_healthy(response, "backup-web-api")
        )

    def test_load_balancer_heartbeat_accepts_fresh_matching_process(self):
        raw = '{"pid": 116534, "timestamp": 997.0}'
        command = (
            "python3 /project/mininet/load_balancer.py "
            "--http-backends 10.10.20.2:5000,10.10.20.8:5000"
        )
        self.assertTrue(
            lifecycle.load_balancer_heartbeat_is_valid(
                raw,
                command,
                ["--http-backends",
                 "10.10.20.2:5000,10.10.20.8:5000"],
                now=1000.0,
            )
        )

    def test_stale_heartbeat_is_rejected(self):
        raw = '{"pid": 116534, "timestamp": 990.0}'
        command = "python3 /project/load_balancer.py --check-interval 1"
        self.assertFalse(
            lifecycle.load_balancer_heartbeat_is_valid(
                raw, command, ["--check-interval", "1"], now=1000.0
            )
        )

    def test_wrong_process_or_configuration_is_rejected(self):
        raw = '{"pid": 116534, "timestamp": 999.0}'
        wrong_process = "python3 unrelated.py --check-interval 1"
        self.assertFalse(
            lifecycle.load_balancer_heartbeat_is_valid(
                raw, wrong_process, ["--check-interval", "1"], now=1000.0
            )
        )

        correct_process = (
            "python3 /project/load_balancer.py --check-interval 1"
        )
        self.assertFalse(
            lifecycle.load_balancer_heartbeat_is_valid(
                raw, correct_process, ["--dns-bind-address", "10.10.20.100"],
                now=1000.0
            )
        )

    def test_malformed_heartbeat_is_rejected(self):
        self.assertFalse(
            lifecycle.load_balancer_heartbeat_is_valid(
                "not-json",
                "python3 load_balancer.py",
                [],
                now=1000.0,
            )
        )



class GroupFakeHost:
    def __init__(self, outputs, commands):
        self.outputs = outputs
        self.process_commands = commands

    def cmd(self, command):
        if command.startswith("ss "):
            if "-ltnp" in command:
                return self.outputs.get("tcp", "")
            if "-lunp" in command:
                return self.outputs.get("udp", "")
        if "/proc/" in command and "/cmdline" in command:
            return self.process_commands.get(1234, "")
        return ""


class ListenerGroupTests(unittest.TestCase):
    def setUp(self):
        self.tcp = (
            "LISTEN 0 128 10.10.20.100:53 0.0.0.0:* "
            'users:(("python3",pid=1234,fd=4))'
        )
        self.udp = (
            "UNCONN 0 0 10.10.20.100:53 0.0.0.0:* "
            'users:(("python3",pid=1234,fd=5))'
        )
        self.command = "python3 load_balancer.py --dns-bind-address 10.10.20.100"
        self.endpoints = [
            ("tcp", "10.10.20.100", 53),
            ("udp", "10.10.20.100", 53),
        ]

    def host(self, tcp=None, udp=None, command=None):
        return GroupFakeHost(
            {"tcp": self.tcp if tcp is None else tcp,
             "udp": self.udp if udp is None else udp},
            {1234: self.command if command is None else command},
        )

    def test_complete_group_owned_by_one_expected_process(self):
        result = lifecycle.listener_group_state(
            self.host(), self.endpoints, ["load_balancer.py"]
        )
        self.assertEqual(result[0], "healthy")
        self.assertEqual(result[1], 1234)

    def test_no_listeners_is_absent(self):
        result = lifecycle.listener_group_state(
            self.host(tcp="", udp=""), self.endpoints, ["load_balancer.py"]
        )
        self.assertEqual(result[0], "absent")

    def test_partial_group_is_conflict(self):
        result = lifecycle.listener_group_state(
            self.host(udp=""), self.endpoints, ["load_balancer.py"]
        )
        self.assertEqual(result[0], "conflict")

    def test_wrong_bind_address_is_conflict(self):
        wrong = self.tcp.replace("10.10.20.100:53", "0.0.0.0:53")
        result = lifecycle.listener_group_state(
            self.host(tcp=wrong), self.endpoints, ["load_balancer.py"]
        )
        self.assertEqual(result[0], "conflict")

    def test_wrong_process_is_conflict(self):
        result = lifecycle.listener_group_state(
            self.host(command="python3 unrelated.py"),
            self.endpoints,
            ["load_balancer.py"],
        )
        self.assertEqual(result[0], "conflict")

    def test_heartbeat_pid_must_match_listener_owner(self):
        raw = '{"pid": 9999, "timestamp": 999.0}'
        self.assertFalse(
            lifecycle.load_balancer_heartbeat_is_valid(
                raw,
                self.command,
                ["--dns-bind-address", "10.10.20.100"],
                now=1000.0,
                expected_pid=1234,
            )
        )




class StartupFakeHost:
    def __init__(
        self, tcp="", command="python3 service_stub.py --port 5000",
        start_succeeds=True,
    ):
        self.tcp = tcp
        self.command = command
        self.start_succeeds = start_succeeds
        self.launch_count = 0

    def cmd(self, command):
        if command.startswith("ss "):
            return self.tcp if "-ltnp" in command else ""
        if "/proc/" in command and "/cmdline" in command:
            return self.command
        if command == "launch-service":
            self.launch_count += 1
            if self.start_succeeds:
                self.tcp = (
                'LISTEN 0 128 0.0.0.0:5000 0.0.0.0:* '
                'users:(("python3",pid=1234,fd=3))'
            )
        return ""


class EnsureListenerGroupTests(unittest.TestCase):
    endpoint = [("tcp", "0.0.0.0", 5000)]
    tokens = ["service_stub.py", "--port", "5000"]

    def test_healthy_service_is_reused_without_launch(self):
        host = StartupFakeHost(
            tcp=('LISTEN 0 128 0.0.0.0:5000 0.0.0.0:* '
                 'users:(("python3",pid=1234,fd=3))')
        )
        pid, started = lifecycle.ensure_listener_group(
            host, self.endpoint, self.tokens, "launch-service"
        )
        self.assertEqual(pid, 1234)
        self.assertFalse(started)
        self.assertEqual(host.launch_count, 0)

    def test_absent_service_is_started_once(self):
        host = StartupFakeHost(tcp="")
        pid, started = lifecycle.ensure_listener_group(
            host, self.endpoint, self.tokens, "launch-service",
            timeout=0.2, poll_interval=0.001,
        )
        self.assertEqual(pid, 1234)
        self.assertTrue(started)
        self.assertEqual(host.launch_count, 1)

    def test_conflicting_service_is_not_replaced(self):
        host = StartupFakeHost(
            tcp=('LISTEN 0 128 0.0.0.0:5000 0.0.0.0:* '
                 'users:(("python3",pid=1234,fd=3))'),
            command="python3 unrelated_server.py",
        )
        with self.assertRaises(RuntimeError):
            lifecycle.ensure_listener_group(
                host, self.endpoint, self.tokens, "launch-service"
            )
        self.assertEqual(host.launch_count, 0)

    def test_unhealthy_existing_service_is_not_restarted(self):
        host = StartupFakeHost(
            tcp=('LISTEN 0 128 0.0.0.0:5000 0.0.0.0:* '
                 'users:(("python3",pid=1234,fd=3))')
        )
        with self.assertRaises(RuntimeError):
            lifecycle.ensure_listener_group(
                host, self.endpoint, self.tokens, "launch-service",
                health_check=lambda pid, command: False,
            )
        self.assertEqual(host.launch_count, 0)

    def test_failed_start_is_not_retried_as_duplicate(self):
        host = StartupFakeHost(tcp="", start_succeeds=False)
        with self.assertRaises(RuntimeError):
            lifecycle.ensure_listener_group(
                host, self.endpoint, self.tokens, "launch-service",
                timeout=0.01, poll_interval=0.001,
            )
        self.assertEqual(host.launch_count, 1)


if __name__ == "__main__":
    unittest.main()
