#!/usr/bin/env python3
"""Regression tests for safe run-lifecycle recovery after timeouts."""
import csv
import json
from pathlib import Path
import tempfile

from mininet import attack_manager


class Host:
    name = "h5"

    @staticmethod
    def IP():
        return "10.10.20.5"


class Controller:
    def __init__(self):
        self.run_id = None
        self.generation = None

    def _ack(self, state):
        return {
            "success": True,
            "run_id": self.run_id,
            "generation": self.generation,
            "state": state,
        }

    def start(self, run_id, generation):
        self.run_id, self.generation = run_id, generation
        return self._ack("active")

    def stop(self, run_id, generation):
        return self._ack("draining")

    def wait_drained(self, run_id, generation):
        raise attack_manager.RunLifecycleError("simulated drain timeout")


class Process:
    pid = 12345
    returncode = 0

    def __init__(self):
        self.timeout = None

    def communicate(self, timeout):
        self.timeout = timeout
        return b"ok", None


class ExecutorHost(Host):
    def __init__(self):
        self.process = Process()

    def popen(self, *args, **kwargs):
        return self.process


def test_drain_timeout_preserves_active_identity_and_latch():
    with tempfile.TemporaryDirectory(prefix="attack_manager_recovery_") as temp:
        root = Path(temp)
        manifest = root / "run_manifest.csv"
        active_path = root / "active_run.json"
        old_active_path = attack_manager.ACTIVE_RUN_FILE
        attack_manager.ACTIVE_RUN_FILE = active_path
        controller = Controller()
        try:
            try:
                attack_manager.run_experiment(
                    Host(), "true", run_type="normal", label="",
                    target_host="h2", target_ip="10.10.20.2",
                    service_name="http_api", duration_sec=10,
                    experiment_category="normal_baseline",
                    controller=controller, manifest_path=manifest,
                    executor=lambda *args: (0, "ok"),
                )
            except attack_manager.RunLifecycleError as exc:
                assert "simulated drain timeout" in str(exc)
            else:
                raise AssertionError("drain timeout must fail the run")

            active = json.loads(active_path.read_text(encoding="utf-8"))
            assert active["status"] == "active"
            assert active["run_id"] == controller.run_id
            assert active["generation"] == controller.generation
            latch = manifest.with_name(manifest.name + ".in_flight.json")
            assert latch.exists(), "unresolved drain must retain the identity latch"
            with manifest.open(newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            assert len(rows) == 1 and rows[0]["status"] == "failed"
        finally:
            attack_manager.ACTIVE_RUN_FILE = old_active_path


def test_host_command_exit_grace_exceeds_inner_timeout():
    host = ExecutorHost()
    attack_manager.execute_host_command(
        host, "true", "00000000-0000-0000-0000-000000000000", 1, 20
    )
    assert host.process.timeout == 20 + attack_manager.HOST_COMMAND_EXIT_GRACE_SEC


def main():
    test_drain_timeout_preserves_active_identity_and_latch()
    test_host_command_exit_grace_exceeds_inner_timeout()
    print("PASS: drain timeout preserves the active identity and in-flight latch")
    print("PASS: host command receives bounded post-timeout cleanup grace")


if __name__ == "__main__":
    main()
