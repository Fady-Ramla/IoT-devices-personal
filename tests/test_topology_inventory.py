import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "mininet" / "vlan_config_38host.py"


def load_config():
    spec = importlib.util.spec_from_file_location("secureiot_topology_test_config", CONFIG_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TopologyInventoryTests(unittest.TestCase):
    def test_inventory_is_single_source_of_truth(self):
        config = load_config()
        self.assertEqual(len(config.HOSTS), 38)
        self.assertEqual(len(config.SWITCH_NAMES), 6)
        self.assertIn(len(config.INTER_SWITCH_LINKS), (11, 12))
        self.assertEqual(set(config.NETWORKS), {10, 20, 30, 40, 50})
        expected_iot_hosts = {f"h{i}" for i in range(5, 17)}
        profiles = getattr(config, "IOT_DEVICE_PROFILES", {})
        if profiles:
            self.assertEqual(set(profiles), expected_iot_hosts)
            for host_id, profile in profiles.items():
                self.assertEqual(config.HOSTS[host_id]["role"], profile["role"])
        else:
            role_hosts = {
                host_id for host_id, spec in config.HOSTS.items()
                if spec["role"] == "iot"
            }
            self.assertEqual(role_hosts, expected_iot_hosts)


if __name__ == "__main__":
    unittest.main()
