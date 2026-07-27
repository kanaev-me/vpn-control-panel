import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
if str(PANEL) not in sys.path:
    sys.path.insert(0, str(PANEL))

from dashboard_status import normalize_dashboard_data


class DashboardStatusTests(unittest.TestCase):
    def test_missing_artifact_does_not_make_healthy_services_red(self):
        states = {
            "tenant-panel": "active",
            "caddy": "active",
            "ipsec": "active",
            "xl2tpd": "active",
        }

        data = normalize_dashboard_data(
            None,
            service_names=tuple(states),
            service_state=states.__getitem__,
        )

        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["services"], states)
        self.assertEqual(data["reasons"], [])

    def test_live_service_failure_is_authoritative_over_stale_json(self):
        raw = {
            "status": "ok",
            "services": {"tenant-panel": "active", "ipsec": "active"},
        }
        states = {"tenant-panel": "active", "ipsec": "failed"}

        data = normalize_dashboard_data(
            raw,
            service_names=tuple(states),
            service_state=states.__getitem__,
        )

        self.assertEqual(data["status"], "bad")
        self.assertEqual(data["services"]["ipsec"], "failed")
        self.assertIn("ipsec: failed", data["reasons"])

    def test_attention_counters_are_preserved_without_false_service_failures(self):
        data = normalize_dashboard_data(
            {
                "auth_fail_count_30m": "0",
                "old_profile_clients_2h": 0,
                "possible_multi_device_clients_2h": "2",
            },
            service_names=("panel", "ipsec"),
            service_state=lambda _name: "active",
        )

        self.assertEqual(data["status"], "warn")
        self.assertEqual(data["possible_multi_device_clients_2h"], 2)
        self.assertEqual(data["services"], {"panel": "active", "ipsec": "active"})


if __name__ == "__main__":
    unittest.main()
