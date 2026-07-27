import subprocess
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
if str(PANEL) not in sys.path:
    sys.path.insert(0, str(PANEL))

from live_session_collector import parse_connections_status, read_ipsec_status


ACTIVE_STATUS = r'''
"ikev2-cp"[17]: established IKE SA: #42
"ikev2-cp"[17]: 159.194.225.119[@vpn.example.test]...203.0.113.25[CN=ivanov-ivan-phone]===10.10.10.15; routed-tunnel; their_ip=10.10.10.15;
"ikev2-cp"[18]: established IKE SA: #43
"ikev2-cp"[18]: 159.194.225.119[@vpn.example.test]...198.51.100.8[@petrov-petr-tablet]===10.10.10.16; routed-tunnel; their_ip=10.10.10.16;
'''


class LiveSessionCollectorTests(unittest.TestCase):
    def test_parses_routed_ikev2_clients(self):
        connections = parse_connections_status(ACTIVE_STATUS)

        self.assertEqual(
            connections,
            [
                {
                    "client": "ivanov-ivan-phone",
                    "remote_ip": "203.0.113.25",
                    "vpn_ip": "10.10.10.15",
                    "ike_sa": "42",
                },
                {
                    "client": "petrov-petr-tablet",
                    "remote_ip": "198.51.100.8",
                    "vpn_ip": "10.10.10.16",
                    "ike_sa": "43",
                },
            ],
        )

    def test_ignores_loaded_but_not_routed_connection_definition(self):
        status = (
            '"ikev2-cp": 0.0.0.0/0===159.194.225.119[@vpn.example.test]'
            '...%any[%fromcert]==={10.10.10.10-10.10.10.250}; unrouted;\n'
        )
        self.assertEqual(parse_connections_status(status), [])

    def test_failed_ipsec_command_raises_instead_of_returning_empty_snapshot(self):
        def failed_runner(*_args, **_kwargs):
            return subprocess.CompletedProcess(
                args=["ipsec", "status"],
                returncode=1,
                stdout="temporary pluto failure",
            )

        with self.assertRaisesRegex(RuntimeError, "ipsec status failed"):
            read_ipsec_status(runner=failed_runner)


if __name__ == "__main__":
    unittest.main()
