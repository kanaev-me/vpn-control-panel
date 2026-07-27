import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
if str(PANEL) not in sys.path:
    sys.path.insert(0, str(PANEL))

from runtime_config import load_runtime_config


class RuntimeConfigDomainTests(unittest.TestCase):
    def test_normalizes_case_and_idn_to_dns_hostname(self):
        self.assertEqual(
            load_runtime_config({"VPN_PUBLIC_DOMAIN": "VPN.Example.COM"}).public_domain,
            "vpn.example.com",
        )
        self.assertEqual(
            load_runtime_config({"VPN_PUBLIC_DOMAIN": "пример.рф"}).public_domain,
            "xn--e1afmkfd.xn--p1ai",
        )

    def test_rejects_non_hostname_domain_values(self):
        invalid_values = (
            "https://vpn.example.com",
            "vpn.example.com/path",
            "vpn.example.com:443",
            "vpn_example.com",
            "vpn..example.com",
            "-vpn.example.com",
            "vpn-.example.com",
            "localhost",
            "127.0.0.1",
            "*.example.com",
            f"{'a' * 64}.example.com",
        )

        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    ValueError,
                    "VPN_PUBLIC_DOMAIN must be a DNS host name without scheme, path or port",
                ):
                    load_runtime_config({"VPN_PUBLIC_DOMAIN": value})


if __name__ == "__main__":
    unittest.main()
