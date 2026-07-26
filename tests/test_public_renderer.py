import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "scripts" / "render-tenant-deployment.py"


class PublicRendererTests(unittest.TestCase):
    def test_generic_bundle_renders_without_private_names_or_invented_capacity(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "bundle"
            subprocess.run(
                [sys.executable, str(RENDERER), "--env", str(ROOT / "config" / "panel.env.example"), "--output", str(output)],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue((output / "systemd" / "vpn-panel.service").is_file())
            self.assertTrue((output / "Caddyfile").is_file())
            combined = "\n".join(path.read_text(encoding="utf-8") for path in output.rglob("*") if path.is_file()).casefold()
            self.assertIn("vpn.example.invalid", combined)
            panel_env = (output / "panel.env").read_text(encoding="utf-8")
            self.assertIn("VPN_CHANNEL_CAPACITY_MBIT=''", panel_env)
            self.assertIn("channel_capacity_mbit=unset", (output / "MANIFEST.txt").read_text(encoding="utf-8"))

    def test_service_prefix_containing_vpn_is_not_replaced_recursively(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = root / "nuova.env"
            output = root / "bundle"
            env.write_text(
                "\n".join(
                    [
                        'VPN_APP_NAME="Nuova VPN"',
                        "VPN_BRAND_NAME=Nuova",
                        "VPN_PUBLIC_DOMAIN=vpn.nuova.group",
                        "VPN_SERVICE_PREFIX=nuova-vpn",
                        "VPN_PANEL_APP_DIR=/opt/nuova-vpn-panel",
                        "VPN_PANEL_DB_PATH=/opt/nuova-vpn-panel/panel.db",
                        "VPN_PANEL_ACTION_LOG=/opt/nuova-vpn-panel/actions.log",
                        "VPN_PANEL_STATUS_DIR=/var/lib/nuova-vpn-panel/status",
                        "VPN_PANEL_INSTRUCTIONS_DIR=/var/lib/nuova-vpn-panel/instructions",
                        "VPN_PANEL_CACHE_DIR=/var/cache/nuova-vpn-panel",
                        "VPN_PANEL_SERVICE=nuova-vpn-panel",
                        "VPN_DEFAULT_ACCESS_GROUP=nuova",
                        "VPN_CHANNEL_CAPACITY_MBIT=500",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            subprocess.run(
                [sys.executable, str(RENDERER), "--env", str(env), "--output", str(output)],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            unit = (output / "systemd" / "nuova-vpn-panel.service").read_text(encoding="utf-8")
            self.assertIn("Description=Nuova VPN Panel", unit)
            self.assertIn("WorkingDirectory=/opt/nuova-vpn-panel", unit)
            self.assertIn("EnvironmentFile=/opt/nuova-vpn-panel/panel.env", unit)
            self.assertIn("ExecStart=/usr/bin/python3 /opt/nuova-vpn-panel/app.py", unit)

            panel_env = (output / "panel.env").read_text(encoding="utf-8")
            self.assertIn("VPN_CHANNEL_CAPACITY_MBIT=500.0", panel_env)
            self.assertIn("channel_capacity_mbit=500.0", (output / "MANIFEST.txt").read_text(encoding="utf-8"))

            combined = "\n".join(
                path.read_text(encoding="utf-8")
                for path in output.rglob("*")
                if path.is_file()
            )
            self.assertNotIn("nuova-nuova", combined)

    def test_nonpositive_channel_capacity_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = root / "bad.env"
            output = root / "bundle"
            env.write_text(
                "\n".join(
                    [
                        "VPN_PUBLIC_DOMAIN=vpn.example.test",
                        "VPN_SERVICE_PREFIX=example-vpn",
                        "VPN_CHANNEL_CAPACITY_MBIT=0",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(RENDERER), "--env", str(env), "--output", str(output)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("VPN_CHANNEL_CAPACITY_MBIT", result.stderr)


if __name__ == "__main__":
    unittest.main()
