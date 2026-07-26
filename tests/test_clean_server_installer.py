import subprocess
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "install.sh"
INSTALLER = ROOT / "scripts" / "install-clean-server.sh"


class CleanServerInstallerTests(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(["bash", "-n", str(ENTRYPOINT)], check=True)
        subprocess.run(["bash", "-n", str(INSTALLER)], check=True)

    def test_entrypoint_delegates_to_clean_installer(self):
        text = ENTRYPOINT.read_text(encoding="utf-8")
        self.assertIn("scripts/install-clean-server.sh", text)
        self.assertIn('"$@"', text)
        self.assertIn("Panel database already exists", text)
        self.assertIn("deploy-source.sh", text)

    def test_entrypoint_refuses_existing_database_before_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            database = root / "panel.db"
            database.touch()
            env_file = root / "panel.env"
            env_file.write_text(
                "\n".join(
                    (
                        "VPN_APP_NAME=Example VPN",
                        "VPN_BRAND_NAME=Example",
                        "VPN_PUBLIC_DOMAIN=vpn.example.test",
                        "VPN_SERVICE_PREFIX=example-vpn",
                        f"VPN_PANEL_DB_PATH={database}",
                    )
                )
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                ["bash", str(ENTRYPOINT), "--env", str(env_file)],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Clean installation refused", result.stderr)
            self.assertIn("deploy-source.sh", result.stderr)

    def test_installer_bootstraps_complete_panel_surface(self):
        text = INSTALLER.read_text(encoding="utf-8")
        lowered = text.casefold()
        self.assertNotIn("s" + "oved", lowered)
        self.assertIn("render-tenant-deployment.py", text)
        self.assertIn("check-vpn-prerequisites.py", text)
        self.assertIn("materialize-tenant-panel.py", text)
        self.assertIn("bootstrap-panel-admin.py", text)
        self.assertIn("systemctl enable --now", text)
        self.assertIn("caddy validate", text)
        self.assertIn("/health", text)
        self.assertNotIn("systemctl restart ipsec", lowered)
        self.assertNotIn("systemctl restart xl2tp", lowered)

    def test_vpn_preflight_runs_before_any_package_or_panel_mutation(self):
        text = INSTALLER.read_text(encoding="utf-8")
        preflight = text.index("check-vpn-prerequisites.py")
        apt_install = text.index("apt-get update")
        materialize = text.index("materialize-tenant-panel.py")
        self.assertLess(preflight, apt_install)
        self.assertLess(preflight, materialize)

    def test_installer_never_overwrites_upstream_ikev2_helper(self):
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertNotIn("vendor/hwdsl2/ikev2.sh", text)
        self.assertNotIn('install -m 0755 "$ROOT/vendor', text)
        self.assertIn("Never overwrite", text)

    def test_installer_rejects_missing_tenant_config(self):
        result = subprocess.run(
            ["bash", str(INSTALLER)],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertTrue(
            "Run as root" in (result.stderr or "")
            or "Explicit --env is required" in (result.stderr or "")
        )


if __name__ == "__main__":
    unittest.main()
