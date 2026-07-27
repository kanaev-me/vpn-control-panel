import subprocess
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "install.sh"
INSTALLER = ROOT / "scripts" / "install-clean-server.sh"
DEPLOY = ROOT / "scripts" / "deploy-source.sh"


class CleanServerInstallerTests(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(["bash", "-n", str(ENTRYPOINT)], check=True)
        subprocess.run(["bash", "-n", str(INSTALLER)], check=True)
        subprocess.run(["bash", "-n", str(DEPLOY)], check=True)

    def test_entrypoint_delegates_to_clean_installer_and_has_password_recovery(self):
        text = ENTRYPOINT.read_text(encoding="utf-8")
        self.assertIn("scripts/install-clean-server.sh", text)
        self.assertIn('"$@"', text)
        self.assertIn("Panel database already exists", text)
        self.assertIn("deploy-source.sh", text)
        self.assertIn("Repeat panel administrator password", text)
        self.assertIn("Passwords do not match", text)
        self.assertIn("reset-admin-password", text)
        self.assertIn("--replace-existing", text)
        self.assertIn("DELETE FROM panel_sessions", text)
        self.assertIn("before-password-reset", text)

    def test_entrypoint_verifies_real_login_and_protected_pages(self):
        text = ENTRYPOINT.read_text(encoding="utf-8")
        self.assertIn('request("POST", "/login"', text)
        self.assertIn('("/access", "Доступ")', text)
        self.assertIn('("/channel", "Канал")', text)
        self.assertIn('request("GET", "/api/me"', text)
        self.assertIn('cookie.startswith("vpn_vpn_session=")', text)
        self.assertIn("administrator_login=ok", text)
        self.assertIn("protected_pages=ok", text)
        self.assertIn("dashboard_defaults=ok", text)
        self.assertIn("panel unknown", text)
        self.assertIn("caddy unknown", text)
        self.assertIn("ipsec unknown", text)

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

    def test_source_deploy_updates_rendered_units_safely(self):
        text = DEPLOY.read_text(encoding="utf-8")
        lowered = text.casefold()
        self.assertIn('"$STAGE/rendered/systemd/"*.service', text)
        self.assertIn('"$STAGE/rendered/systemd/"*.timer', text)
        self.assertIn("SYSTEMD_BACKUP_DIR", text)
        self.assertIn('install -m 0644 "$unit" "/etc/systemd/system/$(basename "$unit")"', text)
        self.assertIn("systemctl daemon-reload", text)
        self.assertIn("systemctl enable --now", text)
        self.assertIn("systemd_units=updated", text)
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
