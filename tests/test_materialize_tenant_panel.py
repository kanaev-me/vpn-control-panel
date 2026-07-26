import os
import socket
import subprocess
import sys
from http.cookiejar import CookieJar
from pathlib import Path
import tempfile
import time
import unittest
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener, urlopen


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "materialize-tenant-panel.py"
BOOTSTRAP = ROOT / "scripts" / "bootstrap-panel-admin.py"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class MaterializeTenantPanelTests(unittest.TestCase):
    def materialize(self, output: Path) -> None:
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--output",
                str(output),
                "--service-prefix",
                "example-vpn",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        )

    def test_materialized_panel_is_compilable_tenant_neutral_and_hardened(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "panel"
            self.materialize(output)

            self.assertTrue((output / "app.py").is_file())
            self.assertTrue((output / "runtime_config.py").is_file())
            self.assertFalse((output / "pulse_export_mikrotiks.py").exists())
            self.assertFalse((output / "sync_known_networks_from_pulse.sh").exists())
            self.assertIn(
                "_NETWORK_LABELS = {}",
                (output / "networks_page_cleanup.py").read_text(encoding="utf-8"),
            )

            combined = "\n".join(
                path.read_text(encoding="utf-8")
                for path in output.iterdir()
                if path.is_file() and path.suffix in {".py", ".sh"}
            ).casefold()
            self.assertNotIn("s" + "oved", combined)
            self.assertNotIn("со" + "вед", combined)
            self.assertNotIn("со\u0301" + "вед", combined)
            self.assertIn("default_access_group", combined)

            app_text = (output / "app.py").read_text(encoding="utf-8")
            self.assertIn("live_state = service_state(key)", app_text)
            self.assertIn("Пропускная способность канала не настроена", app_text)
            self.assertIn("except Exception:\n        metrics = {}", app_text)
            self.assertNotIn('metrics.get("capacity_mbit") or 250', app_text)
            self.assertNotIn('or metrics.get("capacity_mbit") or 250', app_text)

            subprocess.run(
                [sys.executable, "-m", "compileall", "-q", str(output)],
                cwd=ROOT,
                check=True,
            )

    def test_materialized_panel_starts_accepts_login_and_survives_bad_optional_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "panel"
            db_path = root / "panel.db"
            password_file = root / "password"
            password = "correct horse battery staple"
            password_file.write_text(password + "\n", encoding="utf-8")
            self.materialize(output)
            subprocess.run(
                [
                    sys.executable,
                    str(BOOTSTRAP),
                    "--db",
                    str(db_path),
                    "--username",
                    "admin",
                    "--display-name",
                    "Example Administrator",
                    "--password-file",
                    str(password_file),
                    "--default-group",
                    "example",
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )

            status_dir = root / "status"
            status_dir.mkdir()
            (status_dir / "channel-metrics.json").write_text(
                "{}\n{}\n", encoding="utf-8"
            )

            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_systemctl = fake_bin / "systemctl"
            fake_systemctl.write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = is-active ]; then echo active; exit 0; fi\n"
                "exit 0\n",
                encoding="utf-8",
            )
            fake_systemctl.chmod(0o755)

            port = free_port()
            env = os.environ.copy()
            env.update(
                {
                    "PATH": str(fake_bin) + os.pathsep + env.get("PATH", ""),
                    "VPN_APP_NAME": "Example VPN",
                    "VPN_BRAND_NAME": "Example",
                    "VPN_PUBLIC_DOMAIN": "vpn.example.test",
                    "VPN_SERVICE_PREFIX": "example-vpn",
                    "VPN_PANEL_HOST": "127.0.0.1",
                    "VPN_PANEL_PORT": str(port),
                    "VPN_PANEL_APP_DIR": str(output),
                    "VPN_PANEL_DB_PATH": str(db_path),
                    "VPN_PANEL_ACTION_LOG": str(root / "actions.log"),
                    "VPN_PANEL_STATUS_DIR": str(status_dir),
                    "VPN_PANEL_INSTRUCTIONS_DIR": str(root / "instructions"),
                    "VPN_PANEL_CACHE_DIR": str(root / "cache"),
                    "VPN_IKEV2_SCRIPT": str(root / "ikev2.sh"),
                    "VPN_CERT_DB": "sql:/nonexistent",
                    "VPN_PANEL_SERVICE": "example-vpn-panel",
                    "VPN_CADDY_SERVICE": "caddy",
                    "VPN_IPSEC_SERVICE": "ipsec",
                    "VPN_L2TP_SERVICE": "xl2tpd",
                    "VPN_DEFAULT_ACCESS_GROUP": "example",
                    "VPN_PULSE_ENDPOINT_ENABLED": "0",
                    "VPN_PULSE_SYNC_ENABLED": "0",
                }
            )
            process = subprocess.Popen(
                [sys.executable, str(output / "app.py")],
                cwd=output,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                deadline = time.time() + 15
                last_error = None
                while time.time() < deadline:
                    if process.poll() is not None:
                        output_text = process.stdout.read() if process.stdout else ""
                        self.fail(f"materialized panel exited early: {output_text}")
                    try:
                        with urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                            self.assertEqual(response.status, 200)
                            self.assertEqual(response.read(), b"OK\n")
                            break
                    except Exception as exc:
                        last_error = exc
                        time.sleep(0.2)
                else:
                    self.fail(f"materialized panel health did not start: {last_error!r}")

                opener = build_opener(HTTPCookieProcessor(CookieJar()))
                request = Request(
                    f"http://127.0.0.1:{port}/login",
                    data=urlencode({"username": "admin", "password": password}).encode("utf-8"),
                    method="POST",
                )
                with opener.open(request, timeout=20) as response:
                    self.assertEqual(response.status, 200)
                    body = response.read().decode("utf-8")
                    self.assertIn("Example VPN", body)
                    self.assertNotIn("s" + "oved", body.casefold())
                    self.assertIn("Пропускная способность канала не задана", body)
                    self.assertNotIn("250 Мбит/с", body)
                    self.assertNotIn("panel unknown", body)
                    self.assertIn(">panel<", body)
                    self.assertIn(">caddy<", body)
                    self.assertIn(">ipsec<", body)

                with opener.open(f"http://127.0.0.1:{port}/channel", timeout=20) as response:
                    self.assertEqual(response.status, 200)
                    body = response.read().decode("utf-8")
                    self.assertIn("Пропускная способность канала не настроена", body)
                    self.assertNotIn("250 Мбит/с", body)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    def test_materializer_rejects_invalid_service_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--output",
                    str(Path(tmp) / "panel"),
                    "--service-prefix",
                    "Bad Prefix",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
