import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-vpn-prerequisites.py"
SPEC = importlib.util.spec_from_file_location("vpn_prerequisites", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class VpnPrerequisiteTests(unittest.TestCase):
    def make_valid_layout(self, root: Path):
        ikev2_script = root / "opt" / "src" / "ikev2.sh"
        ikev2_script.parent.mkdir(parents=True)
        ikev2_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        ikev2_script.chmod(0o755)

        cert_db = root / "etc" / "ipsec.d"
        cert_db.mkdir(parents=True)
        (cert_db / "cert9.db").write_bytes(b"test")
        (cert_db / "key4.db").write_bytes(b"test")
        ikev2_config = cert_db / "ikev2.conf"
        ikev2_config.write_text("conn ikev2-cp\n", encoding="utf-8")
        ipsec_config = root / "etc" / "ipsec.conf"
        ipsec_config.write_text("include /etc/ipsec.d/*.conf\n", encoding="utf-8")
        return ikev2_script, cert_db, ikev2_config, ipsec_config

    def test_valid_hwdsl2_layout_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ikev2_script, cert_db, ikev2_config, ipsec_config = self.make_valid_layout(root)
            completed = subprocess.CompletedProcess([], 0)
            with patch.object(MODULE.shutil, "which", return_value="/usr/bin/fake"), patch.object(
                MODULE.subprocess, "run", return_value=completed
            ) as run:
                errors = MODULE.validate_prerequisites(
                    ikev2_script=ikev2_script,
                    cert_db=f"sql:{cert_db}",
                    ipsec_service="ipsec.service",
                    ikev2_config=ikev2_config,
                    ipsec_config=ipsec_config,
                )
            self.assertEqual(errors, [])
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args_list[0].args[0], ["systemctl", "is-active", "--quiet", "ipsec"])
            self.assertEqual(run.call_args_list[1].args[0], [str(ikev2_script), "--listclients"])

    def test_missing_vpn_stack_fails_before_command_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(MODULE.shutil, "which", return_value=None), patch.object(
                MODULE.subprocess, "run"
            ) as run:
                errors = MODULE.validate_prerequisites(
                    ikev2_script=root / "missing-ikev2.sh",
                    cert_db=f"sql:{root / 'missing-db'}",
                    ipsec_service="ipsec",
                    ikev2_config=root / "missing-ikev2.conf",
                    ipsec_config=root / "missing-ipsec.conf",
                )
            self.assertGreaterEqual(len(errors), 6)
            run.assert_not_called()

    def test_inactive_ipsec_service_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ikev2_script, cert_db, ikev2_config, ipsec_config = self.make_valid_layout(root)
            with patch.object(MODULE.shutil, "which", return_value="/usr/bin/fake"), patch.object(
                MODULE.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 3),
            ):
                errors = MODULE.validate_prerequisites(
                    ikev2_script=ikev2_script,
                    cert_db=f"sql:{cert_db}",
                    ipsec_service="ipsec",
                    ikev2_config=ikev2_config,
                    ipsec_config=ipsec_config,
                )
            self.assertEqual(errors, ["IPsec service is not active: ipsec"])

    def test_cli_explains_required_upstream_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--ikev2-script",
                    str(root / "ikev2.sh"),
                    "--cert-db",
                    f"sql:{root / 'db'}",
                    "--ipsec-service",
                    "ipsec",
                    "--ikev2-config",
                    str(root / "ikev2.conf"),
                    "--ipsec-config",
                    str(root / "ipsec.conf"),
                    "--domain",
                    "vpn.example.test",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("Install hwdsl2/setup-ipsec-vpn first", result.stderr)
            self.assertIn("https://get.vpnsetup.net", result.stderr)
            self.assertIn("VPN_DNS_NAME='vpn.example.test'", result.stderr)


if __name__ == "__main__":
    unittest.main()
