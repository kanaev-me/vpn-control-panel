import subprocess
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RENDERER = ROOT / "scripts" / "render-tenant-deployment.py"


class PublicRendererTests(unittest.TestCase):
    def test_generic_bundle_renders_without_private_names(self):
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


if __name__ == "__main__":
    unittest.main()
