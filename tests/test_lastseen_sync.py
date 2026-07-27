import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "panel" / "lastseen_sync.py"


class LastseenSyncTests(unittest.TestCase):
    def run_sync(self, db_path: Path) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "VPN_PANEL_DB_PATH": str(db_path),
                "VPN_PANEL_APP_DIR": str(db_path.parent / "panel"),
                "VPN_PANEL_STATUS_DIR": str(db_path.parent / "status"),
                "VPN_PANEL_INSTRUCTIONS_DIR": str(db_path.parent / "instructions"),
                "VPN_PANEL_CACHE_DIR": str(db_path.parent / "cache"),
                # These tests cover behavior-table synchronization in isolation.
                # Live Libreswan parsing has its own unit tests and stays enabled
                # by default in the installed systemd service.
                "VPN_SKIP_LIVE_SESSION_COLLECTION": "1",
            }
        )
        return subprocess.run(
            [sys.executable, str(SCRIPT)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )

    def test_missing_vpn_sessions_is_clean_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "panel.db"
            sqlite3.connect(db_path).close()

            result = self.run_sync(db_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("vpn_sessions_missing=1", result.stdout)
            self.assertIn("live_connections: 0", result.stdout)
            self.assertIn("latest_clients: 0", result.stdout)

    def test_empty_vpn_sessions_table_is_clean_noop(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "panel.db"
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    "create table vpn_sessions (client text, remote_ip text, last_seen integer)"
                )
                conn.commit()
            finally:
                conn.close()

            result = self.run_sync(db_path)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("vpn_sessions_missing=1", result.stdout)
            self.assertIn("live_connections: 0", result.stdout)
            self.assertIn("latest_clients: 0", result.stdout)
            self.assertIn("summary_updates: 0", result.stdout)
            self.assertIn("place_updates: 0", result.stdout)


if __name__ == "__main__":
    unittest.main()
