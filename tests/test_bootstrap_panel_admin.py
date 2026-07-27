import sqlite3
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "bootstrap-panel-admin.py"
sys.path.insert(0, str(ROOT / "panel"))

from auth_passwords import verify_password  # noqa: E402


class BootstrapPanelAdminTests(unittest.TestCase):
    def run_bootstrap(
        self,
        db: Path,
        password_file: Path,
        *extra: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--db",
                str(db),
                "--username",
                "admin",
                "--display-name",
                "VPN Administrator",
                "--password-file",
                str(password_file),
                "--default-group",
                "company",
                *extra,
            ],
            cwd=ROOT,
            check=check,
            capture_output=True,
            text=True,
        )

    def test_bootstrap_creates_owner_and_required_tables(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "panel.db"
            password_file = root / "password"
            password = "correct horse battery staple"
            password_file.write_text(password + "\n", encoding="utf-8")

            self.run_bootstrap(db, password_file)

            self.assertTrue(db.is_file())
            self.assertEqual(db.stat().st_mode & 0o777, 0o600)

            conn = sqlite3.connect(db)
            try:
                tables = {
                    row[0]
                    for row in conn.execute(
                        "select name from sqlite_master where type='table'"
                    )
                }
                self.assertTrue(
                    {
                        "panel_users",
                        "panel_sessions",
                        "panel_groups",
                        "panel_user_groups",
                        "vpn_client_meta",
                        "vpn_sessions",
                    }.issubset(tables)
                )
                row = conn.execute(
                    "select password_hash, role, display_name, is_enabled "
                    "from panel_users where username='admin'"
                ).fetchone()
                self.assertIsNotNone(row)
                self.assertTrue(verify_password(password, row[0]))
                self.assertEqual(row[1:], ("owner", "VPN Administrator", 1))
                self.assertEqual(
                    conn.execute(
                        "select can_view, can_create, can_delete "
                        "from panel_user_groups "
                        "where username='admin' and group_name='company'"
                    ).fetchone(),
                    (1, 1, 1),
                )
                self.assertEqual(conn.execute("pragma integrity_check").fetchone()[0], "ok")
            finally:
                conn.close()

    def test_existing_administrator_is_not_replaced_implicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "panel.db"
            first_file = root / "first-password"
            second_file = root / "second-password"
            first_password = "correct horse battery staple"
            second_password = "another deliberately strong password"
            first_file.write_text(first_password + "\n", encoding="utf-8")
            second_file.write_text(second_password + "\n", encoding="utf-8")

            self.run_bootstrap(db, first_file)
            result = self.run_bootstrap(db, second_file, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing to replace", result.stderr)

            conn = sqlite3.connect(db)
            try:
                stored_hash = conn.execute(
                    "select password_hash from panel_users where username='admin'"
                ).fetchone()[0]
            finally:
                conn.close()
            self.assertTrue(verify_password(first_password, stored_hash))
            self.assertFalse(verify_password(second_password, stored_hash))

            self.run_bootstrap(db, second_file, "--replace-existing")
            conn = sqlite3.connect(db)
            try:
                replaced_hash = conn.execute(
                    "select password_hash from panel_users where username='admin'"
                ).fetchone()[0]
            finally:
                conn.close()
            self.assertFalse(verify_password(first_password, replaced_hash))
            self.assertTrue(verify_password(second_password, replaced_hash))

    def test_explicit_password_replacement_revokes_only_target_user_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = root / "panel.db"
            first_file = root / "first-password"
            second_file = root / "second-password"
            first_file.write_text("correct horse battery staple\n", encoding="utf-8")
            second_file.write_text("another deliberately strong password\n", encoding="utf-8")

            self.run_bootstrap(db, first_file)
            conn = sqlite3.connect(db)
            try:
                conn.executemany(
                    "insert into panel_sessions "
                    "(session_id, username, created_at, last_seen, expires_at) "
                    "values(?,?,?,?,?)",
                    (
                        ("admin-session-a", "admin", 1, 1, 9999999999),
                        ("admin-session-b", "admin", 2, 2, 9999999999),
                        ("other-session", "other-user", 3, 3, 9999999999),
                    ),
                )
                conn.commit()
            finally:
                conn.close()

            self.run_bootstrap(db, second_file, "--replace-existing")
            conn = sqlite3.connect(db)
            try:
                admin_sessions = conn.execute(
                    "select session_id from panel_sessions where username='admin'"
                ).fetchall()
                other_sessions = conn.execute(
                    "select session_id from panel_sessions where username='other-user'"
                ).fetchall()
            finally:
                conn.close()

            self.assertEqual(admin_sessions, [])
            self.assertEqual(other_sessions, [("other-session",)])

    def test_short_password_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            password_file = root / "password"
            password_file.write_text("short\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--db",
                    str(root / "panel.db"),
                    "--username",
                    "admin",
                    "--password-file",
                    str(password_file),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
