import sqlite3
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
if str(PANEL) not in sys.path:
    sys.path.insert(0, str(PANEL))

from auth_sessions import prune_invalid_session_records, resolve_session_record


class AuthSessionTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.executescript(
            """
            create table panel_users (
                username text primary key,
                role text,
                display_name text,
                is_enabled integer not null
            );
            create table panel_sessions (
                session_id text primary key,
                username text not null,
                created_at integer not null,
                last_seen integer not null,
                expires_at
            );
            """
        )

    def tearDown(self):
        self.conn.close()

    def add_user(self, username="admin", role="owner", enabled=1):
        self.conn.execute(
            "insert into panel_users(username, role, display_name, is_enabled) values(?,?,?,?)",
            (username, role, "Administrator", enabled),
        )

    def add_session(
        self,
        session_id="session",
        username="admin",
        expires_at=101,
        last_seen=1,
    ):
        self.conn.execute(
            "insert into panel_sessions(session_id, username, created_at, last_seen, expires_at) "
            "values(?,?,?,?,?)",
            (session_id, username, 1, last_seen, expires_at),
        )
        self.conn.commit()

    def test_resolves_only_strictly_unexpired_integer_session(self):
        self.add_user(role=" owner ")
        self.add_session(expires_at=101)

        user = resolve_session_record(self.conn, "session", now=100)

        self.assertEqual(user, {
            "username": "admin",
            "role": "owner",
            "display_name": "Administrator",
        })
        self.assertEqual(
            self.conn.execute(
                "select last_seen from panel_sessions where session_id='session'"
            ).fetchone(),
            (100,),
        )

    def test_recent_session_resolution_avoids_redundant_sqlite_write(self):
        self.add_user()
        self.add_session(expires_at=1000, last_seen=95)
        changes_before = self.conn.total_changes

        user = resolve_session_record(self.conn, "session", now=100)

        self.assertEqual(user["username"], "admin")
        self.assertEqual(self.conn.total_changes, changes_before)
        self.assertEqual(
            self.conn.execute(
                "select last_seen from panel_sessions where session_id='session'"
            ).fetchone(),
            (95,),
        )

    def test_stale_session_refreshes_last_seen_once_interval_elapsed(self):
        self.add_user()
        self.add_session(expires_at=1000, last_seen=40)

        resolve_session_record(self.conn, "session", now=100)

        self.assertEqual(
            self.conn.execute(
                "select last_seen from panel_sessions where session_id='session'"
            ).fetchone(),
            (100,),
        )

    def test_exact_expiry_boundary_is_revoked(self):
        self.add_user()
        self.add_session(expires_at=100)

        self.assertIsNone(resolve_session_record(self.conn, "session", now=100))
        self.assertIsNone(
            self.conn.execute(
                "select 1 from panel_sessions where session_id='session'"
            ).fetchone()
        )

    def test_whitespace_role_and_text_expiry_fail_closed(self):
        self.add_user(username="blank-role", role="   ")
        self.add_user(username="text-expiry", role="owner")
        self.add_session("blank-role-session", "blank-role", 1000)
        self.add_session("text-expiry-session", "text-expiry", "1000")

        self.assertIsNone(resolve_session_record(self.conn, "blank-role-session", now=100))
        self.assertIsNone(resolve_session_record(self.conn, "text-expiry-session", now=100))
        self.assertEqual(
            self.conn.execute("select count(*) from panel_sessions").fetchone(),
            (0,),
        )

    def test_prune_uses_same_expiry_boundary(self):
        self.add_user()
        self.add_session("expired", expires_at=100)
        self.add_session("active", expires_at=101)

        removed = prune_invalid_session_records(self.conn, now=100)

        self.assertEqual(removed, 1)
        self.assertEqual(
            self.conn.execute(
                "select session_id from panel_sessions order by session_id"
            ).fetchall(),
            [("active",)],
        )


if __name__ == "__main__":
    unittest.main()
