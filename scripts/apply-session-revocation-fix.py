#!/usr/bin/env python3
"""One-time exact transformer for password-reset session revocation."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = {
    ROOT / "scripts" / "bootstrap-panel-admin.py": (
        "d09d46879e309ef2d5b53b2d76511a90af9198e1",
        "58227fd253e303129988e1100207e52f8e354a46",
    ),
    ROOT / "tests" / "test_bootstrap_panel_admin.py": (
        "d859ad9cadadbaba192595723a14a3c8f3fdf9d6",
        "c3b602ef2cb8034a72dbae3009805e4effe439bb",
    ),
}


def blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise RuntimeError(f"expected one exact anchor, found {source.count(old)}")
    return source.replace(old, new, 1)


bootstrap = ROOT / "scripts" / "bootstrap-panel-admin.py"
source = bootstrap.read_text(encoding="utf-8")
source = replace_once(
    source,
    '''        if existing:\n            conn.execute(\n                """\n                UPDATE panel_users\n                SET password_hash=?, role='owner', display_name=?, is_enabled=1, updated_at=?\n                WHERE username=?\n                """,\n                (stored_hash, display_name or username, now, username),\n            )\n        else:\n''',
    '''        if existing:\n            conn.execute(\n                """\n                UPDATE panel_users\n                SET password_hash=?, role='owner', display_name=?, is_enabled=1, updated_at=?\n                WHERE username=?\n                """,\n                (stored_hash, display_name or username, now, username),\n            )\n            conn.execute(\n                "DELETE FROM panel_sessions WHERE username=?",\n                (username,),\n            )\n        else:\n''',
)
bootstrap.write_text(source, encoding="utf-8")

tests = ROOT / "tests" / "test_bootstrap_panel_admin.py"
source = tests.read_text(encoding="utf-8")
source = replace_once(
    source,
    '''    def test_short_password_is_rejected(self):\n''',
    '''    def test_explicit_password_replacement_revokes_only_target_user_sessions(self):\n        with tempfile.TemporaryDirectory() as tmp:\n            root = Path(tmp)\n            db = root / "panel.db"\n            first_file = root / "first-password"\n            second_file = root / "second-password"\n            first_file.write_text("correct horse battery staple\\n", encoding="utf-8")\n            second_file.write_text("another deliberately strong password\\n", encoding="utf-8")\n\n            self.run_bootstrap(db, first_file)\n            conn = sqlite3.connect(db)\n            try:\n                conn.executemany(\n                    "insert into panel_sessions "\n                    "(session_id, username, created_at, last_seen, expires_at) "\n                    "values(?,?,?,?,?)",\n                    (\n                        ("admin-session-a", "admin", 1, 1, 9999999999),\n                        ("admin-session-b", "admin", 2, 2, 9999999999),\n                        ("other-session", "other-user", 3, 3, 9999999999),\n                    ),\n                )\n                conn.commit()\n            finally:\n                conn.close()\n\n            self.run_bootstrap(db, second_file, "--replace-existing")\n            conn = sqlite3.connect(db)\n            try:\n                admin_sessions = conn.execute(\n                    "select session_id from panel_sessions where username='admin'"\n                ).fetchall()\n                other_sessions = conn.execute(\n                    "select session_id from panel_sessions where username='other-user'"\n                ).fetchall()\n            finally:\n                conn.close()\n\n            self.assertEqual(admin_sessions, [])\n            self.assertEqual(other_sessions, [("other-session",)])\n\n    def test_short_password_is_rejected(self):\n''',
)
tests.write_text(source, encoding="utf-8")

for path, (before, after) in TARGETS.items():
    current = blob_sha(path.read_bytes())
    if current == before:
        raise RuntimeError(f"{path}: transformation did not change file")
    if current != after:
        raise RuntimeError(f"{path}: unexpected output blob {current}, expected {after}")
    print(f"updated={path.relative_to(ROOT)} blob={current}")
