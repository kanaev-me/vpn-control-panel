#!/usr/bin/env python3
"""Create the initial panel database and owner account on a clean host."""

from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time


USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@+-]{1,64}$")
GROUP_RE = re.compile(r"^[A-Za-z0-9_.@+-]{1,64}$")
PBKDF2_ITERATIONS = 600_000


def password_hash(password: str) -> str:
    salt = secrets.token_bytes(32)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=32,
    )
    return "$".join(
        (
            "pbkdf2_sha256",
            str(PBKDF2_ITERATIONS),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(digest).decode("ascii"),
        )
    )


def read_password(path: Path) -> str:
    password = path.read_text(encoding="utf-8").rstrip("\r\n")
    if len(password) < 12:
        raise ValueError("administrator password must contain at least 12 characters")
    if len(password) > 1024:
        raise ValueError("administrator password is too long")
    return password


def bootstrap(
    db_path: Path,
    username: str,
    display_name: str,
    password: str,
    default_group: str,
    *,
    replace_existing: bool = False,
) -> None:
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("administrator username contains unsupported characters")
    if not GROUP_RE.fullmatch(default_group):
        raise ValueError("default group contains unsupported characters")

    db_path.parent.mkdir(parents=True, exist_ok=True)
    now = int(time.time())
    stored_hash = password_hash(password)

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS panel_users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                display_name TEXT NOT NULL DEFAULT '',
                is_enabled INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS panel_sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_panel_sessions_expires_at
                ON panel_sessions(expires_at);

            CREATE TABLE IF NOT EXISTS panel_groups (
                name TEXT PRIMARY KEY,
                title TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS panel_user_groups (
                username TEXT NOT NULL,
                group_name TEXT NOT NULL,
                can_view INTEGER NOT NULL DEFAULT 1,
                can_create INTEGER NOT NULL DEFAULT 1,
                can_delete INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (username, group_name)
            );

            CREATE TABLE IF NOT EXISTS vpn_client_meta (
                client TEXT PRIMARY KEY,
                group_name TEXT NOT NULL,
                created_by TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL DEFAULT 0,
                comment TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL DEFAULT 0,
                person_name TEXT NOT NULL DEFAULT '',
                person_slug TEXT NOT NULL DEFAULT '',
                device_label TEXT NOT NULL DEFAULT '',
                device_type TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_vpn_client_meta_group
                ON vpn_client_meta(group_name);

            CREATE TABLE IF NOT EXISTS vpn_sessions (
                session_key TEXT PRIMARY KEY,
                client TEXT NOT NULL,
                vpn_ip TEXT,
                remote_ip TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                disconnected_at INTEGER,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_vpn_sessions_client
                ON vpn_sessions(client);
            CREATE INDEX IF NOT EXISTS idx_vpn_sessions_last_seen
                ON vpn_sessions(last_seen);
            """
        )

        existing = conn.execute(
            "SELECT password_hash FROM panel_users WHERE username=?",
            (username,),
        ).fetchone()
        if existing and not replace_existing:
            raise ValueError(
                "administrator already exists; refusing to replace its password "
                "without --replace-existing"
            )

        conn.execute(
            """
            INSERT INTO panel_groups(name, title, created_at, updated_at)
            VALUES(?,?,?,?)
            ON CONFLICT(name) DO UPDATE SET
                title=excluded.title,
                updated_at=excluded.updated_at
            """,
            (default_group, default_group, now, now),
        )

        if existing:
            conn.execute(
                """
                UPDATE panel_users
                SET password_hash=?, role='owner', display_name=?, is_enabled=1, updated_at=?
                WHERE username=?
                """,
                (stored_hash, display_name or username, now, username),
            )
            conn.execute(
                "DELETE FROM panel_sessions WHERE username=?",
                (username,),
            )
        else:
            conn.execute(
                """
                INSERT INTO panel_users
                    (username, password_hash, role, display_name, is_enabled, created_at, updated_at)
                VALUES(?,?,?,?,1,?,?)
                """,
                (username, stored_hash, "owner", display_name or username, now, now),
            )

        conn.execute(
            """
            INSERT INTO panel_user_groups
                (username, group_name, can_view, can_create, can_delete)
            VALUES(?,?,1,1,1)
            ON CONFLICT(username, group_name) DO UPDATE SET
                can_view=1,
                can_create=1,
                can_delete=1
            """,
            (username, default_group),
        )
        conn.execute("PRAGMA user_version=1")
        conn.commit()

        result = conn.execute("PRAGMA integrity_check").fetchone()
        if not result or result[0] != "ok":
            raise RuntimeError(f"SQLite integrity check failed: {result!r}")
    finally:
        conn.close()

    os.chmod(db_path, 0o600)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--display-name", default="Administrator")
    parser.add_argument("--password-file", type=Path, required=True)
    parser.add_argument("--default-group", default="default")
    parser.add_argument(
        "--replace-existing",
        action="store_true",
        help="explicitly replace an existing administrator password",
    )
    args = parser.parse_args()

    bootstrap(
        args.db,
        args.username.strip(),
        args.display_name.strip(),
        read_password(args.password_file),
        args.default_group.strip(),
        replace_existing=args.replace_existing,
    )
    print(f"database={args.db}")
    print(f"administrator={args.username.strip()}")
    print(f"default_group={args.default_group.strip()}")
    print(f"replaced_existing={int(args.replace_existing)}")


if __name__ == "__main__":
    main()
