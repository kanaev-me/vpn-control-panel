#!/usr/bin/env python3
"""Read-only compatibility checks for the live panel authentication database."""

from __future__ import annotations

from dataclasses import dataclass

from auth_cookie import session_id_is_valid
from auth_passwords import (
    MAX_USERNAME_CHARS,
    PasswordHashError,
    parse_password_hash,
)


class AuthDatabaseCompatibilityError(RuntimeError):
    """The current live auth database cannot safely serve this panel version."""


@dataclass(frozen=True)
class AuthDatabaseReport:
    enabled_users: int
    session_rows: int
    invalid_session_ids: int
    max_pbkdf2_iterations: int


_REQUIRED_COLUMNS = {
    "panel_users": {
        "username",
        "display_name",
        "password_hash",
        "role",
        "is_enabled",
    },
    "panel_sessions": {
        "session_id",
        "username",
        "created_at",
        "last_seen",
        "expires_at",
    },
}


def _table_columns(conn, table: str) -> set[str]:
    rows = conn.execute(f'pragma table_info("{table}")').fetchall()
    return {str(row[1]) for row in rows if len(row) > 1}


def inspect_auth_database(conn) -> AuthDatabaseReport:
    """Validate auth schema and enabled password hashes without revealing values."""

    for table, required in _REQUIRED_COLUMNS.items():
        columns = _table_columns(conn, table)
        if not columns:
            raise AuthDatabaseCompatibilityError(f"required table is missing: {table}")
        missing = sorted(required - columns)
        if missing:
            raise AuthDatabaseCompatibilityError(
                f"required columns are missing from {table}: {', '.join(missing)}"
            )

    rows = conn.execute(
        """
        select username, role, password_hash
        from panel_users
        where is_enabled = 1
        """
    ).fetchall()
    if not rows:
        raise AuthDatabaseCompatibilityError("no enabled panel users with login access")

    max_iterations = 0
    for index, row in enumerate(rows, start=1):
        username, role, stored_hash = row
        username = str(username or "").strip()
        role = str(role or "").strip()
        if not username or len(username) > MAX_USERNAME_CHARS:
            raise AuthDatabaseCompatibilityError(
                f"enabled user row {index} has an invalid username contract"
            )
        if not role:
            raise AuthDatabaseCompatibilityError(
                f"enabled user row {index} has an empty role"
            )
        try:
            spec = parse_password_hash(stored_hash)
        except PasswordHashError as exc:
            raise AuthDatabaseCompatibilityError(
                f"enabled user row {index} has an unsupported password hash: {exc}"
            ) from exc
        max_iterations = max(max_iterations, spec.iterations)

    session_rows = 0
    invalid_session_ids = 0
    for (session_id,) in conn.execute("select session_id from panel_sessions"):
        session_rows += 1
        if not session_id_is_valid(session_id):
            invalid_session_ids += 1

    return AuthDatabaseReport(
        enabled_users=len(rows),
        session_rows=session_rows,
        invalid_session_ids=invalid_session_ids,
        max_pbkdf2_iterations=max_iterations,
    )
