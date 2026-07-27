#!/usr/bin/env python3
"""SQLite operations for panel authentication sessions.

The module receives an open DB-API connection. It does not know the database
path, HTTP handler or cookie format, which keeps session rules independently
testable.
"""

from __future__ import annotations

from typing import Callable


UserRecord = dict[str, str]
SESSION_LAST_SEEN_WRITE_INTERVAL = 60


def prune_invalid_session_records(conn, *, now: int) -> int:
    """Delete sessions that can no longer authenticate a valid user.

    Cleanup runs when a new session is issued. It removes expired or malformed
    rows plus sessions whose user is missing, disabled or has no role. Valid
    concurrent sessions are preserved so signing in on one device does not log
    out another device.
    """

    cursor = conn.execute(
        """
        delete from panel_sessions
        where typeof(expires_at) != 'integer'
           or expires_at <= ?
           or not exists (
                select 1
                from panel_users pu
                where pu.username = panel_sessions.username
                  and pu.is_enabled = 1
                  and coalesce(trim(pu.role), '') != ''
           )
        """,
        (now,),
    )
    conn.commit()
    return max(int(cursor.rowcount or 0), 0)


def create_session_record(
    conn,
    username: str,
    *,
    now: int,
    ttl: int,
    session_id_factory: Callable[[], str],
) -> str:
    prune_invalid_session_records(conn, now=now)

    session_id = session_id_factory()
    expires_at = now + ttl
    conn.execute(
        "insert into panel_sessions(session_id, username, created_at, last_seen, expires_at) values(?,?,?,?,?)",
        (session_id, username, now, now, expires_at),
    )
    conn.commit()
    return session_id


def delete_session_record(conn, session_id: str) -> None:
    if not session_id:
        return
    conn.execute("delete from panel_sessions where session_id=?", (session_id,))
    conn.commit()


def resolve_session_record(conn, session_id: str, *, now: int) -> UserRecord | None:
    """Return the active user and refresh last_seen, or revoke the session.

    A session is valid only while the linked user still exists, is enabled, has
    a role and the session has not expired. Invalid rows are removed eagerly so
    disabling a user revokes already-issued sessions on the next request.
    """
    if not session_id:
        return None

    row = conn.execute(
        """
        select ps.username, trim(pu.role), pu.display_name, ps.last_seen
        from panel_sessions ps
        join panel_users pu
          on pu.username = ps.username
         and pu.is_enabled = 1
         and coalesce(trim(pu.role), '') != ''
        where ps.session_id = ?
          and typeof(ps.expires_at) = 'integer'
          and ps.expires_at > ?
        """,
        (session_id, now),
    ).fetchone()

    if not row:
        delete_session_record(conn, session_id)
        return None

    username, role, display_name, last_seen = row
    if not username or not role:
        delete_session_record(conn, session_id)
        return None

    try:
        should_refresh_last_seen = int(last_seen or 0) <= (
            now - SESSION_LAST_SEEN_WRITE_INTERVAL
        )
    except (TypeError, ValueError):
        should_refresh_last_seen = True

    if should_refresh_last_seen:
        conn.execute(
            "update panel_sessions set last_seen = ? where session_id = ?",
            (now, session_id),
        )
        conn.commit()

    return {
        "username": username,
        "role": role,
        "display_name": display_name or username,
    }
