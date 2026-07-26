#!/usr/bin/env python3
"""Strict construction and parsing of the panel authentication cookie."""

from __future__ import annotations

import re


AUTH_COOKIE_NAME = "vpn_vpn_session"
AUTH_SESSION_TTL = 86400 * 7
_MIN_SESSION_ID_CHARS = 32
_MAX_SESSION_ID_CHARS = 128
_SESSION_ID_RE = re.compile(
    rf"[A-Za-z0-9_-]{{{_MIN_SESSION_ID_CHARS},{_MAX_SESSION_ID_CHARS}}}"
)


def session_id_is_valid(session_id: str) -> bool:
    return bool(
        isinstance(session_id, str)
        and _SESSION_ID_RE.fullmatch(session_id)
    )


def auth_cookie_header(session_id: str, *, ttl: int = AUTH_SESSION_TTL) -> str:
    """Build a host-scoped secure session cookie without accepting raw syntax."""

    if not session_id_is_valid(session_id):
        raise ValueError("invalid session id")
    ttl = int(ttl)
    if ttl <= 0:
        raise ValueError("ttl must be positive")
    return (
        f"{AUTH_COOKIE_NAME}={session_id}; Path=/; Max-Age={ttl}; "
        "HttpOnly; Secure; SameSite=Lax"
    )


def clear_auth_cookie_header() -> str:
    return (
        f"{AUTH_COOKIE_NAME}=; Path=/; Max-Age=0; "
        "HttpOnly; Secure; SameSite=Lax"
    )


def _cookie_header_values(headers) -> list[str]:
    try:
        values = headers.get_all("Cookie")
    except AttributeError:
        value = headers.get("Cookie")
        values = [] if value is None else [value]
    if values is None:
        return []
    return [str(value) for value in values]


def get_cookie_session_id(headers) -> str:
    """Return one unambiguous URL-safe session id, otherwise fail closed."""

    matches: list[str] = []
    for raw in _cookie_header_values(headers):
        for part in raw.split(";"):
            if "=" not in part:
                continue
            key, value = part.split("=", 1)
            if key.strip() == AUTH_COOKIE_NAME:
                matches.append(value.strip())

    if len(matches) != 1:
        return ""
    value = matches[0]
    return value if session_id_is_valid(value) else ""
