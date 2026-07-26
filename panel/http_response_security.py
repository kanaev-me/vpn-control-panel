#!/usr/bin/env python3
"""Common security headers for private panel responses."""

from __future__ import annotations

from collections.abc import Iterable


_BASE_HEADERS = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'none'"),
    ("X-Robots-Tag", "noindex, nofollow, noarchive, nosnippet"),
)
_NO_STORE_HEADERS = (
    ("Cache-Control", "no-store"),
    ("Pragma", "no-cache"),
)


def security_header_pairs(
    *,
    no_store: bool = True,
    existing_names: Iterable[str] = (),
) -> tuple[tuple[str, str], ...]:
    """Return missing security headers without duplicating caller headers."""

    existing = {str(name or "").strip().lower() for name in existing_names}
    pairs = _BASE_HEADERS + (_NO_STORE_HEADERS if no_store else ())
    return tuple((name, value) for name, value in pairs if name.lower() not in existing)


def send_security_headers(
    handler,
    *,
    no_store: bool = True,
    existing_names: Iterable[str] = (),
) -> None:
    """Write common security headers through a BaseHTTPRequestHandler-like API."""

    for name, value in security_header_pairs(
        no_store=no_store,
        existing_names=existing_names,
    ):
        handler.send_header(name, value)
