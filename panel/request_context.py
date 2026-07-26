#!/usr/bin/env python3
"""Per-request presentation context for the threaded HTTP server."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Mapping


_CURRENT_USER: ContextVar[dict[str, Any] | None] = ContextVar(
    "vpn_vpn_current_user",
    default=None,
)


def set_current_user(user: Mapping[str, Any] | None) -> None:
    """Set a defensive copy of the authenticated user for this request context."""
    _CURRENT_USER.set(dict(user or {}))


def get_current_user() -> dict[str, Any]:
    """Return a defensive copy so renderers cannot mutate request state."""
    return dict(_CURRENT_USER.get() or {})
