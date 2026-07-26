#!/usr/bin/env python3
"""Explicit authorization predicates used by the panel runtime."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def _value(user: Mapping[str, Any] | None, key: str) -> str:
    if not isinstance(user, Mapping):
        return ""
    return str(user.get(key) or "").strip()


def is_role_owner(user: Mapping[str, Any] | None) -> bool:
    """Return the strict role check used by owner-only administration paths."""

    return _value(user, "role") == "owner"


def owner_only_client_allowed(
    user: Mapping[str, Any] | None,
    client: str = "",
    action: str = "can_view",
) -> bool:
    """Allow client operations only to an explicitly assigned owner role.

    The current application still uses one owner-only decision for viewing and
    deleting client profiles. ``client`` and ``action`` remain in the signature
    so the web layer contract stays unchanged while the broader permission
    model is split out in later stages.
    """

    del client, action
    return is_role_owner(user)
