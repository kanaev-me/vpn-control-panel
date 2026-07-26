#!/usr/bin/env python3
"""Normalization helpers for VPN session history rows."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any


SessionRow = Mapping[str, Any]


def apply_active_start_floor(
    rows: list[SessionRow] | None,
    floor_ts: int | None,
    format_timestamp: Callable[[int], str],
):
    """Clamp active sessions that predate the current Pluto process start.

    Historical inactive sessions are preserved. A row is copied only when its
    visible first_seen values must change, matching the previous wrapper
    behavior without mutating cached/source dictionaries.
    """

    if not floor_ts:
        return rows

    try:
        normalized_floor = int(floor_ts)
    except (TypeError, ValueError):
        return rows
    if normalized_floor <= 0:
        return rows

    fixed = []
    for row in rows or []:
        current = row
        try:
            if row.get("active") and int(row.get("first_seen") or 0) < normalized_floor:
                current = dict(row)
                current["first_seen"] = normalized_floor
                current["first_seen_text"] = format_timestamp(normalized_floor)
        except Exception:
            pass
        fixed.append(current)
    return fixed


def clamp_active_duration_to_floor(
    record: Any,
    floor_ts: int | None,
    *,
    now_timestamp: Callable[[], float],
    format_timestamp: Callable[[int], str],
    format_duration: Callable[[int], str],
):
    """Mutate one active connection summary to the current Pluto start floor.

    Mutation is intentional: the historical wrapper updated the connection
    dictionaries returned by the base history loader in place. Invalid values
    fail open and leave the record untouched.
    """

    try:
        if not isinstance(record, dict) or not floor_ts:
            return record

        normalized_floor = int(floor_ts)
        old_ts = int(record.get("connected_since_ts") or 0)
        if old_ts and old_ts < normalized_floor:
            now = int(now_timestamp())
            record["connected_since_ts"] = normalized_floor
            record["connected_since"] = format_timestamp(normalized_floor)
            record["duration"] = format_duration(max(0, now - normalized_floor))
    except Exception:
        pass
    return record
