#!/usr/bin/env python3
"""Combine optional dashboard artifacts with authoritative live service states."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any


Dashboard = dict[str, Any]


def _positive_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def normalize_dashboard_data(
    raw_data: Mapping[str, Any] | None,
    *,
    service_names: Sequence[str],
    service_state: Callable[[str], str],
) -> Dashboard:
    """Return dashboard data whose service states come from systemd right now.

    The JSON artifact is optional enrichment. Missing, malformed or stale artifacts
    must not make healthy live services appear down. Non-service counters are kept
    when present and the overall level is rebuilt from live services plus the
    supported attention counters.
    """

    data: Dashboard = dict(raw_data) if isinstance(raw_data, Mapping) else {}

    services: dict[str, str] = {}
    for name in service_names:
        clean_name = str(name or "").strip()
        if not clean_name:
            continue
        try:
            value = str(service_state(clean_name) or "unknown").strip() or "unknown"
        except Exception:
            value = "unknown"
        services[clean_name] = value

    data["services"] = services
    data.setdefault("generated_at", "")
    data.setdefault("pluto", {})
    data.setdefault("active_now", None)
    data.setdefault("active_networks", [])

    auth_fail = _positive_int(data.get("auth_fail_count_30m"))
    old_profiles = _positive_int(data.get("old_profile_clients_2h"))
    possible_multi = _positive_int(data.get("possible_multi_device_clients_2h"))

    data["auth_fail_count_30m"] = auth_fail
    data["old_profile_clients_2h"] = old_profiles
    data["possible_multi_device_clients_2h"] = possible_multi

    reasons: list[str] = []
    failed_services = [
        f"{name}: {value}"
        for name, value in services.items()
        if value != "active"
    ]

    if failed_services:
        status = "bad"
        reasons.extend(failed_services)
    elif auth_fail or old_profiles:
        status = "bad"
        if auth_fail:
            reasons.append(f"auth failures: {auth_fail}")
        if old_profiles:
            reasons.append(f"old profiles: {old_profiles}")
    elif possible_multi:
        status = "warn"
        reasons.append(f"possible multi-device: {possible_multi}")
    else:
        status = "ok"

    data["status"] = status
    data["reasons"] = reasons
    return data
