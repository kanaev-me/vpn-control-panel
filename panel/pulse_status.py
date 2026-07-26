#!/usr/bin/env python3
"""Build a public, privacy-safe VPN monitoring contract."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from runtime_config import CONFIG


SAFE_SERVICE_NAMES = ("panel", "caddy", "ipsec", "xl2tpd")
HEALTHY_SERVICE_STATES = {"active", "ok", "running"}


def _as_mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        return default


def _service_state(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return text or "unknown"


def _safe_events(value: Any) -> list[dict[str, str]]:
    """Keep only generic profile create/delete events with an optional timestamp."""

    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return []

    result: list[dict[str, str]] = []
    for raw in value[:20]:
        if not isinstance(raw, Mapping):
            continue

        kind = str(raw.get("kind") or "").strip().lower()
        if kind not in {"vpn_profile_created", "vpn_profile_deleted"}:
            continue

        item = {
            "kind": kind,
            "title": (
                "Создан VPN-профиль"
                if kind == "vpn_profile_created"
                else "Удалён VPN-профиль"
            ),
        }
        timestamp = str(raw.get("dt") or "").strip()
        if timestamp:
            item["dt"] = timestamp[:40]
        result.append(item)

    return result


def build_pulse_status(
    summary: Any,
    services: Any,
    server: Any,
    *,
    host: str = "",
    events: Any = None,
) -> dict[str, Any]:
    """Return only stable operational fields for the configured Pulse endpoint.

    The function deliberately ignores every client/profile/session/IP field in
    the source summary. Adding sensitive fields to the internal panel summary
    can therefore never expand this public contract accidentally.
    """

    source = _as_mapping(summary)
    raw_services = _as_mapping(services)
    raw_server = _as_mapping(server)

    safe_services = {
        name: _service_state(raw_services.get(name))
        for name in SAFE_SERVICE_NAMES
    }
    bad_services = [
        name
        for name, value in safe_services.items()
        if value not in HEALTHY_SERVICE_STATES
    ]

    vpn = {
        "access_count": max(0, _as_int(source.get("access_count"))),
        "valid_count": max(0, _as_int(source.get("valid_count"))),
        "expired_count": max(0, _as_int(source.get("expired_count"))),
        "revoked_count": max(0, _as_int(source.get("revoked_count"))),
        "active_connection_count": max(
            0,
            _as_int(source.get("active_connection_count")),
        ),
        "unknown_connection_count": max(
            0,
            _as_int(source.get("unknown_connection_count")),
        ),
    }

    disk_percent = max(0.0, min(100.0, _as_float(raw_server.get("disk_percent"))))
    safe_server = {
        "disk_percent": round(disk_percent, 1),
        "load1": round(max(0.0, _as_float(raw_server.get("load1"))), 2),
        "load5": round(max(0.0, _as_float(raw_server.get("load5"))), 2),
        "load15": round(max(0.0, _as_float(raw_server.get("load15"))), 2),
    }

    issues: list[str] = []
    if bad_services:
        issues.append("services=" + ",".join(bad_services))
    if vpn["expired_count"]:
        issues.append(f'expired {vpn["expired_count"]}')
    if vpn["revoked_count"]:
        issues.append(f'revoked {vpn["revoked_count"]}')
    if vpn["unknown_connection_count"]:
        issues.append(f'unknown connections {vpn["unknown_connection_count"]}')
    if disk_percent >= 85:
        issues.append(f"disk {disk_percent:.1f}%")

    if bad_services:
        status = "critical"
    elif issues:
        status = "warning"
    else:
        status = "ok"

    summary_text = (
        f'VPN {status}: {vpn["active_connection_count"]} онлайн · '
        f'{vpn["access_count"]} доступов'
    )
    issue_label = "VPN требует внимания: " + " · ".join(issues) if issues else ""
    show_card = status != "ok"
    feed_only = status == "ok"

    payload = {
        "contract": CONFIG.pulse_contract,
        "name": CONFIG.pulse_name,
        "slug": CONFIG.pulse_slug,
        "host": str(host or CONFIG.service_prefix)[:80],
        "status": status,
        "show_card": show_card,
        "feed_only": feed_only,
        "summary": summary_text,
        "issue_label": issue_label,
        "services": safe_services,
        "vpn": vpn,
        "server": safe_server,
        "events": _safe_events(events),
        "tv": {
            "status": status,
            "show_card": show_card,
            "feed_only": feed_only,
            "summary": summary_text,
        },
    }
    return payload
