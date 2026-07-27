#!/usr/bin/env python3
"""Generic runtime configuration for an isolated VPN panel deployment."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from math import isfinite
from pathlib import Path
import os
import re
from typing import Mapping


_TRUE = {"1", "true", "yes", "on", "enabled"}
_FALSE = {"0", "false", "no", "off", "disabled"}
_PREFIX_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _read(env: Mapping[str, str], name: str, default: str) -> str:
    value = env.get(name)
    if value is None or not str(value).strip():
        return default
    return str(value).strip()


def _read_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name)
    if raw is None or not str(raw).strip():
        return default
    value = str(raw).strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise ValueError(f"{name} must be one of: {sorted(_TRUE | _FALSE)}")


def _read_optional_positive_float(env: Mapping[str, str], name: str) -> float | None:
    raw = env.get(name)
    if raw is None or not str(raw).strip():
        return None
    try:
        value = float(str(raw).strip())
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive finite number or empty") from exc
    if not isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be a positive finite number or empty")
    return value


def _absolute_path(value: str, name: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute path")
    return path


def _normalize_public_domain(value: str) -> str:
    raw = str(value or "").strip()
    try:
        domain = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("VPN_PUBLIC_DOMAIN must be a DNS host name without scheme, path or port") from exc

    labels = domain.split(".")
    valid = (
        1 < len(labels)
        and len(domain) <= 253
        and all(_DNS_LABEL_RE.fullmatch(label) for label in labels)
    )
    try:
        is_ip_address = bool(domain and ip_address(domain))
    except ValueError:
        is_ip_address = False

    if not valid or is_ip_address:
        raise ValueError("VPN_PUBLIC_DOMAIN must be a DNS host name without scheme, path or port")
    return domain


@dataclass(frozen=True)
class RuntimeConfig:
    app_name: str
    brand_name: str
    public_domain: str
    service_prefix: str
    panel_host: str
    panel_port: int
    app_dir: Path
    db_path: Path
    action_log: Path
    status_dir: Path
    instructions_dir: Path
    cache_dir: Path
    profile_dir: Path
    ikev2_script: Path
    cert_db: str
    panel_service: str
    caddy_service: str
    ipsec_service: str
    l2tp_service: str
    default_access_group: str
    channel_capacity_mbit: float | None
    pulse_endpoint_enabled: bool
    pulse_sync_enabled: bool
    pulse_contract: str
    pulse_name: str
    pulse_slug: str


def load_runtime_config(env: Mapping[str, str] | None = None) -> RuntimeConfig:
    values: Mapping[str, str] = os.environ if env is None else env

    service_prefix = _read(values, "VPN_SERVICE_PREFIX", "vpn")
    if not _PREFIX_RE.fullmatch(service_prefix):
        raise ValueError("VPN_SERVICE_PREFIX must contain lowercase letters, digits and hyphens")

    app_name = _read(values, "VPN_APP_NAME", "VPN")
    brand_name = _read(values, "VPN_BRAND_NAME", "VPN")
    public_domain = _normalize_public_domain(
        _read(values, "VPN_PUBLIC_DOMAIN", "vpn.example.invalid")
    )

    panel_host = _read(values, "VPN_PANEL_HOST", "127.0.0.1")
    port_raw = _read(values, "VPN_PANEL_PORT", "8711")
    try:
        panel_port = int(port_raw)
    except ValueError as exc:
        raise ValueError("VPN_PANEL_PORT must be an integer") from exc
    if not 1 <= panel_port <= 65535:
        raise ValueError("VPN_PANEL_PORT must be between 1 and 65535")

    app_dir = _absolute_path(
        _read(values, "VPN_PANEL_APP_DIR", f"/opt/{service_prefix}-panel"),
        "VPN_PANEL_APP_DIR",
    )
    state_root = f"/var/lib/{service_prefix}-panel"

    return RuntimeConfig(
        app_name=app_name,
        brand_name=brand_name,
        public_domain=public_domain,
        service_prefix=service_prefix,
        panel_host=panel_host,
        panel_port=panel_port,
        app_dir=app_dir,
        db_path=_absolute_path(
            _read(values, "VPN_PANEL_DB_PATH", str(app_dir / "panel.db")),
            "VPN_PANEL_DB_PATH",
        ),
        action_log=_absolute_path(
            _read(values, "VPN_PANEL_ACTION_LOG", str(app_dir / "actions.log")),
            "VPN_PANEL_ACTION_LOG",
        ),
        status_dir=_absolute_path(
            _read(values, "VPN_PANEL_STATUS_DIR", f"{state_root}/status"),
            "VPN_PANEL_STATUS_DIR",
        ),
        instructions_dir=_absolute_path(
            _read(values, "VPN_PANEL_INSTRUCTIONS_DIR", f"{state_root}/instructions"),
            "VPN_PANEL_INSTRUCTIONS_DIR",
        ),
        cache_dir=_absolute_path(
            _read(values, "VPN_PANEL_CACHE_DIR", f"/var/cache/{service_prefix}-panel"),
            "VPN_PANEL_CACHE_DIR",
        ),
        # The bundled hwdsl2 ikev2.sh creates and exports client files in /root.
        # Separate tenants run on separate VPN hosts, so this path is isolated per host.
        profile_dir=Path("/root"),
        ikev2_script=_absolute_path(
            _read(values, "VPN_IKEV2_SCRIPT", "/opt/src/ikev2.sh"),
            "VPN_IKEV2_SCRIPT",
        ),
        cert_db=_read(values, "VPN_CERT_DB", "sql:/etc/ipsec.d"),
        panel_service=_read(values, "VPN_PANEL_SERVICE", f"{service_prefix}-panel"),
        caddy_service=_read(values, "VPN_CADDY_SERVICE", "caddy"),
        ipsec_service=_read(values, "VPN_IPSEC_SERVICE", "ipsec"),
        l2tp_service=_read(values, "VPN_L2TP_SERVICE", "xl2tpd"),
        default_access_group=_read(values, "VPN_DEFAULT_ACCESS_GROUP", "default"),
        channel_capacity_mbit=_read_optional_positive_float(values, "VPN_CHANNEL_CAPACITY_MBIT"),
        pulse_endpoint_enabled=_read_bool(values, "VPN_PULSE_ENDPOINT_ENABLED", False),
        pulse_sync_enabled=_read_bool(values, "VPN_PULSE_SYNC_ENABLED", False),
        pulse_contract=_read(values, "VPN_PULSE_CONTRACT", "vpn-pulse-v1"),
        pulse_name=_read(values, "VPN_PULSE_NAME", app_name),
        pulse_slug=_read(values, "VPN_PULSE_SLUG", service_prefix),
    )


CONFIG = load_runtime_config()
