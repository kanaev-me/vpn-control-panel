#!/usr/bin/env python3
"""Render an isolated tenant deployment bundle without touching a live server."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import shlex
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_LAYOUT = ROOT / "config" / "source-layout.env.example"
sys.path.insert(0, str(ROOT / "panel"))

from runtime_config import RuntimeConfig, load_runtime_config  # noqa: E402


_SOURCE_KEYS = {
    "VPN_SOURCE_APP_NAME",
    "VPN_SOURCE_SERVICE_PREFIX",
    "VPN_SOURCE_PANEL_UNIT",
    "VPN_SOURCE_APP_DIR",
    "VPN_SOURCE_STATUS_DIR",
    "VPN_SOURCE_INSTRUCTIONS_DIR",
    "VPN_SOURCE_CACHE_DIR",
}


def parse_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(f"{path}:{line_number}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if value and value[0] in {chr(39), chr(34)}:
            parsed = shlex.split(value)
            if len(parsed) != 1:
                raise ValueError(f"{path}:{line_number}: invalid quoted value")
            value = parsed[0]
        values[key] = value
    return values


def load_source_layout(path: Path) -> dict[str, str]:
    values = parse_env(path)
    missing = sorted(_SOURCE_KEYS - values.keys())
    if missing:
        raise ValueError(f"{path}: missing source layout keys: {', '.join(missing)}")
    return values


def env_lines(config: RuntimeConfig) -> list[str]:
    channel_capacity = "" if config.channel_capacity_mbit is None else str(config.channel_capacity_mbit)
    pairs = [
        ("VPN_APP_NAME", config.app_name),
        ("VPN_BRAND_NAME", config.brand_name),
        ("VPN_PUBLIC_DOMAIN", config.public_domain),
        ("VPN_SERVICE_PREFIX", config.service_prefix),
        ("VPN_PANEL_HOST", config.panel_host),
        ("VPN_PANEL_PORT", str(config.panel_port)),
        ("VPN_PANEL_APP_DIR", str(config.app_dir)),
        ("VPN_PANEL_DB_PATH", str(config.db_path)),
        ("VPN_PANEL_ACTION_LOG", str(config.action_log)),
        ("VPN_PANEL_STATUS_DIR", str(config.status_dir)),
        ("VPN_PANEL_INSTRUCTIONS_DIR", str(config.instructions_dir)),
        ("VPN_PANEL_CACHE_DIR", str(config.cache_dir)),
        ("VPN_IKEV2_SCRIPT", str(config.ikev2_script)),
        ("VPN_CERT_DB", config.cert_db),
        ("VPN_PANEL_SERVICE", config.panel_service),
        ("VPN_CADDY_SERVICE", config.caddy_service),
        ("VPN_IPSEC_SERVICE", config.ipsec_service),
        ("VPN_L2TP_SERVICE", config.l2tp_service),
        ("VPN_DEFAULT_ACCESS_GROUP", config.default_access_group),
        ("VPN_CHANNEL_CAPACITY_MBIT", channel_capacity),
        ("VPN_PULSE_ENDPOINT_ENABLED", "1" if config.pulse_endpoint_enabled else "0"),
        ("VPN_PULSE_SYNC_ENABLED", "1" if config.pulse_sync_enabled else "0"),
        ("VPN_PULSE_CONTRACT", config.pulse_contract),
        ("VPN_PULSE_NAME", config.pulse_name),
        ("VPN_PULSE_SLUG", config.pulse_slug),
    ]
    return [f"{key}={shlex.quote(value)}" for key, value in pairs]


def replace_literals_once(text: str, replacements: dict[str, str]) -> str:
    """Replace source literals without re-processing replacement values.

    Sequential ``str.replace`` calls can corrupt a rendered value when the target
    contains the source token. For example, replacing ``/opt/vpn-panel`` with
    ``/opt/nuova-vpn-panel`` and then replacing ``vpn-`` would add ``nuova-`` a
    second time. A single regex pass only matches literals from the original text.
    """

    filtered = {old: new for old, new in replacements.items() if old and old != new}
    if not filtered:
        return text
    pattern = re.compile("|".join(re.escape(old) for old in sorted(filtered, key=len, reverse=True)))
    return pattern.sub(lambda match: filtered[match.group(0)], text)


def render_unit(text: str, config: RuntimeConfig, source: dict[str, str]) -> str:
    replacements = {
        source["VPN_SOURCE_APP_DIR"]: str(config.app_dir),
        source["VPN_SOURCE_STATUS_DIR"]: str(config.status_dir),
        source["VPN_SOURCE_INSTRUCTIONS_DIR"]: str(config.instructions_dir),
        source["VPN_SOURCE_CACHE_DIR"]: str(config.cache_dir),
        f'{source["VPN_SOURCE_SERVICE_PREFIX"]}-': f"{config.service_prefix}-",
        source["VPN_SOURCE_APP_NAME"]: config.app_name,
    }
    return replace_literals_once(text, replacements)


def render_bundle(
    config: RuntimeConfig,
    source: dict[str, str],
    output: Path,
    force: bool = False,
) -> None:
    if output.exists() and any(output.iterdir()):
        if not force:
            raise FileExistsError(f"output directory is not empty: {output}")
        shutil.rmtree(output)
    output.mkdir(parents=True, exist_ok=True)
    units_dir = output / "systemd"
    units_dir.mkdir()

    (output / "panel.env").write_text("\n".join(env_lines(config)) + "\n", encoding="utf-8")
    (output / "Caddyfile").write_text(
        f"{config.public_domain} {{\n    reverse_proxy {config.panel_host}:{config.panel_port}\n}}\n",
        encoding="utf-8",
    )

    panel_name = config.panel_service
    if not panel_name.endswith(".service"):
        panel_name += ".service"
    source_prefix = f'{source["VPN_SOURCE_SERVICE_PREFIX"]}-'
    rendered_names: list[str] = []

    for source_unit in sorted((ROOT / "systemd").iterdir()):
        if not source_unit.is_file() or source_unit.suffix not in {".service", ".timer"}:
            continue
        if not config.pulse_sync_enabled and "known-networks-sync" in source_unit.name:
            continue

        if source_unit.name == source["VPN_SOURCE_PANEL_UNIT"]:
            target_name = panel_name
        else:
            target_name = source_unit.name.replace(source_prefix, f"{config.service_prefix}-", 1)

        target = units_dir / target_name
        target.write_text(
            render_unit(source_unit.read_text(encoding="utf-8"), config, source),
            encoding="utf-8",
        )
        rendered_names.append(target_name)

    if panel_name not in rendered_names:
        raise ValueError(f"source panel unit not found: {source['VPN_SOURCE_PANEL_UNIT']}")

    regular_timers = sorted(
        name
        for name in rendered_names
        if name.endswith(".timer")
        and "pluto-guard" not in name
        and "pluto-watchdog" not in name
    )
    (output / "ENABLE.txt").write_text("\n".join(regular_timers) + "\n", encoding="utf-8")
    (output / "MANIFEST.txt").write_text(
        "\n".join(
            [
                f"app_name={config.app_name}",
                f"domain={config.public_domain}",
                f"service_prefix={config.service_prefix}",
                f"app_dir={config.app_dir}",
                f"status_dir={config.status_dir}",
                f"channel_capacity_mbit={channel_capacity if (channel_capacity := config.channel_capacity_mbit) is not None else 'unset'}",
                f"pulse_endpoint_enabled={int(config.pulse_endpoint_enabled)}",
                f"pulse_sync_enabled={int(config.pulse_sync_enabled)}",
                f"rendered_units={len(rendered_names)}",
                f"regular_timers={len(regular_timers)}",
                "pluto_guard_default=disabled",
                "pluto_watchdog_default=disabled",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env", type=Path, required=True)
    parser.add_argument("--source-layout", type=Path, default=DEFAULT_SOURCE_LAYOUT)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    config = load_runtime_config(parse_env(args.env))
    source = load_source_layout(args.source_layout)
    render_bundle(config, source, args.output, force=args.force)
    print(f"tenant_bundle={args.output}")
    print(f"app_name={config.app_name}")
    print(f"domain={config.public_domain}")
    print(f"service_prefix={config.service_prefix}")


if __name__ == "__main__":
    main()
