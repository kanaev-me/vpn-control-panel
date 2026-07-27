#!/usr/bin/env python3
"""Apply exact, reviewable edits to the large app and behavior builder."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "panel" / "app.py"
BEHAVIOR = ROOT / "panel" / "behavior_build.py"


def replace_once(text: str, old: str, new: str, *, label: str) -> str:
    count = text.count(old)
    if count == 0 and new in text:
        return text
    if count != 1:
        raise RuntimeError(f"{label}: expected one source block, found {count}")
    return text.replace(old, new, 1)


def patch_app() -> None:
    text = APP.read_text(encoding="utf-8")

    text = replace_once(
        text,
        "from runtime_config import CONFIG\n",
        "from runtime_config import CONFIG\n"
        "from dashboard_status import normalize_dashboard_data\n",
        label="dashboard status import",
    )

    old_dashboard = '''def support_dashboard_data():
    try:
        import json as _json
        raw = support_read_file(SUPPORT_STATUS_DIR, "dashboard.json", "{}")
        return _json.loads(raw)
    except Exception as e:
        return {
            "generated_at": "",
            "status": "bad",
            "reasons": ["dashboard_json_error", repr(e)],
            "services": {},
            "pluto": {},
            "active_now": None,
            "auth_fail_count_30m": None,
            "old_profile_clients_2h": None,
            "possible_multi_device_clients_2h": None,
            "active_networks": [],
        }
'''
    new_dashboard = '''def support_dashboard_data():
    raw_data = {}
    try:
        import json as _json
        raw = support_read_file(SUPPORT_STATUS_DIR, "dashboard.json", "{}")
        loaded = _json.loads(raw)
        if isinstance(loaded, dict):
            raw_data = loaded
    except Exception:
        # dashboard.json is optional enrichment. Live systemd state remains the
        # source of truth, so a missing or malformed artifact must not turn every
        # healthy service red.
        raw_data = {}

    return normalize_dashboard_data(
        raw_data,
        service_names=(
            PANEL_SERVICE_NAME,
            CADDY_SERVICE_NAME,
            IPSEC_SERVICE_NAME,
            L2TP_SERVICE_NAME,
        ),
        service_state=service_state,
    )
'''
    text = replace_once(
        text,
        old_dashboard,
        new_dashboard,
        label="support dashboard loader",
    )

    old_pairs = '''    service_pairs = (
        (PANEL_SERVICE_NAME, "panel"),
        ("caddy", "caddy"),
        ("ipsec", "ipsec"),
        ("xl2tpd", "xl2tpd"),
    )
'''
    new_pairs = '''    service_pairs = (
        (PANEL_SERVICE_NAME, "panel"),
        (CADDY_SERVICE_NAME, "caddy"),
        (IPSEC_SERVICE_NAME, "ipsec"),
        (L2TP_SERVICE_NAME, "xl2tpd"),
    )
'''
    text = replace_once(text, old_pairs, new_pairs, label="home service names")

    APP.write_text(text, encoding="utf-8")


def patch_behavior() -> None:
    text = BEHAVIOR.read_text(encoding="utf-8")

    old = '''        required = ["vpn_sessions", "ip_asn_cache"]
        missing = [t for t in required if not table_exists(con, t)]
        if missing:
            raise SystemExit("Missing tables: " + ", ".join(missing))

        con.executescript("""
'''
    new = '''        # A clean panel may not have resolved any remote IP yet. Keep the
        # provider cache available as a normal empty input instead of failing the
        # hourly behavior job before the first VPN connection is observed.
        con.execute("""
            create table if not exists ip_asn_cache (
                ip text primary key,
                asn text,
                provider text,
                label text,
                updated_at integer not null default 0
            )
        """)

        required = ["vpn_sessions"]
        missing = [t for t in required if not table_exists(con, t)]
        if missing:
            raise SystemExit("Missing tables: " + ", ".join(missing))

        con.executescript("""
'''
    text = replace_once(text, old, new, label="behavior empty cache bootstrap")
    BEHAVIOR.write_text(text, encoding="utf-8")


def main() -> None:
    patch_app()
    patch_behavior()
    print("live_session_runtime_fix=applied")


if __name__ == "__main__":
    main()
