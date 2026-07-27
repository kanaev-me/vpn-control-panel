#!/usr/bin/env python3
"""Collect live Libreswan IKEv2 sessions independently of web requests."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Callable


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def client_from_identity(identity: str) -> str:
    identity = str(identity or "").strip()
    if not identity:
        return ""
    if identity.startswith("@"):
        return identity[1:]
    match = re.search(r"CN=([^,\]]+)", identity)
    if match:
        return match.group(1).strip()
    if identity in {"%any", "%fromcert", "unset", "none", "unknown"}:
        return ""
    return ""


def parse_connections_status(status: str) -> list[dict[str, str]]:
    """Parse active routed IKEv2 clients from ``ipsec status`` output."""

    by_serial: dict[str, dict[str, object]] = {}

    for line in str(status or "").splitlines():
        serial_match = re.search(r'"ikev2-cp"\[(\d+)\]', line)
        if not serial_match:
            continue

        serial = serial_match.group(1)
        item = by_serial.setdefault(
            serial,
            {
                "client": "",
                "remote_ip": "",
                "vpn_ip": "",
                "ike_sa": "",
                "routed": False,
            },
        )

        ike_match = re.search(r"established IKE SA: #(\d+)", line)
        if ike_match:
            item["ike_sa"] = ike_match.group(1)

        if "routed-tunnel" not in line:
            continue

        item["routed"] = True

        remote_match = re.search(
            r"\.\.\.([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:\[([^\]]+)\])?",
            line,
        )
        if remote_match:
            item["remote_ip"] = remote_match.group(1)
            client = client_from_identity(remote_match.group(2) or "")
            if client:
                item["client"] = client

        assigned_match = re.search(r"their_ip=([^;]+)", line)
        if assigned_match:
            item["vpn_ip"] = assigned_match.group(1).strip()
        else:
            assigned_match = re.search(
                r"===\{([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:/\d+)?}",
                line,
            )
            if assigned_match:
                item["vpn_ip"] = assigned_match.group(1)

    connections: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for item in by_serial.values():
        if not item.get("routed"):
            continue
        if not item.get("vpn_ip") and not item.get("remote_ip"):
            continue

        client = str(item.get("client") or "имя не определено")
        vpn_ip = str(item.get("vpn_ip") or "")
        remote_ip = str(item.get("remote_ip") or "")
        key = (client, vpn_ip, remote_ip)
        if key in seen:
            continue
        seen.add(key)

        connections.append(
            {
                "client": client,
                "remote_ip": remote_ip,
                "vpn_ip": vpn_ip,
                "ike_sa": str(item.get("ike_sa") or ""),
            }
        )

    return sorted(
        connections,
        key=lambda item: (
            item["client"] == "имя не определено",
            item["client"].lower(),
            item["vpn_ip"],
        ),
    )


def read_ipsec_status(*, runner: CommandRunner = subprocess.run) -> str:
    result = runner(
        ["ipsec", "status"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=15,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"ipsec status failed with exit {result.returncode}: "
            f"{str(result.stdout or '').strip()}"
        )
    return str(result.stdout or "")


def collect_live_sessions(*, runner: CommandRunner = subprocess.run) -> int:
    """Persist one authoritative live-session snapshot.

    A failed ``ipsec status`` call aborts without marking existing active sessions
    disconnected. A successful empty snapshot is meaningful and closes sessions
    that disappeared since the previous sample.
    """

    status = read_ipsec_status(runner=runner)
    connections = parse_connections_status(status)

    # Import lazily so parser tests do not load the monolithic HTTP application.
    from app import update_session_history

    update_session_history(connections)
    return len(connections)


if __name__ == "__main__":
    print(f"live_connections: {collect_live_sessions()}")
