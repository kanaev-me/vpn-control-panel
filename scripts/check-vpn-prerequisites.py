#!/usr/bin/env python3
"""Fail closed unless the hwdsl2 IKEv2 stack is already installed and usable."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess


DEFAULT_IKEV2_CONFIG = Path("/etc/ipsec.d/ikev2.conf")
DEFAULT_IPSEC_CONFIG = Path("/etc/ipsec.conf")


def cert_db_path(value: str) -> Path:
    raw = str(value or "").strip()
    if raw.startswith("sql:"):
        raw = raw[4:]
    return Path(raw)


def validate_prerequisites(
    *,
    ikev2_script: Path,
    cert_db: str,
    ipsec_service: str,
    ikev2_config: Path = DEFAULT_IKEV2_CONFIG,
    ipsec_config: Path = DEFAULT_IPSEC_CONFIG,
) -> list[str]:
    errors: list[str] = []

    if not ikev2_script.is_file():
        errors.append(f"IKEv2 helper not found: {ikev2_script}")
    elif not os.access(ikev2_script, os.X_OK):
        errors.append(f"IKEv2 helper is not executable: {ikev2_script}")

    if shutil.which("ipsec") is None:
        errors.append("Libreswan command not found: ipsec")
    if shutil.which("certutil") is None:
        errors.append("NSS command not found: certutil")
    if shutil.which("systemctl") is None:
        errors.append("systemd command not found: systemctl")

    if not ipsec_config.is_file():
        errors.append(f"IPsec configuration not found: {ipsec_config}")
    if not ikev2_config.is_file():
        errors.append(f"IKEv2 configuration not found: {ikev2_config}")

    database = cert_db_path(cert_db)
    if not database.is_dir():
        errors.append(f"IPsec NSS database directory not found: {database}")
    else:
        modern = (database / "cert9.db").is_file() and (database / "key4.db").is_file()
        legacy = (database / "cert8.db").is_file() and (database / "key3.db").is_file()
        if not modern and not legacy:
            errors.append(f"IPsec NSS database is not initialized: {database}")

    if not errors:
        service = ipsec_service.removesuffix(".service")
        active = subprocess.run(
            ["systemctl", "is-active", "--quiet", service],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        if active.returncode != 0:
            errors.append(f"IPsec service is not active: {service}")

    if not errors:
        result = subprocess.run(
            [str(ikev2_script), "--listclients"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            errors.append("IKEv2 helper cannot list clients; IKEv2 setup is incomplete")

    return errors


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ikev2-script", type=Path, required=True)
    parser.add_argument("--cert-db", required=True)
    parser.add_argument("--ipsec-service", default="ipsec")
    parser.add_argument("--ikev2-config", type=Path, default=DEFAULT_IKEV2_CONFIG)
    parser.add_argument("--ipsec-config", type=Path, default=DEFAULT_IPSEC_CONFIG)
    parser.add_argument("--domain", default="vpn.example.com")
    args = parser.parse_args()

    errors = validate_prerequisites(
        ikev2_script=args.ikev2_script,
        cert_db=args.cert_db,
        ipsec_service=args.ipsec_service,
        ikev2_config=args.ikev2_config,
        ipsec_config=args.ipsec_config,
    )
    if errors:
        print("VPN prerequisite check failed:", file=__import__("sys").stderr)
        for error in errors:
            print(f"  - {error}", file=__import__("sys").stderr)
        print("", file=__import__("sys").stderr)
        print("Install hwdsl2/setup-ipsec-vpn first, then rerun the panel installer:", file=__import__("sys").stderr)
        print("  curl -fsSL https://get.vpnsetup.net -o vpn.sh", file=__import__("sys").stderr)
        print(f"  sudo VPN_DNS_NAME='{args.domain}' sh vpn.sh", file=__import__("sys").stderr)
        raise SystemExit(2)

    print("vpn_prerequisites=ok")
    print(f"ikev2_script={args.ikev2_script}")
    print(f"cert_db={cert_db_path(args.cert_db)}")
    print(f"ipsec_service={args.ipsec_service.removesuffix('.service')}")


if __name__ == "__main__":
    main()
