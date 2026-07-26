#!/usr/bin/env python3
"""Provider lookup and presentation normalization for panel SQLite data."""

from __future__ import annotations

import re

from provider_labels import normalize_provider


_EMPTY_PROVIDER_VALUES = {"", "—", "-", "None", "none"}


def _table_exists(connection, name: str) -> bool:
    try:
        return connection.execute(
            "select 1 from sqlite_master where type='table' and name=?",
            (name,),
        ).fetchone() is not None
    except Exception:
        return False


def _columns(connection, table: str) -> list[str]:
    try:
        return [row["name"] for row in connection.execute(f'pragma table_info("{table}")')]
    except Exception:
        return []


def _empty_provider(value) -> bool:
    return str(value or "").strip() in _EMPTY_PROVIDER_VALUES


def _legacy_nice_provider(provider):
    value = str(provider or "").strip()
    low = value.lower()

    if not value or value == "—":
        return "—"
    if "vimpelcom" in low or "as16345" in low or "beeline" in low or "билайн" in low:
        return "Билайн"
    if "megafon" in low or "мегафон" in low:
        return "МегаФон"
    if "mobile telesystems" in low or low == "mts" or "мтс" in low:
        return "МТС"
    if "tele2" in low or low == "t2":
        return "T2"
    if "yota" in low or "йота" in low:
        return "Yota"
    if "er-telecom" in low or "дом.ru" in low or "dom.ru" in low:
        return "Дом.ru"
    if "rostelecom" in low or "ростелеком" in low:
        return "Ростелеком"
    if "skynet" in low:
        return "SkyNet"
    if "filanco" in low:
        return "Filanco / Citytelecom"
    if "citytelecom" in low:
        return "Citytelecom"
    return value


def nice_provider(provider):
    """Preserve the v43 aliases, then apply the shared wide normalizer."""

    return normalize_provider(_legacy_nice_provider(provider))


def _raw_provider_for_ip(connection, ip: str):
    ip = str(ip or "").strip()
    if not ip:
        return "—"

    if _table_exists(connection, "known_client_networks"):
        row = connection.execute(
            "select title from known_client_networks where ip=?",
            (ip,),
        ).fetchone()
        if row and row["title"]:
            return row["title"]

    if _table_exists(connection, "ip_geo_cache"):
        row = connection.execute(
            """
            select isp, org, as_name
            from ip_geo_cache
            where ip=? and status='success'
            """,
            (ip,),
        ).fetchone()
        if row:
            return row["isp"] or row["org"] or row["as_name"] or "—"

    if _table_exists(connection, "ip_asn_cache"):
        columns = _columns(connection, "ip_asn_cache")
        if "ip" in columns:
            row = connection.execute(
                "select * from ip_asn_cache where ip=? limit 1",
                (ip,),
            ).fetchone()
            if row:
                for column in (
                    "brand",
                    "provider",
                    "org",
                    "name",
                    "as_name",
                    "asn_name",
                ):
                    if column in columns and row[column]:
                        return row[column]

    return "—"


def provider_for_ip(connection, ip: str):
    """Resolve provider with the historical source priority and normalization."""

    provider = _raw_provider_for_ip(connection, ip)

    if _empty_provider(provider):
        try:
            if _table_exists(connection, "ip_asn_cache"):
                columns = _columns(connection, "ip_asn_cache")
                if "ip" in columns:
                    row = connection.execute(
                        "select * from ip_asn_cache where ip=? limit 1",
                        (ip,),
                    ).fetchone()
                    if row:
                        for column in (
                            "brand",
                            "provider",
                            "org",
                            "name",
                            "as_name",
                            "asn_name",
                            "asn_org",
                        ):
                            if column in columns and row[column]:
                                provider = row[column]
                                break
        except Exception:
            pass

    # The old chain normalized in _v43_nice_provider and once more in the final
    # provider_for_ip wrapper. Keep that exact composition.
    return normalize_provider(nice_provider(provider))


def _legacy_pretty_provider_name(raw):
    provider_raw = str(raw or "")
    provider_low = provider_raw.lower()

    if "foton company" in provider_low or "as57988" in provider_low:
        return "Фотон"
    if "seaexpress" in provider_low or "sea express" in provider_low:
        return "Sea Express"
    if (
        provider_raw.strip().upper() in {"TBANK", "T-BANK", "T BANK"}
        or "tbank" in provider_low
        or "tcs-as" in provider_low
    ):
        return "Т-Банк"
    if (
        "information network" in provider_low
        or "infolan" in provider_low
        or "info-lan" in provider_low
    ):
        return "Инфо-Лан"

    value = provider_raw.strip()
    if not value:
        return ""

    value = value.replace("_", " ")
    value = value.replace(" ,", ",").replace(" .", ".").strip()
    low = value.lower()

    rules = [
        ("megafon", "МегаФон"),
        ("mfone", "МегаФон"),
        ("mobile telesystems", "МТС"),
        ("mts", "МТС"),
        ("vimpelcom", "Билайн"),
        ("beeline", "Билайн"),
        ("bee-as", "Билайн"),
        ("t2 mobile", "T2"),
        ("tele2", "T2"),
        ("rostelecom", "Ростелеком"),
        ("rtcomm", "Ростелеком"),
        ("ncnet", "Ростелеком"),
        ("yota", "Yota"),
        ("motiv", "Мотив"),
        ("er-telecom", "Дом.ru"),
        ("er telecom", "Дом.ru"),
        ("dom.ru", "Дом.ru"),
        ("spb-as", "Дом.ru"),
        ("ttk", "ТТК"),
        ("trans-telecom", "ТТК"),
        ("selectel", "Selectel"),
        ("miran", "Miran"),
        ("yandex", "Яндекс"),
        ("cloudflare", "Cloudflare"),
        ("google", "Google"),
        ("amazon", "Amazon"),
        ("microsoft", "Microsoft"),
        ("apple", "Apple"),
        ("hetzner", "Hetzner"),
        ("digitalocean", "DigitalOcean"),
        ("skynet", "SkyNet"),
        ("citylink", "CityLink"),
        ("citytelecom", "Citytelecom"),
        ("koltushsky", "Колтушский интернет"),
        ("kolt-as", "Колтушский интернет"),
        ("unet communication", "Unet"),
        ("unetcom", "Unet"),
        ("etelecom", "Etelecom"),
        ("global network management", "Etelecom"),
        ("elektrosvyaz", "Электросвязь"),
        ("esd-as", "Электросвязь"),
        ("excellent signalman", "Лайнер"),
        ("svyazservice", "Связьсервис"),
        ("liner", "Лайнер"),
    ]

    for needle, name in rules:
        if needle in low:
            return name

    if " - " in value:
        left, right = value.split(" - ", 1)
        if ("as" in left.lower() or left.isupper()) and right.strip():
            value = right.strip()

    clean = value
    clean = re.sub(r"^[A-Z0-9_-]*AS[A-Z0-9_-]*\s*-\s*", "", clean, flags=re.I)
    clean = re.sub(
        r"\b(PJSC|JSC|LLC|LTD|INC|OOO|ZAO|PAO|IP|IE|LIMITED|CORP|CORPORATION|AG)\b",
        "",
        clean,
        flags=re.I,
    )
    clean = re.sub(
        r"\s*,\s*(RU|US|GB|EU|DE|NL|FI|LV|EE|LT|KZ|TR|CN|JP|FR|IT|ES|SE|NO)$",
        "",
        clean,
        flags=re.I,
    )
    clean = re.sub(r"\s+", " ", clean).strip(" ,-·.")
    return clean[:64] if clean else ""


def pretty_provider_name(raw):
    """Apply legacy cosmetic rules followed by the shared wide normalizer."""

    return normalize_provider(_legacy_pretty_provider_name(raw))
