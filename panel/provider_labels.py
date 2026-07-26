#!/usr/bin/env python3
"""Provider label normalization used by the panel presentation layer.

This module is intentionally pure: it does not read the database, environment,
network or filesystem.
"""

from __future__ import annotations

import re


def normalize_provider(value):
    raw = str(value or "").strip()

    if not raw or raw in {"—", "-", "None", "none", "null"}:
        return raw

    low_raw = raw.lower()

    is_aggregate_line = (
        "сесс" in low_raw
        or " ip" in low_raw
        or "·" in raw
        or ("—" in raw and any(ch.isdigit() for ch in raw))
    )

    replacements = [
        (r'\bAS8359\s+MTS\s+PJSC\b', 'МТС'),
        (r'\bMobile\s+TeleSystems\s+PJSC\b', 'МТС'),
        (r'\bMTS\s+PJSC\b', 'МТС'),
        (r'\bAS30881\s+MTS\s+PJSC\b', 'МТС'),

        (r'\bAS15378\s+T2\s+Mobile\s+LLC\b', 'Т2'),
        (r'\bT2\s+Mobile\s+LLC\b', 'Т2'),
        (r'\bTele2\b', 'Т2'),

        (r'\bAS205638\s+"?TBANK"?\s+JSC\b', 'Т-Банк'),
        (r'\bTBANK\s+JSC\b', 'Т-Банк'),
        (r'\bTinkoff\s+Mobile\s+LLC\b', 'Т-Банк'),

        (r'\bJSC\s+"?Severen-Telecom"?\b', 'Северен-Телеком'),
        (r'\bSeveren-Telecom\b', 'Северен-Телеком'),

        (r'\bKoltushsky\s+Internet\s+Ltd\b', 'Колтушский интернет'),
        (r'\bKOLT-AS\b', 'Колтушский интернет'),

        (r'\bAS47236\s+CityLink\s+Ltd\b', 'CityLink'),
        (r'\bCityLink\s+Ltd\s+ISP\b', 'CityLink'),
        (r'\bCityLink\s+Ltd\b', 'CityLink'),

        (r'\bAS12418\s+Quantum\s+CJSC\b', 'Quantum'),
        (r'\bQuantum\s+CJSC\b', 'Quantum'),

        (r'\bSvyazservice\s+LTD\b', 'Svyazservice'),
        (r'\bUnet\s+Communication\s+LLC\b', 'Unet'),
        (r'\bGlobal\s+Network\s+Management\s+Inc\b', 'Global Network'),

        (r'\bTERICOM\s+Ltd\b', 'TERICOM'),
        (r'\bSeaExpress\s+Ltd\b', 'SeaExpress'),
        (r'\bAS31376\s+Smart\s+Telecom\s+Limited\b', 'Smart Telecom'),
        (r'\bSmart\s+Telecom\s+Limited\b', 'Smart Telecom'),
        (r'\bAS42893\s+Home\s+Internet\s+Ltd\b', 'Home Internet'),
        (r'\bHome\s+Internet\s+Ltd\b', 'Home Internet'),
        (r'\bJSC\s+"?Futures\s+Telecom"?\b', 'Futures Telecom'),

        (r'\bOJSC\s+"?North-West\s+Telecom"?\b', 'Северо-Западный Телеком'),
        (r'\bObit-Telecommunications\s+Ltd\b', 'ОБИТ'),
        (r'\bAS51178\s+JSC\s+Avantel\b', 'Авантел'),
        (r'\bJSC\s+Avantel\b', 'Авантел'),
        (r'\bSuperlink\s+LLC\b', 'Superlink'),

        (r'\bKaspNet\s+Ltd\.?\b', 'KaspNet'),
        (r'"?MAYAK\s+NETWORK"?\s+LTD\b', 'MAYAK Network'),
        (r'\bAS47140\s+LLC\s+Oblastnaya\s+Set\b', 'Областная сеть'),
        (r'\bLLC\s+Oblastnaya\s+Set\b', 'Областная сеть'),

        (r'\bJSC\s+"?Ufanet"?\b', 'Уфанет'),
        (r'\bOOO\s+TRK\s+\'\'INTEGRAL\'\'\b', 'Интеграл'),
        (r'\bAS212673\s+OOO\s+TRK\s+\'\'INTEGRAL\'\'\b', 'Интеграл'),

        (r'\bCORBINA-BROADBAND\b', 'Корбина'),
        (r'\bFilanco\s*/\s*Citytelecom\b', 'Citytelecom'),
        (r'\bZ-Telecom\b', 'Дом.ru'),
        (r'\bAS42861\s+Z-Telecom\b', 'Дом.ru'),
    ]

    out = raw

    for pattern, repl in replacements:
        out = re.sub(pattern, repl, out, flags=re.I)

    out = re.sub(r'\b(PJSC|JSC|OJSC|CJSC|LLC|LTD|Ltd\.|Limited|Inc\.?|Corp\.?|Company)\b', '', out, flags=re.I)
    out = re.sub(r'\bAS\d{3,}\b', '', out, flags=re.I)

    out = out.replace('""', '"')
    out = re.sub(r'\s{2,}', ' ', out)
    out = re.sub(r'\s+—', ' —', out)
    out = re.sub(r'—\s+', '— ', out)
    out = re.sub(r'\s+·\s+', ' · ', out)
    out = out.strip(' "\'')

    # Сводную строку очищаем целиком, не схлопывая до одного бренда.
    if is_aggregate_line:
        return out or raw

    low = out.lower().strip()

    if 'megafon' in low or 'мегафон' in low:
        return 'МегаФон'
    if low in {'mts', 'мтс'}:
        return 'МТС'
    if low in {'t2', 'т2'}:
        return 'Т2'
    if 'rostelecom' in low or 'ростелеком' in low:
        return 'Ростелеком'
    if 'skynet' in low:
        return 'SkyNet'
    if 'beeline' in low or 'vimpelcom' in low or 'билайн' in low:
        return 'Билайн'
    if 'severen' in low or 'северен' in low:
        return 'Северен-Телеком'
    if 'citylink' in low:
        return 'CityLink'
    if 'koltush' in low or 'колтуш' in low:
        return 'Колтушский интернет'
    if 'ufanet' in low or 'уфанет' in low:
        return 'Уфанет'
    if 'z-telecom' in low or 'ztelecom' in low:
        return 'Дом.ru'

    return out or raw


def normalize_provider_object(obj):
    if not isinstance(obj, dict):
        return obj

    for key in (
        "provider",
        "current_provider",
        "isp",
        "org",
        "as_name",
        "title",
        "name",
        "network",
        "caption",
    ):
        if key in obj and obj.get(key):
            try:
                obj[key] = normalize_provider(obj.get(key))
            except Exception:
                pass

    return obj


def normalize_profile_data(data):
    if not isinstance(data, dict):
        return data

    for key in ("current_provider", "provider", "isp", "org", "as_name"):
        if key in data and data.get(key):
            try:
                data[key] = normalize_provider(data.get(key))
            except Exception:
                pass

    for list_key in ("sessions", "geo", "networks", "places", "related", "known_networks"):
        rows = data.get(list_key)

        if isinstance(rows, list):
            for row in rows:
                normalize_provider_object(row)

    return data
