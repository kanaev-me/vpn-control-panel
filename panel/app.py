#!/usr/bin/env python3
import html
import json
import os
import zipfile
import io
import re
import subprocess
import sqlite3
import secrets
import time
import copy
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from provider_labels import normalize_profile_data as _vpn_provider_norm_data_v2
from request_context import get_current_user as request_current_user
from request_context import set_current_user as set_request_current_user
from auth_sessions import (
    create_session_record,
    delete_session_record,
    resolve_session_record,
)
from http_input import FormBodyError, read_urlencoded_form
from access_policy import is_role_owner, owner_only_client_allowed
from login_throttle import LoginThrottle, request_source_ip
from csrf_protection import (
    CSRF_FIELD_NAME,
    inject_post_form_tokens,
    token_for_session,
    token_is_valid,
)
from http_response_security import send_security_headers
from auth_passwords import (
    MAX_PASSWORD_CHARS,
    MAX_USERNAME_CHARS,
    login_inputs_are_valid,
    verify_password,
)
from auth_cookie import (
    AUTH_SESSION_TTL,
    auth_cookie_header,
    clear_auth_cookie_header,
    get_cookie_session_id,
)
from session_history import (
    apply_active_start_floor,
    clamp_active_duration_to_floor,
)
from networks_page_cleanup import cleanup_networks_page as _n3_page_cleanup
from channel_page_finalize import finalize_channel_page
from networks_page_finalize import finalize_networks_page
from provider_resolution import (
    nice_provider as _v43_nice_provider,
    pretty_provider_name,
    provider_for_ip as _v4_provider_for_ip,
)
from profile_data_pipeline import run_profile_data_pipeline
from access_passport_pipeline import run_access_passport_pipeline
from pulse_status import build_pulse_status
from design_v2 import design_v2_css
from runtime_config import CONFIG

APP_NAME = CONFIG.app_name
BRAND_NAME = CONFIG.brand_name
PUBLIC_DOMAIN = CONFIG.public_domain
SERVICE_PREFIX = CONFIG.service_prefix
HOST = CONFIG.panel_host
PORT = CONFIG.panel_port
IKEV2_SH = str(CONFIG.ikev2_script)
CERTDB = CONFIG.cert_db
CERT_EXPIRY_CACHE = {}
IPSEC_DB = CONFIG.cert_db
ROOT_DIR = CONFIG.profile_dir
DB_PATH = CONFIG.db_path
ACTION_LOG = CONFIG.action_log
CACHE_DIR = CONFIG.cache_dir
PANEL_SERVICE_NAME = CONFIG.panel_service
CADDY_SERVICE_NAME = CONFIG.caddy_service
IPSEC_SERVICE_NAME = CONFIG.ipsec_service
L2TP_SERVICE_NAME = CONFIG.l2tp_service
DEFAULT_ACCESS_GROUP = CONFIG.default_access_group
PULSE_ENDPOINT_ENABLED = CONFIG.pulse_endpoint_enabled

LOGIN_THROTTLE = LoginThrottle(
    max_failures=8,
    window_seconds=10 * 60,
    block_seconds=15 * 60,
)


def run(cmd, timeout=8):
    try:
        p = subprocess.run(
            cmd,
            shell=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
        )
        return p.returncode, p.stdout.strip()
    except Exception as e:
        return 999, str(e)

def service_state(name):
    code, out = run(["systemctl", "is-active", name], timeout=4)
    return "active" if out.strip() == "active" else out.strip() or "unknown"

def get_uptime():
    code, out = run(["uptime", "-p"], timeout=4)
    return out if code == 0 else ""

def get_ipsec_status():
    code, out = run(["ipsec", "status"], timeout=8)
    return out if code == 0 else ""

def esc(x):
    return html.escape(str(x), quote=True)

def fmt_epoch(ts):
    if not ts:
        return "—"
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%d.%m %H:%M")
    except Exception:
        return "—"

def human_duration(seconds):
    if seconds is None:
        return "—"
    try:
        seconds = int(max(0, seconds))
    except Exception:
        return "—"
    if seconds < 60:
        return "меньше минуты"
    minutes = seconds // 60
    hours = minutes // 60
    days = hours // 24
    if days:
        h = hours % 24
        return f"{days}д {h}ч" if h else f"{days}д"
    if hours:
        m = minutes % 60
        return f"{hours}ч {m}м" if m else f"{hours}ч"
    return f"{minutes}м"

def client_from_identity(identity):
    identity = (identity or "").strip()
    if not identity:
        return ""
    if identity.startswith("@"):
        return identity[1:]
    m = re.search(r"CN=([^,\]]+)", identity)
    if m:
        return m.group(1).strip()
    bad = {"%any", "%fromcert", "unset", "none", "unknown"}
    if identity in bad:
        return ""
    return ""

def _list_clients_from_script_uncached():
    if not os.path.exists(IKEV2_SH):
        return []

    code, out = run([IKEV2_SH, "--listclients"], timeout=20)
    items = []

    for line in out.splitlines():
        raw = line.strip()
        if not raw:
            continue

        low = raw.lower()
        if low.startswith("ikev2 script"):
            continue
        if "checking for existing" in low:
            continue
        if "client name" in low and "certificate status" in low:
            continue
        if set(raw) <= {"-"}:
            continue

        m = re.match(r"^([A-Za-z0-9._@+-]+)\s+(valid|expired|revoked|unknown)\s*$", raw, re.I)
        if m:
            items.append({
                "name": m.group(1),
                "status": m.group(2).lower(),
            })

    return sorted(items, key=lambda x: x["name"].lower())

def list_clients_from_certdb():
    code, out = run(["certutil", "-L", "-d", IPSEC_DB], timeout=10)
    names = []

    for line in out.splitlines():
        raw = line.rstrip()
        if not raw:
            continue
        if not re.search(r"(u,u,u|CTu,u,u)\s*$", raw):
            continue

        name = raw[:60].strip()
        if not name or name == "IKEv2 VPN CA":
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", name):
            continue

        names.append(name)

    return sorted(set(names), key=str.lower)

def list_profiles():
    by_name = {}

    for ext in ("mobileconfig", "p12", "sswan"):
        for p in ROOT_DIR.glob(f"*.{ext}"):
            name = p.name.rsplit(".", 1)[0]
            st = p.stat()
            item = by_name.setdefault(name, {"name": name, "files": [], "mtime": 0})
            item["files"].append(ext)
            item["mtime"] = max(item["mtime"], int(st.st_mtime))

    items = list(by_name.values())
    for item in items:
        item["files"] = sorted(item["files"])

    return sorted(items, key=lambda x: (-x["mtime"], x["name"].lower()))

def list_l2tp_users():
    p = Path("/etc/ppp/chap-secrets")
    if not p.exists():
        return []

    users = []
    try:
        for line in p.read_text(errors="ignore").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split()
            if parts:
                users.append(parts[0].strip('"'))
    except Exception:
        pass

    return sorted(set(users), key=str.lower)

def parse_connections():
    status = get_ipsec_status()
    by_serial = {}

    for line in status.splitlines():
        sm = re.search(r'"ikev2-cp"\[(\d+)\]', line)
        if not sm:
            continue

        serial = sm.group(1)
        item = by_serial.setdefault(serial, {
            "client": "",
            "remote_ip": "",
            "vpn_ip": "",
            "ike_sa": "",
            "routed": False,
        })

        m = re.search(r"established IKE SA: #(\d+)", line)
        if m:
            item["ike_sa"] = m.group(1)

        if "routed-tunnel" not in line:
            continue

        item["routed"] = True

        m = re.search(r"\.\.\.([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:\[([^\]]+)\])?", line)
        if m:
            item["remote_ip"] = m.group(1)
            name = client_from_identity(m.group(2) or "")
            if name:
                item["client"] = name

        m = re.search(r"their_ip=([^;]+)", line)
        if m:
            item["vpn_ip"] = m.group(1).strip()
        else:
            m = re.search(r"==={([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:/\d+)?}", line)
            if m:
                item["vpn_ip"] = m.group(1)

    conns = []
    seen = set()

    for item in by_serial.values():
        if not item.get("routed"):
            continue
        if not item.get("vpn_ip") and not item.get("remote_ip"):
            continue

        client = item.get("client") or "имя не определено"
        key = (client, item.get("vpn_ip") or "", item.get("remote_ip") or "")
        if key in seen:
            continue
        seen.add(key)

        conns.append({
            "client": client,
            "remote_ip": item.get("remote_ip") or "",
            "vpn_ip": item.get("vpn_ip") or "",
            "ike_sa": item.get("ike_sa") or "",
        })

    return sorted(
        conns,
        key=lambda x: (x["client"] == "имя не определено", x["client"].lower(), x["vpn_ip"])
    )

def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS vpn_sessions (
                session_key TEXT PRIMARY KEY,
                client TEXT NOT NULL,
                vpn_ip TEXT,
                remote_ip TEXT,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                disconnected_at INTEGER,
                active INTEGER NOT NULL DEFAULT 1
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_vpn_sessions_client ON vpn_sessions(client)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_vpn_sessions_last_seen ON vpn_sessions(last_seen)")
        con.commit()
    finally:
        con.close()

def session_key_for(c):
    client = c.get("client") or ""
    vpn_ip = c.get("vpn_ip") or ""
    remote_ip = c.get("remote_ip") or ""
    ike_sa = str(c.get("ike_sa") or "").strip()

    # Важно: без ike_sa разные переподключения с тем же client/vpn_ip/remote_ip
    # склеивались в одну "вечную" сессию на дни и недели.
    if ike_sa:
        return "|".join([client, vpn_ip, remote_ip, "ike=" + ike_sa])

    return "|".join([client, vpn_ip, remote_ip])

def update_session_history(conns):
    init_db()
    now = int(time.time())
    active_keys = []

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    try:
        for c in conns:
            key = session_key_for(c)
            if not key.strip("|"):
                continue

            active_keys.append(key)

            row = con.execute(
                "SELECT first_seen FROM vpn_sessions WHERE session_key=?",
                (key,)
            ).fetchone()

            if row is None:
                con.execute(
                    """
                    INSERT INTO vpn_sessions
                    (session_key, client, vpn_ip, remote_ip, first_seen, last_seen, disconnected_at, active)
                    VALUES (?, ?, ?, ?, ?, ?, NULL, 1)
                    """,
                    (
                        key,
                        c.get("client") or "имя не определено",
                        c.get("vpn_ip") or "",
                        c.get("remote_ip") or "",
                        now,
                        now,
                    )
                )
                first_seen = now
            else:
                first_seen = int(row["first_seen"])
                con.execute(
                    """
                    UPDATE vpn_sessions
                    SET client=?, vpn_ip=?, remote_ip=?, last_seen=?, disconnected_at=NULL, active=1
                    WHERE session_key=?
                    """,
                    (
                        c.get("client") or "имя не определено",
                        c.get("vpn_ip") or "",
                        c.get("remote_ip") or "",
                        now,
                        key,
                    )
                )

            c["connected_since_ts"] = first_seen
            c["last_seen_ts"] = now
            c["connected_since"] = fmt_epoch(first_seen)
            c["last_seen"] = fmt_epoch(now)
            c["duration"] = human_duration(now - first_seen)

        if active_keys:
            placeholders = ",".join(["?"] * len(active_keys))
            con.execute(
                f"""
                UPDATE vpn_sessions
                SET active=0, disconnected_at=?
                WHERE active=1 AND session_key NOT IN ({placeholders})
                """,
                [now] + active_keys
            )
        else:
            con.execute(
                "UPDATE vpn_sessions SET active=0, disconnected_at=? WHERE active=1",
                (now,)
            )

        con.commit()

        last_by_client = {}
        for row in con.execute(
            """
            SELECT *
            FROM vpn_sessions
            WHERE client IS NOT NULL
              AND client != ''
              AND client != 'имя не определено'
            ORDER BY last_seen DESC
            """
        ):
            client = row["client"]
            if client in last_by_client:
                continue

            first_seen = int(row["first_seen"]) if row["first_seen"] else None
            last_seen = int(row["last_seen"]) if row["last_seen"] else None
            disconnected_at = int(row["disconnected_at"]) if row["disconnected_at"] else None
            active = bool(row["active"])

            if first_seen:
                if active:
                    duration_seconds = now - first_seen
                elif disconnected_at:
                    duration_seconds = disconnected_at - first_seen
                elif last_seen:
                    duration_seconds = last_seen - first_seen
                else:
                    duration_seconds = None
            else:
                duration_seconds = None

            last_by_client[client] = {
                "first_seen_ts": first_seen,
                "last_seen_ts": last_seen,
                "disconnected_at_ts": disconnected_at,
                "active": active,
                "remote_ip": row["remote_ip"] or "",
                "duration": human_duration(duration_seconds) if duration_seconds is not None else "—",
                "last_connected": fmt_epoch(first_seen),
                "last_seen": fmt_epoch(last_seen),
            }

    finally:
        con.close()

    floor_ts = _vpn_pluto_started_ts()
    if floor_ts:
        conns = [
            clamp_active_duration_to_floor(
                connection,
                floor_ts,
                now_timestamp=time.time,
                format_timestamp=fmt_epoch,
                format_duration=human_duration,
            )
            for connection in (conns or [])
        ]

        try:
            for client, history in list((last_by_client or {}).items()):
                if isinstance(history, dict):
                    last_by_client[client] = clamp_active_duration_to_floor(
                        history,
                        floor_ts,
                        now_timestamp=time.time,
                        format_timestamp=fmt_epoch,
                        format_duration=human_duration,
                    )
        except Exception:
            pass

    return conns, last_by_client

def parse_cert_expiry(raw):
    raw = (raw or "").strip()
    if not raw:
        return None

    raw = " ".join(raw.replace("notAfter=", "").split())

    patterns = [
        "%b %d %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y",
        "%a %b %d %H:%M:%S %Y",
        "%a %b %d %H:%M:%S %Z %Y",
    ]

    for pattern in patterns:
        try:
            return datetime.strptime(raw, pattern)
        except Exception:
            pass

    return None

def _cert_expiry_for_uncached(name):
    name = safe_client_name(name)
    result = {
        "expires_at": "—",
        "expires_raw": "",
        "expires_hint": "",
        "expires_ts": None,
    }

    if not name:
        return result

    # Cache for page/API refreshes. Cert dates change rarely.
    cached = CERT_EXPIRY_CACHE.get(name)
    now_ts = int(time.time())
    if cached and now_ts - cached.get("_cached_at", 0) < 3600:
        return {k: v for k, v in cached.items() if k != "_cached_at"}

    try:
        # Reliable path: export NSS cert to PEM and read notAfter with openssl.
        p1 = subprocess.run(
            ["certutil", "-L", "-d", CERTDB, "-n", name, "-a"],
            text=True,
            capture_output=True,
            timeout=10,
        )

        if p1.returncode == 0 and "BEGIN CERTIFICATE" in (p1.stdout or ""):
            p2 = subprocess.run(
                ["openssl", "x509", "-noout", "-enddate"],
                input=p1.stdout,
                text=True,
                capture_output=True,
                timeout=10,
            )

            if p2.returncode == 0 and "notAfter=" in (p2.stdout or ""):
                raw = p2.stdout.strip().split("=", 1)[1].strip()
                dt = parse_cert_expiry(raw)

                result["expires_raw"] = raw

                if dt:
                    result["expires_at"] = dt.strftime("%d.%m.%Y")
                    result["expires_ts"] = int(dt.timestamp())

                    now = datetime.now(timezone.utc).replace(tzinfo=None)
                    days = (dt - now).days

                    if days < 0:
                        result["expires_hint"] = f"истёк {abs(days)} дн. назад"
                    elif days == 0:
                        result["expires_hint"] = "истекает сегодня"
                    elif days == 1:
                        result["expires_hint"] = "истекает завтра"
                    else:
                        result["expires_hint"] = f"через {days} дн."
                else:
                    result["expires_at"] = raw

                cached_result = dict(result)
                cached_result["_cached_at"] = now_ts
                CERT_EXPIRY_CACHE[name] = cached_result
                return result

    except Exception as e:
        result["expires_hint"] = f"не удалось прочитать дату: {e}"

    cached_result = dict(result)
    cached_result["_cached_at"] = now_ts
    CERT_EXPIRY_CACHE[name] = cached_result
    return result


def _vpn_panel_cache_dir():
    from pathlib import Path
    path = CACHE_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path



def _vpn_panel_cache_clear():
    try:
        cache_dir = _vpn_panel_cache_dir()
        for name in ("list_clients_from_script.pkl", "cert_expiry_for.pkl"):
            try:
                (cache_dir / name).unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        pass


def _vpn_panel_cache_get(bucket, key, ttl_seconds, producer):
    import os
    import pickle
    import time

    now = time.time()
    safe_bucket = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(bucket))
    path = _vpn_panel_cache_dir() / f"{safe_bucket}.pkl"

    data = {}
    try:
        with path.open("rb") as f:
            loaded = pickle.load(f)
            if isinstance(loaded, dict):
                data = loaded
    except Exception:
        data = {}

    item = data.get(key)
    if isinstance(item, dict) and now - float(item.get("ts", 0) or 0) <= ttl_seconds:
        return item.get("value")

    value = producer()

    data[key] = {"ts": now, "value": value}
    tmp = path.with_suffix(".tmp")
    try:
        with tmp.open("wb") as f:
            pickle.dump(data, f)
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass

    return value


def list_clients_from_script():
    # /opt/src/ikev2.sh --listclients занимает около 2.5 сек.
    # Для морды достаточно короткого кэша, чтобы страница не висела при каждом открытии.
    return _vpn_panel_cache_get(
        "list_clients_from_script",
        "all",
        120,
        _list_clients_from_script_uncached,
    )


def cert_expiry_for(*args, **kwargs):
    # Срок сертификата не меняется при каждом открытии морды.
    # Раньше openssl запускался десятки раз на каждую загрузку страницы.
    key = repr((args, sorted(kwargs.items())))
    return _vpn_panel_cache_get(
        "cert_expiry_for",
        key,
        86400,
        lambda: _cert_expiry_for_uncached(*args, **kwargs),
    )


def status_ru(status):
    return {
        "valid": "действует",
        "expired": "срок истёк",
        "revoked": "отозван",
        "unknown": "неизвестно",
    }.get(status or "unknown", status or "неизвестно")

def status_hint(status):
    return {
        "valid": "можно подключаться",
        "expired": "сертификат закончился по дате",
        "revoked": "доступ принудительно отключён",
        "unknown": "статус не удалось определить",
    }.get(status or "unknown", "статус не удалось определить")



# removed old risk/asn/tempblock function: ensure_ip_asn_cache

def provider_short_name(as_name):
    text = (as_name or "").replace("_", " ").strip()
    low = text.lower()

    known = [
        ("megafon", "MegaFon"),
        ("rostelecom", "Rostelecom"),
        ("skynet", "SkyNet"),
        ("er-telecom", "ER-Telecom"),
        ("er telecom", "ER-Telecom"),
        ("dom.ru", "ER-Telecom"),
        ("t2 mobile", "Tele2"),
        ("tele2", "Tele2"),
        ("mts", "MTS"),
        ("mobile telesystems", "MTS"),
        ("vimpelcom", "Beeline"),
        ("beeline", "Beeline"),
        ("citylink", "CityLink"),
        ("yota", "Yota"),
    ]

    for needle, nice in known:
        if needle in low:
            return nice

    if " - " in text:
        text = text.split(" - ", 1)[0].strip()
    if "," in text:
        text = text.split(",", 1)[0].strip()

    return text[:48] if text else "неизвестно"

# removed old risk/asn/tempblock function: sharing_risk_for_legacy



# --- uniqueids-aware profile activity wrapper v1 start ---

# removed old risk/asn/tempblock function: sharing_risk_for
# --- uniqueids-aware profile activity wrapper v1 end ---



# removed old risk/asn/tempblock function: sharing_risk_pill


def human_bytes(value):
    try:
        n = int(value or 0)
    except Exception:
        n = 0

    units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
    x = float(n)

    for unit in units:
        if x < 1024 or unit == units[-1]:
            if unit == "Б":
                return f"{int(x)} {unit}"
            if x < 10:
                return f"{x:.1f} {unit}"
            return f"{x:.0f} {unit}"
        x /= 1024

    return f"{n} Б"

def client_from_ipsec_id(value):
    v = (value or "").strip().strip("'").strip('"')
    if not v:
        return ""

    if v.startswith("@"):
        return v[1:]

    if v.startswith("CN="):
        v = v[3:]
        if "," in v:
            v = v.split(",", 1)[0]
        return v.strip()

    return v

def ensure_ip_asn_cache():
    import sqlite3
    con = sqlite3.connect(DB_PATH, timeout=5)
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS ip_asn_cache (
                ip TEXT PRIMARY KEY,
                asn TEXT,
                provider TEXT,
                label TEXT,
                updated_at INTEGER NOT NULL DEFAULT 0
            )
        """)
        con.commit()
    finally:
        con.close()










def _lookup_provider_team_cymru(ip):
    import socket

    ip = (ip or "").strip()
    if not ip:
        return {"label": "—", "provider": "", "asn": ""}

    try:
        q = f" -v {ip}\n".encode("utf-8")
        with socket.create_connection(("whois.cymru.com", 43), timeout=2.0) as s:
            s.sendall(q)
            data = s.recv(4096).decode("utf-8", "ignore")
    except Exception:
        return {"label": "—", "provider": "", "asn": ""}

    rows = [x.strip() for x in data.splitlines() if x.strip()]
    if len(rows) < 2:
        return {"label": "—", "provider": "", "asn": ""}

    parts = [x.strip() for x in rows[-1].split("|")]
    asn = parts[0] if len(parts) > 0 else ""
    raw_provider = parts[-1] if len(parts) > 0 else ""
    provider = pretty_provider_name(raw_provider)
    if str(asn).strip() == "42387":
        provider = "Сампо.ру"

    return {
        "label": provider or "—",
        "provider": provider,
        "asn": asn,
    }


def ip_network_lookup(ip, allow_lookup=False):
    import sqlite3, time

    ip = (ip or "").strip()
    if not ip:
        return {"label": "—", "provider": "", "asn": "", "country": ""}

    ensure_ip_asn_cache()
    now = int(time.time())
    ttl = 60 * 60 * 24 * 30

    con = sqlite3.connect(DB_PATH, timeout=5)
    con.row_factory = sqlite3.Row
    try:
        row = con.execute("SELECT * FROM ip_asn_cache WHERE ip=?", (ip,)).fetchone()
        if row and now - int(row["updated_at"] or 0) < ttl:
            return {
                "label": row["label"] or ip,
                "provider": row["provider"] or "",
                "asn": row["asn"] or "",
                "country": "",
            }

        if not allow_lookup:
            return {"label": row["label"] if row else ip, "provider": row["provider"] if row else "", "asn": row["asn"] if row else "", "country": ""}

        data = _lookup_provider_team_cymru(ip)
        con.execute(
            "INSERT OR REPLACE INTO ip_asn_cache (ip, asn, provider, label, updated_at) VALUES (?, ?, ?, ?, ?)",
            (ip, data.get("asn") or "", data.get("provider") or "", data.get("label") or ip, now),
        )
        con.commit()
        return {**data, "country": ""}
    finally:
        con.close()


def ip_network_label(ip, allow_lookup=False):
    return ip_network_lookup(ip, allow_lookup=allow_lookup).get("label") or "—"



# active-duration-pluto-floor-v1
def _vpn_pluto_started_ts():
    try:
        import subprocess
        import datetime
        pid = subprocess.check_output(["pgrep", "-x", "pluto"], text=True, timeout=2).splitlines()[0].strip()
        raw = subprocess.check_output(["env", "LC_ALL=C", "ps", "-p", pid, "-o", "lstart="], text=True, timeout=2).strip()
        if not raw:
            return None
        dt = datetime.datetime.strptime(raw, "%a %b %d %H:%M:%S %Y")
        return int(dt.timestamp())
    except Exception:
        return None


def parse_trafficstatus_line(line):
    if "inBytes=" not in line and "outBytes=" not in line:
        return None

    in_m = re.search(r"\binBytes=(\d+)", line)
    out_m = re.search(r"\boutBytes=(\d+)", line)

    if not in_m and not out_m:
        return None

    id_value = ""

    m = re.search(r"\bid='([^']+)'", line)
    if not m:
        m = re.search(r'\bid="([^"]+)"', line)
    if not m:
        m = re.search(r"\bid=([^,\s]+)", line)

    if m:
        id_value = m.group(1)

    client = client_from_ipsec_id(id_value)

    if not client:
        m = re.search(r"\[@([^]]+)\]", line)
        if m:
            client = m.group(1).strip()
        else:
            m = re.search(r"\[CN=([^,\]]+)", line)
            if m:
                client = m.group(1).strip()

    if not client:
        return None

    in_bytes = int(in_m.group(1)) if in_m else 0
    out_bytes = int(out_m.group(1)) if out_m else 0

    return {
        "client": client,
        "in_bytes": in_bytes,
        "out_bytes": out_bytes,
        "total_bytes": in_bytes + out_bytes,
        "raw": line.strip(),
    }

def current_traffic_by_client():
    lines = []

    for cmd in (["ipsec", "trafficstatus"], ["ipsec", "whack", "--trafficstatus"]):
        try:
            r = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
        except Exception:
            continue

        out = (r.stdout or "") + "\n" + (r.stderr or "")
        if out.strip():
            lines = out.splitlines()
            break

    traffic = {}

    for line in lines:
        item = parse_trafficstatus_line(line)
        if not item:
            continue

        client = item["client"]
        cur = traffic.setdefault(client, {
            "in_bytes": 0,
            "out_bytes": 0,
            "total_bytes": 0,
            "items": 0,
            "raw": [],
        })

        cur["in_bytes"] += item["in_bytes"]
        cur["out_bytes"] += item["out_bytes"]
        cur["total_bytes"] += item["total_bytes"]
        cur["items"] += 1

        if len(cur["raw"]) < 3:
            cur["raw"].append(item["raw"])

    for client, cur in traffic.items():
        cur["in_human"] = human_bytes(cur["in_bytes"])
        cur["out_human"] = human_bytes(cur["out_bytes"])
        cur["total_human"] = human_bytes(cur["total_bytes"])
        cur["label"] = f"↓ {cur['in_human']} · ↑ {cur['out_human']}"
        cur["total_label"] = cur["total_human"]

    return traffic


def ensure_traffic_history():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS vpn_traffic_last (
                client TEXT PRIMARY KEY,
                in_bytes INTEGER NOT NULL DEFAULT 0,
                out_bytes INTEGER NOT NULL DEFAULT 0,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS vpn_traffic_daily (
                client TEXT NOT NULL,
                day TEXT NOT NULL,
                in_bytes INTEGER NOT NULL DEFAULT 0,
                out_bytes INTEGER NOT NULL DEFAULT 0,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (client, day)
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_vpn_traffic_daily_day ON vpn_traffic_daily(day)")
        con.commit()
    finally:
        con.close()

def today_key():
    return datetime.now().strftime("%Y-%m-%d")

def record_traffic_snapshot(traffic_by_client):
    ensure_traffic_history()

    now = int(time.time())
    day = today_key()

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    try:
        for client, cur in (traffic_by_client or {}).items():
            client = safe_client_name(client)
            if not client:
                continue

            cur_in = int(cur.get("in_bytes") or 0)
            cur_out = int(cur.get("out_bytes") or 0)
            cur_total = int(cur.get("total_bytes") or (cur_in + cur_out))

            last = con.execute(
                "SELECT in_bytes, out_bytes, total_bytes FROM vpn_traffic_last WHERE client=?",
                (client,)
            ).fetchone()

            if last is None:
                # First observation: remember counters, but do not invent historical daily traffic.
                delta_in = 0
                delta_out = 0
                delta_total = 0
            else:
                last_in = int(last["in_bytes"] or 0)
                last_out = int(last["out_bytes"] or 0)
                last_total = int(last["total_bytes"] or 0)

                if cur_total >= last_total and cur_in >= last_in and cur_out >= last_out:
                    delta_in = cur_in - last_in
                    delta_out = cur_out - last_out
                    delta_total = cur_total - last_total
                else:
                    # Counters reset after reconnect/new IPsec SA. Count the new session from this first seen value.
                    delta_in = cur_in
                    delta_out = cur_out
                    delta_total = cur_total

            con.execute(
                """
                INSERT OR REPLACE INTO vpn_traffic_last
                (client, in_bytes, out_bytes, total_bytes, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (client, cur_in, cur_out, cur_total, now)
            )

            if delta_total > 0 or delta_in > 0 or delta_out > 0:
                con.execute(
                    """
                    INSERT INTO vpn_traffic_daily
                    (client, day, in_bytes, out_bytes, total_bytes, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(client, day) DO UPDATE SET
                        in_bytes = in_bytes + excluded.in_bytes,
                        out_bytes = out_bytes + excluded.out_bytes,
                        total_bytes = total_bytes + excluded.total_bytes,
                        updated_at = excluded.updated_at
                    """,
                    (client, day, delta_in, delta_out, delta_total, now)
                )

        con.commit()

    finally:
        con.close()

def traffic_history_totals_by_client():
    ensure_traffic_history()

    now = datetime.now()
    today = now.strftime("%Y-%m-%d")
    day_7 = (now - timedelta(days=6)).strftime("%Y-%m-%d")
    day_30 = (now - timedelta(days=29)).strftime("%Y-%m-%d")

    result = {}

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    try:
        for label, where, params in (
            ("today", "day = ?", (today,)),
            ("7d", "day >= ?", (day_7,)),
            ("30d", "day >= ?", (day_30,)),
        ):
            rows = con.execute(
                f"""
                SELECT client,
                       COALESCE(SUM(in_bytes), 0) AS in_bytes,
                       COALESCE(SUM(out_bytes), 0) AS out_bytes,
                       COALESCE(SUM(total_bytes), 0) AS total_bytes
                FROM vpn_traffic_daily
                WHERE {where}
                GROUP BY client
                """,
                params
            ).fetchall()

            for row in rows:
                client = row["client"]
                item = result.setdefault(client, {})
                in_b = int(row["in_bytes"] or 0)
                out_b = int(row["out_bytes"] or 0)
                total_b = int(row["total_bytes"] or 0)

                item[f"{label}_in_bytes"] = in_b
                item[f"{label}_out_bytes"] = out_b
                item[f"{label}_total_bytes"] = total_b
                item[f"{label}_label"] = human_bytes(total_b)
                item[f"{label}_detail"] = f"↓ {human_bytes(in_b)} · ↑ {human_bytes(out_b)}"

        for client, item in result.items():
            item.setdefault("today_label", "0 Б")
            item.setdefault("today_detail", "↓ 0 Б · ↑ 0 Б")
            item.setdefault("7d_label", "0 Б")
            item.setdefault("7d_detail", "↓ 0 Б · ↑ 0 Б")
            item.setdefault("30d_label", "0 Б")
            item.setdefault("30d_detail", "↓ 0 Б · ↑ 0 Б")

        return result

    finally:
        con.close()

def traffic_history_for_client(history_by_client, client):
    item = (history_by_client or {}).get(client or "", {})
    return {
        "traffic_today_label": item.get("today_label", "0 Б"),
        "traffic_today_detail": item.get("today_detail", "↓ 0 Б · ↑ 0 Б"),
        "traffic_7d_label": item.get("7d_label", "0 Б"),
        "traffic_7d_detail": item.get("7d_detail", "↓ 0 Б · ↑ 0 Б"),
        "traffic_30d_label": item.get("30d_label", "0 Б"),
        "traffic_30d_detail": item.get("30d_detail", "↓ 0 Б · ↑ 0 Б"),
    }



# removed old risk/asn/tempblock function: ensure_risk_events


# removed old risk/asn/tempblock function: risk_level_label


# removed old risk/asn/tempblock function: risk_level_weight


# removed old risk/asn/tempblock function: risk_event_title




# removed old risk/asn/tempblock function: record_risk_events


# removed old risk/asn/tempblock function: recent_risk_events


# removed old risk/asn/tempblock function: risk_event_level_class




SUMMARY_CACHE_TTL = 90
_SUMMARY_CACHE = {"ts": 0.0, "data": None}

def summary_cache_clear():
    _vpn_panel_cache_clear()
    _SUMMARY_CACHE["ts"] = 0.0
    _SUMMARY_CACHE["data"] = None
    try:
        _PASSPORT_CACHE.clear()
    except Exception:
        pass

def summary_cached(force=False):
    now = time.time()
    data = _SUMMARY_CACHE.get("data")
    if not force and data is not None and (now - float(_SUMMARY_CACHE.get("ts") or 0)) < SUMMARY_CACHE_TTL:
        return data

    data = summary()
    _SUMMARY_CACHE["ts"] = now
    _SUMMARY_CACHE["data"] = data
    return data


def auth_is_owner(user):
    return is_role_owner(user)

def auth_allowed_groups(user, perm="can_view"):
    if auth_is_owner(user):
        return None
    username = (user or {}).get("username") or ""
    if not username:
        return set()
    col = {
        "can_view": "can_view",
        "can_create": "can_create",
        "can_delete": "can_delete",
    }.get(perm, "can_view")
    try:
        conn = auth_db()
        rows = conn.execute(
            f"select group_name from panel_user_groups where username=? and {col}=1",
            (username,),
        ).fetchall()
        conn.close()
        return {r[0] for r in rows}
    except Exception as e:
        print(f"auth_allowed_groups_error={e!r}", flush=True)
        return set()

def auth_client_groups(client_names):
    names = [safe_client_name(x) for x in (client_names or []) if safe_client_name(x)]
    result = {name: DEFAULT_ACCESS_GROUP for name in names}
    if not names:
        return result
    try:
        conn = auth_db()
        placeholders = ",".join("?" for _ in names)
        rows = conn.execute(
            f"select client, group_name from vpn_client_meta where client in ({placeholders})",
            names,
        ).fetchall()
        conn.close()
        for client, group_name in rows:
            if client:
                result[client] = group_name or DEFAULT_ACCESS_GROUP
    except Exception as e:
        print(f"auth_client_groups_error={e!r}", flush=True)
    return result

def summary_for_user(user):
    data = copy.deepcopy(summary_cached())
    if auth_is_owner(user):
        names = [x.get("name") for x in data.get("access_items", [])]
        group_map = auth_client_groups(names)
        for item in data.get("access_items", []):
            item["group_name"] = group_map.get(item.get("name") or "", DEFAULT_ACCESS_GROUP)
        return data

    allowed = auth_allowed_groups(user, "can_view")
    items = data.get("access_items", [])
    group_map = auth_client_groups([x.get("name") for x in items])

    filtered = []
    allowed_names = set()

    for item in items:
        name = item.get("name") or ""
        group_name = group_map.get(name, DEFAULT_ACCESS_GROUP)
        item["group_name"] = group_name
        if group_name in allowed:
            filtered.append(item)
            allowed_names.add(name)

    data["access_items"] = filtered
    data["access_count"] = len(filtered)
    data["valid_count"] = len([x for x in filtered if x.get("status") == "valid"])
    data["expired_count"] = len([x for x in filtered if x.get("status") == "expired"])
    data["revoked_count"] = len([x for x in filtered if x.get("status") == "revoked"])
    data["sharing_attention_count"] = len([x for x in filtered if x.get("sharing_level") in ("questions", "suspicious", "high")])
    data["sharing_high_count"] = len([x for x in filtered if x.get("sharing_level") == "high"])
    data["sharing_suspicious_count"] = len([x for x in filtered if x.get("sharing_level") == "suspicious"])

    data["connections"] = [
        c for c in data.get("connections", [])
        if c.get("client") in allowed_names
    ]

    data["profiles"] = [
        p for p in data.get("profiles", [])
        if p.get("name") in allowed_names
    ]

    data["script_clients"] = [
        x for x in data.get("script_clients", [])
        if x.get("name") in allowed_names
    ]

    data["clients"] = [
        x for x in data.get("clients", [])
        if x in allowed_names
    ]

    data["risk_events"] = [
        e for e in data.get("risk_events", [])
        if e.get("client") in allowed_names
    ]

    data["active_connection_count"] = len(data["connections"])
    data["profile_count"] = len(data["profiles"])
    data["client_count_script"] = len(data["script_clients"])
    data["client_count_certdb"] = len(data["clients"])

    return data


def summary():
    cert_clients = list_clients_from_certdb()
    script_clients = list_clients_from_script()
    profiles = list_profiles()
    conns, last_by_client = update_session_history(parse_connections())
    traffic_by_client = current_traffic_by_client()
    record_traffic_snapshot(traffic_by_client)
    traffic_history_by_client = traffic_history_totals_by_client()

    for _conn in conns:
        _conn["remote_network"] = ip_network_label(_conn.get("remote_ip") or "", allow_lookup=True)
        _t = traffic_by_client.get(_conn.get("client") or "", {})
        _conn["traffic_in_bytes"] = _t.get("in_bytes", 0)
        _conn["traffic_out_bytes"] = _t.get("out_bytes", 0)
        _conn["traffic_total_bytes"] = _t.get("total_bytes", 0)
        _conn["traffic_label"] = _t.get("label", "—")
        _conn["traffic_total_label"] = _t.get("total_label", "—")
        _hist = traffic_history_for_client(traffic_history_by_client, _conn.get("client") or "")
        _conn["traffic_today_label"] = _hist["traffic_today_label"]
        _conn["traffic_today_detail"] = _hist["traffic_today_detail"]
        _conn["traffic_7d_label"] = _hist["traffic_7d_label"]
        _conn["traffic_7d_detail"] = _hist["traffic_7d_detail"]
        _conn["traffic_30d_label"] = _hist["traffic_30d_label"]
        _conn["traffic_30d_detail"] = _hist["traffic_30d_detail"]

    profile_names = {p["name"] for p in profiles}
    connected_by_name = {
        c["client"]: c
        for c in conns
        if c.get("client") and c.get("client") != "имя не определено"
    }

    access_items = []
    source_clients = script_clients or [{"name": name, "status": "unknown"} for name in cert_clients]

    for item in source_clients:
        name = item["name"]
        current = connected_by_name.get(name)
        last = last_by_client.get(name, {})

        if current:
            last_connected_ts = current.get("connected_since_ts") or current.get("last_seen_ts")
            last_connected = fmt_epoch(last_connected_ts)
            last_remote_ip = current.get("remote_ip") or ""
            last_remote_network = current.get("remote_network") or ip_network_label(last_remote_ip, allow_lookup=False)
            current_traffic_label = current.get("traffic_label") or "—"
            current_traffic_total_label = current.get("traffic_total_label") or "—"
            last_duration = current.get("duration") or "—"
            last_seen = current.get("last_seen") or "—"
        else:
            last_connected_ts = last.get("first_seen_ts")
            last_connected = last.get("last_connected") or "—"
            last_remote_ip = last.get("remote_ip") or ""
            last_remote_network = ip_network_label(last_remote_ip, allow_lookup=False)
            current_traffic_label = "—"
            current_traffic_total_label = "—"
            last_duration = last.get("duration") or "—"
            last_seen = last.get("last_seen") or "—"

        status = item.get("status", "unknown")
        expiry = cert_expiry_for(name)

        sharing = {
            "sharing_score": 0,
            "sharing_level": "normal",
            "sharing_label": "норма",
            "sharing_reasons": [],
            "sharing_reasons_text": "проверки отключены",
            "sharing_details": {"policy": "disabled"},
        }
        traffic_hist = traffic_history_for_client(traffic_history_by_client, name)

        access_items.append({
            "name": name,
            "status": status,
            "status_ru": status_ru(status),
            "status_hint": status_hint(status),
            "expires_at": expiry.get("expires_at") or "—",
            "expires_hint": expiry.get("expires_hint") or "",
            "expires_raw": expiry.get("expires_raw") or "",
            "expires_ts": expiry.get("expires_ts"),
            "has_files": name in profile_names,
            "connected": bool(current),
            "last_connected": last_connected,
            "last_connected_ts": last_connected_ts,
            "last_seen": last_seen,
            "last_remote_ip": last_remote_ip,
            "last_remote_network": last_remote_network,
            "last_duration": last_duration,
            "current_duration": current.get("duration") if current else "",
            "traffic_label": current_traffic_label,
            "traffic_total_label": current_traffic_total_label,
            "traffic_today_label": traffic_hist["traffic_today_label"],
            "traffic_today_detail": traffic_hist["traffic_today_detail"],
            "traffic_7d_label": traffic_hist["traffic_7d_label"],
            "traffic_7d_detail": traffic_hist["traffic_7d_detail"],
            "traffic_30d_label": traffic_hist["traffic_30d_label"],
            "traffic_30d_detail": traffic_hist["traffic_30d_detail"],
            **sharing,
        })

    # Risk/activity checks are intentionally disabled.
    risk_events = []

    # --- dedupe access_items v1 ---
    seen=set()
    fixed=[]
    for x in access_items:
        n=x.get("name")
        if n in seen:
            continue
        seen.add(n)
        fixed.append(x)
    access_items=fixed

    return {
        "app": APP_NAME,
        "host": os.uname().nodename,
        "uptime": get_uptime(),
        "ipsec": service_state(IPSEC_SERVICE_NAME),
        "xl2tpd": service_state(L2TP_SERVICE_NAME),
        "journal_lookback": "SQLite-история панели",
        "journal_ok": True,
        "history_source": "panel_sqlite",
        "access_count": len(access_items),
        "valid_count": len([x for x in access_items if x.get("status") == "valid"]),
        "expired_count": len([x for x in access_items if x.get("status") == "expired"]),
        "revoked_count": len([x for x in access_items if x.get("status") == "revoked"]),
        "sharing_attention_count": len([x for x in access_items if x.get("sharing_level") in ("questions", "suspicious", "high")]),
        "sharing_high_count": len([x for x in access_items if x.get("sharing_level") == "high"]),
        "sharing_suspicious_count": len([x for x in access_items if x.get("sharing_level") == "suspicious"]),
        "client_count_certdb": len(cert_clients),
        "client_count_script": len(script_clients),
        "profile_count": len(profiles),
        "active_connection_count": len(conns),
        "unknown_connection_count": len([c for c in conns if c.get("client") == "имя не определено"]),
        "l2tp_user_count": len(list_l2tp_users()),
        "access_items": access_items,
        "risk_events": risk_events,
        "clients": cert_clients,
        "script_clients": script_clients,
        "profiles": profiles[:160],
        "connections": conns,
        "l2tp_users": list_l2tp_users(),
    }


PROFILE_DOWNLOAD_DIR = "/root"
PROFILE_DOWNLOAD_KINDS = {
    "mobileconfig": {
        "suffix": ".mobileconfig",
        "content_type": "application/x-apple-aspen-config",
        "label": "для iPhone / iPad",
    },
    "sswan": {
        "suffix": ".sswan",
        "content_type": "application/octet-stream",
        "label": "для Android",
    },
    "p12": {
        "suffix": ".p12",
        "content_type": "application/x-pkcs12",
        "label": "для Windows",
    },
}

def safe_client_name(name):
    name = (name or "").strip()
    if not re.match(r"^[A-Za-z0-9._@+-]{1,80}$", name):
        return ""
    return name

def current_client_status(name):
    for item in list_clients_from_script():
        if item.get("name") == name:
            return item.get("status", "unknown")
    return ""

def profile_files_for(name):
    return [ROOT_DIR / f"{name}.{ext}" for ext in ("mobileconfig", "p12", "sswan")]

def write_action_log(client, ok, lines):
    ACTION_LOG.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "OK" if ok else "FAIL"
    text = "\n".join(str(x) for x in lines)
    with ACTION_LOG.open("a", encoding="utf-8") as f:
        f.write(f"\n[{ts}] revoke_delete client={client} status={status}\n{text}\n")

def revoke_delete_client(client):
    client = safe_client_name(client)
    lines = []

    if not client:
        return False, ["Некорректное имя доступа."]

    status_before = current_client_status(client)
    if not status_before:
        return False, [f"Доступ {client} не найден в ikev2.sh --listclients."]

    lines.append(f"Доступ: {client}")
    lines.append(f"Статус до действия: {status_before}")

    if status_before == "valid":
        code, out = run([IKEV2_SH, "--revokeclient", client, "--yes"], timeout=60)
        lines.append("")
        lines.append("Шаг 1: revokeclient")
        lines.append(f"exit={code}")
        if out:
            lines.append(out)
        if code != 0:
            write_action_log(client, False, lines)
            return False, lines + ["", "Остановлено: revokeclient завершился с ошибкой, delete не выполнялся."]
    elif status_before in ("expired", "revoked"):
        lines.append("")
        lines.append(f"Шаг 1: revokeclient пропущен, потому что статус уже {status_before}.")
    else:
        write_action_log(client, False, lines)
        return False, lines + ["", f"Остановлено: неизвестный статус {status_before}."]

    code, out = run([IKEV2_SH, "--deleteclient", client, "--yes"], timeout=60)
    lines.append("")
    lines.append("Шаг 2: deleteclient")
    lines.append(f"exit={code}")
    if out:
        lines.append(out)
    if code != 0:
        write_action_log(client, False, lines)
        return False, lines + ["", "Остановлено: deleteclient завершился с ошибкой, файлы установки не удалялись."]

    removed = []
    missing = []
    for fp in profile_files_for(client):
        try:
            if fp.exists():
                fp.unlink()
                removed.append(str(fp))
            else:
                missing.append(str(fp))
        except Exception as e:
            lines.append(f"Ошибка удаления файла {fp}: {e}")

    lines.append("")
    lines.append("Шаг 3: файлы установки")
    if removed:
        lines.append("Удалены:")
        lines.extend(removed)
    if missing:
        lines.append("Не найдены:")
        lines.extend(missing)

    lines.append("")
    # cleanup-dead-ui-and-cache-fix-v1: clear list/cert caches before checking final delete status.
    try:
        _vpn_panel_cache_clear()
    except Exception:
        pass
    status_after = current_client_status(client)
    lines.append(f"Статус после действия: {status_after or 'не найден'}")

    ok = not status_after
    if ok:
        lines.append("Готово: доступ отозван/удалён, файлы установки очищены.")
    else:
        lines.append("Внимание: доступ всё ещё виден в списке клиентов, проверь вручную.")

    write_action_log(client, ok, lines)
    return ok, lines

def result_page(title, ok, lines):
    title = str(title or ("Готово" if ok else "Ошибка"))
    cls = "oktext" if ok else "badtext"
    log_text = "\n".join(str(x) for x in (lines or []))

    html = """<!doctype html>
<html lang="ru" class="access-passport-server-v1">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root {
  color-scheme: dark;
  --bg:#080a0f;
  --card:#111620;
  --text:#eef3ff;
  --muted:#8d99ad;
  --line:#253044;
  --ok:#42d392;
  --bad:#ff647c;
}
body {
  margin:0;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  background:radial-gradient(circle at top left,#142033 0,#080a0f 36%,#080a0f 100%);
  color:var(--text);
}
.wrap {
  max-width:900px;
  margin:0 auto;
  padding:28px;
}
.card {
  background:rgba(17,24,39,.94);
  border:1px solid rgba(255,255,255,.09);
  border-radius:24px;
  padding:22px;
  box-shadow:0 18px 60px rgba(0,0,0,.18);
}
h1 {
  margin:0 0 10px;
  font-size:34px;
  letter-spacing:-.04em;
}
.muted {
  color:var(--muted);
  line-height:1.45;
}
.oktext { color:var(--ok); }
.badtext { color:var(--bad); }
pre {
  margin-top:16px;
  padding:14px;
  border-radius:16px;
  border:1px solid var(--line);
  background:#0b1018;
  color:var(--text);
  white-space:pre-wrap;
  line-height:1.45;
  overflow:auto;
  max-height:520px;
}
.actions {
  display:flex;
  flex-wrap:wrap;
  gap:10px;
  margin-top:16px;
}
.btn {
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:38px;
  border-radius:14px;
  padding:9px 13px;
  text-decoration:none;
  font-size:14px;
  font-weight:800;
  color:var(--text);
  background:#182132;
  border:1px solid var(--line);
}
.primary {
  background:linear-gradient(180deg,#eef4ff,#b8c9ff);
  color:#07101f;
  border:0;
}

</style>
</head>
<body>
<div class="wrap">
  <section class="card">
    <h1 class="__CLS__">__TITLE__</h1>
    <p class="muted">Ниже технический журнал выполнения.</p>
    <div class="actions">
      <a class="btn primary" href="/">На главную</a>
      <a class="btn" href="/create-access">Создать доступ</a>
    </div>
    <pre>__LOG__</pre>
  </section>
</div>
</body>
</html>"""

    return (
        html
        .replace("__TITLE__", esc(title))
        .replace("__CLS__", cls)
        .replace("__LOG__", esc(log_text or "Нет строк журнала."))
    )

def valid_new_access_name(name):
    name = str(name or "").strip()

    if not name:
        return False, "Имя доступа пустое."

    if len(name) < 2:
        return False, "Имя доступа слишком короткое."

    if len(name) > 64:
        return False, "Имя доступа слишком длинное. Максимум 64 символа."

    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", name):
        return False, "Разрешены только латиница, цифры, точка, подчёркивание и дефис. Первый символ — буква или цифра."

    if ".." in name or "__" in name or "--" in name:
        return False, "Не используй двойные точки, подчёркивания или дефисы подряд."

    return True, ""

def existing_access_name_set():
    try:
        data = summary()
        return {
            safe_client_name(x.get("name") or "").lower()
            for x in data.get("access_items", [])
            if safe_client_name(x.get("name") or "")
        }
    except Exception:
        return set()



def profile_download_path(client, kind):
    from pathlib import Path

    client = safe_client_name(client or "")
    kind = str(kind or "").strip().lower()

    if not client:
        return None, "bad client"

    if kind not in PROFILE_DOWNLOAD_KINDS:
        return None, "bad kind"

    try:
        existing = existing_access_name_set()
    except Exception:
        existing = set()

    if client.lower() not in existing:
        return None, "client not found"

    root = Path(PROFILE_DOWNLOAD_DIR).resolve()
    suffix = PROFILE_DOWNLOAD_KINDS[kind]["suffix"]
    path = (root / f"{client}{suffix}").resolve()

    if path.parent != root:
        return None, "path escape"

    if not path.exists() or not path.is_file():
        return None, "file not found"

    return path, None



IPHONE_PROFILE_INSTRUCTION = """Перед установкой VPN сначала откройте на iPhone:

Настройки → Основные → VPN и управление устройством

Удалите старые VPN-подключения и профили, если они там есть.

Потом откройте файл, который я отправил. Если он пришёл архивом ZIP — сначала сохраните или распакуйте его в приложении «Файлы».

Дальше нажмите на файл .mobileconfig.

После этого откройте Настройки — вверху появится пункт «Загружен профиль». Нажмите на него и завершите установку.

Важно: этот VPN-профиль выдан строго для одного конкретного устройства.

Строго запрещено передавать этот файл другим людям, пересылать его третьим лицам или устанавливать на другое устройство.

При передаче профиля или установке на чужое/дополнительное устройство VPN-доступ будет заблокирован.
"""

def iphone_profile_instruction_text():
    return IPHONE_PROFILE_INSTRUCTION.strip() + "\n"

def mobileconfig_zip_download(client):
    client = safe_client_name(client or "")
    path, err = profile_download_path(client, "mobileconfig")
    if err:
        return None, None, err

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(path, arcname=f"{client}.mobileconfig")
        z.writestr("Инструкция.txt", iphone_profile_instruction_text())

    return f"{client}.zip", buf.getvalue(), None


def profile_download_url(client, kind):
    from urllib.parse import quote

    client_q = quote(str(client or ""), safe="")
    kind_q = quote(str(kind or ""), safe="")
    return f"/download-profile?client={client_q}&kind={kind_q}"


def profile_download_links_html(client):
    # download-buttons-single-menu-v1
    client = safe_client_name(client or "")
    if not client:
        return '<span class="muted">Некорректное имя доступа.</span>'

    buttons = []

    mobile_path, mobile_err = profile_download_path(client, "mobileconfig")
    if not mobile_err:
        zip_href = profile_download_url(client, "mobileconfig_zip")
        buttons.append(f'<a class="primaryButton" href="{esc(zip_href)}">Скачать ZIP для iPhone / iPad</a>')

    for kind, info in PROFILE_DOWNLOAD_KINDS.items():
        if kind == "mobileconfig":
            continue

        path, err = profile_download_path(client, kind)
        if err:
            continue

        href = profile_download_url(client, kind)
        label = info["label"]
        buttons.append(f'<a class="softButton" href="{esc(href)}">Скачать {esc(label)}</a>')

    if not buttons:
        return '<span class="muted">Файлы профиля не найдены.</span>'

    return f"""
    <div class="card" style="margin:14px 0;padding:16px;border-radius:18px;">
      <h3 style="margin-top:0;">Скачать файлы</h3>
      <p class="muted">Выберите файл для нужного устройства. Для iPhone / iPad скачивайте ZIP: внутри будет профиль VPN и инструкция.</p>
      <p style="display:flex;flex-wrap:wrap;gap:10px;">{" ".join(buttons)}</p>
    </div>
    """


def ru_translit_slug(text):
    import re

    text = (text or "").strip().lower().replace("ё", "е")
    table = {
        "а": "a", "б": "b", "в": "v", "г": "g", "д": "d",
        "е": "e", "ж": "zh", "з": "z", "и": "i", "й": "y",
        "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
        "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
        "ф": "f", "х": "h", "ц": "ts", "ч": "ch", "ш": "sh",
        "щ": "sch", "ъ": "", "ы": "y", "ь": "", "э": "e",
        "ю": "yu", "я": "ya",
    }

    out = []
    for ch in text:
        if ch in table:
            out.append(table[ch])
        elif "a" <= ch <= "z" or "0" <= ch <= "9":
            out.append(ch)
        else:
            out.append("-")

    slug = "".join(out)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug


def device_kind_label(kind):
    kind = (kind or "").strip().lower()
    return {
        "phone": "телефон",
        "tablet": "планшет",
        "pc": "комп",
    }.get(kind, "устройство")


def device_kind_slug(kind):
    kind = (kind or "").strip().lower()
    return {
        "phone": "phone",
        "tablet": "tablet",
        "pc": "pc",
    }.get(kind, "")


def build_access_name_from_ru(first_name, last_name, device_kind):
    first = ru_translit_slug(first_name)
    last = ru_translit_slug(last_name)
    device = device_kind_slug(device_kind)

    if not first:
        return "", "Введи имя на русском."
    if not last:
        return "", "Введи фамилию на русском."
    if not device:
        return "", "Выбери тип устройства."

    client = safe_client_name(f"{last}-{first}-{device}")
    if not client:
        return "", "Не получилось собрать техническое имя доступа."

    return client, ""



def create_access_page(first_name="", last_name="", device_kind="phone", error=""):
    # vpn-create-access-product-v1
    first_name = str(first_name or "").strip()
    last_name = str(last_name or "").strip()
    device_kind = device_kind_slug(device_kind) or "phone"

    def selected(value):
        return " selected" if value == device_kind else ""

    error_html = ""
    if error:
        error_html = f"""
            <div class="create-access-alert bad">
                <strong>Не получилось создать доступ</strong>
                <span>{esc(error)}</span>
            </div>
        """

    generated, gen_error = build_access_name_from_ru(first_name, last_name, device_kind)
    preview_value = generated if generated and not gen_error else "ivanov-aleksandr-phone"

    css = """
<style>
/* vpn-create-access-product-v1 */
.create-access-card{display:grid;gap:18px}
.create-back-link{display:inline-flex;align-items:center;gap:7px;color:#8ec7ff;text-decoration:none;font-weight:800;margin-bottom:2px}
.create-access-intro{display:grid;gap:7px;margin:0 0 4px}
.create-access-intro strong{font-size:18px}
.create-access-steps{display:grid;gap:14px}
.create-step{border:1px solid rgba(148,163,184,.16);background:rgba(15,23,42,.34);border-radius:20px;padding:15px;display:grid;gap:12px}
.create-step-head{display:flex;align-items:flex-start;gap:11px}
.create-step-num{width:28px;height:28px;border-radius:999px;background:rgba(141,199,255,.14);border:1px solid rgba(141,199,255,.28);color:#8ec7ff;display:inline-flex;align-items:center;justify-content:center;font-weight:950;font-size:14px;flex:0 0 auto}
.create-step-title{display:grid;gap:2px}
.create-step-title strong{font-size:18px;line-height:1.15}
.create-step-title span{color:var(--muted);font-size:14px;line-height:1.3}
.create-field-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.create-access-card label{display:block;margin:0 0 7px;color:var(--muted);font-weight:900;letter-spacing:.03em}
.create-access-card .textInput{width:100%;box-sizing:border-box}
.create-preview-card{border:1px solid rgba(141,199,255,.22);background:rgba(141,199,255,.075);border-radius:18px;padding:13px;display:grid;gap:9px}
.create-preview-row{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.create-preview-row span{color:var(--muted);font-size:13px;font-weight:850;text-transform:uppercase;letter-spacing:.06em}
.create-preview-row strong{font-size:16px;overflow-wrap:anywhere;text-align:right}
.create-access-alert{border-radius:18px;padding:13px 14px;display:grid;gap:5px}
.create-access-alert strong{font-size:16px}
.create-access-alert span{color:var(--muted);line-height:1.35}
.create-access-alert.warn{border:1px solid rgba(251,191,36,.28);background:rgba(251,191,36,.08)}
.create-access-alert.bad{border:1px solid rgba(255,100,124,.34);background:rgba(255,100,124,.09)}
.create-submit-row{display:grid;gap:10px}
.create-submit-row .primaryButton{width:100%;justify-content:center;padding:15px 18px;border-radius:18px;font-size:17px}
.create-submit-hint{color:var(--muted);font-size:13px;line-height:1.35}
@media(max-width:760px){
  .create-access-card{gap:16px}
  .create-access-card h2{font-size:28px;line-height:1.05}
  .create-field-grid{grid-template-columns:1fr}
  .create-step{padding:14px;border-radius:19px}
  .create-step-title strong{font-size:17px}
  .create-preview-row{display:grid;gap:4px}
  .create-preview-row strong{text-align:left;font-size:17px}
}
/* /vpn-create-access-product-v1 */
</style>
"""

    script = """
<script>
(function(){
  function ready(fn){
    if(document.readyState === "loading") document.addEventListener("DOMContentLoaded", fn);
    else fn();
  }
  var map = {
    "а":"a","б":"b","в":"v","г":"g","д":"d","е":"e","ё":"e","ж":"zh","з":"z","и":"i","й":"y","к":"k","л":"l","м":"m","н":"n","о":"o","п":"p","р":"r","с":"s","т":"t","у":"u","ф":"f","х":"h","ц":"ts","ч":"ch","ш":"sh","щ":"sch","ъ":"","ы":"y","ь":"","э":"e","ю":"yu","я":"ya"
  };
  function slug(s){
    s = String(s || "").toLowerCase().trim();
    var out = "";
    for(var i=0;i<s.length;i++){
      var ch = s[i];
      if(map[ch] !== undefined) out += map[ch];
      else if(/[a-z0-9]/.test(ch)) out += ch;
      else out += "-";
    }
    return out.replace(/-+/g, "-").replace(/^-|-$/g, "");
  }
  function dev(v){
    if(v === "tablet") return "tablet";
    if(v === "pc") return "pc";
    return "phone";
  }
  ready(function(){
    var form = document.querySelector("[data-create-access-form]");
    if(!form) return;
    var first = form.querySelector("[name=first_name]");
    var last = form.querySelector("[name=last_name]");
    var device = form.querySelector("[name=device_kind]");
    var preview = document.querySelector("[data-create-preview]");
    function update(){
      var a = slug(last && last.value);
      var b = slug(first && first.value);
      var d = dev(device && device.value);
      var value = (a && b) ? (a + "-" + b + "-" + d) : "ivanov-aleksandr-" + d;
      if(preview) preview.textContent = value;
    }
    ["input","change"].forEach(function(ev){
      if(first) first.addEventListener(ev, update);
      if(last) last.addEventListener(ev, update);
      if(device) device.addEventListener(ev, update);
    });
    update();
  });
})();
</script>
"""

    body = f"""
        {css}
        <section class="card create-access-card">
            <a class="create-back-link" href="/access">← К доступам</a>

            <div class="create-access-intro">
                <h2>Данные доступа</h2>
                <p class="muted">
                    Создаём отдельный VPN-профиль для конкретного человека и одного устройства.
                </p>
            </div>

            {error_html}

            <div class="create-access-alert warn">
                <strong>Один профиль — одно устройство</strong>
                <span>Не ставьте один и тот же конфиг на два телефона или компьютера. Для второго устройства создайте отдельный доступ.</span>
            </div>

            <form method="post" action="/create-access" data-create-access-form>
                <div class="create-access-steps">
                    <div class="create-step">
                        <div class="create-step-head">
                            <span class="create-step-num">1</span>
                            <div class="create-step-title">
                                <strong>Человек</strong>
                                <span>Имя и фамилию пишем на русском. Панель сама соберёт латинское имя доступа.</span>
                            </div>
                        </div>

                        <div class="create-field-grid">
                            <div>
                                <label>Имя</label>
                                <input class="textInput" name="first_name" value="{esc(first_name)}" placeholder="Александр" autocomplete="off" required>
                            </div>
                            <div>
                                <label>Фамилия</label>
                                <input class="textInput" name="last_name" value="{esc(last_name)}" placeholder="Иванов" autocomplete="off" required>
                            </div>
                        </div>
                    </div>

                    <div class="create-step">
                        <div class="create-step-head">
                            <span class="create-step-num">2</span>
                            <div class="create-step-title">
                                <strong>Устройство</strong>
                                <span>Для каждого телефона, планшета или компьютера нужен отдельный профиль.</span>
                            </div>
                        </div>

                        <div>
                            <label>Тип устройства</label>
                            <select class="textInput" name="device_kind" required>
                                <option value="phone"{selected("phone")}>Телефон</option>
                                <option value="tablet"{selected("tablet")}>Планшет</option>
                                <option value="pc"{selected("pc")}>Компьютер</option>
                            </select>
                        </div>
                    </div>

                    <div class="create-step">
                        <div class="create-step-head">
                            <span class="create-step-num">3</span>
                            <div class="create-step-title">
                                <strong>Проверка</strong>
                                <span>Так доступ будет называться внутри VPN и панели.</span>
                            </div>
                        </div>

                        <div class="create-preview-card">
                            <div class="create-preview-row">
                                <span>Техническое имя</span>
                                <strong data-create-preview>{esc(preview_value)}</strong>
                            </div>
                            <div class="create-preview-row">
                                <span>Группа доступа</span>
                                <strong>vpn</strong>
                            </div>
                        </div>
                    </div>

                    <div class="create-submit-row">
                        <button class="primaryButton" type="submit">Создать VPN-доступ</button>
                        <div class="create-submit-hint">
                            После создания откроется результат с техническим журналом и ссылкой на паспорт доступа.
                        </div>
                    </div>
                </div>
            </form>
        </section>
        {script}
    """
    return access_passport_shell("Создать доступ", body)




# vpn-people-meta-save-v1
def access_person_display_name(first_name, last_name):
    first = str(first_name or "").strip()
    last = str(last_name or "").strip()
    return " ".join(x for x in (last, first) if x).strip()

def access_person_slug_from_base(base, device_kind):
    base = safe_client_name(base or "")
    device = device_kind_slug(device_kind) or ""
    suffix = "-" + device if device else ""
    if suffix and base.endswith(suffix):
        return safe_client_name(base[:-len(suffix)])
    return base

def save_access_person_meta(client, first_name, last_name, device_kind, base=""):
    import sqlite3 as _sqlite3
    import time as _time

    client = safe_client_name(client or "")
    if not client:
        return False

    person_name = access_person_display_name(first_name, last_name)
    device_type = device_kind_slug(device_kind) or "phone"
    device_label = device_kind_label(device_type)
    person_slug = access_person_slug_from_base(base or client, device_type) or client
    now = int(_time.time())

    con = _sqlite3.connect(DB_PATH)
    con.row_factory = _sqlite3.Row
    try:
        row = con.execute(
            "select group_name, created_by, created_at, comment from vpn_client_meta where client=?",
            (client,)
        ).fetchone()

        if row:
            con.execute("""
                update vpn_client_meta
                set person_name=?, person_slug=?, device_label=?, device_type=?, updated_at=?
                where client=?
            """, (person_name, person_slug, device_label, device_type, now, client))
        else:
            con.execute("""
                insert into vpn_client_meta
                (client, group_name, created_by, created_at, comment, updated_at,
                 person_name, person_slug, device_label, device_type)
                values (?, 'vpn', 'vpn', ?, '', ?, ?, ?, ?, ?)
            """, (client, now, now, person_name, person_slug, device_label, device_type))

        con.commit()
        return True
    except Exception as e:
        print(f"save_access_person_meta_error={e!r}", flush=True)
        return False
    finally:
        con.close()
# /vpn-people-meta-save-v1


def create_access_client_from_ru(first_name, last_name, device_kind):
    base, err = build_access_name_from_ru(first_name, last_name, device_kind)
    if err:
        return False, base, [err]

    last_error = []
    for n in range(1, 100):
        client = base if n == 1 else safe_client_name(f"{base}-{n}")
        ok, clean_client, lines = create_access_client(client, client)
        if ok:
            meta_ok = save_access_person_meta(clean_client, first_name, last_name, device_kind, base)
            lines.insert(0, f"Человек: {access_person_display_name(first_name, last_name)}")
            lines.insert(1, f"Устройство: {device_kind_label(device_kind)}")
            lines.insert(2, f"Техническое имя: {clean_client}")
            lines.insert(3, "Метаданные: сохранены" if meta_ok else "Метаданные: не сохранены")
            return ok, clean_client, lines

        last_error = lines
        text = " ".join(str(x) for x in lines).lower()
        duplicate_words = ["already", "exists", "duplicate", "существ", "занят"]
        if not any(w in text for w in duplicate_words):
            return ok, clean_client, lines

    return False, base, last_error or ["Не получилось подобрать свободное имя доступа."]



def delete_access_result_page(client, ok, lines):
    # vpn-access-result-flow-product-v1
    client = safe_client_name(client or "")
    title = "Доступ удалён" if ok else "Ошибка удаления"
    cls = "ok" if ok else "bad"
    note = (
        "VPN-доступ удалён. Профиль больше не должен отображаться в списке доступов."
        if ok else
        "Удаление не завершилось. Проверьте технический журнал."
    )
    log_text = "\n".join(str(x) for x in (lines or [])) or "Нет строк журнала."

    passport_link = ""
    if not ok and client:
        passport_link = f'<a class="softButton" href="/access?client={esc(client)}">Открыть паспорт доступа</a>'

    css = """
<style>
/* vpn-access-result-flow-product-v1 delete */
.delete-result-card{display:grid;gap:16px}
.delete-result-status{font-size:44px;line-height:.98;font-weight:950;letter-spacing:-.05em}
.delete-result-status.ok{color:var(--ok)}
.delete-result-status.bad{color:var(--bad)}
.delete-result-box{border:1px solid rgba(148,163,184,.16);background:rgba(15,23,42,.38);border-radius:18px;padding:14px;display:grid;gap:5px}
.delete-result-box span{color:var(--muted);font-size:11px;font-weight:900;letter-spacing:.08em;text-transform:uppercase}
.delete-result-box b{font-size:18px;overflow-wrap:anywhere}
.delete-result-actions{display:flex;flex-wrap:wrap;gap:10px}
.delete-result-log{border:1px solid rgba(148,163,184,.14);border-radius:18px;padding:12px;background:rgba(0,0,0,.12)}
.delete-result-log summary{cursor:pointer;color:#8ec7ff;font-weight:850}
.delete-result-log pre{margin:12px 0 0;white-space:pre-wrap;overflow:auto;max-height:420px;border-radius:14px;border:1px solid var(--line);background:#080d15;padding:12px;color:var(--text);font-size:12px;line-height:1.4}
@media(max-width:760px){
  .delete-result-status{font-size:38px}
  .delete-result-actions{display:grid}
  .delete-result-actions a{justify-content:center;text-align:center}
}
/* /vpn-access-result-flow-product-v1 delete */
</style>
"""

    body = f"""
        {css}
        <section class="card delete-result-card">
            <div class="delete-result-status {cls}">{esc(title)}</div>
            <p class="muted">{esc(note)}</p>

            <div class="delete-result-box">
                <span>техническое имя</span>
                <b>{esc(client or "—")}</b>
            </div>

            <div class="delete-result-actions">
                <a class="primaryButton" href="/access">К доступам</a>
                <a class="softButton" href="/create-access">Создать новый доступ</a>
                {passport_link}
            </div>

            <details class="delete-result-log">
                <summary>Показать технический журнал</summary>
                <pre>{esc(log_text)}</pre>
            </details>
        </section>
    """
    return access_passport_shell(title, body)




def create_access_result_page(client, ok, lines):
    # vpn-access-result-flow-product-v1
    client = safe_client_name(client or "")
    lines = [str(x) for x in (lines or [])]
    status = "Доступ создан" if ok else "Доступ не создан"
    status_cls = "ok" if ok else "bad"

    person = ""
    device = ""
    tech_name = client

    for line in lines:
        if line.startswith("Человек:"):
            person = line.split(":", 1)[1].strip()
        elif line.startswith("Устройство:"):
            device = line.split(":", 1)[1].strip()
        elif line.startswith("Техническое имя:"):
            tech_name = safe_client_name(line.split(":", 1)[1].strip()) or client

    log_text = "\n".join(lines) or "Нет строк журнала."

    if ok:
        summary = f"""
            <div class="result-flow-grid">
                <div class="result-flow-cell"><span>человек</span><b>{esc(person or "—")}</b></div>
                <div class="result-flow-cell"><span>устройство</span><b>{esc(device or "—")}</b></div>
                <div class="result-flow-cell wide"><span>техническое имя</span><b>{esc(tech_name or client or "—")}</b></div>
                <div class="result-flow-cell wide"><span>правило</span><b>один профиль — одно устройство</b></div>
            </div>
        """
        actions = f"""
            <div class="result-flow-actions">
                <a class="primaryButton" href="/access?client={esc(client)}">Открыть паспорт доступа</a>
                <a class="softButton" href="/create-access">Создать ещё</a>
                <a class="softButton" href="/access">К доступам</a>
            </div>
        """
        downloads = f"""
            <div class="result-flow-downloads">
                <h3>Файлы профиля</h3>
                <p class="muted">Можно сразу скачать файл установки или открыть паспорт доступа.</p>
                {profile_download_links_html(client)}
            </div>
        """
        note = "VPN-профиль создан. Теперь скачайте файл для нужного устройства или откройте паспорт доступа."
    else:
        visible_errors = "".join(f"<li>{esc(x)}</li>" for x in lines[:6]) or "<li>Неизвестная ошибка.</li>"
        summary = f"""
            <div class="result-flow-alert bad">
                <strong>Создание не завершилось</strong>
                <ul>{visible_errors}</ul>
            </div>
        """
        actions = f"""
            <div class="result-flow-actions">
                <a class="primaryButton" href="/create-access">Попробовать снова</a>
                <a class="softButton" href="/access">К доступам</a>
            </div>
        """
        downloads = ""
        note = "Профиль не создан. Проверьте данные или журнал ниже."

    css = """
<style>
/* vpn-access-result-flow-product-v1 */
.result-flow-card{display:grid;gap:16px}
.result-flow-top{display:grid;gap:7px}
.result-flow-status{font-size:44px;line-height:.98;font-weight:950;letter-spacing:-.05em}
.result-flow-status.ok{color:var(--ok)}
.result-flow-status.bad{color:var(--bad)}
.result-flow-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.result-flow-cell{border:1px solid rgba(148,163,184,.16);background:rgba(15,23,42,.38);border-radius:16px;padding:12px}
.result-flow-cell.wide{grid-column:1/-1}
.result-flow-cell span{display:block;color:var(--muted);font-size:11px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;margin-bottom:5px}
.result-flow-cell b{display:block;font-size:18px;line-height:1.2;overflow-wrap:anywhere}
.result-flow-actions{display:flex;flex-wrap:wrap;gap:10px}
.result-flow-downloads{border:1px solid rgba(141,199,255,.18);background:rgba(141,199,255,.055);border-radius:20px;padding:15px;display:grid;gap:9px}
.result-flow-downloads h3{margin:0;font-size:22px}
.result-flow-alert{border-radius:18px;padding:14px;border:1px solid rgba(255,100,124,.34);background:rgba(255,100,124,.09)}
.result-flow-alert strong{font-size:18px}
.result-flow-alert ul{margin:10px 0 0;padding-left:20px}
.result-flow-log{border:1px solid rgba(148,163,184,.14);border-radius:18px;padding:12px;background:rgba(0,0,0,.12)}
.result-flow-log summary{cursor:pointer;color:#8ec7ff;font-weight:850}
.result-flow-log pre{margin:12px 0 0;white-space:pre-wrap;overflow:auto;max-height:420px;border-radius:14px;border:1px solid var(--line);background:#080d15;padding:12px;color:var(--text);font-size:12px;line-height:1.4}
@media(max-width:760px){
  .result-flow-status{font-size:38px}
  .result-flow-grid{grid-template-columns:1fr}
  .result-flow-actions{display:grid}
  .result-flow-actions a{justify-content:center;text-align:center}
}
/* /vpn-access-result-flow-product-v1 */
</style>
"""

    body = f"""
        {css}
        <section class="card result-flow-card">
            <div class="result-flow-top">
                <a class="create-back-link" href="/access">← К доступам</a>
                <div class="result-flow-status {status_cls}">{esc(status)}</div>
                <p class="muted">{esc(note)}</p>
            </div>

            {summary}
            {actions}
            {downloads}

            <details class="result-flow-log">
                <summary>Показать технический журнал</summary>
                <pre>{esc(log_text)}</pre>
            </details>
        </section>
    """
    return access_passport_shell(status, body)


def create_access_client(client, confirm):
    raw_client = str(client or "").strip()
    client = safe_client_name(raw_client)
    confirm = str(confirm or "").strip()

    lines = []

    if raw_client != client:
        return False, client, ["Имя было бы изменено после очистки. Введи имя без пробелов и запрещённых символов."]

    ok, msg = valid_new_access_name(client)
    if not ok:
        return False, client, [msg]

    if confirm != client:
        return False, client, ["Подтверждение не совпало с именем доступа."]

    if client.lower() in existing_access_name_set():
        return False, client, ["Такой доступ уже существует."]

    script = IKEV2_SH
    if not os.path.exists(script):
        return False, client, [f"Не найден скрипт {script}."]

    before = {
        ext: os.path.exists(f"/root/{client}.{ext}")
        for ext in ("mobileconfig", "p12", "sswan")
    }

    try:
        proc = subprocess.run(
            [script, "--addclient", client],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=240,
            cwd="/root",
        )
    except subprocess.TimeoutExpired:
        return False, client, ["Создание доступа заняло слишком много времени и было остановлено."]
    except Exception as e:
        return False, client, [f"Ошибка запуска ikev2.sh: {type(e).__name__}: {e}"]

    if proc.returncode != 0:
        tail = "\n".join((proc.stdout or "").splitlines()[-8:])
        lines.append(f"ikev2.sh завершился с кодом {proc.returncode}.")
        if tail:
            lines.append("Последние строки вывода: " + tail)
        return False, client, lines

    try:
        exp = subprocess.run(
            [script, "--exportclient", client],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=180,
            cwd="/root",
        )
        if exp.returncode != 0:
            lines.append(f"Доступ создан, но exportclient вернул код {exp.returncode}.")
    except Exception as e:
        lines.append(f"Доступ создан, но exportclient не удалось выполнить: {type(e).__name__}: {e}")

    after = {
        ext: os.path.exists(f"/root/{client}.{ext}")
        for ext in ("mobileconfig", "p12", "sswan")
    }

    lines.append("Доступ создан.")
    for ext in ("mobileconfig", "p12", "sswan"):
        mark = "есть" if after.get(ext) else "не найден"
        extra = "новый файл" if after.get(ext) and not before.get(ext) else ""
        lines.append(f"/root/{client}.{ext}: {mark}" + (f" ({extra})" if extra else ""))

    try:
        with ACTION_LOG.open("a", encoding="utf-8") as f:
            f.write(f"{datetime.now().isoformat(timespec='seconds')} create_access client={client}\n")
    except Exception:
        pass

    return True, client, lines



def access_effectively_deleted(client):
    client = safe_client_name(client or "")
    if not client:
        return False
    try:
        _vpn_panel_cache_clear()
    except Exception:
        pass

    try:
        still_exists = client.lower() in existing_access_name_set()
    except Exception:
        still_exists = True

    try:
        files_absent = all(
            not os.path.exists(f"/root/{client}.{ext}")
            for ext in ("mobileconfig", "p12", "sswan")
        )
    except Exception:
        files_absent = False

    return (not still_exists) and files_absent



def confirm_revoke_delete_page(client):
    # vpn-access-result-flow-product-v1
    client = safe_client_name(client)
    if not client:
        return result_page("Ошибка", False, ["Некорректное имя доступа."])

    status = current_client_status(client) or "не найден"
    meta = {}
    try:
        meta = access_human_meta(client) or {}
    except Exception:
        meta = {}

    person = str(meta.get("person_name") or "").strip()
    device = str(meta.get("device_label") or "").strip()
    human = " · ".join(x for x in (person, device) if x) or client

    css = """
<style>
/* vpn-access-result-flow-product-v1 confirm */
.delete-flow-card{display:grid;gap:16px}
.delete-flow-alert{border:1px solid rgba(255,100,124,.34);background:rgba(255,100,124,.09);border-radius:20px;padding:15px;display:grid;gap:7px}
.delete-flow-alert strong{color:var(--bad);font-size:21px;line-height:1.15}
.delete-flow-alert span{color:var(--muted);line-height:1.4}
.delete-flow-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.delete-flow-cell{border:1px solid rgba(148,163,184,.16);background:rgba(15,23,42,.38);border-radius:16px;padding:12px}
.delete-flow-cell.wide{grid-column:1/-1}
.delete-flow-cell span{display:block;color:var(--muted);font-size:11px;font-weight:900;letter-spacing:.08em;text-transform:uppercase;margin-bottom:5px}
.delete-flow-cell b{display:block;font-size:17px;line-height:1.2;overflow-wrap:anywhere}
.delete-flow-form{display:grid;gap:12px}
.delete-flow-form label{color:var(--muted);font-weight:900}
.delete-flow-form input{width:100%;box-sizing:border-box}
.delete-flow-actions{display:flex;flex-wrap:wrap;gap:10px}
.delete-flow-actions button,.delete-flow-actions a{justify-content:center}
@media(max-width:760px){
  .delete-flow-grid{grid-template-columns:1fr}
  .delete-flow-actions{display:grid}
}
/* /vpn-access-result-flow-product-v1 confirm */
</style>
"""

    body = f"""
        {css}
        <section class="card delete-flow-card">
            <a class="create-back-link" href="/access?client={esc(client)}">← В паспорт доступа</a>

            <div>
                <h2>Отключить и удалить</h2>
                <p class="muted">Удаляем VPN-профиль, сертификат и файлы установки.</p>
            </div>

            <div class="delete-flow-alert">
                <strong>Действие необратимое</strong>
                <span>После удаления этот профиль больше не сможет подключаться. Для восстановления придётся создать новый доступ.</span>
            </div>

            <div class="delete-flow-grid">
                <div class="delete-flow-cell wide"><span>доступ</span><b>{esc(human)}</b></div>
                <div class="delete-flow-cell wide"><span>техническое имя</span><b>{esc(client)}</b></div>
                <div class="delete-flow-cell"><span>статус</span><b>{esc(status)}</b></div>
                <div class="delete-flow-cell"><span>подтверждение</span><b>введите имя доступа</b></div>
            </div>

            <form class="delete-flow-form" method="post" action="/revoke-delete">
                <input type="hidden" name="client" value="{esc(client)}">
                <label>Введите точно: {esc(client)}</label>
                <input class="textInput" name="confirm" autocomplete="off" placeholder="{esc(client)}" required>
                <div class="delete-flow-actions">
                    <button class="dangerButton" type="submit">Отключить и удалить</button>
                    <a class="softButton" href="/access?client={esc(client)}">Отмена</a>
                </div>
            </form>
        </section>
    """
    return access_passport_shell("Удалить доступ", body)





def yesno(value):
    return "да" if value else "нет"

def fmt_ts(ts):
    try:
        ts = int(ts or 0)
    except Exception:
        ts = 0

    if not ts:
        return "—"

    return datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M:%S")

def access_sessions_for(client, limit=60):
    client = safe_client_name(client)
    if not client:
        return []

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    try:
        rows = con.execute(
            """
            SELECT client, vpn_ip, remote_ip, first_seen, last_seen, disconnected_at, active
            FROM vpn_sessions
            WHERE client = ?
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (client, int(limit))
        ).fetchall()

        out = []
        for r in rows:
            remote_ip = r["remote_ip"] or ""
            out.append({
                "vpn_ip": r["vpn_ip"] or "",
                "remote_ip": remote_ip,
                "remote_network": ip_network_label(remote_ip, allow_lookup=False),
                "first_seen": int(r["first_seen"] or 0),
                "last_seen": int(r["last_seen"] or 0),
                "disconnected_at": int(r["disconnected_at"] or 0),
                "active": bool(r["active"]) and not r["disconnected_at"],
                "first_seen_text": fmt_ts(r["first_seen"]),
                "last_seen_text": fmt_ts(r["last_seen"]),
                "disconnected_text": fmt_ts(r["disconnected_at"]),
            })
    finally:
        con.close()

    try:
        floor_ts = _vpn_pluto_started_ts() if "_vpn_pluto_started_ts" in globals() else None
    except Exception:
        floor_ts = None

    return apply_active_start_floor(out, floor_ts, fmt_ts)


# removed old risk/asn/tempblock function: access_risk_events_for


PASSPORT_CACHE_TTL = 90
_PASSPORT_CACHE = {}



def access_passport_page_cached(client, user=None):
    client = safe_client_name(client)
    username = (user or {}).get("username") or ""
    role = (user or {}).get("role") or ""
    key = (username, role, client)
    now = time.time()

    cached = _PASSPORT_CACHE.get(key)
    if cached and (now - float(cached.get("ts") or 0)) < PASSPORT_CACHE_TTL:
        return cached.get("html") or ""

    html = access_passport_page(client, user)
    _PASSPORT_CACHE[key] = {"ts": now, "html": html}
    return html


def _access_passport_base_page(client, user=None):
    client = safe_client_name(client)
    data = summary_cached()

    item = None
    for candidate in data.get("access_items", []):
        if safe_client_name(candidate.get("name") or "") == client:
            item = candidate
            break

    if item is None:
        body = f"""
        <section class="card">
            <div class="crumb"><a href="/">← На главную</a></div>
            <h1>Доступ не найден</h1>
            <p class="muted">Профиль <strong>{esc(client or '—')}</strong> не найден в списке IKEv2-доступов. Если этот доступ только что удаляли — всё нормально: он уже удалён.</p>\n            <p class="muted">Вернись на главную страницу: в списке этого доступа уже быть не должно.</p>
        </section>
        """
        return access_passport_shell("Доступ не найден", body)

    sessions = access_sessions_for(client)
    events = []  # hidden: no risk UI in passport

    connected_text = "подключён сейчас" if item.get("connected") else "не подключён"
    connected_class = "ok" if item.get("connected") else "muted"

    session_rows = "".join(
        f"<tr>"
        f"<td>{'онлайн' if r.get('active') else 'завершена'}</td>"
        f"<td>{esc(r.get('first_seen_text') or '—')}</td>"
        f"<td>{esc(r.get('last_seen_text') or '—')}</td>"
        f"<td>{esc(r.get('remote_ip') or '—')}</td>"
        f"<td>{esc(r.get('remote_network') or '—')}</td>"
        f"</tr>"
        for r in sessions
    ) or '<tr><td colspan="5" class="muted">Истории сессий пока нет</td></tr>'

    event_rows = "".join(
        f"<tr>"
        f"<td>{esc(e.get('time') or '—')}</td>"
        f"<td><span class='riskpill {risk_event_level_class(e.get('new_level'))}'>{esc(e.get('label') or '—')}</span></td>"
        f"<td>{esc(e.get('title') or '—')}<div class='cellhint'>{esc(e.get('reasons') or '')}</div></td>"
        f"</tr>"
        for e in events
    ) or '<tr><td colspan="3" class="muted">Событий риска по этому доступу пока нет</td></tr>'

    risk_reasons = item.get("sharing_reasons_text") or "нет подозрительной активности профиля"

    group_name = item.get("group_name") or auth_client_group(client) or "vpn"
    group_manage_html = ""
    if auth_is_owner(user or {}):
        try:
            conn = auth_db()
            groups = conn.execute("select name,title from panel_groups order by name").fetchall()
            conn.close()
        except Exception:
            groups = []
        options = "".join(
            f'<option value="{esc(name)}" {"selected" if name == group_name else ""}>{esc(title)} · {esc(name)}</option>'
            for name, title in groups
        )
        group_manage_html = f"""
        <section class="card">
            <h2>Группа доступа</h2>
            <p class="muted">Текущая группа: <strong>{esc(group_name)}</strong>. От группы зависят видимость и права админов.</p>
            <form method="post" action="/set-client-group">
                <input type="hidden" name="client" value="{esc(client)}">
                <select name="group_name" style="width:100%;max-width:360px;padding:10px;border-radius:12px;border:1px solid var(--line);background:#0d121b;color:var(--text);font-size:15px;">
                    {options}
                </select>
                <button type="submit" style="margin-top:12px;">Сохранить группу</button>
            </form>
        </section>
        """

    body = f"""
        


        {access_human_passport_card_html(client)}

        <section class="grid">
            <div class="card">
                <h2>Состояние</h2>
                <table class="kv">
                    <tbody>
                        <tr><th>Сертификат</th><td>{esc(item.get('status_ru') or item.get('status') or '—')}</td></tr>
                        <tr><th>Действует до</th><td>{esc(item.get('expires_at') or '—')}<div class="cellhint">{esc(item.get('expires_hint') or '')}</div></td></tr>
                        <tr><th>Файлы</th><td>{yesno(item.get('has_files'))}</td></tr>
                        <tr><th>Сейчас</th><td><span class="{connected_class}">{esc(connected_text)}</span></td></tr>
                        <tr><th>Последний вход</th><td>{esc(item.get('last_connected') or '—')}</td></tr>
                        <tr><th>Внешний IP</th><td>{esc(item.get('last_remote_ip') or '—')}</td></tr>
                        <tr><th>Сеть</th><td>{esc(item.get('last_remote_network') or '—')}</td></tr>
                        <tr><th>Длительность</th><td>{esc(item.get('last_duration') or '—')}</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2>Трафик</h2>
                <table class="kv">
                    <tbody>
                        <tr><th>Текущая сессия</th><td>{esc(item.get('traffic_label') or '—')}</td></tr>
                        <tr><th>Всего в текущем сеансе</th><td>{esc(item.get('traffic_total_label') or '—')}</td></tr>
                        <tr><th>Сегодня</th><td>{esc(item.get('traffic_today_label') or '0 Б')}<div class="cellhint">{esc(item.get('traffic_today_detail') or '')}</div></td></tr>
                        <tr><th>7 дней</th><td>{esc(item.get('traffic_7d_label') or '0 Б')}<div class="cellhint">{esc(item.get('traffic_7d_detail') or '')}</div></td></tr>
                        <tr><th>30 дней</th><td>{esc(item.get('traffic_30d_label') or '0 Б')}<div class="cellhint">{esc(item.get('traffic_30d_detail') or '')}</div></td></tr>
                    </tbody>
                </table>
            </div>
        </section>


        <section class="card passport-download-card">
            <h2>Файлы профиля</h2>
            <p class="muted">Скачайте файл установки для нужного устройства.</p>
            <p>{profile_download_links_html(client)}</p>
        </section>

        <section class="card passport-manage-card">
            <h2>Управление</h2>
            <p class="muted">Опасные действия требуют отдельного подтверждения точным именем доступа.</p>
            <p>
                <a class="dangerButton" href="/confirm-revoke-delete?client={esc(client)}">Отключить и удалить</a>
            </p>
        </section>

        {group_manage_html}


        <section class="card passport-history-card">
            <h2>История сессий и IP</h2>
            <div class="tablewrap passport-history-tablewrap">
                <table>
                    <thead><tr><th>Статус</th><th>Начало</th><th>Последний раз</th><th>Внешний IP</th><th>Сеть</th></tr></thead>
                    <tbody>{session_rows}</tbody>
                </table>
            </div>
            {access_session_cards_mobile_html(session_rows)}
        </section>

    """

    return access_passport_shell(client, body)



# vpn-access-passport-server-product-fix-v1
def access_passport_server_fix_css():
    return """
/* vpn-access-passport-server-product-fix-v1 */
@media(max-width:760px){
  html.access-passport-server-v1 .passport-history-tablewrap{
    display:none !important;
  }
  html.access-passport-server-v1 .passport-session-cards{
    display:grid !important;
    gap:10px !important;
    margin-top:12px !important;
  }
  html.access-passport-server-v1 .passport-session-card{
    border:1px solid rgba(148,163,184,.22) !important;
    background:rgba(15,23,42,.64) !important;
    border-radius:18px !important;
    padding:13px 13px !important;
    display:grid !important;
    gap:10px !important;
  }
  html.access-passport-server-v1 .passport-session-top{
    display:flex !important;
    justify-content:space-between !important;
    align-items:center !important;
    gap:10px !important;
  }
  html.access-passport-server-v1 .passport-session-top strong{
    font-size:17px !important;
    line-height:1.15 !important;
  }
  html.access-passport-server-v1 .passport-session-top .pill{
    flex:0 0 auto !important;
    font-size:12px !important;
  }
  html.access-passport-server-v1 .passport-session-grid{
    display:grid !important;
    grid-template-columns:1fr 1fr !important;
    gap:8px !important;
  }
  html.access-passport-server-v1 .passport-session-cell{
    border:1px solid rgba(148,163,184,.14) !important;
    background:rgba(255,255,255,.025) !important;
    border-radius:13px !important;
    padding:9px 10px !important;
    min-width:0 !important;
  }
  html.access-passport-server-v1 .passport-session-cell span{
    display:block !important;
    color:var(--muted) !important;
    font-size:10px !important;
    font-weight:900 !important;
    letter-spacing:.08em !important;
    text-transform:uppercase !important;
    margin-bottom:5px !important;
  }
  html.access-passport-server-v1 .passport-session-cell b{
    display:block !important;
    font-size:14px !important;
    line-height:1.2 !important;
    font-weight:850 !important;
    overflow-wrap:anywhere !important;
  }
}
@media(max-width:420px){
  html.access-passport-server-v1 .passport-session-grid{
    grid-template-columns:1fr !important;
  }
}

/* vpn-access-passport-kv-mobile-fix-v1 */
@media(max-width:760px){
  html.access-passport-server-v1 table.kv,
  html.access-passport-server-v1 table.kv tbody,
  html.access-passport-server-v1 table.kv tr,
  html.access-passport-server-v1 table.kv th,
  html.access-passport-server-v1 table.kv td{
    display:block !important;
    width:100% !important;
    box-sizing:border-box !important;
  }

  html.access-passport-server-v1 table.kv{
    border-collapse:separate !important;
    border-spacing:0 !important;
  }

  html.access-passport-server-v1 table.kv tr{
    padding:11px 0 !important;
    border-bottom:1px solid var(--line) !important;
  }

  html.access-passport-server-v1 table.kv tr:last-child{
    border-bottom:0 !important;
  }

  html.access-passport-server-v1 table.kv th{
    padding:0 0 5px 0 !important;
    border:0 !important;
    color:var(--muted) !important;
    font-size:11px !important;
    line-height:1.15 !important;
    font-weight:900 !important;
    letter-spacing:.09em !important;
    text-transform:uppercase !important;
    text-align:left !important;
    white-space:normal !important;
  }

  html.access-passport-server-v1 table.kv td{
    padding:0 !important;
    border:0 !important;
    text-align:left !important;
    font-size:18px !important;
    line-height:1.22 !important;
    white-space:normal !important;
    overflow:visible !important;
    overflow-wrap:anywhere !important;
  }

  html.access-passport-server-v1 table.kv td .cellhint{
    margin-top:4px !important;
    font-size:13px !important;
    line-height:1.25 !important;
    white-space:normal !important;
    overflow-wrap:anywhere !important;
  }

  html.access-passport-server-v1 table.kv td .ok,
  html.access-passport-server-v1 table.kv td .warn,
  html.access-passport-server-v1 table.kv td .bad{
    display:inline-block !important;
    max-width:100% !important;
    white-space:normal !important;
    overflow-wrap:anywhere !important;
  }
}
/* /vpn-access-passport-kv-mobile-fix-v1 */

/* /vpn-access-passport-server-product-fix-v1 */
"""
# /vpn-access-passport-server-product-fix-v1


# vpn-access-passport-server-product-v1
def access_passport_server_css():
    return """
/* vpn-access-passport-server-product-v1 */
.access-passport-server-v1 .passport-session-cards{display:none}
.access-passport-server-v1 .passport-session-card{border:1px solid rgba(255,255,255,.075);background:rgba(0,0,0,.11);border-radius:15px;padding:11px 12px;display:grid;gap:8px}
.access-passport-server-v1 .passport-session-top{display:flex;justify-content:space-between;align-items:center;gap:10px}
.access-passport-server-v1 .passport-session-top strong{font-size:14px;line-height:1.2}
.access-passport-server-v1 .passport-session-grid{display:grid;grid-template-columns:1fr 1fr;gap:7px}
.access-passport-server-v1 .passport-session-cell{border:1px solid rgba(255,255,255,.06);background:rgba(255,255,255,.025);border-radius:12px;padding:8px 9px}
.access-passport-server-v1 .passport-session-cell span{display:block;color:var(--muted);font-size:10px;font-weight:900;letter-spacing:.075em;text-transform:uppercase;margin-bottom:4px}
.access-passport-server-v1 .passport-session-cell b{display:block;font-size:13px;line-height:1.25;font-weight:800;overflow-wrap:anywhere}
.access-passport-server-v1 .passport-download-card p:last-child{display:flex;gap:8px;flex-wrap:wrap}
@media(max-width:760px){
  .access-passport-server-v1 .shell-title h1{font-size:31px;line-height:1.02;overflow-wrap:anywhere}
  .access-passport-server-v1 .shell-subtitle{font-size:15px;line-height:1.25}
  .access-passport-server-v1 .card{padding:15px;border-radius:22px}
  .access-passport-server-v1 .card h2{font-size:22px;line-height:1.12}
  .access-passport-server-v1 table{table-layout:fixed;width:100%}
  .access-passport-server-v1 th,.access-passport-server-v1 td{font-size:14px;line-height:1.25;overflow-wrap:anywhere;word-break:normal}
  .access-passport-server-v1 td:first-child,.access-passport-server-v1 th:first-child{width:42%}
  .access-passport-server-v1 .passport-history-tablewrap{display:none!important}
  .access-passport-server-v1 .passport-session-cards{display:grid;gap:8px;margin-top:10px}
  .access-passport-server-v1 .passport-download-card .btn,
  .access-passport-server-v1 .card .btn{max-width:100%;white-space:normal;text-align:center}
}
@media(max-width:420px){
  .access-passport-server-v1 .shell-title h1{font-size:29px}
  .access-passport-server-v1 .passport-session-grid{grid-template-columns:1fr}
}
/* /vpn-access-passport-server-product-v1 */
"""

def access_session_cards_mobile_html(session_rows):
    try:
        import re as _re
        from html import unescape as _unescape

        def clean(x):
            x = _re.sub(r"<[^>]+>", " ", str(x or ""))
            x = _unescape(x)
            return _re.sub(r"\s+", " ", x).strip()

        def short_dt(x):
            x = clean(x)
            x = _re.sub(r"(\d{2})\.(\d{2})\.2026\s+(\d{2}:\d{2})(?::\d{2})?", r"\1.\2 \3", x)
            return x

        cards = []
        for tr in _re.findall(r"<tr[^>]*>(.*?)</tr>", str(session_rows or ""), _re.S)[:8]:
            tds = _re.findall(r"<td[^>]*>(.*?)</td>", tr, _re.S)
            if not tds or len(tds) < 3:
                continue

            status = clean(tds[0]) or "сессия"
            start = short_dt(tds[1] if len(tds) > 1 else "")
            last = short_dt(tds[2] if len(tds) > 2 else "")
            ip = clean(tds[3] if len(tds) > 3 else "")
            network = clean(tds[4] if len(tds) > 4 else "")

            is_online = ("сейчас" in status.lower()) or ("online" in status.lower()) or ("подключ" in status.lower())
            pill_cls = "ok" if is_online else ""
            pill_text = "онлайн" if is_online else "история"

            cards.append(f"""
                <div class="passport-session-card">
                    <div class="passport-session-top">
                        <strong>{esc(status)}</strong>
                        <span class="pill {pill_cls}">{esc(pill_text)}</span>
                    </div>
                    <div class="passport-session-grid">
                        <div class="passport-session-cell"><span>начало</span><b>{esc(start or "—")}</b></div>
                        <div class="passport-session-cell"><span>последний раз</span><b>{esc(last or "—")}</b></div>
                        <div class="passport-session-cell"><span>IP</span><b>{esc(ip or "—")}</b></div>
                        <div class="passport-session-cell"><span>сеть</span><b>{esc(network or "—")}</b></div>
                    </div>
                </div>
            """)

        if not cards:
            return ""

        return '<div class="passport-session-cards">' + "".join(cards) + "</div>"
    except Exception as e:
        print(f"access_session_cards_mobile_html_error={e!r}", flush=True)
        return ""
# /vpn-access-passport-server-product-v1


def access_passport_shell(title, body):
    # vpn-access-passport-unified-header-v1
    # vpn-access-passport-server-product-v1
    raw_title = str(title or "Доступ")
    shell_title = raw_title
    subtitle = "Профиль, устройство и подключения"

    try:
        client_for_title = safe_client_name(raw_title)
        if client_for_title == raw_title and client_for_title:
            meta = access_human_meta(client_for_title)
            person = str(meta.get("person_name") or "").strip()
            device = str(meta.get("device_label") or "").strip()

            if person:
                shell_title = person
            else:
                shell_title = "Доступ: " + client_for_title

            bits = []
            if device:
                bits.append(device)
            bits.append(client_for_title)
            subtitle = " · ".join(bits)
    except Exception:
        try:
            if safe_client_name(shell_title) == shell_title and shell_title:
                shell_title = "Доступ: " + shell_title
        except Exception:
            pass

    if str(title).startswith("Создать"):
        subtitle = "Новый VPN-профиль для пользователя и устройства"

    return f"""<!doctype html>
<html lang="ru" class="access-passport-server-v1">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{esc(shell_title)} · {esc(APP_NAME)}</title>
    <style>
{support_shell_css()}
{access_passport_server_css()}
{access_passport_server_fix_css()}
        :root {{
            --bg:#0b0f17;
            --card:#121824;
            --card2:#161e2d;
            --text:#e7edf7;
            --muted:#93a4bb;
            --line:#263246;
            --ok:#52d273;
            --bad:#ff6b6b;
            --blue:#80bfff;
        }}
        * {{ box-sizing:border-box; }}
        body {{ margin:0;
            font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
            background:linear-gradient(180deg,#0b0f17,#0d1320);
            color:var(--text);
        }}
        a {{ color:var(--blue); text-decoration:none; }}
        a:hover {{ text-decoration:underline; }}
        main {{ max-width:1320px; margin:0 auto; padding:24px; }}
        .hero {{ display:flex; justify-content:space-between; gap:18px; align-items:flex-start; margin-bottom:18px; }}
        .hero h1 {{ margin:8px 0 6px; font-size:34px; letter-spacing:-.03em; }}
        .heroRight {{ text-align:right; padding-top:10px; }}
        .crumb {{ color:var(--muted); font-size:14px; }}
        .muted {{ color:var(--muted); }}
        .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; }}
        .card {{ background:rgba(18,24,36,.92);
            border:1px solid var(--line);
            border-radius:18px;
            padding:18px;
            margin-bottom:16px;
            box-shadow:0 12px 40px rgba(0,0,0,.18);
        }}
        .card h2 {{ margin:0 0 12px; font-size:18px; }}
        .tablewrap {{ overflow:auto; }}
        table {{ width:100%; border-collapse:collapse; }}
        th, td {{
            text-align:left;
            padding:10px 12px;
            border-bottom:1px solid var(--line);
            vertical-align:top;
            white-space:nowrap;
        }}
        th {{ color:var(--muted); font-weight:700; font-size:13px; }}
        .kv th {{ width:170px; }}
        .cellhint {{ color:var(--muted); font-size:12px; margin-top:4px; white-space:normal; }}
        .ok {{ color:var(--ok); font-weight:800; }}
        .riskLine {{ display:flex; gap:12px; align-items:center; margin-bottom:10px; }}
        .riskpill {{ display:inline-flex;
            border-radius:999px;
            padding:4px 9px;
            font-size:12px;
            font-weight:800;
            border:1px solid var(--line);
            white-space:nowrap;
        }}
        .risk_normal {{ color:var(--muted); background:#151b28; }}
        .risk_questions {{ color:#ffd166; background:rgba(255,209,102,.12); border-color:rgba(255,209,102,.28); }}
        .risk_suspicious {{ color:#ffb86b; background:rgba(255,184,107,.13); border-color:rgba(255,184,107,.30); }}
        .risk_high {{ color:#ff7b7b; background:rgba(255,107,107,.14); border-color:rgba(255,107,107,.32); }}
        label {{ display:block;
            color:var(--muted);
            font-weight:800;
            margin:14px 0 6px;
        }}
        .textInput {{ width:100%;
            max-width:420px;
            padding:12px 14px;
            border-radius:12px;
            border:1px solid var(--line);
            background:#0d1320;
            color:var(--text);
            font-size:16px;
            outline:none;
        }}
        .textInput:focus {{
            border-color:var(--blue);
        }}
        .primaryButton, .softButton {{ display:inline-flex;
            align-items:center;
            justify-content:center;
            margin:8px 8px 0 0;
            padding:10px 14px;
            border-radius:12px;
            border:1px solid var(--line);
            font-weight:800;
            text-decoration:none;
            cursor:pointer;
        }}
        .primaryButton {{ background:rgba(128,191,255,.14);
            color:var(--blue);
            border-color:rgba(128,191,255,.35);
        }}
        .softButton {{ background:var(--card2);
            color:var(--text);
        }}
        .badtext {{ color:var(--bad);
            font-weight:800;
        }}
        .dangerButton {{ display:inline-flex;
            align-items:center;
            justify-content:center;
            padding:10px 14px;
            border-radius:12px;
            border:1px solid rgba(255,107,107,.35);
            background:rgba(255,107,107,.12);
            color:#ff7b7b;
            font-weight:800;
            text-decoration:none;
        }}
        .dangerButton:hover {{ background:rgba(255,107,107,.18);
            text-decoration:none;
        }}
        @media (max-width:900px) {{
            main {{ padding:14px; }}
            .hero {{ flex-direction:column; }}
            .heroRight {{ text-align:left; }}
            .grid {{ grid-template-columns:1fr; }}
            th, td {{ white-space:normal; }}
        }}
    </style>
</head>
<body>
<main>
{vpn_support_header_html('Доступ: ' + raw_title if safe_client_name(raw_title) == raw_title else shell_title, subtitle).replace('Доступ: ' + raw_title, shell_title, 1)}
{body}
</main>
</body>
</html>"""



# vpn-home-css-single-source-v1
# /vpn-home-css-single-source-v1

# vpn-access-card-last-seen-db-v1
# /vpn-access-card-last-seen-db-v1

# vpn-provider-map-short-v1
# /vpn-provider-map-short-v1

# vpn-access-index-simple-v1

# vpn-human-client-labels-v1
def access_human_meta(client):
    import sqlite3 as _sqlite3

    client = safe_client_name(client or "")
    if not client:
        return {}

    try:
        con = _sqlite3.connect(DB_PATH)
        try:
            con.row_factory = _sqlite3.Row
            row = con.execute("""
                select client, person_name, person_slug, device_label, device_type
                from vpn_client_meta
                where client=?
            """, (client,)).fetchone()
            return dict(row) if row else {}
        finally:
            con.close()
    except Exception as e:
        print(f"access_human_meta_error={e!r}", flush=True)
        return {}

def access_human_label(client):
    client = safe_client_name(client or "")
    m = access_human_meta(client)
    person = str(m.get("person_name") or "").strip()
    device = str(m.get("device_label") or "").strip()

    if person and device:
        return f"{person} · {device}"
    if person:
        return person
    return client or "—"


def access_channel_provider_label(remote_ip):
    remote_ip = str(remote_ip or "").strip()
    if not remote_ip or remote_ip == "—":
        return "провайдер не определён"
    try:
        data = ip_network_lookup(remote_ip, allow_lookup=True)
        label = str(data.get("label") or data.get("provider") or "").strip()
        if label and label != remote_ip:
            try:
                label = pretty_provider_name(label)
            except Exception:
                pass
            return label
    except Exception as e:
        print(f"access_channel_provider_label_error={e!r}", flush=True)
    return "провайдер не определён"

def access_human_channel_cell_html(client, remote_ip="", vpn_ip=""):
    client = safe_client_name(client or "")
    label = access_human_label(client)
    provider = access_channel_provider_label(remote_ip)
    sub_bits = []
    if client and label != client:
        sub_bits.append(client)
    if provider:
        sub_bits.append(f"провайдер: {provider}")
    sub = " · ".join(x for x in sub_bits if x)
    return f"<b>{esc(label)}</b><span class=\"sub\">{esc(sub)}</span>"

def access_human_passport_card_html(client):
    client = safe_client_name(client or "")
    m = access_human_meta(client)
    person = str(m.get("person_name") or "").strip()
    device = str(m.get("device_label") or "").strip()

    if not person and not device:
        return ""

    bits = []
    if person:
        bits.append(person)
    if device:
        bits.append(device)

    return f"""
        <section class="card">
            <h2>{esc(" · ".join(bits))}</h2>
            <p class="muted">Техническое имя доступа: <strong>{esc(client)}</strong></p>
        </section>
"""
# /vpn-human-client-labels-v1


def access_device_rows_html():
    text = support_read_file(SUPPORT_STATUS_DIR, "device-watch.txt", "")

    def section(name):
        try:
            return _vpn_support_section(text, name)
        except Exception:
            return []

    def human_old_profile_detail(line):
        rest = line.split(":", 1)[1].strip() if ":" in line else line
        fails = ""
        ips = ""
        providers = ""

        m = re.search(r"fails=([0-9]+)", rest)
        if m:
            fails = m.group(1)

        m = re.search(r"ips=([^ ]+)", rest)
        if m:
            ips = m.group(1)

        m = re.search(r"providers=(.*)$", rest)
        if m:
            providers = m.group(1).strip(" -")

        bits = []
        if fails:
            bits.append(f"{fails} попытки подключения после удаления/отзыва")
        else:
            bits.append("старый или отозванный профиль продолжает подключаться")

        if providers and providers != "—":
            bits.append(f"сеть: {providers}")
        elif ips:
            bits.append("сеть не определена")

        return " · ".join(bits)

    rows = ""

    old = [x for x in section("===== REVOKED / OLD PROFILE ATTEMPTS =====") if ": fails=" in x]
    suspicious = [x for x in section("===== SUSPICIOUS ROAMING / POSSIBLE MULTI-DEVICE =====") if ": ok_connects=" in x]
    active_multi = [x for x in section("===== ACTIVE SAME-CLIENT MULTI-IP =====") if ": " in x and not x.startswith("OK:")]

    for line in active_multi[:10]:
        client = safe_client_name(line.split(":", 1)[0].strip())
        if client:
            rows += f"<tr><td><span class='pill bad'>сейчас</span></td><td><a href='/access?client={esc(client)}'>{esc(client)}</a></td><td>одновременно активен с разных IP — проверить, не используется ли один конфиг на двух устройствах</td></tr>"

    for line in suspicious[:10]:
        client = safe_client_name(line.split(":", 1)[0].strip())
        if not client:
            continue
        try:
            reason = _vpn_support_suspicion_detail(line)
        except Exception:
            reason = "возможный дубль устройства или разные сети"
        rows += f"<tr><td><span class='pill warn'>проверить</span></td><td><a href='/access?client={esc(client)}'>{esc(client)}</a></td><td>{esc(reason)}</td></tr>"

    for line in old[:10]:
        client = safe_client_name(line.split(":", 1)[0].strip())
        if not client:
            continue
        detail = human_old_profile_detail(line)
        rows += f"<tr><td><span class='pill warn'>старый профиль</span></td><td><a href='/access?client={esc(client)}'>{esc(client)}</a></td><td>{esc(detail)}</td></tr>"

    if not rows:
        rows = "<tr><td><span class='pill ok'>OK</span></td><td>Проблемных устройств нет</td><td>Старые профили и явные дубли за последнее окно не найдены</td></tr>"

    return rows


# vpn-access-mobile-density-and-problems-v1
def access_problem_cards_html():
    """Compact mobile-friendly view built from legacy problem rows."""
    rows = access_device_rows_html()

    # vpn-access-problem-real-clients-only-v1:
    # The legacy problem table can contain technical/debug words in rendered cells
    # such as "ips" or "providers". Only show real VPN clients known to metadata.
    try:
        real_clients = set()
        con = sqlite3.connect(DB_PATH)
        try:
            for row in con.execute("select client from vpn_client_meta"):
                if row and row[0]:
                    real_clients.add(str(row[0]).strip())
        finally:
            con.close()
    except Exception:
        real_clients = set()

    technical_problem_tokens = {
        "ip", "ips", "provider", "providers", "remote_ip", "remote_ips",
        "asn", "cache", "traffic", "sessions", "session", "rows",
        "client", "clients", "none", "null", "unknown",
    }

    def is_real_problem_client(client):
        c = str(client or "").strip()
        if not c:
            return False
        if c.lower() in technical_problem_tokens:
            return False
        if real_clients:
            return c in real_clients
        return True

    def clean(fragment):
        try:
            fragment = re.sub(r"<[^>]+>", " ", str(fragment or ""))
            fragment = html.unescape(fragment)
            fragment = re.sub(r"\s+", " ", fragment).strip()
            return fragment
        except Exception:
            return str(fragment or "").strip()

    entries = []
    for tr in re.findall(r"<tr>(.*?)</tr>", rows or "", re.S):
        tds = re.findall(r"<td[^>]*>(.*?)</td>", tr, re.S)
        if len(tds) < 2:
            continue

        state = clean(tds[0])
        access_cell = tds[1]
        reason = clean(tds[2]) if len(tds) > 2 else ""

        href_m = re.search(r"href=['\"]([^'\"]+)['\"]", access_cell or "")
        href = href_m.group(1) if href_m else ""
        client = clean(access_cell)

        if "Проблемных устройств нет" in client or state.upper() == "OK":
            return """
              <div class="access-problem-summary ok-state">Всё спокойно</div>
              <div class="access-problem-list is-ok">
                <div class="access-problem-row no-link ok-row">
                  <div class="access-problem-main">
                    <strong>Проблемных устройств нет</strong>
                    <span>Старые профили и явные дубли за последнее окно не найдены</span>
                  </div>
                  <span class="pill ok">OK</span>
                </div>
              </div>
            """

        if not client:
            continue

        if not is_real_problem_client(client):
            continue

        level = "bad" if state == "сейчас" else "warn"
        label = "сейчас" if state == "сейчас" else "проверить"
        if "стар" in state.lower():
            label = "старый"

        entries.append({
            "client": client,
            "href": href or f"/access?client={esc(client)}",
            "reason": reason or "требует проверки",
            "level": level,
            "label": label,
        })

    if not entries:
        return """
          <div class="access-problem-summary ok-state">Всё спокойно</div>
          <div class="access-problem-list is-ok">
            <div class="access-problem-row no-link ok-row">
              <div class="access-problem-main">
                <strong>Проблемных устройств нет</strong>
                <span>Старые профили и явные дубли за последнее окно не найдены</span>
              </div>
              <span class="pill ok">OK</span>
            </div>
          </div>
        """

    n = len(entries)
    if n % 10 == 1 and n % 100 != 11:
        word = "требует"
    else:
        word = "требуют"

    cards = []
    for e in entries[:12]:
        cards.append(f"""
          <a class="access-problem-row {esc(e['level'])}" href="{esc(e['href'])}">
            <div class="access-problem-main">
              <strong>{esc(e['client'])}</strong>
              <span>{esc(e['reason'])}</span>
            </div>
            <span class="pill {esc(e['level'])}">{esc(e['label'])}</span>
          </a>
        """)

    return f"""
      <div class="access-problem-summary">{n} {word} проверки</div>
      <div class="access-problem-list">{''.join(cards)}</div>
    """
# /vpn-access-mobile-density-and-problems-v1



# vpn-access-device-cards-v1
# /vpn-access-device-cards-v1



# vpn-access-people-grammar-v1
def access_ru_device_count(n):
    try:
        n = int(n)
    except Exception:
        n = 0
    if n % 10 == 1 and n % 100 != 11:
        word = "устройство"
    elif n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        word = "устройства"
    else:
        word = "устройств"
    return f"{n} {word}"

def access_ru_profile_count(n):
    try:
        n = int(n)
    except Exception:
        n = 0
    if n % 10 == 1 and n % 100 != 11:
        word = "профиль"
    elif n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        word = "профиля"
    else:
        word = "профилей"
    return f"{n} {word}"
# /vpn-access-people-grammar-v1


# vpn-access-people-groups-v1
def access_meta_map_for_clients(client_names):
    import sqlite3 as _sqlite3

    names = [safe_client_name(x) for x in (client_names or []) if safe_client_name(x)]
    if not names:
        return {}

    result = {}
    con = _sqlite3.connect(DB_PATH)
    con.row_factory = _sqlite3.Row
    try:
        placeholders = ",".join("?" for _ in names)
        rows = con.execute(f"""
            select client, person_name, person_slug, device_label, device_type, comment
            from vpn_client_meta
            where client in ({placeholders})
        """, names).fetchall()
        for r in rows:
            result[r["client"]] = dict(r)
    except Exception as e:
        print(f"access_meta_map_for_clients_error={e!r}", flush=True)
    finally:
        con.close()
    return result


def access_format_last_connected_display(value):
    raw = str(value or "").strip()
    if not raw or raw == "—":
        return ""

    import datetime as _dt
    import re

    def nice(d):
        if getattr(d, "tzinfo", None) is not None:
            d = d.astimezone().replace(tzinfo=None)

        now = _dt.datetime.now()
        days = (now.date() - d.date()).days
        hm = d.strftime("%H:%M")

        if days == 0:
            return f"сегодня {hm}"
        if days == 1:
            return f"вчера {hm}"
        if days == 2:
            return f"позавчера {hm}"

        if d.year == now.year:
            return d.strftime("%d.%m %H:%M")
        return d.strftime("%d.%m.%Y %H:%M")

    try:
        # epoch seconds / milliseconds
        if re.match(r"^\d{10,13}$", raw):
            ts = int(raw)
            if ts > 9999999999:
                ts = ts / 1000
            return nice(_dt.datetime.fromtimestamp(ts))

        # ISO / sqlite datetime
        x = raw.replace("Z", "+00:00").replace("T", " ")
        try:
            return nice(_dt.datetime.fromisoformat(x))
        except Exception:
            pass

        for fmt in (
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%d.%m.%Y %H:%M:%S",
            "%d.%m.%Y %H:%M",
            "%d.%m %H:%M:%S",
            "%d.%m %H:%M",
        ):
            try:
                d = _dt.datetime.strptime(raw, fmt)

                # Если год не был указан, считаем текущий год.
                # Если дата получилась в будущем — значит это прошлый год.
                if "%Y" not in fmt:
                    now = _dt.datetime.now()
                    d = d.replace(year=now.year)
                    if d.date() > now.date():
                        d = d.replace(year=now.year - 1)

                return nice(d)
            except Exception:
                pass
    except Exception:
        pass

    # Если ничего не распознали — лучше показать как есть, чем сломать список.
    return raw


def access_people_cards_html(items, user=None):
    user = user or {}
    items = items or []

    names = []
    by_name = {}
    for item in items:
        name = safe_client_name(item.get("name") or item.get("client") or "")
        if not name:
            continue
        try:
            if not auth_client_allowed(user, name, "can_view"):
                continue
        except Exception:
            pass
        names.append(name)
        by_name[name] = item

    meta = access_meta_map_for_clients(names)

    people = {}
    unbound = []

    for name in names:
        item = by_name.get(name) or {}
        m = meta.get(name) or {}

        person_name = str(m.get("person_name") or "").strip()
        person_slug = safe_client_name(m.get("person_slug") or "")
        device_label = str(m.get("device_label") or "").strip()
        device_type = str(m.get("device_type") or "").strip()

        device = {
            "client": name,
            "device_label": device_label or "устройство",
            "device_type": device_type,
            "connected": bool(item.get("connected")),
            "status": item.get("status") or "unknown",
            "status_ru": item.get("status_ru") or status_ru(item.get("status") or "unknown"),
            "last_connected": item.get("last_seen") or item.get("last_connected") or "—",
            "traffic_label": item.get("traffic_label") or "",
            "provider": item.get("last_remote_network") or "",
            "expires_at": item.get("expires_at") or "—",
        }

        if person_name and person_slug:
            g = people.setdefault(person_slug, {
                "title": person_name,
                "slug": person_slug,
                "devices": [],
            })
            g["devices"].append(device)
        else:
            unbound.append(device)

    def online_pill(v):
        return "<span class='pill ok'>онлайн</span>" if v else "<span class='pill'>не в сети</span>"

    def provider_badge(provider):
        provider = str(provider or "").strip()
        if not provider or provider == "—":
            return ""
        try:
            provider = pretty_provider_name(provider)
        except Exception:
            pass
        low = provider.lower()
        if "не определ" in low or provider == "—":
            return ""
        return f"<span class='pill provider-pill'>{esc(provider)}</span>"

    def device_row(d):
        traffic = str(d.get("traffic_label") or "").strip()
        last = access_format_last_connected_display(d.get("last_connected"))
        connected = bool(d.get("connected"))

        meta_bits = []
        if connected:
            meta_bits.append("подключен сейчас")
        if traffic and traffic != "—":
            meta_bits.append(traffic)

        meta_line = " · ".join(meta_bits)
        meta_html = f'<div class="person-device-meta">{esc(meta_line)}</div>' if meta_line else ""

        last_line = ""
        if not connected:
            if last and last != "—":
                last_line = f'<div class="person-device-meta">последняя активность {esc(last)}</div>'
            else:
                last_line = '<div class="person-device-meta">ещё не подключался</div>'

        provider_html = provider_badge(d.get('provider'))
        state_html = f"""
            <div class="person-device-state">
              {provider_html}
            </div>""" if connected and provider_html else ""

        return f"""
          <a class="person-device {'is-online' if connected else ''}" href="/access?client={esc(d['client'])}">
            <div class="person-device-main">
              <strong>{esc(d.get('device_label') or 'устройство')}</strong>
              <div class="person-device-client">{esc(d['client'])}</div>
              {meta_html}
              {last_line}
            </div>
            {state_html}
          </a>"""

    css = """
<style>
/* vpn-access-mobile-product-polish-v1 */
.people-list{display:grid;gap:12px}
.person-card{border:1px solid rgba(255,255,255,.075);background:rgba(255,255,255,.022);border-radius:20px;padding:13px;box-shadow:0 12px 30px rgba(0,0,0,.10)}
.person-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:11px}
.person-title{font-size:17px;font-weight:900;letter-spacing:-.01em}
.person-sub{color:var(--muted);font-size:13px;margin-top:3px}
.person-devices{display:grid;gap:7px}
.person-device{position:relative;display:flex;justify-content:space-between;gap:12px;align-items:center;text-decoration:none;color:var(--text);border:1px solid rgba(255,255,255,.065);background:rgba(0,0,0,.105);border-radius:15px;padding:11px 12px;overflow:hidden;transition:background .15s ease,border-color .15s ease,transform .15s ease}
.person-device:hover{background:rgba(255,255,255,.045);border-color:rgba(255,255,255,.11);transform:translateY(-1px)}
.person-device-main{min-width:0}
.person-device strong{display:block;font-size:14px;line-height:1.25;letter-spacing:-.005em}
.person-device-client{color:var(--muted);font-size:11px;margin-top:3px;line-height:1.3;opacity:.62;word-break:break-word}
.person-device-meta{color:var(--muted);font-size:12px;margin-top:4px;line-height:1.35;word-break:break-word}
.person-device-state{display:flex;gap:7px;align-items:center;flex-wrap:wrap;justify-content:flex-end;flex-shrink:0}
.provider-pill{max-width:170px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.person-device.is-online{border-color:rgba(66,211,146,.24);background:rgba(66,211,146,.052);box-shadow:inset 3px 0 0 rgba(66,211,146,.72)}
.person-device.is-online:hover{background:rgba(66,211,146,.075);border-color:rgba(66,211,146,.32)}
.person-unbound{opacity:.88}
@media(max-width:760px){
  .people-list{gap:11px}
  .person-card{border-radius:18px;padding:12px}
  .person-head{margin-bottom:9px}
  .person-title{font-size:16px}
  .person-sub{font-size:12px}
  .person-device{align-items:flex-start;padding:10px 11px;border-radius:14px;gap:9px}
  .person-device-state{justify-content:flex-start;max-width:48%}
  .provider-pill{max-width:128px}
}
@media(max-width:420px){
  .person-device{display:block}
  .person-device-state{margin-top:7px;max-width:100%}
  .provider-pill{max-width:100%}
}
/* /vpn-access-mobile-product-polish-v1 */
</style>
"""

    cards = []

    for _, g in sorted(people.items(), key=lambda kv: kv[1]["title"].lower()):
        devices = sorted(g["devices"], key=lambda d: (0 if d.get("connected") else 1, d.get("device_label") or "", d.get("client") or ""))
        online = sum(1 for d in devices if d.get("connected"))
        cards.append(f"""
        <div class="person-card">
          <div class="person-head">
            <div>
              <div class="person-title">{esc(g['title'])}</div>
              <div class="person-sub">{access_ru_device_count(len(devices))} · {online} онлайн</div>
            </div>
          </div>
          <div class="person-devices">
            {''.join(device_row(d) for d in devices)}
          </div>
        </div>""")

    if unbound:
        devices = sorted(unbound, key=lambda d: (0 if d.get("connected") else 1, d.get("client") or ""))
        cards.append(f"""
        <div class="person-card person-unbound">
          <div class="person-head">
            <div>
              <div class="person-title">Без привязки к человеку</div>
              <div class="person-sub">{access_ru_profile_count(len(devices))} без привязки</div>
            </div>
          </div>
          <div class="person-devices">
            {''.join(device_row(d) for d in devices)}
          </div>
        </div>""")

    if not cards:
        cards.append('<div class="muted">Доступов нет</div>')

    return css + '<div class="people-list">' + "".join(cards) + "</div>"
# /vpn-access-people-groups-v1


def access_index_page(user=None):
    user = user or {}
    data = summary_for_user(user)
    items = data.get("access_items") or []

    rows = ""
    for item in items:
        name = safe_client_name(item.get("name") or item.get("client") or "")
        if not name:
            continue
        try:
            if not auth_client_allowed(user, name, "can_view"):
                continue
        except Exception:
            pass

        group = item.get("group") or item.get("group_name") or item.get("client_group") or "—"
        status = item.get("status_label") or item.get("status") or "доступ"
        online = "онлайн" if item.get("connected") else "не онлайн"
        last = item.get("last_seen_label") or item.get("last_seen_text") or item.get("last_success_text") or "—"

        rows += (
            "<tr>"
            f"<td><a href='/access?client={esc(name)}'>{esc(name)}</a></td>"
            f"<td>{esc(group)}</td>"
            f"<td>{esc(status)}</td>"
            f"<td>{esc(online)}</td>"
            f"<td>{esc(last)}</td>"
            "</tr>"
        )

    if not rows:
        rows = '<tr><td colspan="5" class="muted">Доступов нет</td></tr>'

    cards = access_people_cards_html(items, user)
    problem_cards = access_problem_cards_html()
    problem_summary = problem_cards.split('<div class="access-problem-list"', 1)[0] if '<div class="access-problem-list"' in problem_cards else problem_cards
    problem_list = ('<div class="access-problem-list"' + problem_cards.split('<div class="access-problem-list"', 1)[1]) if '<div class="access-problem-list"' in problem_cards else ""

    # vpn-access-problems-ok-compact-v1
    problem_is_ok = ("ok-state" in problem_cards) or ("Проблемных устройств нет" in problem_cards)
    problem_title = "Проверка доступов" if problem_is_ok else "Нужна проверка"
    problem_intro = "Дубли, старые профили и подозрительные подключения проверены." if problem_is_ok else "Возможные дубли, старые профили или один конфиг на нескольких устройствах."
    if problem_is_ok:
        problem_details = ""
    else:
        problem_details = f"""
  <details class="access-problem-details">
    <summary>Показать устройства</summary>
    {problem_list}
  </details>"""

    body = f"""
<section class="card access-problems-card {'is-ok' if problem_is_ok else 'has-problems'}" id="devices">
  <div class="problem-head">
    <div>
      <h2>{problem_title}</h2>
      <p class="muted">{problem_intro}</p>
    </div>
    {problem_summary}
  </div>
  <div class="problem-table-wrap">
    <table>
      <thead><tr><th>Тип</th><th>Доступ</th><th>Что проверить</th></tr></thead>
      <tbody>{access_device_rows_html()}</tbody>
    </table>
  </div>
  {problem_details}
</section>

<section class="card access-all-card">
  <div class="section-head access-all-head"><h2>Все доступы</h2><a class="btn primary" href="/create-access">Создать доступ</a></div>
  <div class="access-list">
    {cards}
  </div>
</section>
"""
    return _vpn_access_catalog_only_html_v1(
        support_shell_page("Доступы", body, "Профили и устройства")
    )


# vpn-access-catalog-only-v1
def _vpn_access_remove_section_containing_v1(html, needle):
    try:
        idx = html.find(needle)
        if idx < 0:
            return html

        start = html.rfind("<section", 0, idx)
        end = html.find("</section>", idx)
        if start >= 0 and end >= 0:
            end += len("</section>")
            return html[:start] + "\n" + html[end:]

        return html
    except Exception as e:
        print(f"access_remove_section_v1_error={e!r}", flush=True)
        return html

def _vpn_access_catalog_only_html_v1(html):
    # Раздел "Доступы" — это каталог профилей.
    # Проверки и поводы для внимания живут на главной.
    for needle in ("Проверка доступов", "Нужна проверка"):
        html = _vpn_access_remove_section_containing_v1(html, needle)
    return html

# /vpn-access-catalog-only-v1

# /vpn-access-index-simple-v1



# vpn-home-shell-v1
def home_overview_page(user=None):
    import json as _json

    user = user or {}
    data = summary_for_user(user)
    items = data.get("access_items") or []

    access_count = data.get("access_count") or data.get("total_accesses") or len(items)
    online_count = data.get("online_count") or data.get("connected_count") or 0
    if not online_count:
        try:
            online_count = sum(1 for x in items if x.get("connected"))
        except Exception:
            online_count = 0

    sd = support_dashboard_data() or {}
    status = sd.get("status") or "unknown"
    status_cls = support_status_class(status)
    status_label = support_status_label(status)

    services = sd.get("services") or {}
    service_pairs = (
        (PANEL_SERVICE_NAME, "panel"),
        ("caddy", "caddy"),
        ("ipsec", "ipsec"),
        ("xl2tpd", "xl2tpd"),
    )
    service_bad = []
    chips = ""
    for key, label in service_pairs:
        val = services.get(key, "unknown")
        ok = val == "active"
        if not ok:
            service_bad.append(f"{label}: {val}")
        chip_label = label if ok else f"{label} {val}"
        chips += f'<span class="home-chip {"ok" if ok else "bad"}">{esc(chip_label)}</span>'

    watch = support_read_file(SUPPORT_STATUS_DIR, "device-watch.txt", "")
    try:
        old = [x for x in _vpn_support_section(watch, "===== REVOKED / OLD PROFILE ATTEMPTS =====") if ": fails=" in x]
    except Exception:
        old = []
    try:
        suspicious = [x for x in _vpn_support_section(watch, "===== SUSPICIOUS ROAMING / POSSIBLE MULTI-DEVICE =====") if ": ok_connects=" in x]
    except Exception:
        suspicious = []

    old_count = len(old)
    suspicious_count = sd.get("possible_multi_device_clients_2h") or len(suspicious)
    # vpn-home-auth-kpi-single-source-v1
    # Единый источник правды для верхней KPI-цифры: dashboard.json -> auth_fail_count_30m.
    # Старые ключи оставлены только как fallback.
    auth_fail = sd.get("auth_fail_count_30m")
    if auth_fail is None:
        auth_fail = sd.get("auth_fail_30m") or sd.get("auth_fail_30m_count") or sd.get("auth_failures_30m") or 0
    # /vpn-home-auth-kpi-single-source-v1
    try:
        auth_fail_int = int(auth_fail or 0)
    except Exception:
        auth_fail_int = 0

    checks = ""
    if old:
        for line in old[:3]:
            client = safe_client_name(line.split(":", 1)[0].strip())
            if client:
                checks += f"""
  <a class="home-check-row warn" href="/access?client={esc(client)}">
    <span class="pill warn">старый профиль</span>
    <strong>{esc(client)}</strong>
    <span class="muted">удалить старый профиль на устройстве</span>
  </a>"""
    if suspicious_count:
        checks += f"""
  <a class="home-check-row warn" href="/access#devices">
    <span class="pill warn">проверить</span>
    <strong>Возможные дубли</strong>
    <span class="muted">{esc(suspicious_count)} за последнее окно</span>
  </a>"""
    if auth_fail_int:
        checks += f"""
  <div class="home-check-row warn">
    <span class="pill warn">вход</span>
    <strong>Ошибки входа</strong>
    <span class="muted">{esc(auth_fail_int)} за 30 минут</span>
  </div>"""
    if not checks:
        checks = """
  <div class="home-check-row ok">
    <span class="pill ok">OK</span>
    <strong>Всё спокойно</strong>
    <span class="muted">старых профилей и явных дублей сейчас не видно</span>
  </div>"""

    metrics = _json.loads(support_read_file(SUPPORT_STATUS_DIR, "channel-metrics.json", "{}"))
    day = metrics.get("day") or {}
    hour = metrics.get("hour") or {}

    def f(v):
        try:
            return float(v or 0)
        except Exception:
            return 0.0

    def fmt(v, digits=1):
        try:
            fv = float(v or 0)
            if fv.is_integer():
                return str(int(fv))
            return str(round(fv, digits))
        except Exception:
            return str(v)

    current = f(day.get("current_mbps") or hour.get("current_mbps"))
    cap = f(metrics.get("capacity_mbit") or 250)
    used_pct = max(0.0, min(100.0, current / cap * 100.0 if cap else 0.0))
    free = max(0.0, 100.0 - used_pct)
    peak = f(day.get("peak_mbps"))

    if free >= 50:
        channel_label, channel_cls, channel_text = "свободно", "ok", "Канал работает с хорошим запасом."
    elif free >= 20:
        channel_label, channel_cls, channel_text = "нагрузка", "warn", "Канал заметно загружен, но запас ещё есть."
    else:
        channel_label, channel_cls, channel_text = "плотно", "bad", "Канал близко к пределу, стоит посмотреть нагрузку."

    generated = sd.get("generated_at") or data.get("generated_at") or "—"

    create_btn = ""
    try:
        if auth_create_group_for_user(user):
            create_btn = '<a class="btn primary" href="/create-access">Создать доступ</a>'
    except Exception:
        pass

    try:
        attention_count = old_count + int(suspicious_count or 0) + auth_fail_int
    except Exception:
        attention_count = old_count + auth_fail_int

    attention_label = "всё спокойно" if attention_count == 0 else f"{attention_count} требует внимания"
    attention_cls = "ok" if attention_count == 0 else "warn"
    service_title = "Сервисы работают" if not service_bad else "Проверить сервисы"
    service_note = "panel · caddy · ipsec · xl2tpd активны" if not service_bad else "Есть сервисы не в active-состоянии"

    body = f"""
<style>
/* vpn-home-mobile-product-polish-v1 */
.home-summary-card{{padding:18px}}
.home-summary-head{{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:14px}}
.home-summary-head h2,.home-attention-card h2,.home-channel-card h2,.home-actions-card h2{{margin:0}}
.home-summary-note{{color:var(--muted);font-size:13px;margin-top:4px}}
.home-metric-grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}}
.home-metric{{border:1px solid rgba(255,255,255,.075);background:rgba(0,0,0,.12);border-radius:16px;padding:13px 14px;text-decoration:none;color:var(--text);min-width:0}}
.home-metric b{{display:block;font-size:34px;line-height:1;font-weight:950;letter-spacing:-.035em}}
.home-metric span{{display:block;color:var(--muted);font-size:13px;margin-top:7px;line-height:1.2}}
.home-metric small{{display:block;color:var(--muted);font-size:11px;margin-top:2px;opacity:.78}}
.home-service-card{{display:flex;justify-content:space-between;align-items:center;gap:14px}}
.home-service-card h2{{margin:0 0 6px}}
.home-service-note{{color:var(--muted);font-size:14px;line-height:1.35}}
.home-chip-list{{display:flex;gap:7px;flex-wrap:wrap;justify-content:flex-end}}
.home-chip{{display:inline-flex;align-items:center;min-height:30px;border-radius:999px;padding:0 10px;border:1px solid rgba(255,255,255,.10);font-size:12px;font-weight:900;color:var(--muted);background:rgba(255,255,255,.035)}}
.home-chip.ok{{color:var(--ok);border-color:rgba(66,211,146,.25);background:rgba(66,211,146,.075)}}
.home-chip.bad{{color:var(--bad);border-color:rgba(255,100,124,.24);background:rgba(255,100,124,.075)}}
.home-check-list{{display:grid;gap:8px;margin-top:12px}}
.home-check-row{{display:flex;align-items:center;justify-content:space-between;gap:10px;border:1px solid rgba(255,255,255,.075);background:rgba(0,0,0,.11);border-radius:15px;padding:11px 12px;text-decoration:none;color:var(--text)}}
.home-check-row strong{{font-size:14px;line-height:1.2}}
.home-check-row .muted{{font-size:12px;line-height:1.25;text-align:right}}
.home-check-row.ok{{border-color:rgba(66,211,146,.14);background:rgba(66,211,146,.045)}}
.home-check-row.warn{{border-color:rgba(255,191,105,.18);background:rgba(255,191,105,.05)}}
.home-channel-head{{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:8px}}
.home-channel-main{{font-size:42px;font-weight:950;letter-spacing:-.045em;line-height:1;margin-top:8px}}
.home-channel-sub{{color:var(--muted);font-size:14px;margin-top:6px}}
.home-channel-bar{{height:9px;border-radius:999px;background:rgba(255,255,255,.13);overflow:hidden;margin:13px 0 11px;border:1px solid rgba(255,255,255,.08)}}
.home-channel-bar span{{display:block;height:100%;width:var(--home-used,0%);max-width:100%;border-radius:999px;background:linear-gradient(90deg,rgba(95,178,255,.9),rgba(66,211,146,.9))}}
.home-mini-grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:12px}}
.home-mini{{border:1px solid rgba(255,255,255,.075);background:rgba(0,0,0,.10);border-radius:14px;padding:10px 11px}}
.home-mini b{{display:block;font-size:22px;line-height:1;font-weight:950}}
.home-mini span{{display:block;color:var(--muted);font-size:11px;margin-top:5px;line-height:1.2}}
.home-action-row{{display:flex;gap:9px;flex-wrap:wrap;margin-top:12px}}
@media(max-width:760px){{
  .shell-title h1{{font-size:34px;line-height:1}}
  .shell-subtitle{{font-size:16px;line-height:1.25}}
  .home-summary-card{{padding:15px}}
  .home-summary-head{{margin-bottom:12px}}
  .home-metric-grid{{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}}
  .home-metric{{border-radius:14px;padding:12px}}
  .home-metric b{{font-size:31px}}
  .home-metric span{{font-size:12px;margin-top:6px}}
  .home-service-card{{display:block}}
  .home-chip-list{{justify-content:flex-start;margin-top:11px}}
  .home-check-row{{align-items:flex-start}}
  .home-check-row .muted{{text-align:left}}
  .home-channel-main{{font-size:39px}}
  .home-mini-grid{{grid-template-columns:repeat(3,minmax(0,1fr));gap:7px}}
  .home-mini{{padding:9px}}
  .home-mini b{{font-size:19px}}
  .home-actions-card .btn{{min-height:34px;padding:0 11px;font-size:13px}}
}}
@media(max-width:420px){{
  .home-metric b{{font-size:29px}}
  .home-channel-main{{font-size:36px}}
  .home-mini-grid{{grid-template-columns:repeat(2,minmax(0,1fr))}}
}}

/* vpn-home-check-mobile-layout-fix-v1b */
.home-check-row.ok{{
  display:grid;
  grid-template-columns:auto 1fr;
  grid-template-areas:
    "badge title"
    "badge text";
  align-items:center;
  justify-content:start;
  column-gap:12px;
  row-gap:3px;
}}
.home-check-row.ok .pill{{grid-area:badge}}
.home-check-row.ok strong{{
  grid-area:title;
  white-space:nowrap;
  overflow:hidden;
  text-overflow:ellipsis;
  font-size:15px;
}}
.home-check-row.ok .muted{{
  grid-area:text;
  text-align:left;
}}
@media(max-width:760px){{
  .home-attention-card .home-channel-head{{
    align-items:center;
  }}
  .home-check-row.ok{{
    padding:11px 12px;
  }}
  .home-check-row.ok strong{{
    font-size:14px;
    line-height:1.15;
  }}
  .home-check-row.ok .muted{{
    font-size:12px;
    line-height:1.25;
  }}
}}
@media(max-width:420px){{
  .home-check-row.ok{{
    grid-template-columns:auto 1fr;
    column-gap:10px;
  }}
}}
/* /vpn-home-check-mobile-layout-fix-v1b */

/* /vpn-home-mobile-product-polish-v1 */
</style>

<section class="card home-summary-card">
  <div class="home-summary-head">
    <div>
      <h2>Сводка сейчас</h2>
      <div class="home-summary-note">обновлено: {esc(generated)}</div>
    </div>
    <span class="pill {status_cls}">{esc(status_label)}</span>
  </div>
  <div class="home-metric-grid">
    <a class="home-metric" href="/access"><b>{esc(access_count)}</b><span>доступов</span></a>
    <a class="home-metric" href="/access"><b>{esc(online_count)}</b><span>онлайн</span></a>
    <div class="home-metric"><b>{esc(old_count)}</b><span>старых профилей</span></div>
    <div class="home-metric"><b>{esc(auth_fail_int)}</b><span>ошибок входа</span><small>за 30 минут</small></div>
  </div>
</section>

<section class="card home-service-card">
  <div>
    <h2>{esc(service_title)}</h2>
    <div class="home-service-note">{esc(service_note)}</div>
  </div>
  <div class="home-chip-list">{chips}</div>
</section>

<section class="card home-attention-card">
  <div class="home-channel-head">
    <h2>Проверки</h2>
    <span class="pill {attention_cls}">{esc(attention_label)}</span>
  </div>
  <div class="home-check-list">{checks}</div>
</section>

<section class="card home-channel-card">
  <div class="home-channel-head">
    <h2>Канал</h2>
    <span class="pill {channel_cls}">{esc(channel_label)}</span>
  </div>
  <div class="home-channel-main">{esc(fmt(current))} Мбит/с</div>
  <div class="home-channel-sub">из {esc(fmt(cap))} Мбит/с · свободно {esc(fmt(free))}%</div>
  <div class="home-channel-bar" style="--home-used:{used_pct:.1f}%"><span></span></div>
  <p class="muted">{esc(channel_text)}</p>
  <div class="home-mini-grid">
    <div class="home-mini"><b>{esc(fmt(peak))}</b><span>пик сегодня</span></div>
    <div class="home-mini"><b>{esc(fmt(free))}%</b><span>запас</span></div>
    <div class="home-mini"><b>{esc(fmt(cap))}</b><span>канал Мбит/с</span></div>
  </div>
  <p><a class="btn" href="/channel">Открыть канал</a></p>
</section>

<section class="card home-actions-card">
  <h2>Быстрые действия</h2>
  <div class="home-action-row">
    <a class="btn" href="/access">Открыть доступы</a>
    {create_btn}
    <a class="btn" href="/instructions">Тексты для клиента</a>
  </div>
</section>
"""
    return _vpn_home_finalize_summary_v3(
        support_shell_page(APP_NAME, body, "Сводка по доступам и состоянию VPN")
    )


# vpn-home-summary-integrated-v3
def _vpn_home_read_device_watch_v3():
    try:
        return support_read_file(SUPPORT_STATUS_DIR, "device-watch.txt", "")
    except Exception:
        return ""

def _vpn_home_multi_ip_items_v3():
    text = _vpn_home_read_device_watch_v3()
    items = []
    in_block = False
    cur = None

    for raw in str(text or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        if line.startswith("===== ACTIVE SAME-CLIENT MULTI-IP"):
            in_block = True
            cur = None
            continue

        if in_block and line.startswith("====="):
            break

        if not in_block or line.startswith("OK:"):
            continue

        if "active_remote_ips=" in line and ":" in line:
            if cur:
                items.append(cur)
            client = line.split(":", 1)[0].strip()
            count = ""
            try:
                count = line.split("active_remote_ips=", 1)[1].split()[0].strip()
            except Exception:
                count = ""
            cur = {"client": client, "count": count, "ips": "", "providers": ""}
            continue

        if cur and line.startswith("ips:"):
            cur["ips"] = line.split(":", 1)[1].strip()
            continue

        if cur and line.startswith("providers:"):
            cur["providers"] = line.split(":", 1)[1].strip()
            continue

    if cur:
        items.append(cur)

    return items


# vpn-home-auth-fail-details-v1
# vpn-home-auth-fail-details-safe-v2
def _vpn_home_auth_fail_details_v1(limit=3):
    """
    Безопасная версия: не вытаскивает кандидатов из обычных successful-connects.
    Показывает только явные секции ошибок/старых профилей, иначе честно говорит,
    что деталей в текущем статусе нет.
    """
    try:
        import re as _re

        texts = []
        for filename in ("vpn-now.txt", "daily-report.txt", "device-watch.txt"):
            try:
                texts.append(support_read_file(SUPPORT_STATUS_DIR, filename, ""))
            except Exception:
                pass

        joined = "\n".join(str(x or "") for x in texts)
        if not joined.strip():
            return ""

        sections = []

        # Явные секции с ошибками. Специально НЕ берём successful connects и TOP NOISE.
        patterns = [
            r"===== AUTH(?:ORIZATION)? FAIL(?:S|URES)?[^\n]*=====\s*(.*?)(?:\n=====|\Z)",
            r"===== FAILED CONNECTS[^\n]*=====\s*(.*?)(?:\n=====|\Z)",
            r"===== AUTH FAILURES[^\n]*=====\s*(.*?)(?:\n=====|\Z)",
            r"===== OLD / REVOKED PROFILES =====\s*(.*?)(?:\n=====|\Z)",
            r"===== REVOKED / OLD PROFILE ATTEMPTS =====\s*(.*?)(?:\n=====|\Z)",
        ]

        for pat in patterns:
            for m in _re.finditer(pat, joined, _re.S | _re.I):
                block = m.group(1).strip()
                if block:
                    sections.append(block)

        if not sections:
            return ""

        bits = []
        seen = set()

        for block in sections:
            for raw in block.splitlines():
                line = raw.strip()
                if not line or line.startswith("OK:"):
                    continue

                low = line.lower()
                if "noise" in low or "successful" in low or "connects ---" in low:
                    continue

                # client в начале строки
                m = _re.match(r"^([A-Za-z0-9_.@:-][A-Za-z0-9_.@:-]{1,80})\b(.*)$", line)
                if not m:
                    continue

                client = m.group(1).strip()
                rest = m.group(2).strip()

                if client.lower() in ("generated_at", "window", "status", "ok"):
                    continue

                key = client.lower()
                if key in seen:
                    continue
                seen.add(key)

                count = ""
                cm = _re.search(r"(?:fails?|failures?|count)\s*=\s*(\d+)", rest, _re.I)
                if cm:
                    count = cm.group(1)

                ip = ""
                im = _re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", rest)
                if im:
                    ip = im.group(0)

                provider = ""
                if ip:
                    tail = rest.split(ip, 1)[1].strip()
                    provider = " ".join(tail.split()[:3]).strip()

                part = client
                if count:
                    part += f" ×{count}"

                extra = []
                if ip:
                    extra.append(f"IP {ip}")
                if provider:
                    extra.append(provider)

                if extra:
                    part += " · " + " · ".join(extra)

                bits.append(part)

                if len(bits) >= limit:
                    break

            if len(bits) >= limit:
                break

        if bits:
            return "Кого видно в секциях ошибок: " + "; ".join(bits) + "."

        return ""
    except Exception as e:
        print(f"home_auth_fail_details_safe_v2_error={e!r}", flush=True)
        return ""
# /vpn-home-auth-fail-details-safe-v2
# /vpn-home-auth-fail-details-v1

def _vpn_home_attention_items_v3(data):
    data = data or {}
    items = []

    services = data.get("services") or {}
    down = []
    for name, value in services.items():
        if str(value or "").strip() not in ("active", "ok"):
            down.append(f"{name}: {value}")
    if down:
        items.append({
            "level": "bad",
            "kind": "service",
            "title": "Сервис не работает",
            "text": "; ".join(down),
        })

    try:
        auth_fail = int(data.get("auth_fail_count_30m") or 0)
    except Exception:
        auth_fail = 0
    if auth_fail > 0:
        details = _vpn_home_auth_fail_details_v1()
        text = f"{auth_fail} ошибок авторизации за 30 минут."
        if details:
            text += " " + details
        else:
            text += " В текущем статусе нет списка конкретных профилей по этим ошибкам — нужно дописать сбор деталей auth fail в refresh-скрипте."
        items.append({
            "level": "bad",
            "kind": "auth",
            "title": f"Ошибки входа: {auth_fail}",
            "text": text,
        })

    try:
        old_profiles = int(data.get("old_profile_clients_2h") or 0)
    except Exception:
        old_profiles = 0
    if old_profiles > 0:
        items.append({
            "level": "bad",
            "kind": "old",
            "title": "Старые профили",
            "text": f"{old_profiles} старых или отозванных профилей пытались подключиться.",
        })

    for x in _vpn_home_multi_ip_items_v3()[:3]:
        client = x.get("client") or "—"
        count = x.get("count") or "несколько"
        providers = x.get("providers") or ""
        ips = x.get("ips") or ""
        tail = []
        if providers:
            tail.append(f"провайдеры: {providers}")
        if ips:
            tail.append(f"IP: {ips}")
        text = f"Профиль одновременно активен с {count} разных IP."
        if tail:
            text += " " + " · ".join(tail)
        items.append({
            "level": "warn",
            "kind": "access",
            "title": client,
            "text": text,
        })

    reasons = [str(x) for x in (data.get("reasons") or [])]
    if "pluto_cpu_high" in reasons:
        try:
            cpu = float(((data.get("pluto") or {}).get("cpu") or 0))
        except Exception:
            cpu = 0.0
        cpu_text = f"{cpu:.1f}% CPU" if cpu else "высокая нагрузка CPU"
        items.append({
            "level": "warn",
            "kind": "load",
            "title": "Нагрузка VPN-процесса",
            "text": f"IPsec/pluto использует {cpu_text}. VPN работает, но сервер занят.",
        })

    return items

def _vpn_home_level_label_v3(items):
    if any(x.get("level") == "bad" for x in items):
        return "bad", "Проблема"
    if items:
        kinds = {x.get("kind") for x in items}
        if kinds == {"load"}:
            return "warn", "Нагрузка"
        return "warn", "Внимание"
    return "ok", "OK"

def _vpn_home_summary_insert_html_v3(data, items):
    data = data or {}
    level, label = _vpn_home_level_label_v3(items)

    services = data.get("services") or {}
    service_names = [
        (PANEL_SERVICE_NAME, "panel"),
        (CADDY_SERVICE_NAME, "caddy"),
        (IPSEC_SERVICE_NAME, "ipsec"),
        (L2TP_SERVICE_NAME, "xl2tpd"),
    ]

    service_chips = ""
    for raw, short in service_names:
        value = str(services.get(raw) or "unknown").strip()
        cls = "ok" if value in ("active", "ok") else "bad"
        service_chips += f'<span class="summary-service-chip {esc(cls)}">{esc(short)}</span>'

    attention_html = ""
    if items:
        rows = ""
        for x in items[:4]:
            cls = x.get("level") or "warn"
            rows += f"""
            <div class="summary-attention-item {esc(cls)}">
              <strong>{esc(x.get("title") or "Проверить")}</strong>
              <span>{esc(x.get("text") or "")}</span>
            </div>
            """

        attention_html = f"""
        <div class="summary-attention-box {esc(level)}">
          <div class="summary-attention-head">
            <strong>Требует внимания</strong>
            <span>{esc(label)}</span>
          </div>
          <div class="summary-attention-list">
            {rows}
          </div>
        </div>
        """
    else:
        # vpn-home-ok-summary-compact-v1
        # Когда всё спокойно, не плодим большую зелёную карточку внутри сводки.
        # Достаточно верхнего OK-бейджа и строки сервисов.
        attention_html = ""
        # /vpn-home-ok-summary-compact-v1

    return f"""
<style>
/* vpn-home-summary-integrated-v3 */
.summary-attention-box{{
  margin-top:16px;
  border:1px solid rgba(148,163,184,.16);
  background:rgba(15,23,42,.38);
  border-radius:22px;
  padding:14px;
  display:grid;
  gap:12px;
}}
.summary-attention-box.ok{{
  border-color:rgba(52,211,153,.22);
  background:rgba(16,185,129,.06);
}}
.summary-attention-box.warn{{
  border-color:rgba(251,191,36,.28);
  background:rgba(251,191,36,.07);
}}
.summary-attention-box.bad{{
  border-color:rgba(255,100,124,.30);
  background:rgba(255,100,124,.07);
}}
.summary-attention-head{{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:10px;
}}
.summary-attention-head strong{{
  font-size:18px;
  line-height:1.1;
}}
.summary-attention-head span{{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:28px;
  padding:5px 10px;
  border-radius:999px;
  font-size:12px;
  font-weight:900;
  white-space:nowrap;
}}
.summary-attention-box.ok .summary-attention-head span{{
  color:#8ff0bd;
  background:rgba(52,211,153,.12);
  border:1px solid rgba(52,211,153,.25);
}}
.summary-attention-box.warn .summary-attention-head span{{
  color:#f8d77a;
  background:rgba(251,191,36,.12);
  border:1px solid rgba(251,191,36,.28);
}}
.summary-attention-box.bad .summary-attention-head span{{
  color:#ff9bad;
  background:rgba(255,100,124,.12);
  border:1px solid rgba(255,100,124,.28);
}}
.summary-attention-list{{
  display:grid;
  gap:8px;
}}
.summary-attention-item{{
  border:1px solid rgba(148,163,184,.13);
  background:rgba(2,6,23,.24);
  border-radius:16px;
  padding:11px 12px;
  display:grid;
  gap:3px;
}}
.summary-attention-item strong{{
  font-size:15px;
  line-height:1.18;
}}
.summary-attention-item span{{
  color:var(--muted);
  font-size:13px;
  line-height:1.32;
}}
.summary-attention-item.ok strong{{
  color:#48de95;
}}
.summary-attention-item.warn strong{{
  color:#ffc86b;
}}
.summary-attention-item.bad strong{{
  color:#ff7590;
}}
.summary-services-row{{
  margin-top:12px;
  display:grid;
  gap:8px;
}}
.summary-services-title{{
  color:var(--muted);
  font-size:13px;
  line-height:1.2;
}}
.summary-services-chips{{
  display:flex;
  flex-wrap:wrap;
  gap:7px;
}}
.summary-service-chip{{
  display:inline-flex;
  align-items:center;
  justify-content:center;
  min-height:28px;
  padding:4px 10px;
  border-radius:999px;
  font-size:13px;
  font-weight:900;
}}
.summary-service-chip.ok{{
  color:#48de95;
  background:rgba(52,211,153,.10);
  border:1px solid rgba(52,211,153,.22);
}}
.summary-service-chip.bad{{
  color:#ff7590;
  background:rgba(255,100,124,.10);
  border:1px solid rgba(255,100,124,.24);
}}
@media(max-width:760px){{
  .summary-attention-box{{
    margin-top:14px;
    border-radius:20px;
    padding:13px;
  }}
  .summary-attention-head strong{{
    font-size:17px;
  }}
}}
/* /vpn-home-summary-integrated-v3 */
</style>
<div class="summary-attention-integrated">
  {attention_html}
  <div class="summary-services-row">
    <div class="summary-services-title">Сервисы</div>
    <div class="summary-services-chips">{service_chips}</div>
  </div>
</div>
"""

def _vpn_home_remove_section_containing_v3(html, needle):
    idx = html.find(needle)
    if idx < 0:
        return html

    start = html.rfind("<section", 0, idx)
    end = html.find("</section>", idx)
    if start >= 0 and end >= 0:
        end += len("</section>")
        return html[:start] + "\n" + html[end:]

    return html

def _vpn_home_cleanup_v3(html):
    for needle in ("Что означает статус", "Проверки", "Сервисы работают", "Требует внимания"):
        html = _vpn_home_remove_section_containing_v3(html, needle)
    return html

def _vpn_home_set_main_badge_v3(html, level, label):
    import re as _re

    def repl(m):
        tag = m.group(1)
        cls = m.group(2)
        new_cls = _re.sub(r'\b(ok|bad|warn)\b', level, cls, count=1)
        tag = tag.replace(f'class="{cls}"', f'class="{new_cls}"', 1)
        return tag + esc(label) + "</span>"

    new_html, n = _re.subn(
        r'(<span\s+class="([^"]*\b(?:ok|bad|warn)\b[^"]*)"[^>]*>)\s*(?:Проблема|Нагрузка|Внимание|всё спокойно|OK|ok)\s*</span>',
        repl,
        html,
        count=1,
        flags=_re.S,
    )
    return new_html if n else html

def _vpn_home_insert_into_summary_v3(html, insert_html):
    idx = html.find("Сводка сейчас")
    if idx < 0:
        return html

    end = html.find("</section>", idx)
    if end < 0:
        return html

    return html[:end] + "\n" + insert_html + "\n" + html[end:]

def _vpn_home_finalize_summary_v3(html):
    try:
        data = support_dashboard_data()
        items = _vpn_home_attention_items_v3(data)
        level, label = _vpn_home_level_label_v3(items)

        html = _vpn_home_cleanup_v3(html)
        html = _vpn_home_set_main_badge_v3(html, level, label)
        html = _vpn_home_insert_into_summary_v3(html, _vpn_home_summary_insert_html_v3(data, items))
        return html
    except Exception as e:
        print(f"home_summary_integrated_v3_error={e!r}", flush=True)
        return html
# /vpn-home-summary-integrated-v3

# /vpn-home-mobile-product-polish-v1
# /vpn-home-shell-v1

def auth_db():
    return sqlite3.connect(DB_PATH)

def login_page(error="", selected=""):
    selected = str(selected or "")[:MAX_USERNAME_CHARS]
    error_html = f'<div class="loginError">{esc(error)}</div>' if error else ""
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Вход · {esc(APP_NAME)}</title>
<style>
:root {{
  color-scheme: dark;
  --bg:#070a10;
  --card:#111827;
  --text:#eef4ff;
  --muted:#8d9ab0;
  --line:#263247;
  --blue:#82aaff;
  --bad:#ff647c;
}}
* {{ box-sizing:border-box; }}
body {{
  margin:0;
  min-height:100vh;
  display:grid;
  place-items:center;
  padding:24px;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  background:
    radial-gradient(circle at 18% 0%, rgba(68,104,168,.32) 0, transparent 34%),
    linear-gradient(180deg,#080b12 0%,#070a10 100%);
  color:var(--text);
}}
.card {{
  width:min(430px,100%);
  background:linear-gradient(180deg,rgba(17,24,39,.96),rgba(10,15,24,.92));
  border:1px solid rgba(255,255,255,.09);
  border-radius:28px;
  padding:24px;
  box-shadow:0 24px 80px rgba(0,0,0,.28);
}}
.kicker {{
  color:var(--blue);
  font-size:12px;
  font-weight:900;
  letter-spacing:.12em;
  text-transform:uppercase;
  margin-bottom:8px;
}}
h1 {{ margin:0; font-size:34px; letter-spacing:-.055em; }}
p {{ margin:8px 0 18px; color:var(--muted); line-height:1.45; }}
label {{ display:block; margin:14px 0 7px; color:var(--muted); font-size:13px; font-weight:800; }}
input {{
  width:100%;
  border:1px solid var(--line);
  background:#0b1220;
  color:var(--text);
  border-radius:14px;
  padding:12px 13px;
  font-size:16px;
  outline:none;
}}
input:focus {{ border-color:rgba(130,170,255,.8); }}
button {{
  width:100%;
  margin-top:18px;
  border:0;
  border-radius:15px;
  padding:12px 14px;
  font-size:15px;
  font-weight:900;
  color:#07101f;
  background:linear-gradient(180deg,#eef4ff,#b8c9ff);
}}
.loginError {{
  margin:12px 0;
  color:#ffd0d7;
  background:rgba(255,100,124,.10);
  border:1px solid rgba(255,100,124,.24);
  border-radius:14px;
  padding:10px 12px;
  font-size:14px;
}}
</style>
</head>
<body>
  <main class="card">
    <div class="kicker">VPN Control Panel</div>
    <h1>{esc(APP_NAME)}</h1>
    <p>Введи имя пользователя и пароль.</p>
    {error_html}
    <form method="post" action="/login">
      <label>Имя пользователя</label>
      <input name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="{MAX_USERNAME_CHARS}" value="{esc(selected)}" required>
      <label>Пароль</label>
      <input name="password" type="password" autocomplete="current-password" maxlength="{MAX_PASSWORD_CHARS}" required>
      <button type="submit">Войти</button>
    </form>
  </main>
</body>
</html>"""

def create_auth_session(username):
    conn = auth_db()
    try:
        return create_session_record(
            conn,
            username,
            now=int(time.time()),
            ttl=AUTH_SESSION_TTL,
            session_id_factory=lambda: secrets.token_urlsafe(32),
        )
    finally:
        conn.close()

def delete_auth_session(session_id):
    if not session_id:
        return
    conn = None
    try:
        conn = auth_db()
        delete_session_record(conn, session_id)
    except Exception:
        pass
    finally:
        if conn is not None:
            conn.close()

def check_login(username, password):
    username = str(username or "").strip()
    password = str(password or "")
    if not login_inputs_are_valid(username, password):
        return False

    conn = None
    try:
        conn = auth_db()
        row = conn.execute(
            "select password_hash from panel_users where username=? and is_enabled=1",
            (username,),
        ).fetchone()
        if not row:
            return False
        return verify_password(password, row[0])
    except Exception:
        return False
    finally:
        if conn is not None:
            conn.close()

def send_html_raw(handler, html, status=200, headers=None):
    body = html.encode("utf-8")
    headers = list(headers or [])
    handler.send_response(status)
    handler.send_header("Content-Type", "text/html; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    send_security_headers(handler, existing_names=[name for name, _value in headers])
    for name, value in headers:
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(body)

def redirect_raw(handler, location, headers=None):
    headers = list(headers or [])
    handler.send_response(303)
    handler.send_header("Location", location)
    send_security_headers(handler, existing_names=[name for name, _value in headers])
    for name, value in headers:
        handler.send_header(name, value)
    handler.end_headers()



def current_auth_user(handler):
    sid = get_cookie_session_id(handler.headers)
    if not sid:
        return None

    conn = None
    try:
        conn = auth_db()
        return resolve_session_record(conn, sid, now=int(time.time()))
    except Exception as e:
        print(f"auth_current_user_error={e!r}", flush=True)
        return None
    finally:
        if conn is not None:
            conn.close()


def auth_client_group(client):
    client = safe_client_name(client)
    if not client:
        return ""
    return auth_client_groups([client]).get(client, DEFAULT_ACCESS_GROUP)

def auth_client_allowed(user, client, perm="can_view"):
    return owner_only_client_allowed(user, client, perm)

def auth_create_group_for_user(user):
    if auth_is_owner(user):
        return DEFAULT_ACCESS_GROUP
    allowed = auth_allowed_groups(user, "can_create") or set()
    if not allowed:
        return ""
    if len(allowed) == 1:
        return next(iter(allowed))
    return sorted(allowed)[0]

def auth_set_client_meta(client, group_name, user):
    client = safe_client_name(client)
    group_name = group_name or DEFAULT_ACCESS_GROUP
    username = (user or {}).get("username") or ""
    if not client:
        return
    now = int(time.time())
    try:
        conn = auth_db()
        conn.execute(
            """
            insert into vpn_client_meta(client, group_name, created_by, created_at, comment, updated_at)
            values(?,?,?,?,?,?)
            on conflict(client) do update set
              group_name=excluded.group_name,
              updated_at=excluded.updated_at
            """,
            (client, group_name, username, now, "", now),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"auth_set_client_meta_error={e!r}", flush=True)

def auth_delete_client_meta(client):
    client = safe_client_name(client)
    if not client:
        return
    try:
        conn = auth_db()
        conn.execute("delete from vpn_client_meta where client=?", (client,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"auth_delete_client_meta_error={e!r}", flush=True)






# support-pack-panel-v1
SUPPORT_STATUS_DIR = str(CONFIG.status_dir)
SUPPORT_INSTRUCTIONS_DIR = str(CONFIG.instructions_dir)

SUPPORT_INSTRUCTION_FILES = [
    ("common", "00-common.txt", "Общее правило"),
    ("iphone", "iphone-ipad.txt", "iPhone / iPad"),
    ("macos", "macos.txt", "macOS"),
    ("android", "android.txt", "Android"),
    ("windows", "windows.txt", "Windows"),
    ("message", "message-template.txt", "Сообщение пользователю"),
]

def support_read_file(base, filename, fallback="Файл пока не сформирован."):
    try:
        import os as _os
        filename = str(filename or "")
        if "/" in filename or "\\" in filename or filename.startswith("."):
            return fallback
        path = _os.path.join(base, filename)
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception as e:
        return fallback + "\n\nerror=" + repr(e) + "\n"

def support_dashboard_data():
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

def support_status_label(status):
    if status == "ok":
        return "OK"
    if status == "warn":
        return "Внимание"
    if status == "bad":
        return "Проблема"
    return status or "unknown"

def support_status_class(status):
    if status == "ok":
        return "ok"
    if status == "bad":
        return "bad"
    if status == "warn":
        return "warn"
    return "neutral"


# vpn-unified-support-header-v1
def vpn_support_active_key(title):
    t = str(title or "").lower()
    if "доступ" in t:
        return "access"
    if "канал" in t:
        return "channel"
    if "устрой" in t:
        return "access"
    if "отч" in t or "ежеднев" in t:
        return "report"
    if "инструк" in t:
        return "instructions"
    return "home"

def vpn_support_current_user_label():
    import os

    user = request_current_user()
    if isinstance(user, dict):
        display = str(user.get("display_name") or user.get("username") or "").strip()
        role = str(user.get("role") or "").strip()
        if display and role:
            return f"{display} · {role}"
        if display:
            return display

    for name in (
        "APP_AUTH_USER",
        "APP_USER",
        "AUTH_USER",
        "ADMIN_USER",
        "PANEL_USER",
        "VPN_PANEL_USER",
        "VPN_VPN_USER",
        "VPN_VPN_PANEL_USER",
        "USERNAME",
    ):
        v = globals().get(name) or os.environ.get(name)
        if v:
            return str(v)

    return "пользователь"


def vpn_support_header_html(title, subtitle=""):
    active = vpn_support_active_key(title)
    user_label = vpn_support_current_user_label()

    items = [
        ("/", "Главная", "home"),
        ("/access", "Доступы", "access"),
        ("/channel", "Канал", "channel"),
    ]

    links = []
    for href, label, key in items:
        cls = "shell-link active" if key == active else "shell-link"
        links.append(f'<a class="{cls}" href="{href}">{esc(label)}</a>')

    sub = f'<div class="shell-subtitle">{esc(subtitle)}</div>' if subtitle else ""

    return f"""
<header class="shell-head">
  <div class="shell-topline">
    <div class="shell-kicker">{esc(APP_NAME)}</div>
    <div class="shell-user">
      <span class="shell-user-name">{esc(user_label)}</span>
      <form class="shell-logout-form" method="post" action="/logout">
        <button class="shell-logout-button" type="submit">Выйти</button>
      </form>
    </div>
  </div>
  <nav class="shell-nav">
    {''.join(links)}
  </nav>
  <div class="shell-title">
    <h1>{esc(title)}</h1>
    {sub}
  </div>
</header>
"""
# /vpn-unified-support-header-v1


# vpn-support-shell-css-single-source-v1
def support_shell_css():
    return """\
:root {
  color-scheme: dark;
  --bg: #07101f;
  --bg2: #0b1424;
  --card: #111827;
  --card2: #182235;
  --line: rgba(255,255,255,.10);
  --text: #eef4ff;
  --muted: #8d9ab0;
  --ok: #42d392;
  --warn: #ffbf69;
  --bad: #ff647c;
  --blue: #65a8ff;
}

* { box-sizing: border-box; }


/* vpn-unified-support-header-css-v1 */
.shell-head {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 16px;
  align-items: start;
  margin-bottom: 18px;
}

.shell-title h1 {
  margin: 0;
  font-size: 40px;
  line-height: .98;
  letter-spacing: -.055em;
}

.shell-kicker {
  margin-bottom: 7px;
  color: var(--blue);
  font-size: 13px;
  font-weight: 950;
  letter-spacing: .08em;
  text-transform: uppercase;
}

.shell-subtitle {
  margin-top: 10px;
  color: var(--muted);
  font-size: 18px;
  line-height: 1.25;
}

.shell-user {
  display: flex;
  gap: 8px;
  align-items: center;
  justify-content: flex-end;
  color: var(--muted);
  font-size: 13px;
  font-weight: 800;
  white-space: nowrap;
}


/* vpn-support-header-user-label-css-v1 */
.shell-user-name {
  display: inline-flex;
  align-items: center;
  min-height: 32px;
  padding: 0 10px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,.08);
  background: rgba(255,255,255,.035);
  color: var(--muted);
  font-weight: 900;
}
/* /vpn-support-header-user-label-css-v1 */

.shell-logout-form {
  margin: 0;
}

.shell-user a,
.shell-logout-button {
  display: inline-flex;
  align-items: center;
  min-height: 32px;
  padding: 0 11px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: rgba(255,255,255,.055);
  color: var(--text);
  text-decoration: none;
  font: inherit;
  cursor: pointer;
}

.shell-nav {
  grid-column: 1 / -1;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.shell-link {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 38px;
  padding: 0 13px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: rgba(255,255,255,.055);
  color: var(--text);
  text-decoration: none;
  font-weight: 850;
}

.shell-link.active {
  background: rgba(101,168,255,.18);
  border-color: rgba(101,168,255,.38);
}

@media(max-width:760px) {
  .shell-head {
    display: block;
  }

  .shell-title h1 {
    font-size: 38px;
  }

  .shell-user {
    margin-top: 12px;
    justify-content: flex-start;
  }

  .shell-nav {
    margin-top: 14px;
  }
}

@media(max-width:420px) {
  .shell-title h1 {
    font-size: 36px;
  }

  .shell-subtitle {
    font-size: 17px;
  }

  .shell-link {
    min-height: 34px;
    padding: 0 11px;
    font-size: 14px;
  }
}

/* vpn-shell-menu-polish-v1 */
.shell-nav {
  width: fit-content;
  max-width: 100%;
  padding: 5px;
  border: 1px solid rgba(255,255,255,.09);
  border-radius: 999px;
  background: rgba(3,7,17,.34);
  box-shadow: inset 0 1px 0 rgba(255,255,255,.04);
}

.shell-link {
  min-height: 34px;
  padding: 0 13px;
  border: 0;
  background: transparent;
  color: var(--muted);
  font-size: 14px;
  font-weight: 900;
}

.shell-link.active {
  color: var(--text);
  background: rgba(101,168,255,.22);
  box-shadow: 0 0 0 1px rgba(101,168,255,.28);
}

@media(max-width:520px) {
  .shell-nav {
    width: 100%;
    border-radius: 20px;
  }
  .shell-link {
    flex: 1 1 auto;
    min-width: calc(50% - 4px);
  }
}

/* vpn-shell-menu-mobile-scroll-v1 */
@media(max-width:520px) {
  .shell-nav {
    display: flex;
    flex-wrap: nowrap;
    overflow-x: auto;
    gap: 5px;
    width: 100%;
    padding: 5px;
    border-radius: 999px;
    -webkit-overflow-scrolling: touch;
    scrollbar-width: none;
  }
  .shell-nav::-webkit-scrollbar { display: none; }
  .shell-link {
    flex: 0 0 auto;
    min-width: 0;
    padding: 0 14px;
    white-space: nowrap;
  }
}
/* /vpn-shell-menu-mobile-scroll-v1 */

/* vpn-shell-menu-mobile-fit4-v1 */
@media(max-width:520px) {
  .shell-nav {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    overflow: visible;
    gap: 4px;
    width: 100%;
    border-radius: 22px;
  }
  .shell-link {
    min-width: 0;
    width: 100%;
    padding: 0 4px;
    font-size: 13px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
}
/* /vpn-shell-menu-mobile-fit4-v1 */


/* /vpn-shell-menu-polish-v1 */


/* vpn-header-order-v1 */
.shell-head { display:block; }
.shell-topline {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  flex-wrap:wrap;
  margin-bottom:12px;
}
.shell-nav { margin:0 0 18px; }
.shell-title { margin-top:0; }
@media(max-width:760px) {
  .shell-user { margin-top:0; justify-content:flex-end; }
  .shell-nav { margin-top:0; margin-bottom:18px; }
}

/* vpn-home-check-card-css-v1 */
.home-check-list {
  display: grid;
  gap: 10px;
  margin-top: 12px;
}
.home-check-row {
  display: grid;
  gap: 8px;
  padding: 14px;
  border: 1px solid rgba(148,163,184,.18);
  border-radius: 18px;
  background: rgba(15,23,42,.45);
  color: inherit;
  text-decoration: none;
}
.home-check-row strong {
  font-size: 20px;
  overflow-wrap: anywhere;
}
.home-check-row .pill {
  width: fit-content;
}

/* vpn-section-head-css-v1 */
.section-head {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  flex-wrap:wrap;
  margin-bottom:16px;
}
.section-head h2 { margin:0; }

/* vpn-access-device-cards-css-v1 */
.access-device-list {
  display:grid;
  gap:12px;
  margin-top:16px;
}
.access-device-card {
  display:grid;
  gap:8px;
  padding:16px;
  border:1px solid rgba(148,163,184,.18);
  border-radius:20px;
  background:rgba(15,23,42,.45);
}
.access-device-card .device-access {
  font-size:20px;
  font-weight:800;
  overflow-wrap:anywhere;
}
.access-device-card .device-action {
  color:#9aa8bd;
  font-size:16px;
  line-height:1.35;
}
.access-device-card .pill {
  width:fit-content;
}
/* /vpn-access-device-cards-css-v1 */


/* vpn-access-problem-table-mobile-v1 */
@media(max-width:760px) {
  .card .tablewrap table {
    font-size:15px;
  }
  .card .tablewrap th {
    font-size:11px;
  }
  .card .tablewrap td {
    vertical-align:top;
  }
  .card .tablewrap td:nth-child(1) {
    width:1%;
    white-space:nowrap;
  }
  .card .tablewrap td:nth-child(2) {
    word-break:break-word;
  }
}
/* /vpn-access-problem-table-mobile-v1 */


/* vpn-access-mobile-density-and-problems-v1 */
.access-problems-card { overflow:hidden; }
.problem-head { display:flex; justify-content:space-between; gap:14px; align-items:flex-start; margin-bottom:12px; }
.problem-head h2 { margin-bottom:8px; }
.access-problem-summary { flex:0 0 auto; align-self:flex-start; border:1px solid rgba(255,191,105,.26); background:rgba(255,191,105,.075); color:var(--warn); border-radius:999px; padding:8px 11px; font-size:12px; font-weight:950; white-space:nowrap; }
.access-problem-summary.ok-state { color:var(--ok); border-color:rgba(66,211,146,.25); background:rgba(66,211,146,.08); }
.access-problem-list { display:none; }
.access-problem-row { color:var(--text); text-decoration:none; border:1px solid rgba(255,255,255,.075); background:rgba(0,0,0,.11); border-radius:15px; padding:11px 12px; display:flex; align-items:center; justify-content:space-between; gap:12px; }
.access-problem-row.warn { border-color:rgba(255,191,105,.18); }
.access-problem-row.bad { border-color:rgba(255,100,124,.22); }
.access-problem-row.ok-row { border-color:rgba(66,211,146,.18); }
.access-problem-main { min-width:0; }
.access-problem-main strong { display:block; font-size:14px; line-height:1.2; overflow-wrap:anywhere; }
.access-problem-main span { display:block; margin-top:4px; color:var(--muted); font-size:12px; line-height:1.3; }
@media(max-width:760px) {
  .wrap { padding:20px 15px 38px; }
  .shell-head { margin-bottom:14px; }
  .shell-topline { margin-bottom:10px; gap:10px; }
  .shell-kicker { font-size:12px; letter-spacing:.075em; }
  .shell-user { gap:7px; }
  .shell-user-name, .shell-user a { min-height:30px; padding:0 10px; }
  .shell-nav { margin-bottom:14px; }
  .shell-title h1 { font-size:34px; line-height:1; }
  .shell-subtitle { margin-top:7px; font-size:16px; line-height:1.22; }
  .card { border-radius:22px; padding:15px; margin:12px 0; }
  .access-problems-card h2 { font-size:24px; margin-bottom:6px; }
  .access-problems-card .muted { font-size:15px; line-height:1.34; margin:0; }
  .problem-head { display:block; margin-bottom:0; }
  .problem-head .access-problem-summary { display:inline-flex; margin-top:11px; }
  .problem-table-wrap { display:none; }
  .access-problem-list { display:grid; gap:8px; margin-top:10px; }
  .access-problem-row .pill { padding:5px 8px; font-size:11px; }
  .access-all-head { align-items:center; margin-bottom:12px; }
  .access-all-head h2 { font-size:25px; }
  .access-all-head .btn { min-height:34px; padding:0 11px; font-size:13px; }
  .access-all-card .people-list { gap:10px; }
  .access-all-card .person-card { border-radius:17px; padding:11px; }
  .access-all-card .person-head { margin-bottom:8px; }
  .access-all-card .person-title { font-size:15px; }
  .access-all-card .person-sub { font-size:12px; }
  .access-all-card .person-devices { gap:7px; }
  .access-all-card .person-device { padding:9px 10px; border-radius:13px; }
  .access-all-card .person-device strong { font-size:13px; }
  .access-all-card .person-device-client { font-size:10px; }
  .access-all-card .person-device-meta { font-size:11px; }
}
@media(max-width:420px) {
  .wrap { padding:18px 14px 34px; }
  .shell-title h1 { font-size:32px; }
  .shell-subtitle { font-size:15px; }
  .access-problems-card h2 { font-size:23px; }
  .access-all-head h2 { font-size:24px; }
  .access-problem-row { padding:10px 11px; }
}
/* /vpn-access-mobile-density-and-problems-v1 */


/* vpn-access-problems-mobile-quiet-v1 */
.access-problem-details { display:none; }
.access-problem-details summary {
  cursor:pointer;
  user-select:none;
  list-style:none;
}
.access-problem-details summary::-webkit-details-marker { display:none; }
@media(max-width:760px) {
  .access-problems-card {
    padding:14px 15px !important;
  }
  .access-problems-card h2 {
    font-size:22px !important;
    margin-bottom:5px !important;
  }
  .access-problems-card .muted {
    font-size:13px !important;
    line-height:1.28 !important;
    opacity:.78;
  }
  .problem-head .access-problem-summary {
    margin-top:9px !important;
    padding:7px 10px !important;
    font-size:12px !important;
  }
  .access-problem-details {
    display:block;
    margin-top:10px;
  }
  .access-problem-details summary {
    display:inline-flex;
    align-items:center;
    min-height:32px;
    border:1px solid rgba(255,255,255,.10);
    background:rgba(255,255,255,.035);
    border-radius:999px;
    padding:0 11px;
    color:var(--muted);
    font-size:12px;
    font-weight:850;
  }
  .access-problem-details[open] summary {
    margin-bottom:9px;
    color:var(--text);
    border-color:rgba(255,191,105,.25);
    background:rgba(255,191,105,.07);
  }
  .access-problem-details:not([open]) .access-problem-list {
    display:none !important;
  }
  .access-problem-details[open] .access-problem-list {
    display:grid !important;
  }
}
@media(max-width:420px) {
  .access-problems-card h2 {
    font-size:21px !important;
  }
}
/* /vpn-access-problems-mobile-quiet-v1 */\n
/* vpn-access-problem-real-clients-only-v1 */

/* vpn-access-problems-ok-compact-v1 */
.access-problems-card.is-ok .problem-table-wrap,
.access-problems-card.is-ok .access-problem-details,
.access-problems-card.is-ok .access-problem-list {
  display:none !important;
}
.access-problems-card.is-ok {
  border-color:rgba(66,211,146,.13);
}
@media(max-width:760px) {
  .access-problems-card.is-ok {
    padding:13px 15px !important;
  }
  .access-problems-card.is-ok .problem-head {
    margin-bottom:0 !important;
  }
  .access-problems-card.is-ok h2 {
    font-size:21px !important;
  }
  .access-problems-card.is-ok .muted {
    max-width:95%;
  }
  .access-problems-card.is-ok .problem-head .access-problem-summary {
    margin-top:9px !important;
  }
}
/* /vpn-access-problems-ok-compact-v1 */






/* /vpn-section-head-css-v1 */

/* /vpn-home-check-card-css-v1 */

/* /vpn-header-order-v1 */

/* /vpn-unified-support-header-css-v1 */

body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle at 50% -12%, rgba(55,112,210,.26), transparent 42%),
    linear-gradient(180deg, var(--bg2), var(--bg) 54%, #04070d);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}

.wrap {
  width: min(100%, 1180px);
  margin: 0 auto;
  padding: 24px 18px 42px;
}

.top {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
  margin-bottom: 18px;
}

h1 {
  margin: 0;
  font-size: 40px;
  line-height: .98;
  letter-spacing: -.055em;
}

h2 {
  margin: 0 0 12px;
  font-size: 28px;
  line-height: 1.05;
  letter-spacing: -.045em;
}

a { color: #dce7ff; }

.nav {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  justify-content: flex-end;
}

.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 38px;
  padding: 0 13px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: rgba(255,255,255,.055);
  color: var(--text);
  text-decoration: none;
  font-weight: 850;
}

.btn.primary {
  background: rgba(101,168,255,.18);
  border-color: rgba(101,168,255,.36);
  color: var(--text);
}

.card {
  background: linear-gradient(180deg, rgba(17,24,39,.94), rgba(10,16,28,.92));
  border: 1px solid var(--line);
  border-radius: 24px;
  padding: 18px;
  margin: 14px 0;
  overflow: auto;
}

.grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.stat {
  background: rgba(255,255,255,.045);
  border: 1px solid var(--line);
  border-radius: 20px;
  padding: 16px;
}

.num {
  color: var(--text);
  font-size: 30px;
  font-weight: 900;
  letter-spacing: -.04em;
}

.label, .muted {
  color: var(--muted);
}

.pill {
  display: inline-flex;
  align-items: center;
  border-radius: 999px;
  padding: 6px 10px;
  border: 1px solid var(--line);
  font-size: 12px;
  font-weight: 900;
  white-space: nowrap;
}

.ok { color: var(--ok); border-color: rgba(66,211,146,.35); background: rgba(66,211,146,.10); }
.warn { color: var(--warn); border-color: rgba(255,191,105,.38); background: rgba(255,191,105,.10); }
.bad { color: var(--bad); border-color: rgba(255,100,124,.38); background: rgba(255,100,124,.10); }
.neutral { color: #d6deee; background: rgba(255,255,255,.06); }

pre {
  white-space: pre-wrap;
  word-break: break-word;
  margin: 0;
  font-size: 13px;
  line-height: 1.45;
  color: #e8eefb;
}

table {
  width: 100%;
  border-collapse: collapse;
  min-width: 560px;
}

td, th {
  text-align: left;
  border-bottom: 1px solid var(--line);
  padding: 10px 8px;
  color: var(--text);
}

th {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: .04em;
}


/* vpn-access-list-cards-css-v1 */
.access-list { display:grid; gap:10px; }
.access-card {
  display:grid;
  grid-template-columns:12px minmax(0,1fr) auto 18px;
  gap:12px;
  align-items:center;
  padding:14px;
  border-radius:18px;
  border:1px solid var(--line);
  background:rgba(255,255,255,.045);
  color:var(--text);
  text-decoration:none;
}
.access-card:hover { background:rgba(255,255,255,.065); text-decoration:none; }
.status-dot { width:10px; height:10px; border-radius:999px; background:var(--muted); }
.access-card.is-online .status-dot { background:var(--ok); box-shadow:0 0 0 5px rgba(66,211,146,.10); }
.access-card.has-problem { border-color:rgba(255,191,105,.34); }
.access-main b { display:block; color:var(--text); font-size:16px; line-height:1.1; }
.access-main em { display:block; margin-top:4px; color:var(--muted); font-size:13px; font-style:normal; line-height:1.25; }
.access-right { text-align:right; }
.speed { color:var(--text); font-size:20px; font-weight:950; letter-spacing:-.04em; }
.speed.hot { color:var(--warn); }
.offline-status { color:var(--muted); font-weight:900; }
.access-meta { margin-top:4px; color:var(--muted); font-size:12px; }
.chev { color:var(--muted); font-size:26px; line-height:1; }
@media(max-width:520px) {
  .access-card { grid-template-columns:12px minmax(0,1fr) 18px; }
  .access-right { grid-column:2 / 3; text-align:left; margin-top:6px; }
}
/* /vpn-access-list-cards-css-v1 */

/* vpn-support-channel-css-v1 */
.channel-page .card { overflow: hidden; }

.channel-hero {
  padding: 22px;
  border-radius: 28px;
  background:
    radial-gradient(circle at 0% 0%, rgba(101,168,255,.18), transparent 46%),
    linear-gradient(180deg, rgba(255,255,255,.075), rgba(255,255,255,.035));
  border: 1px solid rgba(255,255,255,.10);
}

.channel-hero-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.channel-badge {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  padding: 0 12px;
  border-radius: 999px;
  font-size: 13px;
  font-weight: 900;
  border: 1px solid var(--line);
}

.channel-badge.ok { color: var(--ok); background: rgba(66,211,146,.10); border-color: rgba(66,211,146,.34); }
.channel-badge.warn { color: var(--warn); background: rgba(255,191,105,.10); border-color: rgba(255,191,105,.36); }
.channel-badge.bad { color: var(--bad); background: rgba(255,100,124,.10); border-color: rgba(255,100,124,.36); }

.channel-now { margin-top: 18px; }

.channel-now b {
  display: block;
  font-size: 54px;
  line-height: .92;
  letter-spacing: -.07em;
}

.channel-now span {
  display: block;
  margin-top: 9px;
  color: var(--muted);
  font-size: 16px;
}

.channel-bar {
  height: 11px;
  margin-top: 18px;
  border-radius: 999px;
  overflow: hidden;
  background: rgba(255,255,255,.11);
  border: 1px solid rgba(255,255,255,.09);
}

.channel-bar i {
  display: block;
  height: 100%;
  border-radius: 999px;
  background: linear-gradient(90deg, #65a8ff, #42d392);
}

.channel-note {
  margin-top: 12px;
  color: var(--muted);
  line-height: 1.35;
}

.channel-kpis {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin-top: 12px;
}

.channel-kpi {
  background: rgba(255,255,255,.045);
  border: 1px solid rgba(255,255,255,.085);
  border-radius: 20px;
  padding: 14px;
}

.channel-kpi b {
  display: block;
  color: var(--text);
  font-size: 28px;
  line-height: 1;
  letter-spacing: -.055em;
}

.channel-kpi span {
  display: block;
  margin-top: 7px;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.2;
}

.channel-traffic-table {
  width: 100%;
  min-width: 0;
  border-collapse: separate;
  border-spacing: 0 8px;
}

.channel-traffic-table th {
  border: 0;
  color: var(--muted);
  font-size: 12px;
  padding: 0 10px 3px;
}

.channel-traffic-table td {
  border: 0;
  background: rgba(255,255,255,.045);
  padding: 12px 10px;
  vertical-align: middle;
}

.channel-traffic-table td:first-child { border-radius: 16px 0 0 16px; }
.channel-traffic-table td:last-child { border-radius: 0 16px 16px 0; }

.channel-traffic-table b {
  display: block;
  color: var(--text);
  font-size: 15px;
}

.channel-traffic-table .sub {
  display: block;
  margin-top: 4px;
  color: var(--muted);
  font-size: 12px;
}

.channel-traffic-table strong {
  display: block;
  color: var(--text);
  font-size: 22px;
  line-height: 1;
  letter-spacing: -.04em;
}

.channel-traffic-table small {
  display: block;
  margin-top: 3px;
  color: var(--muted);
  font-size: 11px;
}

.channel-traffic-table em {
  display: block;
  color: var(--muted);
  font-style: normal;
  font-size: 13px;
  white-space: nowrap;
}

.channel-history { background: rgba(255,255,255,.035); }
/* /vpn-support-channel-css-v1 */


/* vpn-channel-mobile-provider-cards-v2 */
@media(max-width:760px) {
  .channel-traffic-table thead { display:none; }
  .channel-traffic-table,
  .channel-traffic-table tbody {
    display:block;
    width:100%;
  }
  .channel-traffic-table tr {
    display:grid;
    grid-template-columns:minmax(0,1fr) auto;
    gap:12px;
    align-items:center;
    margin:0 0 10px;
    padding:14px;
    border-radius:20px;
    background:rgba(255,255,255,.045);
    border:1px solid rgba(255,255,255,.065);
  }
  .channel-traffic-table td {
    display:block;
    padding:0;
    background:transparent;
    border-radius:0 !important;
  }
  .channel-traffic-table td:nth-child(2) {
    text-align:right;
    min-width:76px;
  }
  .channel-traffic-table td:nth-child(3) {
    display:none !important;
  }
  .channel-traffic-table b {
    font-size:20px;
    line-height:1.12;
    letter-spacing:-.035em;
  }
  .channel-traffic-table .sub {
    font-size:13px;
    line-height:1.3;
    margin-top:5px;
  }
  .channel-traffic-table strong {
    font-size:34px;
    line-height:.95;
  }
  .channel-traffic-table small {
    font-size:12px;
  }
}
/* /vpn-channel-mobile-provider-cards-v2 */


@media(max-width:760px) {
  .top { display: block; }
  .nav { margin-top: 14px; justify-content: flex-start; }
  .grid { grid-template-columns: 1fr 1fr; }
  .channel-now b { font-size: 44px; }
  .channel-kpis { grid-template-columns: 1fr 1fr; }
  .channel-traffic-table th:nth-child(3),
  .channel-traffic-table td:nth-child(3) { display: none; }
}

@media(max-width:420px) {
  .wrap { padding: 18px 14px 34px; }
  h1 { font-size: 36px; }
  h2 { font-size: 25px; }
  .btn { min-height: 34px; padding: 0 11px; font-size: 14px; }
  .channel-hero { padding: 18px; }
  .channel-now b { font-size: 38px; }
  .channel-kpis { grid-template-columns: 1fr 1fr; gap: 8px; }
  .channel-kpi { padding: 12px; border-radius: 18px; }
  .channel-kpi b { font-size: 24px; }
  .channel-kpi span { font-size: 12px; }
  .channel-history p { font-size: 15px; line-height: 1.35; }
}
""" + design_v2_css()
# /vpn-support-shell-css-single-source-v1



# vpn-access-passport-remove-dead-js-v1

def support_shell_page(title, body, subtitle=""):
    return f"""<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} · {esc(APP_NAME)}</title>
<style>
{support_shell_css()}
</style>
</head>
<body>
<div class="wrap">
{vpn_support_header_html(title, subtitle)}
{body}
</div>
</body>
</html>"""

# vpn-channel-mbps-units-v1
# vpn-channel-mbps-units-fix-v1b
def _vpn_ch_mbps(v):
    try:
        return f"{float(v):.1f}"
    except Exception:
        return "0.0"

def _vpn_ch_mbps_label(v):
    return f"{_vpn_ch_mbps(v)}\u00a0Мбит/с"
# /vpn-channel-mbps-units-fix-v1b
# /vpn-channel-mbps-units-v1


# vpn-channel-graphs-calendar-ui-v1
def _vpn_channel_graphs_calendar_ui_v1(hist):
    try:
        import json as _json
        ins = _json.loads(support_read_file(SUPPORT_STATUS_DIR, "channel-insights.json", "{}"))
        cal = (hist or {}).get("calendar") or {}

        def fmt(v):
            try:
                return _vpn_ch_mbps_label(v)
            except Exception:
                try:
                    return str(round(float(v or 0),1)) + " Мбит/с"
                except Exception:
                    return "0 Мбит/с"

        def samples(v):
            try:
                return int(v or 0)
            except Exception:
                return 0

        css = """<style>
.channel-mini-bars{display:grid;gap:8px;margin-top:10px}
.channel-mini-row{display:grid;grid-template-columns:54px 1fr 88px;gap:9px;align-items:center}
.channel-mini-row span{font-size:12px;color:var(--muted);font-weight:900}
.channel-mini-row i{height:10px;border-radius:999px;background:rgba(255,255,255,.09);overflow:hidden;border:1px solid rgba(255,255,255,.07)}
.channel-mini-row i u{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,rgba(95,178,255,.9),rgba(66,211,146,.9))}
.channel-mini-row b{text-align:right;font-size:12px}
.channel-two-cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.channel-cal-list{display:grid;gap:7px;margin-top:10px}
.channel-cal-line{border:1px solid rgba(148,163,184,.13);background:rgba(255,255,255,.035);border-radius:14px;padding:9px 10px}
.channel-cal-line b{display:block;font-size:14px}
.channel-cal-line span{display:block;color:var(--muted);font-size:12px;margin-top:3px}
@media(max-width:760px){.channel-two-cols{grid-template-columns:1fr}.channel-mini-row{grid-template-columns:48px 1fr 82px}}
</style>"""

        def bars(items, label_key):
            vals=[float(x.get("p95_mbps") or 0) for x in items if samples(x.get("samples"))>0]
            mx=max(vals or [0.0])
            out=""
            for x in items:
                sm=samples(x.get("samples"))
                val=float(x.get("p95_mbps") or 0)
                w=0 if mx<=0 or sm<=0 else max(3,min(100,val/mx*100))
                lab=x.get(label_key) or x.get("label") or "—"
                out += '<div class="channel-mini-row"><span>'+esc(lab)+'</span><i><u style="width:'+esc(f"{w:.1f}")+'%"></u></i><b>'+esc(fmt(val) if sm else "—")+'</b></div>'
            return out or '<p class="muted">Данных пока нет.</p>'

        weekdays = ins.get("weekdays") or []
        hours = ins.get("hours") or []
        graphs_html = ""
        if weekdays or hours:
            graphs_html = (
                '<section class="card channel-typical-graphs"><h2>График типичной нагрузки</h2>'
                '<div class="channel-two-cols">'
                '<div><p class="muted">Дни недели: обычно до</p><div class="channel-mini-bars">' + bars(weekdays, "label") + '</div></div>'
                '<div><p class="muted">Часы суток: обычно до</p><div class="channel-mini-bars">' + bars(hours, "label") + '</div></div>'
                '</div></section>'
            )

        def cal_card(k,t):
            d=cal.get(k) or {}
            sm=samples(d.get("samples"))
            if sm<=0:
                return '<div class="channel-kpi"><b>—</b><span>'+esc(t)+' · данных нет</span></div>'
            return '<div class="channel-kpi"><b>'+esc(fmt(d.get("peak_mbps")))+'</b><span>'+esc(t)+' · пик · '+esc(str(sm))+' зам.</span><small>обычно до '+esc(fmt(d.get("p95_mbps")))+' · средняя '+esc(fmt(d.get("avg_mbps")))+'</small></div>'

        days=""
        for d in (cal.get("days_7") or [])[:7]:
            sm=samples(d.get("samples"))
            days += '<div class="channel-cal-line"><b>'+esc(d.get("label") or d.get("date") or "—")+'</b><span>пик '+esc(fmt(d.get("peak_mbps")) if sm else "—")+' · обычно до '+esc(fmt(d.get("p95_mbps")) if sm else "—")+' · '+esc(str(sm))+' зам.</span></div>'

        hrs=""
        for h in (cal.get("hours_today") or []):
            sm=samples(h.get("samples"))
            if sm>0:
                hrs += '<div class="channel-cal-line"><b>'+esc(h.get("label") or "—")+'</b><span>пик '+esc(fmt(h.get("peak_mbps")))+' · обычно до '+esc(fmt(h.get("p95_mbps")))+' · '+esc(str(sm))+' зам.</span></div>'
        if not hrs:
            hrs='<p class="muted">За сегодня почасовых данных пока нет.</p>'

        calendar_html=""
        if cal:
            calendar_html = (
                '<section class="card channel-calendar"><h2>По календарю</h2>'
                '<div class="channel-kpis">'+cal_card("today","Сегодня с 00:00 МСК")+cal_card("yesterday","Вчера")+'</div>'
                '<div class="channel-two-cols">'
                '<div><p class="muted">Последние 7 календарных дней</p><div class="channel-cal-list">'+days+'</div></div>'
                '<div><p class="muted">Сегодня по часам</p><div class="channel-cal-list">'+hrs+'</div></div>'
                '</div></section>'
            )

        return css + graphs_html + calendar_html
    except Exception as e:
        try:
            print(f"channel_graphs_calendar_ui_v1_error={e!r}", flush=True)
        except Exception:
            pass
        return ""
# /vpn-channel-graphs-calendar-ui-v1

def channel_page():
    import json as _json

    def load_json(name):
        try:
            return _json.loads(support_read_file(SUPPORT_STATUS_DIR, name, "{}"))
        except Exception:
            return {}

    def fnum(v, default=0.0):
        try:
            return float(v or default)
        except Exception:
            return default

    def inum(v, default=0):
        try:
            return int(float(v or default))
        except Exception:
            return default

    def mb(v):
        try:
            return _vpn_ch_mbps_label(v)
        except Exception:
            return f"{fnum(v):.1f} Мбит/с"

    metrics = load_json("channel-metrics.json")
    hist = load_json("channel-history-summary.json")
    insights = load_json("channel-insights.json")

    day = metrics.get("day") or {}
    calendar = hist.get("calendar") or {}
    today = calendar.get("today") or {}
    ranges = hist.get("ranges") or {}
    records = insights.get("records") or {}

    capacity = fnum(hist.get("capacity_mbit") or metrics.get("capacity_mbit") or 250, 250)
    current = fnum(metrics.get("current_mbps") or day.get("current_mbps") or (hist.get("last") or {}).get("current_mbps"))
    used_pct = 0 if capacity <= 0 else max(0, min(100, current / capacity * 100))
    free_pct = max(0, 100 - used_pct)

    if used_pct >= 85:
        status, status_cls, note = "Плотно", "bad", "Канал близко к пределу."
    elif used_pct >= 55:
        status, status_cls, note = "Нагрузка", "warn", "Канал заметно загружен, но запас ещё есть."
    else:
        status, status_cls, note = "Свободно", "ok", "Канал работает с хорошим запасом."

    def kpi(title, value, sub=""):
        return (
            '<div class="cr-kpi"><span>' + esc(title) + '</span><b>' + esc(value) + '</b>'
            + (('<small>' + esc(sub) + '</small>') if sub else '') + '</div>'
        )

    top = metrics.get("top") or (hist.get("last") or {}).get("top") or []
    top_html = ""
    for item in top[:5]:
        client = item.get("client") or item.get("name") or ""
        if not client:
            continue
        total = fnum(item.get("total_mbps") or item.get("current_mbps"))
        try:
            who = access_human_channel_cell_html(client, item.get("remote_ip") or "", item.get("vpn_ip") or "")
        except Exception:
            who = esc(client)
        top_html += '<div class="cr-user"><div>' + who + '</div><b>' + esc(mb(total)) + '</b></div>'
    if not top_html:
        top_html = '<div class="cr-empty">Разбивка по клиентам сейчас недоступна.</div>'

    hours_today = [h for h in (calendar.get("hours_today") or []) if inum(h.get("samples")) > 0]
    hour_max = max([fnum(h.get("peak_mbps")) for h in hours_today] or [0.0])
    today_chart = ""
    for h in hours_today:
        hour = inum(h.get("hour"))
        peak = fnum(h.get("peak_mbps"))
        usual = fnum(h.get("p95_mbps"))
        height = 4 if hour_max <= 0 else max(4, min(100, peak / hour_max * 100))
        title = f"{hour:02d}:00–{(hour + 1) % 24:02d}:00 · пик {mb(peak)} · обычно до {mb(usual)}"
        today_chart += (
            '<div class="cr-col" title="' + esc(title) + '">'
            '<div class="cr-col-track"><i style="height:' + esc(f"{height:.1f}") + '%"></i></div>'
            '<span>' + esc(f"{hour:02d}") + '</span></div>'
        )
    if not today_chart:
        today_chart = '<div class="cr-empty">Почасовые данные за сегодня пока не накопились.</div>'

    weekdays = insights.get("weekdays") or []
    wd_max = max([fnum(x.get("p95_mbps")) for x in weekdays] or [0.0])
    wd_labels = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"]
    weekday_chart = ""
    for i, x in enumerate(weekdays[:7]):
        val = fnum(x.get("p95_mbps"))
        height = 4 if wd_max <= 0 else max(4, min(100, val / wd_max * 100))
        weekday_chart += (
            '<div class="cr-col cr-col-day" title="' + esc(f"{x.get('label') or wd_labels[i]} · обычно до {mb(val)}") + '">'
            '<div class="cr-col-track"><i style="height:' + esc(f"{height:.1f}") + '%"></i></div>'
            '<span>' + esc(wd_labels[i]) + '</span><small>' + esc(f"{val:.1f}".replace(".", ",")) + '</small></div>'
        )

    all_hours = [x for x in (insights.get("hours") or []) if inum(x.get("samples")) > 0]
    hour_typ_max = max([fnum(x.get("p95_mbps")) for x in all_hours] or [0.0])
    heat = ""
    for x in all_hours[:24]:
        hour = inum(x.get("hour"))
        val = fnum(x.get("p95_mbps"))
        level = 0 if hour_typ_max <= 0 else max(0.08, min(1.0, val / hour_typ_max))
        title = f"{hour:02d}:00–{(hour + 1) % 24:02d}:00 · обычно до {mb(val)}"
        heat += (
            '<div class="cr-heat-cell" title="' + esc(title) + '" style="--level:' + esc(f"{level:.3f}") + '">'
            '<span>' + esc(f"{hour:02d}") + '</span></div>'
        )

    busiest_day = records.get("busiest_weekday") or {}
    busiest_hour = records.get("busiest_hour") or {}
    quiet_day = records.get("quietest_weekday") or {}

    days_7 = list(reversed((calendar.get("days_7") or [])[:7]))
    day_peak_max = max([fnum(d.get("peak_mbps")) for d in days_7] or [0.0])
    days_chart = ""
    for d in days_7:
        peak = fnum(d.get("peak_mbps"))
        usual = fnum(d.get("p95_mbps"))
        height = 4 if day_peak_max <= 0 else max(4, min(100, usual / day_peak_max * 100))
        marker = 4 if day_peak_max <= 0 else max(4, min(100, peak / day_peak_max * 100))
        title = f"{d.get('label') or d.get('date') or '—'} · пик {mb(peak)} · обычно до {mb(usual)}"
        days_chart += (
            '<div class="cr-day-col" title="' + esc(title) + '"><div class="cr-day-track">'
            '<i style="height:' + esc(f"{height:.1f}") + '%"></i>'
            '<u style="bottom:' + esc(f"{marker:.1f}") + '%"></u></div>'
            '<span>' + esc(d.get("label") or d.get("date") or "—") + '</span></div>'
        )

    def range_card(key, title):
        r = ranges.get(key) or {}
        return kpi(title, mb(r.get("peak_mbps")), "средняя " + mb(r.get("avg_mbps")) + " · обычно до " + mb(r.get("p95_mbps")))

    updated = hist.get("generated_at") or metrics.get("generated_at") or ""

    css = """
<style>
/* channel-redesign-v2 */
.channel-page-v2{display:grid;gap:14px}.channel-page-v2 .card{overflow:hidden}
.cr-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.cr-head h2{margin:0}
.cr-hero{display:grid;grid-template-columns:1.1fr .9fr;gap:16px;margin-top:14px}
.cr-speed{font-size:50px;line-height:1;font-weight:950;letter-spacing:-.045em;white-space:nowrap}.cr-sub{color:var(--muted);margin-top:7px}
.cr-meter{height:10px;border-radius:999px;background:rgba(255,255,255,.09);overflow:hidden;margin:15px 0 11px;border:1px solid rgba(255,255,255,.07)}
.cr-meter i{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,rgba(95,178,255,.95),rgba(66,211,146,.95))}
.cr-users{display:grid;gap:8px}.cr-user{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;padding:10px 11px;border-radius:15px;border:1px solid rgba(148,163,184,.13);background:rgba(255,255,255,.035)}
.cr-user b{white-space:nowrap}.cr-empty{color:var(--muted);padding:12px;border-radius:14px;background:rgba(255,255,255,.035);border:1px solid rgba(148,163,184,.12)}
.cr-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.cr-kpi{padding:14px;border-radius:18px;background:rgba(255,255,255,.035);border:1px solid rgba(148,163,184,.13)}
.cr-kpi span{display:block;color:var(--muted);font-size:12px;font-weight:900}.cr-kpi b{display:block;font-size:24px;margin-top:6px;white-space:nowrap}.cr-kpi small{display:block;color:var(--muted);font-size:12px;font-weight:800;line-height:1.35;margin-top:7px}
.cr-chart-wrap{margin-top:15px}.cr-chart-title{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:10px}.cr-chart-title b{font-size:14px}.cr-chart-title span{color:var(--muted);font-size:12px}
.cr-columns{height:178px;display:grid;grid-template-columns:repeat(24,minmax(0,1fr));gap:4px;align-items:end}.cr-col{height:100%;display:grid;grid-template-rows:1fr auto;gap:6px;min-width:0}
.cr-col-track{height:100%;display:flex;align-items:flex-end;background:rgba(255,255,255,.035);border-radius:8px;overflow:hidden}.cr-col-track i{display:block;width:100%;min-height:4px;border-radius:7px 7px 0 0;background:linear-gradient(180deg,rgba(66,211,146,.95),rgba(95,178,255,.78))}
.cr-col span{text-align:center;color:var(--muted);font-size:9px;font-weight:900}.cr-col:nth-child(even) span{opacity:.28}
.cr-typical-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:14px}.cr-typical-summary{display:grid;gap:9px;margin-bottom:12px}
.cr-summary-line{display:grid;grid-template-columns:1fr auto;gap:10px;align-items:center;padding:11px 12px;border-radius:15px;background:rgba(255,255,255,.035);border:1px solid rgba(148,163,184,.13)}
.cr-summary-line span{color:var(--muted);font-size:12px;font-weight:900}.cr-summary-line b{white-space:nowrap}
.cr-weekdays{height:156px;display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:7px;align-items:end}.cr-col-day{grid-template-rows:1fr auto auto}.cr-col-day span{opacity:1!important;font-size:11px}.cr-col-day small{text-align:center;color:var(--muted);font-size:10px}
.cr-heat{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:6px}.cr-heat-cell{aspect-ratio:1;border-radius:8px;display:grid;place-items:center;background:rgba(66,211,146,calc(.08 + var(--level) * .72));border:1px solid rgba(148,163,184,.12)}.cr-heat-cell span{font-size:10px;font-weight:900}
.cr-days{height:190px;display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:9px;align-items:end;margin-top:14px}.cr-day-col{height:100%;display:grid;grid-template-rows:1fr auto;gap:7px;min-width:0}
.cr-day-track{height:100%;position:relative;background:rgba(255,255,255,.035);border-radius:10px;overflow:hidden}.cr-day-track i{position:absolute;left:0;right:0;bottom:0;border-radius:9px 9px 0 0;background:linear-gradient(180deg,rgba(66,211,146,.92),rgba(95,178,255,.72))}.cr-day-track u{position:absolute;left:12%;right:12%;height:2px;background:rgba(255,255,255,.88);border-radius:99px;text-decoration:none}
.cr-day-col span{text-align:center;color:var(--muted);font-size:10px;font-weight:900}.cr-history-kpis{margin-top:15px;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.cr-foot{margin-top:12px;color:var(--muted);font-size:12px}
@media(max-width:900px){.cr-hero,.cr-typical-grid{grid-template-columns:1fr}}
@media(max-width:620px){.cr-speed{font-size:42px}.cr-kpis{grid-template-columns:1fr 1fr}.cr-kpi b{font-size:21px}.cr-columns{height:150px;gap:2px}.cr-col span{display:none}.cr-col:nth-child(3n+1) span{display:block;opacity:1}.cr-heat{grid-template-columns:repeat(8,minmax(0,1fr))}.cr-history-kpis{grid-template-columns:1fr}.cr-days{height:165px;gap:5px}}

/* channel-polish-v3-real */
.cr-hero:has(.cr-empty){grid-template-columns:1fr}
.cr-hero:has(.cr-empty)>div:last-child{display:none}
.cr-hero:has(.cr-empty)>div:first-child:after{
 content:"Разбивка по клиентам сейчас недоступна.";
 display:block;margin-top:12px;padding:10px 12px;
 color:var(--muted);border-radius:14px;
 background:rgba(255,255,255,.035);
 border:1px solid rgba(148,163,184,.12)
}
.cr-weekdays{gap:10px}
.cr-col-day{
 padding:8px 5px 7px;border-radius:14px;
 background:rgba(255,255,255,.025);
 border:1px solid rgba(148,163,184,.12)
}
.cr-col-day small{white-space:nowrap;font-size:11px;font-weight:900}
.cr-legend{
 display:flex;justify-content:flex-end;gap:16px;
 margin-top:12px;color:var(--muted);
 font-size:11px;font-weight:850
}
.cr-legend span{display:flex;align-items:center;gap:7px}
.cr-legend i{display:inline-block;width:22px}
.cr-legend-fill{
 height:8px;border-radius:5px;
 background:linear-gradient(90deg,rgba(95,178,255,.82),rgba(66,211,146,.95))
}
.cr-legend-peak{
 height:2px;border-radius:99px;background:rgba(255,255,255,.9)
}
@media(max-width:620px){
 .cr-weekdays{gap:4px}
 .cr-col-day{padding:7px 2px 6px}
 .cr-col-day small{font-size:9px}
 .cr-legend{justify-content:flex-start}
}
/* /channel-polish-v3-real */

</style>
"""

    body = f"""
{css}
<div class="channel-page-v2">
<section class="card"><div class="cr-head"><h2>Канал сейчас</h2><span class="channel-badge {esc(status_cls)}">{esc(status)}</span></div>
<div class="cr-hero"><div><div class="cr-speed">{esc(mb(current))}</div><div class="cr-sub">из {esc(mb(capacity))} · свободно {esc(f'{free_pct:.1f}%')}</div><div class="cr-meter"><i style="width:{esc(f'{used_pct:.1f}')}%"></i></div><div class="cr-sub">{esc(note)}</div></div>
<div><div class="cr-chart-title"><b>Кто нагружает</b><span>сейчас</span></div><div class="cr-users">{top_html}</div></div></div></section>
<section class="card"><div class="cr-head"><h2>Сегодня</h2><span class="pill">с 00:00 МСК</span></div><div class="cr-kpis" style="margin-top:14px">{kpi('сейчас',mb(current))}{kpi('пик',mb(today.get('peak_mbps')))}{kpi('обычно до',mb(today.get('p95_mbps')))}{kpi('средняя',mb(today.get('avg_mbps')))}</div><div class="cr-chart-wrap"><div class="cr-chart-title"><b>Нагрузка по часам</b><span>пик каждого часа</span></div><div class="cr-columns">{today_chart}</div></div></section>
<section class="card"><div class="cr-head"><h2>Когда обычно нагружают</h2><span class="pill">вся история</span></div><div class="cr-typical-grid"><div><div class="cr-typical-summary"><div class="cr-summary-line"><span>Самый загруженный день</span><b>{esc(busiest_day.get('label') or '—')}</b></div><div class="cr-summary-line"><span>Самый спокойный день</span><b>{esc(quiet_day.get('label') or '—')}</b></div><div class="cr-summary-line"><span>Самый загруженный час</span><b>{esc(busiest_hour.get('label') or '—')}</b></div></div><div class="cr-chart-title"><b>По дням недели</b><span>обычно до</span></div><div class="cr-weekdays">{weekday_chart}</div></div><div><div class="cr-chart-title"><b>По времени суток</b><span>чем ярче, тем выше нагрузка</span></div><div class="cr-heat">{heat}</div></div></div></section>
<section class="card"><div class="cr-head"><h2>История</h2><span class="pill">7 календарных дней</span></div><div class="cr-legend"><span><i class="cr-legend-fill"></i>обычная нагрузка</span><span><i class="cr-legend-peak"></i>пик</span></div><div class="cr-days">{days_chart}</div><div class="cr-history-kpis">{range_card('24h','24 часа')}{range_card('7d','7 дней')}{range_card('30d','30 дней')}</div><div class="cr-foot">Обновлено: {esc(updated)}</div></section>
</div>
"""
    return finalize_channel_page(
        support_shell_page("Канал", body, "Подробная нагрузка VPN-канала"),
        _vpn_channel_history_replace_v1,
    )

# /vpn-channel-manual-route-v1

def support_dashboard_page():
    data = support_dashboard_data()
    status = data.get("status") or "unknown"
    status_class = support_status_class(status)
    reasons = data.get("reasons") or []
    services = data.get("services") or {}
    pluto = data.get("pluto") or {}
    networks = data.get("active_networks") or []

    services_html = ""
    for name in (PANEL_SERVICE_NAME, CADDY_SERVICE_NAME, IPSEC_SERVICE_NAME, L2TP_SERVICE_NAME):
        value = services.get(name, "unknown")
        cls = "ok" if value == "active" else "bad"
        services_html += f'<span class="pill {cls}">{esc(name)}: {esc(value)}</span> '

    network_rows = ""
    for n in networks[:20]:
        network_rows += f"<tr><td>{esc(n.get('label'))}</td><td>{esc(n.get('count'))}</td></tr>"
    if not network_rows:
        network_rows = '<tr><td colspan="2" class="muted">Нет данных</td></tr>'

    body = f"""
<section class="card">
  <span class="pill {status_class}">Статус: {esc(support_status_label(status))}</span>
  <div class="muted" style="margin-top:8px;">Данные сформированы: {esc(data.get('generated_at') or '—')}</div>
  <div class="muted" style="margin-top:8px;">Причины: {esc(', '.join(map(str, reasons)) if reasons else 'нет')}</div>
</section>

<section class="grid">
  <div class="stat"><div class="num">{esc(data.get('auth_fail_count_30m'))}</div><div class="label">auth fail за 30 мин</div></div>
  <div class="stat"><div class="num">{esc(data.get('old_profile_clients_2h'))}</div><div class="label">старые профили за 2 часа</div></div>
  <div class="stat"><div class="num">{esc(data.get('possible_multi_device_clients_2h'))}</div><div class="label">подозрения на 2 устройства</div></div>
</section>

<section class="card">
  <h2>Сервисы</h2>
  <div>{services_html}</div>
</section>

<section class="card">
  <h2>Pluto</h2>
  <div class="muted">PID: {esc(pluto.get('pid') or '—')} · CPU: {esc(pluto.get('cpu'))}% · uptime: {esc(pluto.get('etime') or '—')}</div>
  <pre style="margin-top:10px;">{esc(pluto.get('raw') or '')}</pre>
</section>

<section class="card">
  <h2>Активные сети</h2>
  <table><thead><tr><th>Провайдер</th><th>Клиентов</th></tr></thead><tbody>{network_rows}</tbody></table>
</section>

<section class="card">
  <h2>Быстрые действия</h2>
  <div class="nav">
    <a class="btn primary" href="/device-watch">Открыть контроль устройств</a>
    <a class="btn" href="/daily-report">Открыть ежедневный отчёт</a>
    <a class="btn" href="/instructions">Открыть инструкции</a>
  </div>
</section>
"""
    return support_shell_page(f"{APP_NAME} сейчас", body, "Мини-дашборд поддержки")

def support_text_report_page(title, filename, subtitle=""):
    text = support_read_file(SUPPORT_STATUS_DIR, filename)
    body = f'<section class="card"><pre>{esc(text)}</pre></section>'
    return support_shell_page(title, body, subtitle)

def support_instructions_page():
    rows = ""
    for key, filename, title in SUPPORT_INSTRUCTION_FILES:
        rows += f'<tr><td><a href="/instruction?name={esc(key)}">{esc(title)}</a></td><td><code>{esc(filename)}</code></td></tr>'
    body = f"""
<section class="card">
  <h2>Готовые инструкции</h2>
  <table><thead><tr><th>Инструкция</th><th>Файл</th></tr></thead><tbody>{rows}</tbody></table>
</section>
<section class="card">
  <div class="muted">Все тексты лежат в {esc(SUPPORT_INSTRUCTIONS_DIR)} и обновляются скриптом.</div>
</section>
"""
    return support_shell_page("Инструкции VPN", body, "Готовые тексты для пользователей")

def support_instruction_page(name):
    name = (name or "").strip()
    found = None
    for key, filename, title in SUPPORT_INSTRUCTION_FILES:
        if key == name:
            found = (filename, title)
            break
    if not found:
        body = '<section class="card"><p>Инструкция не найдена.</p></section>'
        return support_shell_page("Инструкция не найдена", body)
    filename, title = found
    text = support_read_file(SUPPORT_INSTRUCTIONS_DIR, filename)
    body = f'<section class="card"><pre>{esc(text)}</pre></section>'
    return support_shell_page(title, body, "Можно копировать пользователю")


# vpn-support-suspicion-reason-v1
def _vpn_support_suspicion_detail(line):
    try:
        import re as _re
        raw = str(line or "")
        rest = raw.split(":", 1)[1].strip() if ":" in raw else raw.strip()

        def val(key):
            m = _re.search(r"(?:^|\s)" + _re.escape(key) + r"=([^\s]+)", rest)
            return (m.group(1).strip(" ,;") if m else "")

        def short_list(value, limit=2):
            value = str(value or "").strip()
            if not value:
                return ""
            parts = [x.strip(" ,;[]()") for x in _re.split(r"[,;|]", value) if x.strip(" ,;[]()")]
            if not parts:
                return value[:42]
            shown = parts[:limit]
            suffix = "" if len(parts) <= limit else f" +{len(parts)-limit}"
            return ", ".join(shown) + suffix

        bits = []

        ok = val("ok_connects") or val("connects") or val("ok")
        if ok:
            bits.append(f"{ok} подключений")

        remote_ips = val("remote_ips") or val("ips") or val("ip")
        if remote_ips:
            if str(remote_ips).isdigit():
                bits.append(f"{remote_ips} IP")
            else:
                bits.append("IP: " + short_list(remote_ips, 2))

        networks = val("networks") or val("providers") or val("asn")
        if networks:
            if str(networks).isdigit():
                bits.append(f"{networks} сети")
            else:
                bits.append("сети: " + short_list(networks, 2))

        vpn_ips = val("vpn_ips") or val("vpn_ip")
        if vpn_ips:
            if str(vpn_ips).isdigit():
                bits.append(f"{vpn_ips} VPN-IP")
            else:
                bits.append("VPN-IP: " + short_list(vpn_ips, 2))

        if bits:
            return " · ".join(bits)

        rest = rest.replace("ok_connects=", "успешных подключений: ")
        rest = rest.replace("remote_ips=", "IP: ")
        rest = rest.replace("vpn_ips=", "VPN-IP: ")
        rest = rest.replace("networks=", "сети: ")
        rest = " ".join(rest.split())

        if rest:
            return rest[:120] + ("…" if len(rest) > 120 else "")

        return "один профиль мог появиться в разных сетях"
    except Exception:
        return "один профиль мог появиться в разных сетях"
# /vpn-support-suspicion-reason-v1

def _vpn_support_section(text, title):
    out = []
    inside = False
    for line in (text or "").splitlines():
        if line.strip() == title:
            inside = True
            continue
        if inside and line.startswith("====="):
            break
        if inside:
            out.append(line.strip())
    return [x for x in out if x]

def is_public_auth_path(path):
    return path in ("/login", "/health", "/pulse.json")

def require_app_auth(handler, path):
    if is_public_auth_path(path):
        return True
    user = current_auth_user(handler)
    if user:
        handler.current_user = user
        return True
    redirect_raw(handler, "/login")
    return False


def read_post_form(handler, require_csrf=True):
    try:
        form = read_urlencoded_form(handler.headers, handler.rfile)
    except FormBodyError as exc:
        handler.close_connection = True
        handler.send_text(exc.status_code, exc.public_message + "\n")
        return None

    if require_csrf:
        session_id = get_cookie_session_id(handler.headers)
        submitted = (form.get(CSRF_FIELD_NAME) or [""])[0]
        if not token_is_valid(session_id, submitted):
            source = request_source_ip(handler.client_address, handler.headers)
            print(f"csrf_rejected source={source} path={handler.path}", flush=True)
            handler.send_text(
                403,
                result_page(
                    "Запрос отклонён",
                    False,
                    ["Защитный токен отсутствует или устарел. Обнови страницу и повтори действие."],
                ),
                "text/html; charset=utf-8",
            )
            return None

    return form


def send_login_throttled(handler, username, retry_after, source):
    retry_after = max(1, int(retry_after))
    handler.close_connection = True
    print(
        f"login_throttled source={source} retry_after={retry_after}",
        flush=True,
    )
    send_html_raw(
        handler,
        login_page("Слишком много попыток входа. Повтори через несколько минут.", username),
        status=429,
        headers=[
            ("Retry-After", str(retry_after)),
            ("Cache-Control", "no-store"),
        ],
    )


class Handler(BaseHTTPRequestHandler):

    def send_profile_download(self, client, kind):
        if kind == "mobileconfig_zip":
            filename, data, err = mobileconfig_zip_download(client)
            if err:
                self.send_text(404, "profile file not found\n")
                return

            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(data)))
            send_security_headers(self)
            self.end_headers()
            self.wfile.write(data)
            return
        path, err = profile_download_path(client, kind)
        if err:
            self.send_text(404, "not found\n")
            return

        info = PROFILE_DOWNLOAD_KINDS[kind]
        data = path.read_bytes()
        filename = path.name

        self.send_response(200)
        self.send_header("Content-Type", info["content_type"])
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        send_security_headers(self)
        self.end_headers()

        try:
            self.wfile.write(data)
        except BrokenPipeError:
            return
        except ConnectionResetError:
            return

        try:
            print(f"profile_download client={safe_client_name(client)} kind={kind} file={filename}")
        except Exception:
            pass

    def log_message(self, fmt, *args):
        return

    def send_text(self, code, body, content_type="text/plain; charset=utf-8"):
        if content_type.lower().startswith("text/html") and getattr(self, "current_user", None):
            session_id = get_cookie_session_id(self.headers)
            csrf_token = token_for_session(session_id)
            body = inject_post_form_tokens(body, csrf_token)
        raw = body.encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            send_security_headers(self)
            self.end_headers()
            self.wfile.write(raw)
        except BrokenPipeError:
            return
        except ConnectionResetError:
            return

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if not require_app_auth(self, path):
            return
        # vpn-current-user-context-v1
        set_request_current_user(getattr(self, "current_user", {}) or {})

        if path == "/login":
            send_html_raw(self, login_page())
            return


        if path == "/health":
            self.send_text(200, "OK\n")
            return

        if path == "/api/me":
            user = getattr(self, "current_user", {}) or {}
            username = user.get("username") or ""
            groups = []
            try:
                conn = auth_db()
                rows = conn.execute(
                    "select group_name, can_view, can_create, can_delete from panel_user_groups where username=? order by group_name",
                    (username,),
                ).fetchall()
                conn.close()
                for group_name, can_view, can_create, can_delete in rows:
                    groups.append({
                        "group_name": group_name,
                        "can_view": bool(can_view),
                        "can_create": bool(can_create),
                        "can_delete": bool(can_delete),
                    })
            except Exception as e:
                groups = [{"error": repr(e)}]

            body = {
                "username": username,
                "display_name": user.get("display_name") or username,
                "role": user.get("role") or "",
                "groups": groups,
            }
            self.send_text(200, json.dumps(body, ensure_ascii=False, indent=2), "application/json; charset=utf-8")
            return

        if path == "/api/summary":
            data = summary_for_user(getattr(self, "current_user", {}) or {})
            self.send_text(200, json.dumps(data, ensure_ascii=False, indent=2), "application/json; charset=utf-8")
            return
        if path == "/download-profile":
            qs = parse_qs(parsed.query)
            client = (qs.get("client") or [""])[0]
            kind = (qs.get("kind") or [""])[0]
            if not auth_client_allowed(getattr(self, "current_user", {}) or {}, client, "can_view"):
                self.send_text(404, "not found\n")
                return
            self.send_profile_download(client, kind)
            return
        if path == "/confirm-revoke-delete":
            qs = parse_qs(parsed.query)
            client = (qs.get("client") or [""])[0]
            if not auth_client_allowed(getattr(self, "current_user", {}) or {}, client, "can_delete"):
                self.send_text(403, result_page("Нет доступа", False, ["У этого пользователя нет права удалять этот VPN-доступ."]), "text/html; charset=utf-8")
                return
            self.send_text(200, confirm_revoke_delete_page(client), "text/html; charset=utf-8")
            return
        if path == "/access":
            user = getattr(self, "current_user", {}) or {}
            qs = parse_qs(parsed.query)
            raw_client = (qs.get("client") or [""])[0]
            if not str(raw_client or "").strip():
                self.send_text(200, access_index_page(user), "text/html; charset=utf-8")
                return
            client = safe_client_name(raw_client)
            if not auth_client_allowed(user, client, "can_view"):
                self.send_text(404, result_page("Доступ не найден", False, ["VPN-доступ не найден или недоступен этому пользователю."]), "text/html; charset=utf-8")
                return
            self.send_text(200, access_passport_page_cached(client, user), "text/html; charset=utf-8")
            return
        if path == "/create-access":
            if not auth_create_group_for_user(getattr(self, "current_user", {}) or {}):
                self.send_text(403, result_page("Нет доступа", False, ["У этого пользователя нет права создавать VPN-доступы."]), "text/html; charset=utf-8")
                return
            self.send_text(200, create_access_page(), "text/html; charset=utf-8")
            return
        if path == "/vpn-dashboard":
            self.send_text(200, support_dashboard_page(), "text/html; charset=utf-8")
            return
        if path == "/device-watch":
            redirect_raw(self, "/access#devices")
            return
        if path == "/daily-report":
            self.send_text(200, support_text_report_page("Ежедневный отчёт", "daily-report.txt", "Сводка по VPN за день"), "text/html; charset=utf-8")
            return
        if path == "/instructions":
            self.send_text(200, support_instructions_page(), "text/html; charset=utf-8")
            return
        if path == "/instruction":
            qs = parse_qs(parsed.query)
            name = (qs.get("name") or [""])[0]
            self.send_text(200, support_instruction_page(name), "text/html; charset=utf-8")
            return
        if path == "/channel":
            self.send_text(200, channel_page(), "text/html; charset=utf-8")
            return
        if path == "/":
            user = getattr(self, "current_user", {}) or {}
            self.send_text(200, home_overview_page(user), "text/html; charset=utf-8")
            return
        self.send_text(404, "not found\n")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path != "/login" and not require_app_auth(self, path):
            return
        # vpn-current-user-context-v1-post
        set_request_current_user(getattr(self, "current_user", {}) or {})

        if path == "/login":
            source = request_source_ip(self.client_address, self.headers)
            now = int(time.time())
            retry_after = LOGIN_THROTTLE.retry_after(source, now=now)
            if retry_after:
                send_login_throttled(self, "", retry_after, source)
                return

            form = read_post_form(self, require_csrf=False)
            if form is None:
                return
            username = (form.get("username") or [""])[0].strip()
            password = (form.get("password") or [""])[0]
            if check_login(username, password):
                LOGIN_THROTTLE.record_success(source)
                sid = create_auth_session(username)
                redirect_raw(self, "/", [("Set-Cookie", auth_cookie_header(sid))])
                return

            retry_after = LOGIN_THROTTLE.record_failure(source, now=now)
            print(
                f"login_failed source={source} blocked={int(bool(retry_after))}",
                flush=True,
            )
            if retry_after:
                send_login_throttled(self, username, retry_after, source)
                return
            send_html_raw(self, login_page("Неверный пароль или пользователь отключён.", username), status=403)
            return

        if path == "/logout":
            form = read_post_form(self)
            if form is None:
                return
            sid = get_cookie_session_id(self.headers)
            delete_auth_session(sid)
            redirect_raw(self, "/login", [("Set-Cookie", clear_auth_cookie_header())])
            return

        if path == "/set-client-group":
            user = getattr(self, "current_user", {}) or {}
            if not auth_is_owner(user):
                self.send_text(403, result_page("Нет доступа", False, ["Только owner может менять группы доступов."]), "text/html; charset=utf-8")
                return

            form = read_post_form(self)
            if form is None:
                return
            client = safe_client_name((form.get("client") or [""])[0])
            group_name = safe_client_name((form.get("group_name") or [""])[0])

            if not client or not group_name:
                self.send_text(400, result_page("Ошибка", False, ["Некорректный доступ или группа."]), "text/html; charset=utf-8")
                return

            try:
                conn = auth_db()
                group_exists = conn.execute("select 1 from panel_groups where name=?", (group_name,)).fetchone()
                conn.close()
            except Exception:
                group_exists = None

            if not group_exists:
                self.send_text(400, result_page("Ошибка", False, [f"Группа {group_name} не найдена."]), "text/html; charset=utf-8")
                return

            if safe_client_name(client).lower() not in existing_access_name_set():
                self.send_text(404, result_page("Доступ не найден", False, [f"VPN-доступ {client} не найден."]), "text/html; charset=utf-8")
                return

            auth_set_client_meta(client, group_name, user)
            summary_cache_clear()
            redirect_raw(self, f"/access?client={client}")
            return

        if path == "/create-access":
            user = getattr(self, "current_user", {}) or {}
            create_group = auth_create_group_for_user(user)
            if not create_group:
                self.send_text(403, result_page("Нет доступа", False, ["У этого пользователя нет права создавать VPN-доступы."]), "text/html; charset=utf-8")
                return
            form = read_post_form(self)
            if form is None:
                return
            first_name = (form.get("first_name") or [""])[0]
            last_name = (form.get("last_name") or [""])[0]
            device_kind = (form.get("device_kind") or ["phone"])[0]
            ok, clean_client, lines = create_access_client_from_ru(first_name, last_name, device_kind)
            if ok:
                auth_set_client_meta(clean_client, create_group, user)
                summary_cache_clear()
                pass
            self.send_text(200 if ok else 400, create_access_result_page(clean_client, ok, lines), "text/html; charset=utf-8")
            return

        if path == "/revoke-delete":
            form = read_post_form(self)
            if form is None:
                return
            client = safe_client_name((form.get("client") or [""])[0])
            confirm = (form.get("confirm") or [""])[0].strip()

            if not client or confirm != client:
                self.send_text(
                    400,
                    result_page("Не подтверждено", False, ["Имя подтверждения не совпало с именем доступа.", f"Ожидалось: {client or '—'}"]),
                    "text/html; charset=utf-8"
                )
                return

            if not auth_client_allowed(getattr(self, "current_user", {}) or {}, client, "can_delete"):
                self.send_text(
                    403,
                    result_page("Нет доступа", False, ["У этого пользователя нет права удалять этот VPN-доступ."]),
                    "text/html; charset=utf-8"
                )
                return

            ok, lines = revoke_delete_client(client)
            if not ok:
                try:
                    _vpn_panel_cache_clear()
                except Exception:
                    pass
                try:
                    _PASSPORT_CACHE.clear()
                except Exception:
                    pass
            if not ok and access_effectively_deleted(client):
                ok = True
                lines = list(lines or []) + ["Доступ уже отсутствует в IKEv2 и файлы установки уже удалены. Считаем операцию успешной."]
            if ok:
                auth_delete_client_meta(client)
                summary_cache_clear()
                pass
            self.send_text(200 if ok else 500, delete_access_result_page(client, ok, lines), "text/html; charset=utf-8")
            return

        self.send_text(404, "not found\n")
        return


# vpn-channel-history-period-cards-v1
def _vpn_ch_esc_v1(x):
    try:
        return esc(x)
    except Exception:
        import html as _html
        return _html.escape(str(x if x is not None else ""))

def _vpn_ch_float_v1(v):
    try:
        return float(v or 0)
    except Exception:
        return 0.0

def _vpn_ch_mbps_label_v1(v):
    try:
        return _vpn_ch_mbps_label(v)
    except Exception:
        x = _vpn_ch_float_v1(v)
        if x >= 100:
            return f"{x:.0f} Мбит/с"
        if x >= 10:
            return f"{x:.1f} Мбит/с"
        return f"{x:.2f} Мбит/с".rstrip("0").rstrip(".")

def _vpn_ch_pct_label_v1(v):
    x = _vpn_ch_float_v1(v)
    if x >= 10:
        return f"{x:.0f}%"
    return f"{x:.1f}%"

def _vpn_ch_samples_label_v1(n):
    try:
        n = int(n or 0)
    except Exception:
        n = 0
    return f"{n} замеров"


def _vpn_channel_history_replace_v1(html):
    if not isinstance(html, str):
        return html

    new_section = _vpn_channel_history_period_cards_html_v1()
    if not new_section:
        return html

    import re as _re

    patterns = [
        r'<section class="card channel-history">.*?</section>',
        r'<section class="card channel-history[^"]*">.*?</section>',
        r'<section class="[^"]*channel-history[^"]*">.*?</section>',
    ]

    for pattern in patterns:
        replaced, count = _re.subn(pattern, new_section, html, count=1, flags=_re.S)
        if count:
            return replaced

    marker = "</main>"
    if marker in html:
        return html.replace(marker, new_section + marker, 1)

    return html

# /vpn-channel-history-period-cards-v1



# vpn-channel-history-human-p95-v2
def _vpn_ch_samples_label_human_v2(n):
    try:
        n = int(n or 0)
    except Exception:
        n = 0
    if 11 <= (n % 100) <= 14:
        word = "замеров"
    else:
        last = n % 10
        if last == 1:
            word = "замер"
        elif 2 <= last <= 4:
            word = "замера"
        else:
            word = "замеров"
    return f"{n} {word}"

def _vpn_ch_generated_label_human_v2(value):
    import re as _re
    value = str(value or "").strip()
    m = _re.match(r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})", value)
    if m:
        y, mo, d, h, mi = m.groups()
        return f"{d}.{mo}.{y} {h}:{mi}"
    return value or "—"

# /vpn-channel-history-human-p95-v2



# vpn-channel-history-human-copy-final-v3
# /vpn-channel-history-human-copy-final-v3



# vpn-channel-history-max-sample-label-v4
def _vpn_channel_history_period_cards_html_v1():
    import json as _json

    try:
        raw = support_read_file(SUPPORT_STATUS_DIR, "channel-history-summary.json", "{}")
    except Exception:
        raw = "{}"

    try:
        hist = _json.loads(raw or "{}")
    except Exception:
        hist = {}

    ranges = hist.get("ranges") or {}
    generated = _vpn_ch_generated_label_human_v2(hist.get("generated_at"))

    periods = [
        ("24h", "24 часа"),
        ("7d", "7 дней"),
        ("30d", "Вся история"),
    ]

    cards = []
    for key, title in periods:
        r = ranges.get(key) or {}

        try:
            samples = int(r.get("samples") or 0)
        except Exception:
            samples = 0

        if samples <= 0:
            continue

        peak = _vpn_ch_mbps_label_v1(r.get("peak_mbps") or 0)
        avg = _vpn_ch_mbps_label_v1(r.get("avg_mbps") or 0)
        usual_high = _vpn_ch_mbps_label_v1(r.get("p95_mbps") or 0)
        peak_pct = _vpn_ch_pct_label_v1(r.get("peak_pct") or 0)

        cards.append(f"""
        <div class="channel-history-period-card">
          <div class="channel-history-period-head">
            <strong>{_vpn_ch_esc_v1(title)}</strong>
            <span>{_vpn_ch_esc_v1(_vpn_ch_samples_label_human_v2(samples))}</span>
          </div>

          <div class="channel-history-period-values">
            <div>
              <b>{_vpn_ch_esc_v1(peak)}</b>
              <span>макс. замер</span>
            </div>
            <div>
              <b>{_vpn_ch_esc_v1(avg)}</b>
              <span>средняя</span>
            </div>
          </div>

          <div class="channel-history-period-foot">
            Обычно до {_vpn_ch_esc_v1(usual_high)} · максимум {_vpn_ch_esc_v1(peak_pct)} канала
          </div>
        </div>
        """)

    if not cards:
        return ""

    css = """
<style>
/* vpn-channel-history-max-sample-label-v4 */
.channel-history.vpn-channel-history-period-cards-v1 {
  overflow: hidden;
}
.channel-history-title-v1 {
  margin-bottom: 18px;
}
.channel-history-title-v1 h2 {
  margin-bottom: 8px;
}
.channel-history-title-v1 p {
  margin: 0;
}
.channel-history-period-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
}
.channel-history-period-card {
  border: 1px solid rgba(255,255,255,.08);
  background: rgba(255,255,255,.032);
  border-radius: 18px;
  padding: 12px;
  min-width: 0;
}
.channel-history-period-head {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  align-items: baseline;
  margin-bottom: 10px;
}
.channel-history-period-head strong {
  font-size: 15px;
  font-weight: 900;
  letter-spacing: -.02em;
}
.channel-history-period-head span {
  color: var(--muted);
  font-size: 11px;
  white-space: nowrap;
}
.channel-history-period-values {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
}
.channel-history-period-values div {
  border-radius: 14px;
  background: rgba(0,0,0,.13);
  padding: 9px 10px 10px;
  min-width: 0;
}
.channel-history-period-values b {
  display: block;
  font-size: 18px;
  line-height: 1.08;
  font-weight: 850;
  letter-spacing: -.035em;
  white-space: nowrap;
}
.channel-history-period-values span {
  display: block;
  margin-top: 4px;
  color: var(--muted);
  font-size: 11px;
}
.channel-history-period-foot {
  margin-top: 9px;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.35;
}
.channel-history-updated-v2 {
  margin-top: 13px !important;
  font-size: 13px !important;
  line-height: 1.35 !important;
}
@media (max-width: 760px) {
  .channel-history-period-grid {
    grid-template-columns: 1fr;
    gap: 9px;
  }
  .channel-history-period-card {
    border-radius: 17px;
    padding: 11px;
  }
  .channel-history-period-values b {
    font-size: 17px;
  }
  .channel-history-period-foot {
    font-size: 11.5px;
  }
}
/* /vpn-channel-history-max-sample-label-v4 */
</style>
"""

    return css + f"""
<section class="card channel-history vpn-channel-history-period-cards-v1">
  <div class="channel-history-title-v1">
    <h2>История</h2>
    <p class="muted">Максимальный замер, средняя и обычная верхняя нагрузка.</p>
  </div>

  <div class="channel-history-period-grid">
    {''.join(cards)}
  </div>

  <p class="muted channel-history-updated-v2">Обновлено: {_vpn_ch_esc_v1(generated)}</p>
</section>
"""
# /vpn-channel-history-max-sample-label-v4



# vpn-access-behavior-ui-v1

def _vpn_behavior_open_db_v1():
    import sqlite3 as _sqlite3
    con = _sqlite3.connect(DB_PATH)
    con.row_factory = _sqlite3.Row
    return con


def _vpn_behavior_table_exists_v1(con, name):
    try:
        return con.execute(
            "select 1 from sqlite_master where type='table' and name=?",
            (name,),
        ).fetchone() is not None
    except Exception:
        return False


def _vpn_behavior_time_hint_v1(row):
    try:
        parts = []
        work = int(row["work_pct"] or 0)
        evening = int(row["evening_pct"] or 0)
        night = int(row["night_pct"] or 0)
        weekend = int(row["weekend_pct"] or 0)

        variants = [
            (work, "рабочее время"),
            (evening, "вечером"),
            (night, "ночью"),
            (weekend, "выходные"),
        ]
        variants.sort(reverse=True)

        for value, label in variants[:2]:
            if value >= 35:
                parts.append(f"{label} {value}%")

        return " · ".join(parts) if parts else "время без явного паттерна"
    except Exception:
        return "время без явного паттерна"


def _vpn_behavior_conf_class_v1(conf):
    try:
        conf = int(conf or 0)
    except Exception:
        conf = 0

    if conf >= 5:
        return "high"
    if conf >= 3:
        return "mid"
    return "low"


def access_behavior_panel_html(client):
    """Human behavior block for access passport. Read-only."""
    client = safe_client_name(client or "")
    if not client:
        return ""

    try:
        con = _vpn_behavior_open_db_v1()

        if not _vpn_behavior_table_exists_v1(con, "vpn_behavior_places"):
            con.close()
            return ""

        summary = None
        if _vpn_behavior_table_exists_v1(con, "vpn_behavior_client_summary"):
            summary = con.execute("""
                select total_sessions, total_days, total_ips,
                       top_place_label, top_provider, top_confidence,
                       mobile_sessions, shared_network_sessions,
                       unknown_provider_sessions, updated_at
                from vpn_behavior_client_summary
                where client=?
            """, (client,)).fetchone()

        places = con.execute("""
            select provider, place_code, place_label, confidence,
                   sessions, days, ips, main_ip, main_ip_sessions, shared_clients,
                   first_seen, last_seen, work_pct, evening_pct, night_pct, weekend_pct,
                   updated_at, sample_ips_json
            from vpn_behavior_places
            where client=?
            order by confidence desc, days desc, sessions desc
            limit 6
        """, (client,)).fetchall()

        con.close()

    except Exception as e:
        print(f"access_behavior_panel_html_error={e!r}", flush=True)
        return ""

    if not places and not summary:
        return """
<style>
/* vpn-access-behavior-ui-v1 */
.behavior-empty-v1{border:1px dashed rgba(148,163,184,.24);background:rgba(148,163,184,.045);border-radius:16px;padding:13px;color:var(--muted);font-size:14px;line-height:1.35}
/* /vpn-access-behavior-ui-v1 */
</style>
<section class="card access-behavior-card vpn-access-behavior-v1">
  <h2>Поведение доступа</h2>
  <div class="behavior-empty-v1">История ещё копится. Когда появятся повторяющиеся сети, здесь будут дом, работа, мобильный интернет и необычные места.</div>
</section>
"""

    total_line = ""
    updated_line = ""

    if summary:
        total_sessions = int(summary["total_sessions"] or 0)
        total_days = int(summary["total_days"] or 0)
        total_ips = int(summary["total_ips"] or 0)
        mobile_sessions = int(summary["mobile_sessions"] or 0)
        shared_sessions = int(summary["shared_network_sessions"] or 0)
        unknown_sessions = int(summary["unknown_provider_sessions"] or 0)

        total_line = (
            f"{total_sessions} сессий · {total_days} дней · {total_ips} IP · "
            f"мобильных {mobile_sessions} · общих сетей {shared_sessions}"
        )

        if unknown_sessions:
            total_line += f" · неизвестных сетей {unknown_sessions}"

        try:
            updated_line = fmt_ts(summary["updated_at"])
        except Exception:
            updated_line = "—"

    cards = []

    for row in places:
        provider = row["provider"] or "—"
        place_label = row["place_label"] or "📍 место"
        conf = int(row["confidence"] or 0)
        sessions = int(row["sessions"] or 0)
        days = int(row["days"] or 0)
        ips = int(row["ips"] or 0)
        main_ip = row["main_ip"] or "—"
        main_ip_sessions = int(row["main_ip_sessions"] or 0)
        shared_clients = int(row["shared_clients"] or 0)
        conf_cls = _vpn_behavior_conf_class_v1(conf)
        time_hint = _vpn_behavior_time_hint_v1(row)

        shared_hint = ""
        if shared_clients >= 3:
            shared_hint = f" · общий IP с {shared_clients} доступами"
        elif shared_clients == 2:
            shared_hint = " · общий IP с ещё одним доступом"

        main_hint = f"основной IP {main_ip}"
        if main_ip_sessions:
            main_hint += f" ({main_ip_sessions} сесс.)"

        cards.append(f"""
        <div class="behavior-place-card-v1 conf-{esc(conf_cls)}">
          <div class="behavior-place-top-v1">
            <strong>{esc(place_label)}</strong>
            <span class="behavior-conf-v1">{esc(str(conf))}/5</span>
          </div>
          <div class="behavior-provider-v1">{esc(provider)}</div>
          <div class="behavior-facts-v1">
            <span>{sessions} сесс.</span>
            <span>{days} дн.</span>
            <span>{ips} IP</span>
          </div>
          <div class="behavior-note-v1">{esc(main_hint)}{esc(shared_hint)}</div>
          <div class="behavior-note-v1">{esc(time_hint)}</div>
        </div>
        """)

    if not cards:
        cards_html = '<div class="behavior-empty-v1">Повторяющиеся места ещё не выделились.</div>'
    else:
        cards_html = "".join(cards)

    subtitle = esc(total_line or "Поведенческий профиль строится по истории VPN-сессий, IP, провайдеров и времени подключения.")
    updated_html = f'<p class="muted behavior-updated-v1">Агрегатор: {esc(updated_line)}</p>' if updated_line else ""

    return f"""
<style>
/* vpn-access-behavior-ui-v1 */
.access-behavior-card.vpn-access-behavior-v1{{overflow:hidden}}
.behavior-head-v1{{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;margin-bottom:13px}}
.behavior-head-v1 h2{{margin:0 0 6px!important}}
.behavior-summary-v1{{margin:0;color:var(--muted);font-size:13px;line-height:1.35}}
.behavior-grid-v1{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}}
.behavior-place-card-v1{{border:1px solid rgba(148,163,184,.16);background:rgba(255,255,255,.028);border-radius:17px;padding:12px;min-width:0}}
.behavior-place-card-v1.conf-high{{border-color:rgba(82,210,115,.24);background:rgba(82,210,115,.055)}}
.behavior-place-card-v1.conf-mid{{border-color:rgba(255,209,102,.22);background:rgba(255,209,102,.045)}}
.behavior-place-top-v1{{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:7px}}
.behavior-place-top-v1 strong{{font-size:15px;line-height:1.18;font-weight:950;overflow-wrap:anywhere}}
.behavior-conf-v1{{flex:0 0 auto;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.14);border-radius:999px;padding:4px 8px;font-size:11px;font-weight:950;color:var(--muted)}}
.behavior-provider-v1{{font-size:18px;line-height:1.15;font-weight:900;letter-spacing:-.025em;margin-bottom:9px;overflow-wrap:anywhere}}
.behavior-facts-v1{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px}}
.behavior-facts-v1 span{{border:1px solid rgba(255,255,255,.08);background:rgba(0,0,0,.12);border-radius:999px;padding:4px 7px;font-size:11px;font-weight:850;color:var(--muted)}}
.behavior-note-v1{{color:var(--muted);font-size:12px;line-height:1.35;overflow-wrap:anywhere;margin-top:4px}}
.behavior-updated-v1{{margin:12px 0 0!important;font-size:12px!important}}
.behavior-empty-v1{{border:1px dashed rgba(148,163,184,.24);background:rgba(148,163,184,.045);border-radius:16px;padding:13px;color:var(--muted);font-size:14px;line-height:1.35}}
@media(max-width:980px){{.behavior-grid-v1{{grid-template-columns:1fr 1fr}}}}
@media(max-width:640px){{.behavior-head-v1{{display:block}}.behavior-grid-v1{{grid-template-columns:1fr}}.behavior-provider-v1{{font-size:17px}}}}
/* /vpn-access-behavior-ui-v1 */
</style>
<section class="card access-behavior-card vpn-access-behavior-v1">
  <div class="behavior-head-v1">
    <div>
      <h2>Поведение доступа</h2>
      <p class="behavior-summary-v1">{subtitle}</p>
    </div>
  </div>
  <div class="behavior-grid-v1">
    {cards_html}
  </div>
  {updated_html}
</section>
"""



def _access_passport_stage_behavior(client, user, html):
    try:
        if "vpn-access-behavior-v1" in html:
            return html

        insert = access_behavior_panel_html(client)
        if not insert:
            return html

        needle = '<section class="card passport-history-card">'
        if needle in html:
            return html.replace(needle, insert + "\n" + needle, 1)

        return html.replace("</main>", insert + "\n</main>", 1)

    except Exception as e:
        print(f"access_behavior_inject_error={e!r}", flush=True)
        return html
# /vpn-access-behavior-ui-v1


# vpn-access-matches-ui-v1

def _vpn_matches_human_v1(row):
    bits = []
    for k in ("person_name", "device_label", "device_type", "group_name"):
        try:
            v = (row[k] or "").strip()
        except Exception:
            v = ""
        if v:
            bits.append(v)
    return " / ".join(bits)


def _vpn_matches_provider_line_v1(providers_json):
    import json as _json
    try:
        data = _json.loads(providers_json or "{}")
    except Exception:
        data = {}

    if not data:
        return "провайдеры не определены"

    parts = []
    for provider, cnt in list(data.items())[:4]:
        provider = provider or "—"
        try:
            cnt = int(cnt)
        except Exception:
            cnt = 1
        if cnt > 1:
            parts.append(f"{provider}×{cnt}")
        else:
            parts.append(provider)

    return ", ".join(parts) if parts else "провайдеры не определены"


def _vpn_matches_examples_line_v1(examples_json):
    import json as _json
    try:
        examples = _json.loads(examples_json or "[]")
    except Exception:
        examples = []

    out = []
    for e in examples[:3]:
        ip = e.get("ip") or "—"
        provider = e.get("provider") or "—"
        pair_sessions = int(e.get("pair_sessions_on_ip") or 0)
        clients_count = int(e.get("clients_count") or 0)
        mobile = e.get("mobile")

        suffix = []
        if pair_sessions:
            suffix.append(f"{pair_sessions} сесс.")
        if clients_count:
            suffix.append(f"{clients_count} доступов")
        if mobile:
            suffix.append("мобильная")

        tail = " · ".join(suffix)
        if tail:
            out.append(f"{provider} {ip} ({tail})")
        else:
            out.append(f"{provider} {ip}")

    return "; ".join(out)


def access_matches_panel_html(client):
    """Shows smart related accesses in access passport."""
    import sqlite3 as _sqlite3
    import urllib.parse as _urlparse

    client = safe_client_name(client or "")
    if not client:
        return ""

    try:
        con = _sqlite3.connect(DB_PATH)
        try:
            con.row_factory = _sqlite3.Row

            exists = con.execute(
                "select 1 from sqlite_master where type='table' and name='vpn_behavior_matches'"
            ).fetchone()

            if not exists:
                return ""

            rows = con.execute("""
                select client_a, client_b, score, label,
                       shared_ip_count, stable_ip_count, mobile_ip_count,
                       unknown_ip_count, max_clients_on_ip, pair_sessions,
                       providers_json, examples_json, updated_at
                from vpn_behavior_matches
                where (client_a=? or client_b=?)
                  and score >= 50
                order by score desc, shared_ip_count desc, pair_sessions desc
                limit 5
            """, (client, client)).fetchall()

            if not rows:
                return ""

            others = []
            for r in rows:
                other = r["client_b"] if r["client_a"] == client else r["client_a"]
                others.append(other)

            meta = {}
            if others:
                qmarks = ",".join(["?"] * len(others))
                try:
                    for m in con.execute(f"""
                        select client, person_name, device_label, device_type, group_name
                        from vpn_client_meta
                        where client in ({qmarks})
                    """, others):
                        meta[m["client"]] = m
                except Exception:
                    pass

        finally:
            con.close()

    except Exception as e:
        print(f"access_matches_panel_html_error={e!r}", flush=True)
        return ""

    cards = []

    for r in rows:
        other = r["client_b"] if r["client_a"] == client else r["client_a"]
        other_meta = meta.get(other)
        human = _vpn_matches_human_v1(other_meta) if other_meta else ""
        title = human or other
        subtitle = other if human else "техимя доступа"

        score = int(r["score"] or 0)
        label = r["label"] or "связь"
        shared_ip_count = int(r["shared_ip_count"] or 0)
        stable_ip_count = int(r["stable_ip_count"] or 0)
        mobile_ip_count = int(r["mobile_ip_count"] or 0)
        max_clients_on_ip = int(r["max_clients_on_ip"] or 0)
        pair_sessions = int(r["pair_sessions"] or 0)

        providers = _vpn_matches_provider_line_v1(r["providers_json"])
        examples = _vpn_matches_examples_line_v1(r["examples_json"])

        if score >= 75:
            cls = "strong"
        elif score >= 50:
            cls = "mid"
        else:
            cls = "low"

        href = "/access?client=" + _urlparse.quote(other)

        mass_hint = ""
        if max_clients_on_ip >= 6:
            mass_hint = f" · массовая сеть до {max_clients_on_ip} доступов"

        examples_html = ""
        if examples:
            examples_html = f'<div class="match-examples-v1">{esc(examples)}</div>'

        cards.append(f"""
        <a class="match-card-v1 match-{esc(cls)}" href="{esc(href)}">
          <div class="match-top-v1">
            <strong>{esc(title)}</strong>
            <span>{score}/100</span>
          </div>
          <div class="match-sub-v1">{esc(subtitle)}</div>
          <div class="match-label-v1">{esc(label)}</div>
          <div class="match-facts-v1">
            <span>{shared_ip_count} общих IP</span>
            <span>{stable_ip_count} стабильных</span>
            <span>{mobile_ip_count} мобильных</span>
            <span>{pair_sessions} сесс.</span>
          </div>
          <div class="match-provider-v1">{esc(providers)}{esc(mass_hint)}</div>
          {examples_html}
        </a>
        """)

    if not cards:
        return ""

    return f"""
<style>
/* vpn-access-matches-ui-v1 */
.access-matches-card-v1{{overflow:hidden}}
.matches-grid-v1{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}}
.match-card-v1{{display:block;text-decoration:none;color:inherit;border:1px solid rgba(148,163,184,.16);background:rgba(255,255,255,.028);border-radius:17px;padding:12px;min-width:0}}
.match-card-v1:hover{{border-color:rgba(148,163,184,.34);background:rgba(255,255,255,.045)}}
.match-card-v1.match-strong{{border-color:rgba(82,210,115,.24);background:rgba(82,210,115,.055)}}
.match-card-v1.match-mid{{border-color:rgba(255,209,102,.23);background:rgba(255,209,102,.045)}}
.match-top-v1{{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:4px}}
.match-top-v1 strong{{font-size:15px;font-weight:950;line-height:1.18;overflow-wrap:anywhere}}
.match-top-v1 span{{flex:0 0 auto;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.14);border-radius:999px;padding:4px 8px;font-size:11px;font-weight:950;color:var(--muted)}}
.match-sub-v1{{font-size:12px;color:var(--muted);overflow-wrap:anywhere;margin-bottom:7px}}
.match-label-v1{{font-size:14px;font-weight:900;margin-bottom:8px}}
.match-facts-v1{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px}}
.match-facts-v1 span{{border:1px solid rgba(255,255,255,.08);background:rgba(0,0,0,.12);border-radius:999px;padding:4px 7px;font-size:11px;font-weight:850;color:var(--muted)}}
.match-provider-v1,.match-examples-v1{{font-size:12px;line-height:1.35;color:var(--muted);overflow-wrap:anywhere;margin-top:4px}}
@media(max-width:760px){{.matches-grid-v1{{grid-template-columns:1fr}}}}
/* /vpn-access-matches-ui-v1 */
</style>
<section class="card access-matches-card-v1 vpn-access-matches-v1">
  <h2>Связанные доступы</h2>
  <p class="muted" style="margin-top:-4px">Другие профили, которые пересекались с этим доступом по внешним сетям. Это не доказательство, а поведенческая связка по IP/провайдерам.</p>
  <div class="matches-grid-v1">
    {''.join(cards)}
  </div>
</section>
"""



def _access_passport_stage_matches(client, user, html):

    try:
        if "vpn-access-matches-v1" in html:
            return html

        insert = access_matches_panel_html(client)
        if not insert:
            return html

        needle = '<section class="card passport-history-card">'
        if needle in html:
            return html.replace(needle, insert + "\n" + needle, 1)

        return html.replace("</main>", insert + "\n</main>", 1)

    except Exception as e:
        print(f"access_matches_inject_error={e!r}", flush=True)
        return html

# /vpn-access-matches-ui-v1


# vpn-access-geo-ui-v1

def _vpn_geo_flag_text_v1(row):
    flags = []

    try:
        if int(row["mobile"] or 0):
            flags.append("мобильная сеть, город может врать")
    except Exception:
        pass

    try:
        if int(row["proxy"] or 0):
            flags.append("proxy")
    except Exception:
        pass

    try:
        if int(row["hosting"] or 0):
            flags.append("hosting/серверная сеть")
    except Exception:
        pass

    return " · ".join(flags)


def _vpn_geo_location_text_v1(row):
    parts = []

    for key in ("country_code", "region", "city"):
        try:
            v = (row[key] or "").strip()
        except Exception:
            v = ""
        if v and v not in parts:
            parts.append(v)

    return " · ".join(parts) if parts else "гео не определено"


def access_geo_panel_html(client):
    """Approximate geo for access networks. Uses ip_geo_cache only."""
    import sqlite3 as _sqlite3

    client = safe_client_name(client or "")
    if not client:
        return ""

    try:
        con = _sqlite3.connect(DB_PATH)
        try:
            con.row_factory = _sqlite3.Row

            exists_geo = con.execute(
                "select 1 from sqlite_master where type='table' and name='ip_geo_cache'"
            ).fetchone()

            exists_places = con.execute(
                "select 1 from sqlite_master where type='table' and name='vpn_behavior_places'"
            ).fetchone()

            if not exists_geo or not exists_places:
                return ""

            rows = con.execute("""
                select
                  p.provider as behavior_provider,
                  p.place_label,
                  p.confidence,
                  p.sessions,
                  p.days,
                  p.ips,
                  p.main_ip,
                  p.shared_clients,
                  p.work_pct,
                  p.evening_pct,
                  p.night_pct,
                  p.weekend_pct,
                  g.status,
                  g.country,
                  g.country_code,
                  g.region,
                  g.city,
                  g.zip,
                  g.lat,
                  g.lon,
                  g.timezone,
                  g.isp,
                  g.org,
                  g.as_text,
                  g.as_name,
                  g.mobile,
                  g.proxy,
                  g.hosting,
                  g.updated_at as geo_updated_at
                from vpn_behavior_places p
                join ip_geo_cache g
                  on g.ip = p.main_ip
                 and g.status = 'success'
                where p.client=?
                order by p.confidence desc, p.days desc, p.sessions desc
                limit 8
            """, (client,)).fetchall()

        finally:
            con.close()

    except Exception as e:
        print(f"access_geo_panel_html_error={e!r}", flush=True)
        return ""

    if not rows:
        return ""

    cards = []
    found_geo = 0

    for row in rows:
        main_ip = row["main_ip"] or "—"
        place_label = row["place_label"] or "📍 место"
        behavior_provider = row["behavior_provider"] or "—"
        confidence = int(row["confidence"] or 0)
        sessions = int(row["sessions"] or 0)
        days = int(row["days"] or 0)
        ips = int(row["ips"] or 0)
        shared_clients = int(row["shared_clients"] or 0)

        has_geo = bool(row["country_code"] or row["region"] or row["city"])
        if has_geo:
            found_geo += 1

        location = _vpn_geo_location_text_v1(row)
        flags = _vpn_geo_flag_text_v1(row)

        isp = (row["isp"] or row["org"] or row["as_name"] or "").strip()
        if not isp:
            isp = behavior_provider

        if confidence >= 5:
            cls = "high"
        elif confidence >= 3:
            cls = "mid"
        else:
            cls = "low"

        flag_html = f'<div class="geo-flags-v1">{esc(flags)}</div>' if flags else ""
        shared_html = ""
        if shared_clients >= 3:
            shared_html = f" · общий IP с {shared_clients} доступами"

        coords_html = ""
        try:
            lat = row["lat"]
            lon = row["lon"]
            if lat is not None and lon is not None:
                coords_html = f'<div class="geo-note-v1">координаты провайдера: {esc(str(round(float(lat), 3)))} / {esc(str(round(float(lon), 3)))}</div>'
        except Exception:
            coords_html = ""

        cards.append(f"""
        <div class="geo-card-v1 geo-{esc(cls)}">
          <div class="geo-top-v1">
            <strong>{esc(location)}</strong>
            <span>{confidence}/5</span>
          </div>
          <div class="geo-place-v1">{esc(place_label)}</div>
          <div class="geo-provider-v1">{esc(isp)}</div>
          <div class="geo-facts-v1">
            <span>{sessions} сесс.</span>
            <span>{days} дн.</span>
            <span>{ips} IP</span>
          </div>
          <div class="geo-note-v1">основной IP {esc(main_ip)} · {esc(behavior_provider)}{esc(shared_html)}</div>
          {flag_html}
          {coords_html}
        </div>
        """)

    if found_geo == 0:
        return ""

    return f"""
<style>
/* vpn-access-geo-ui-v1 */
.access-geo-card-v1{{overflow:hidden}}
.geo-grid-v1{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}}
.geo-card-v1{{border:1px solid rgba(148,163,184,.16);background:rgba(255,255,255,.028);border-radius:17px;padding:12px;min-width:0}}
.geo-card-v1.geo-high{{border-color:rgba(82,210,115,.22);background:rgba(82,210,115,.05)}}
.geo-card-v1.geo-mid{{border-color:rgba(255,209,102,.22);background:rgba(255,209,102,.04)}}
.geo-top-v1{{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:5px}}
.geo-top-v1 strong{{font-size:15px;font-weight:950;line-height:1.18;overflow-wrap:anywhere}}
.geo-top-v1 span{{flex:0 0 auto;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.14);border-radius:999px;padding:4px 8px;font-size:11px;font-weight:950;color:var(--muted)}}
.geo-place-v1{{font-size:13px;font-weight:900;margin-bottom:7px;overflow-wrap:anywhere}}
.geo-provider-v1{{font-size:16px;font-weight:950;line-height:1.15;margin-bottom:8px;overflow-wrap:anywhere}}
.geo-facts-v1{{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px}}
.geo-facts-v1 span{{border:1px solid rgba(255,255,255,.08);background:rgba(0,0,0,.12);border-radius:999px;padding:4px 7px;font-size:11px;font-weight:850;color:var(--muted)}}
.geo-note-v1,.geo-flags-v1{{font-size:12px;line-height:1.35;color:var(--muted);overflow-wrap:anywhere;margin-top:4px}}
.geo-flags-v1{{color:#ffd166;font-weight:850}}
@media(max-width:980px){{.geo-grid-v1{{grid-template-columns:1fr 1fr}}}}
@media(max-width:640px){{.geo-grid-v1{{grid-template-columns:1fr}}}}
/* /vpn-access-geo-ui-v1 */
</style>
<section class="card access-geo-card-v1 vpn-access-geo-v1">
  <h2>География сетей</h2>
  <p class="muted" style="margin-top:-4px">Примерное местоположение по внешнему IP провайдера. Это не адрес человека; для мобильных и proxy-сетей город может быть неточным.</p>
  <div class="geo-grid-v1">
    {''.join(cards)}
  </div>
</section>
"""



def _access_passport_stage_geo(client, user, html):

    try:
        if "vpn-access-geo-v1" in html:
            return html

        insert = access_geo_panel_html(client)
        if not insert:
            return html

        # Хотим порядок: Поведение -> География -> Связанные доступы -> История
        needle_matches = '<section class="card access-matches-card-v1'
        if needle_matches in html:
            return html.replace(needle_matches, insert + "\n" + needle_matches, 1)

        needle_history = '<section class="card passport-history-card">'
        if needle_history in html:
            return html.replace(needle_history, insert + "\n" + needle_history, 1)

        return html.replace("</main>", insert + "\n</main>", 1)

    except Exception as e:
        print(f"access_geo_inject_error={e!r}", flush=True)
        return html

# /vpn-access-geo-ui-v1


# vpn-networks-page-v1

def _vpn_networks_meta_map_v1(con):
    out = {}
    try:
        for r in con.execute("""
            select client, person_name, device_label, device_type, group_name
            from vpn_client_meta
        """):
            bits = []
            for k in ("person_name", "device_label", "device_type", "group_name"):
                v = (r[k] or "").strip()
                if v:
                    bits.append(v)
            out[r["client"]] = " / ".join(bits)
    except Exception:
        pass
    return out


def _vpn_networks_client_label_v1(meta, client):
    human = meta.get(client) or ""
    if human:
        return f"{human}"
    return client or "—"


def _vpn_networks_location_v1(row):
    parts = []
    for k in ("country_code", "region", "city"):
        try:
            v = (row[k] or "").strip()
        except Exception:
            v = ""
        if v and v not in parts:
            parts.append(v)
    return " · ".join(parts) if parts else "гео не определено"


def _vpn_networks_geo_flags_v1(row):
    flags = []
    try:
        if int(row["mobile"] or 0):
            flags.append("mobile")
    except Exception:
        pass
    try:
        if int(row["proxy"] or 0):
            flags.append("proxy")
    except Exception:
        pass
    try:
        if int(row["hosting"] or 0):
            flags.append("hosting")
    except Exception:
        pass
    return " · ".join(flags)


def _vpn_networks_table_exists_v1(con, name):
    try:
        return con.execute(
            "select 1 from sqlite_master where type='table' and name=?",
            (name,),
        ).fetchone() is not None
    except Exception:
        return False


def networks_page_v1(user=None):
    import json as _json
    import sqlite3 as _sqlite3
    import urllib.parse as _urlparse
    from collections import Counter as _Counter, defaultdict as _defaultdict

    user = user or {}

    try:
        con = _sqlite3.connect(DB_PATH)
        con.row_factory = _sqlite3.Row
    except Exception as e:
        return support_shell_page(
            "Сети и совпадения",
            f'<section class="card"><h2>Ошибка базы</h2><p class="muted">{esc(repr(e))}</p></section>',
            "Поведенческая аналитика VPN",
        )

    try:
        has_shared = _vpn_networks_table_exists_v1(con, "vpn_behavior_shared_ips")
        has_matches = _vpn_networks_table_exists_v1(con, "vpn_behavior_matches")
        has_geo = _vpn_networks_table_exists_v1(con, "ip_geo_cache")

        meta = _vpn_networks_meta_map_v1(con)

        def allowed(client):
            try:
                return auth_client_allowed(user, client, "can_view")
            except Exception:
                return False

        shared_cards = ""
        city_counter = _Counter()
        city_sessions = _Counter()

        if has_shared:
            sql = """
                select s.remote_ip, s.provider, s.clients_count, s.sessions, s.clients_json,
                       g.country_code, g.region, g.city, g.isp, g.org, g.mobile, g.proxy, g.hosting
                from vpn_behavior_shared_ips s
                left join ip_geo_cache g
                  on g.ip = s.remote_ip and g.status='success'
                where s.clients_count >= 2
                order by s.clients_count desc, s.sessions desc
                limit 80
            """
            rows = con.execute(sql).fetchall()

            for r in rows:
                try:
                    clients = _json.loads(r["clients_json"] or "[]")
                except Exception:
                    clients = []

                clients = [c for c in clients if allowed(c)]
                if len(clients) < 2:
                    continue

                loc = _vpn_networks_location_v1(r)
                flags = _vpn_networks_geo_flags_v1(r)
                provider = r["provider"] or r["isp"] or r["org"] or "—"
                sessions = int(r["sessions"] or 0)
                clients_count = len(clients)

                if loc and loc != "гео не определено":
                    city_counter[loc] += 1
                    city_sessions[loc] += sessions

                if clients_count >= 6:
                    cls = "mass"
                    kind = "массовая сеть"
                elif clients_count >= 3:
                    cls = "shared"
                    kind = "общая сеть"
                else:
                    cls = "pair"
                    kind = "пара доступов"

                flags_html = f'<span class="net-flag-v1">{esc(flags)}</span>' if flags else ""

                client_links = []
                for c in clients[:12]:
                    href = "/access?client=" + _urlparse.quote(c)
                    client_links.append(f'<a href="{esc(href)}">{esc(_vpn_networks_client_label_v1(meta, c))}</a>')
                more = ""
                if len(clients) > 12:
                    more = f'<span class="muted">+{len(clients)-12}</span>'

                shared_cards += f"""
                <div class="network-card-v1 net-{esc(cls)}">
                  <div class="net-top-v1">
                    <strong>{esc(provider)}</strong>
                    <span>{esc(kind)}</span>
                  </div>
                  <div class="net-ip-v1">{esc(r["remote_ip"] or "—")}</div>
                  <div class="net-loc-v1">{esc(loc)} {flags_html}</div>
                  <div class="net-facts-v1">
                    <span>{clients_count} доступов</span>
                    <span>{sessions} сессий</span>
                  </div>
                  <div class="net-clients-v1">
                    {"".join(client_links)}
                    {more}
                  </div>
                </div>
                """

        if not shared_cards:
            shared_cards = '<div class="empty-v1">Общие сети пока не найдены или недоступны этому пользователю.</div>'

        match_cards = ""

        if has_matches:
            rows = con.execute("""
                select client_a, client_b, score, label,
                       shared_ip_count, stable_ip_count, mobile_ip_count,
                       max_clients_on_ip, pair_sessions, providers_json, examples_json
                from vpn_behavior_matches
                where score >= 50
                order by score desc, shared_ip_count desc, pair_sessions desc
                limit 80
            """).fetchall()

            for r in rows:
                a = r["client_a"]
                b = r["client_b"]
                if not (allowed(a) and allowed(b)):
                    continue

                score = int(r["score"] or 0)
                if score >= 75:
                    cls = "strong"
                else:
                    cls = "mid"

                try:
                    providers = _json.loads(r["providers_json"] or "{}")
                except Exception:
                    providers = {}

                provider_line = ", ".join([
                    f"{p}×{c}" if int(c or 0) > 1 else str(p)
                    for p, c in list(providers.items())[:4]
                ]) or "провайдеры не определены"

                href_a = "/access?client=" + _urlparse.quote(a)
                href_b = "/access?client=" + _urlparse.quote(b)

                match_cards += f"""
                <div class="match-row-v1 match-{esc(cls)}">
                  <div class="match-score-v1">{score}/100</div>
                  <div class="match-main-v1">
                    <div class="match-title-v1">
                      <a href="{esc(href_a)}">{esc(_vpn_networks_client_label_v1(meta, a))}</a>
                      <span>↔</span>
                      <a href="{esc(href_b)}">{esc(_vpn_networks_client_label_v1(meta, b))}</a>
                    </div>
                    <div class="match-note-v1">{esc(r["label"] or "связь")} · {esc(provider_line)}</div>
                    <div class="match-facts2-v1">
                      <span>{int(r["shared_ip_count"] or 0)} общих IP</span>
                      <span>{int(r["stable_ip_count"] or 0)} стабильных</span>
                      <span>{int(r["mobile_ip_count"] or 0)} мобильных</span>
                      <span>{int(r["pair_sessions"] or 0)} сессий пары</span>
                      <span>массовость до {int(r["max_clients_on_ip"] or 0)}</span>
                    </div>
                  </div>
                </div>
                """

        if not match_cards:
            match_cards = '<div class="empty-v1">Сильные связки пока не найдены или недоступны этому пользователю.</div>'

        city_cards = ""
        if has_geo:
            # Для owner городская сводка уже собрана выше из общих сетей.
            # Если общих сетей мало, добавляем топ из geo-кэша как общий ориентир.
            if not city_counter:
                for r in con.execute("""
                    select country_code, region, city, count(*) as c, sum(sessions) as s
                    from ip_geo_cache
                    where status='success'
                    group by country_code, region, city
                    order by s desc, c desc
                    limit 12
                """):
                    loc = " · ".join([x for x in (r["country_code"], r["region"], r["city"]) if x]) or "—"
                    city_counter[loc] += int(r["c"] or 0)
                    city_sessions[loc] += int(r["s"] or 0)

            for loc, cnt in city_counter.most_common(12):
                city_cards += f"""
                <div class="city-pill-v1">
                  <strong>{esc(loc)}</strong>
                  <span>{cnt} IP · {city_sessions[loc]} сессий</span>
                </div>
                """

        if not city_cards:
            city_cards = '<div class="empty-v1">Гео-кэш пока пустой.</div>'

    finally:
        try:
            con.close()
        except Exception:
            pass

    body = f"""
<style>
/* vpn-networks-page-v1 */
.networks-hero-v1{{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;margin-bottom:14px}}
.networks-hero-v1 h1{{margin:0;font-size:34px;letter-spacing:-.045em}}
.networks-hero-v1 p{{margin:6px 0 0;color:var(--muted);line-height:1.45}}
.networks-actions-v1{{display:flex;gap:8px;flex-wrap:wrap}}
.networks-actions-v1 a{{text-decoration:none;border:1px solid rgba(255,255,255,.1);background:rgba(255,255,255,.04);color:var(--text);border-radius:999px;padding:9px 12px;font-size:13px;font-weight:850}}
.networks-grid-v1{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}}
.network-card-v1{{border:1px solid rgba(148,163,184,.16);background:rgba(255,255,255,.028);border-radius:18px;padding:13px;min-width:0}}
.network-card-v1.net-mass{{border-color:rgba(130,170,255,.25);background:rgba(130,170,255,.055)}}
.network-card-v1.net-shared{{border-color:rgba(82,210,115,.22);background:rgba(82,210,115,.045)}}
.net-top-v1{{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;margin-bottom:5px}}
.net-top-v1 strong{{font-size:17px;font-weight:950;line-height:1.15;overflow-wrap:anywhere}}
.net-top-v1 span{{font-size:11px;color:var(--muted);border:1px solid rgba(255,255,255,.1);border-radius:999px;padding:4px 8px;background:rgba(0,0,0,.13);white-space:nowrap}}
.net-ip-v1{{font-size:20px;font-weight:950;letter-spacing:-.03em;margin-bottom:5px}}
.net-loc-v1,.match-note-v1{{color:var(--muted);font-size:13px;line-height:1.35;overflow-wrap:anywhere}}
.net-flag-v1{{color:#ffd166;font-weight:900;margin-left:4px}}
.net-facts-v1,.match-facts2-v1{{display:flex;gap:6px;flex-wrap:wrap;margin:9px 0}}
.net-facts-v1 span,.match-facts2-v1 span{{border:1px solid rgba(255,255,255,.08);background:rgba(0,0,0,.12);border-radius:999px;padding:4px 7px;font-size:11px;font-weight:850;color:var(--muted)}}
.net-clients-v1{{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}}
.net-clients-v1 a{{color:var(--text);text-decoration:none;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.035);border-radius:999px;padding:5px 8px;font-size:12px;font-weight:850;max-width:100%;overflow:hidden;text-overflow:ellipsis}}
.match-list-v1{{display:grid;gap:8px}}
.match-row-v1{{display:flex;gap:10px;border:1px solid rgba(148,163,184,.16);background:rgba(255,255,255,.028);border-radius:17px;padding:12px;align-items:flex-start}}
.match-row-v1.match-strong{{border-color:rgba(82,210,115,.22);background:rgba(82,210,115,.045)}}
.match-score-v1{{flex:0 0 auto;border-radius:14px;background:rgba(0,0,0,.16);border:1px solid rgba(255,255,255,.1);padding:8px 9px;font-weight:950;color:var(--muted);font-size:12px}}
.match-main-v1{{min-width:0;flex:1}}
.match-title-v1{{display:flex;gap:7px;flex-wrap:wrap;align-items:center;font-size:15px;font-weight:950;line-height:1.3}}
.match-title-v1 a{{color:var(--text);text-decoration:none;overflow-wrap:anywhere}}
.city-grid-v1{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}}
.city-pill-v1{{border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.035);border-radius:16px;padding:11px}}
.city-pill-v1 strong{{display:block;font-size:14px;line-height:1.25;overflow-wrap:anywhere}}
.city-pill-v1 span{{display:block;margin-top:5px;color:var(--muted);font-size:12px}}
.empty-v1{{border:1px dashed rgba(148,163,184,.24);background:rgba(148,163,184,.045);border-radius:16px;padding:13px;color:var(--muted);font-size:14px;line-height:1.35}}
@media(max-width:900px){{.networks-grid-v1,.city-grid-v1{{grid-template-columns:1fr}}.networks-hero-v1{{display:block}}.networks-actions-v1{{margin-top:12px}}}}
/* /vpn-networks-page-v1 */
</style>

<section class="card">
  <div class="networks-hero-v1">
    <div>
      <h1>Сети и совпадения</h1>
      <p>Общие внешние IP, примерные города и поведенческие связки доступов. Гео — это город/регион провайдера, не точный адрес человека.</p>
    </div>
    <div class="networks-actions-v1">
      <a href="/">На главную</a>
      <a href="/access">Все доступы</a>
      <a href="/channel">Канал</a>
    </div>
  </div>
</section>

<section class="card">
  <h2>Города и регионы</h2>
  <div class="city-grid-v1">{city_cards}</div>
</section>

<section class="card">
  <h2>Общие сети</h2>
  <p class="muted">IP, с которых заходили два и более доступа. Массовые сети полезны как офис/общая точка, но слабее доказывают связь конкретной пары.</p>
  <div class="networks-grid-v1">{shared_cards}</div>
</section>

<section class="card">
  <h2>Сильные связки доступов</h2>
  <p class="muted">Пары профилей, которые пересекались по сетям. Учитываются стабильные IP, мобильный NAT, массовость сети и метаданные доступа.</p>
  <div class="match-list-v1">{match_cards}</div>
</section>
"""

    return finalize_networks_page(
        support_shell_page("Сети и совпадения", body, "Поведенческая аналитика VPN"),
        known_networks_summary_section_html_v1,
    )


_vpn_original_handler_do_GET_networks_page_v1 = Handler.do_GET

def _vpn_handler_do_GET_networks_page_v1(self):
    import urllib.parse as _urlparse

    parsed = _urlparse.urlparse(self.path)
    path = parsed.path

    if path in ("/networks", "/behavior-networks"):
        if not require_app_auth(self, path):
            return
        set_request_current_user(getattr(self, "current_user", {}) or {})
        user = getattr(self, "current_user", {}) or {}
        self.send_text(200, networks_page_v1(user), "text/html; charset=utf-8")
        return

    return _vpn_original_handler_do_GET_networks_page_v1(self)

Handler.do_GET = _vpn_handler_do_GET_networks_page_v1

# /vpn-networks-page-v1


# vpn-known-networks-ui-v1

def _vpn_known_table_exists_v1(con, name):
    try:
        return con.execute(
            "select 1 from sqlite_master where type='table' and name=?",
            (name,),
        ).fetchone() is not None
    except Exception:
        return False


def _vpn_known_status_badge_v1(status):
    status = (status or "").strip().lower()
    if status == "maintenance":
        return "maintenance"
    if status == "active":
        return "active"
    return status or "manual"


def access_known_networks_panel_html(client):
    """Shows known client networks matched by access main IPs."""
    import sqlite3 as _sqlite3

    client = safe_client_name(client or "")
    if not client:
        return ""

    try:
        con = _sqlite3.connect(DB_PATH)
        try:
            con.row_factory = _sqlite3.Row

            if not _vpn_known_table_exists_v1(con, "known_client_networks"):
                return ""

            if not _vpn_known_table_exists_v1(con, "vpn_behavior_places"):
                return ""

            rows = con.execute("""
                select
                  p.place_label,
                  p.provider,
                  p.confidence,
                  p.sessions,
                  p.days,
                  p.ips,
                  p.main_ip,
                  p.shared_clients,
                  k.ip,
                  k.host,
                  k.title,
                  k.customer,
                  k.object_name,
                  k.kind,
                  k.status,
                  k.source,
                  k.note
                from vpn_behavior_places p
                join known_client_networks k
                  on k.ip = p.main_ip
                where p.client=?
                order by p.confidence desc, p.sessions desc
                limit 8
            """, (client,)).fetchall()

        finally:
            con.close()

    except Exception as e:
        print(f"access_known_networks_panel_html_error={e!r}", flush=True)
        return ""

    if not rows:
        return ""

    cards = []

    for r in rows:
        status = _vpn_known_status_badge_v1(r["status"])
        host = (r["host"] or "").strip()
        title = r["title"] or "Известная сеть"
        customer = r["customer"] or "клиент"
        obj = r["object_name"] or "объект"
        note = r["note"] or ""
        provider = r["provider"] or "—"

        host_html = f'<div class="known-host-v1">{esc(host)}</div>' if host else ""
        note_html = f'<div class="known-note-v1">{esc(note)}</div>' if note else ""

        cards.append(f"""
        <div class="known-net-card-v1">
          <div class="known-top-v1">
            <strong>{esc(title)}</strong>
            <span>{esc(status)}</span>
          </div>
          <div class="known-customer-v1">{esc(customer)} · {esc(obj)}</div>
          <div class="known-ip-v1">{esc(r["ip"] or r["main_ip"] or "—")}</div>
          {host_html}
          <div class="known-facts-v1">
            <span>{int(r["sessions"] or 0)} сесс.</span>
            <span>{int(r["days"] or 0)} дн.</span>
            <span>{int(r["confidence"] or 0)}/5</span>
          </div>
          <div class="known-note-v1">совпало с Pulse · {esc(provider)} · {esc(r["place_label"] or "место")}</div>
          {note_html}
        </div>
        """)

    return f"""
<style>
/* vpn-known-networks-ui-v1 */
.access-known-networks-card-v1{{overflow:hidden}}
.known-net-grid-v1{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}}
.known-net-card-v1{{border:1px solid rgba(82,210,115,.25);background:rgba(82,210,115,.055);border-radius:17px;padding:12px;min-width:0}}
.known-top-v1{{display:flex;align-items:flex-start;justify-content:space-between;gap:10px;margin-bottom:5px}}
.known-top-v1 strong{{font-size:16px;font-weight:950;line-height:1.18;overflow-wrap:anywhere}}
.known-top-v1 span{{flex:0 0 auto;border:1px solid rgba(255,255,255,.12);background:rgba(0,0,0,.14);border-radius:999px;padding:4px 8px;font-size:11px;font-weight:950;color:var(--muted)}}
.known-customer-v1{{font-size:13px;font-weight:900;margin-bottom:8px;color:var(--muted);overflow-wrap:anywhere}}
.known-ip-v1{{font-size:22px;font-weight:950;letter-spacing:-.035em;margin-bottom:4px}}
.known-host-v1{{font-size:13px;color:var(--muted);margin-bottom:8px;overflow-wrap:anywhere}}
.known-facts-v1{{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0}}
.known-facts-v1 span{{border:1px solid rgba(255,255,255,.08);background:rgba(0,0,0,.12);border-radius:999px;padding:4px 7px;font-size:11px;font-weight:850;color:var(--muted)}}
.known-note-v1{{font-size:12px;line-height:1.35;color:var(--muted);overflow-wrap:anywhere;margin-top:4px}}
@media(max-width:760px){{.known-net-grid-v1{{grid-template-columns:1fr}}}}
/* /vpn-known-networks-ui-v1 */
</style>
<section class="card access-known-networks-card-v1 vpn-known-networks-v1">
  <h2>Известная клиентская сеть</h2>
  <p class="muted" style="margin-top:-4px">Этот внешний IP совпал со справочником MikroTik из Pulse. Справочник обновляется автоматически.</p>
  <div class="known-net-grid-v1">
    {''.join(cards)}
  </div>
</section>
"""


def known_networks_summary_section_html_v1():
    import sqlite3 as _sqlite3

    try:
        con = _sqlite3.connect(DB_PATH)
        try:
            con.row_factory = _sqlite3.Row

            if not _vpn_known_table_exists_v1(con, "known_client_networks"):
                return ""

            rows = con.execute("""
                select
                  k.ip, k.host, k.title, k.customer, k.object_name, k.status, k.note,
                  g.country_code, g.region, g.city, g.isp, g.org, g.mobile, g.proxy, g.hosting,
                  s.clients_count, s.sessions
                from known_client_networks k
                left join ip_geo_cache g
                  on g.ip = k.ip and g.status='success'
                left join vpn_behavior_shared_ips s
                  on s.remote_ip = k.ip
                order by k.customer, k.object_name, k.ip
            """).fetchall()

        finally:
            con.close()

    except Exception as e:
        print(f"known_networks_summary_section_html_error={e!r}", flush=True)
        return ""

    if not rows:
        return ""

    cards = []
    for r in rows:
        loc_parts = []
        for key in ("country_code", "region", "city"):
            v = (r[key] or "").strip()
            if v and v not in loc_parts:
                loc_parts.append(v)
        loc = " · ".join(loc_parts) if loc_parts else "гео не закэшировано"

        flags = []
        for key, label in (("mobile", "mobile"), ("proxy", "proxy"), ("hosting", "hosting")):
            try:
                if int(r[key] or 0):
                    flags.append(label)
            except Exception:
                pass
        flag_s = " · ".join(flags)

        seen = ""
        if r["clients_count"]:
            seen = f'<div class="known-note-v1">в VPN уже встречался: {int(r["clients_count"] or 0)} доступов · {int(r["sessions"] or 0)} сессий</div>'
        else:
            seen = '<div class="known-note-v1">в VPN пока не встречался как общий IP</div>'

        host = (r["host"] or "").strip()
        host_html = f'<div class="known-host-v1">{esc(host)}</div>' if host else ""

        flag_html = f'<span>{esc(flag_s)}</span>' if flag_s else ""

        cards.append(f"""
        <div class="known-net-card-v1">
          <div class="known-top-v1">
            <strong>{esc(r["title"] or "Известная сеть")}</strong>
            <span>{esc(_vpn_known_status_badge_v1(r["status"]))}</span>
          </div>
          <div class="known-customer-v1">{esc(r["customer"] or "—")} · {esc(r["object_name"] or "—")}</div>
          <div class="known-ip-v1">{esc(r["ip"] or "—")}</div>
          {host_html}
          <div class="known-facts-v1">
            <span>{esc(loc)}</span>
            {flag_html}
          </div>
          <div class="known-note-v1">{esc(r["isp"] or r["org"] or "провайдер не определён")}</div>
          {seen}
        </div>
        """)

    return f"""
<section class="card vpn-known-networks-summary-v1">
  <h2>Известные клиентские сети</h2>
  <p class="muted">Ручной справочник MikroTik из Pulse. Используется для подписи VPN-поведения и совпадений.</p>
  <div class="known-net-grid-v1">
    {''.join(cards)}
  </div>
</section>
"""



def _access_passport_stage_known_networks(client, user, html):

    try:
        if "vpn-known-networks-v1" in html:
            return html

        insert = access_known_networks_panel_html(client)
        if not insert:
            return html

        # Порядок: Поведение -> Известная сеть -> География -> Связанные доступы
        needle_geo = '<section class="card access-geo-card-v1'
        if needle_geo in html:
            return html.replace(needle_geo, insert + "\n" + needle_geo, 1)

        needle_matches = '<section class="card access-matches-card-v1'
        if needle_matches in html:
            return html.replace(needle_matches, insert + "\n" + needle_matches, 1)

        needle_history = '<section class="card passport-history-card">'
        if needle_history in html:
            return html.replace(needle_history, insert + "\n" + needle_history, 1)

        return html.replace("</main>", insert + "\n</main>", 1)

    except Exception as e:
        print(f"known_networks_access_inject_error={e!r}", flush=True)
        return html



# /vpn-known-networks-ui-v1


# vpn-access-profile-layout-v2

def _vpn_profile_v2_next_section_pos(html, start):
    candidates = []
    for needle in ('<section class="card', '<section ', '</main>'):
        pos = html.find(needle, start + 8)
        if pos != -1:
            candidates.append(pos)
    return min(candidates) if candidates else -1


def _vpn_profile_v2_extract_section_by_marker(html, marker):
    m = html.find(marker)
    if m == -1:
        return html, ""

    start = html.rfind("<section", 0, m + len(marker))
    if start == -1:
        return html, ""

    end = _vpn_profile_v2_next_section_pos(html, start)
    if end == -1:
        return html, ""

    section = html[start:end]
    html = html[:start] + html[end:]
    return html, section


def _vpn_profile_v2_extract_section_by_text(html, text):
    m = html.find(text)
    if m == -1:
        return html, ""

    start = html.rfind("<section", 0, m)
    if start == -1:
        return html, ""

    end = _vpn_profile_v2_next_section_pos(html, start)
    if end == -1:
        return html, ""

    section = html[start:end]
    html = html[:start] + html[end:]
    return html, section


def _vpn_profile_v2_strip_section_title(section):
    # Оставляем оригинальный h2 внутри секции: так безопаснее.
    return section


def _vpn_profile_v2_compose_group(title, subtitle, sections, cls):
    sections = [x for x in sections if x and x.strip()]
    if not sections:
        return ""

    inner = "\n".join(_vpn_profile_v2_strip_section_title(x) for x in sections)

    subtitle_html = f'<p class="muted profile-v2-subtitle">{esc(subtitle)}</p>' if subtitle else ""

    return f"""
<section class="card profile-v2-group {esc(cls)}">
  <div class="profile-v2-group-head">
    <h2>{esc(title)}</h2>
    {subtitle_html}
  </div>
  <div class="profile-v2-group-grid">
    {inner}
  </div>
</section>
"""


def _vpn_profile_v2_apply(html):
    if "vpn-access-profile-layout-v2" in html:
        return html

    original_len = len(html)

    # Достаём старые кирпичи.
    html, files = _vpn_profile_v2_extract_section_by_text(html, "Файлы профиля")
    html, management = _vpn_profile_v2_extract_section_by_text(html, "Управление")
    html, group = _vpn_profile_v2_extract_section_by_text(html, "Группа доступа")

    html, behavior = _vpn_profile_v2_extract_section_by_marker(html, '<section class="card access-behavior-card')
    html, known = _vpn_profile_v2_extract_section_by_marker(html, '<section class="card access-known-networks-card-v1')
    html, geo = _vpn_profile_v2_extract_section_by_marker(html, '<section class="card access-geo-card-v1')
    html, matches = _vpn_profile_v2_extract_section_by_marker(html, '<section class="card access-matches-card-v1')
    html, history = _vpn_profile_v2_extract_section_by_marker(html, '<section class="card passport-history-card')

    network_group = _vpn_profile_v2_compose_group(
        "Сети доступа",
        "Привычные сети, клиентские MikroTik из Pulse и примерное гео по IP.",
        [known, behavior, geo],
        "profile-v2-networks"
    )

    related_group = _vpn_profile_v2_compose_group(
        "Связанные доступы",
        "Показываются только уверенные связи от 50/100, без одноразового шума массовых IP.",
        [matches],
        "profile-v2-related"
    )

    service_group = _vpn_profile_v2_compose_group(
        "Профиль и админка",
        "Файлы, группа доступа и опасные действия собраны ниже рабочих данных.",
        [files, group, management],
        "profile-v2-service"
    )

    history_group = _vpn_profile_v2_compose_group(
        "История сессий и IP",
        "Последние подключения компактнее, без визуального растягивания страницы.",
        [history],
        "profile-v2-history"
    )

    ordered = "\n".join(x for x in (network_group, related_group, service_group, history_group) if x)

    css = """
<style>
/* vpn-access-profile-layout-v2 */

main{
  gap:14px!important;
}

.card{
  border-radius:20px!important;
}

main > .card{
  padding:16px!important;
  margin-bottom:12px!important;
}

main > .card h2{
  font-size:22px!important;
  line-height:1.1!important;
  margin-bottom:8px!important;
}

main > .card p.muted{
  font-size:14px!important;
  line-height:1.35!important;
}

.profile-v2-group{
  padding:16px!important;
}

.profile-v2-group-head{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap:16px;
  margin-bottom:12px;
}

.profile-v2-group-head h2{
  margin:0!important;
  font-size:23px!important;
  letter-spacing:-.035em;
}

.profile-v2-subtitle{
  max-width:560px;
  margin:0!important;
  text-align:right;
}

.profile-v2-group-grid{
  display:grid;
  grid-template-columns:1fr;
  gap:10px;
}

.profile-v2-networks .profile-v2-group-grid{
  grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr);
  align-items:start;
}

.profile-v2-networks .access-known-networks-card-v1{
  grid-column:1 / -1;
}

.profile-v2-networks .access-behavior-card-v1,
.profile-v2-networks .access-behavior-card{
  min-width:0;
}

.profile-v2-group-grid > section.card{
  margin:0!important;
  padding:13px!important;
  border-radius:17px!important;
  background:rgba(255,255,255,.024)!important;
  min-width:0!important;
}

.profile-v2-group-grid > section.card > h2{
  font-size:18px!important;
  margin-bottom:6px!important;
}

.profile-v2-group-grid > section.card > p.muted{
  margin-bottom:10px!important;
}

.access-known-networks-card-v1 .known-net-grid-v1,
.access-geo-card-v1 .geo-grid-v1,
.access-matches-card-v1 .matches-grid-v1,
.access-behavior-card .behavior-grid-v1{
  gap:8px!important;
}

.access-behavior-card .behavior-grid-v1{
  grid-template-columns:repeat(2,minmax(0,1fr))!important;
}

.behavior-place-card-v1,
.geo-card-v1,
.match-card-v1,
.known-net-card-v1{
  padding:10px!important;
  border-radius:15px!important;
}

.behavior-place-card-v1 strong,
.geo-top-v1 strong,
.match-top-v1 strong,
.known-top-v1 strong{
  font-size:14px!important;
  line-height:1.15!important;
}

.match-card-v1.match-low{
  display:none!important;
}

.match-examples-v1{
  display:none!important;
}

.geo-note-v1,
.known-note-v1,
.match-provider-v1{
  font-size:11px!important;
}

.access-known-networks-card-v1 .known-net-card-v1 > .known-note-v1:last-child{
  display:none!important;
}

.profile-v2-service .profile-v2-group-grid{
  grid-template-columns:1.2fr .9fr .9fr;
}

.profile-v2-service .profile-v2-group-grid > section.card{
  height:100%;
}

.profile-v2-service button,
.profile-v2-service a,
.profile-v2-service select,
.profile-v2-service input{
  max-width:100%;
}

.profile-v2-history .profile-v2-group-grid > section.card{
  background:rgba(255,255,255,.018)!important;
}

.passport-history-card article,
.passport-history-card .session-card,
.passport-history-card [class*="session"]{
  border-radius:14px!important;
}

.passport-history-card article,
.passport-history-card .session-card{
  padding:10px!important;
}

.passport-history-card h2{
  font-size:18px!important;
}

.passport-history-card{
  max-height:none!important;
}

.profile-v2-related .access-matches-card-v1 .matches-grid-v1{
  grid-template-columns:repeat(2,minmax(0,1fr))!important;
}

.profile-v2-related .match-card-v1{
  min-height:0!important;
}

.profile-v2-related .match-facts-v1{
  margin-bottom:4px!important;
}

.profile-v2-related .match-provider-v1{
  color:var(--muted)!important;
}

@media(max-width:980px){
  .profile-v2-networks .profile-v2-group-grid,
  .profile-v2-service .profile-v2-group-grid,
  .profile-v2-related .access-matches-card-v1 .matches-grid-v1{
    grid-template-columns:1fr!important;
  }

  .profile-v2-group-head{
    display:block;
  }

  .profile-v2-subtitle{
    text-align:left;
    margin-top:6px!important;
  }
}

@media(max-width:640px){
  main > .card,
  .profile-v2-group{
    padding:13px!important;
    border-radius:18px!important;
  }

  main > .card h2,
  .profile-v2-group-head h2{
    font-size:21px!important;
  }

  .access-behavior-card .behavior-grid-v1,
  .access-geo-card-v1 .geo-grid-v1,
  .access-matches-card-v1 .matches-grid-v1,
  .access-known-networks-card-v1 .known-net-grid-v1{
    grid-template-columns:1fr!important;
  }
}

/* /vpn-access-profile-layout-v2 */
</style>
"""

    if "</head>" in html:
        html = html.replace("</head>", css + "\n</head>", 1)
    else:
        html = css + html

    # Чуть помечаем main, чтобы CSS не был совсем вслепую.
    if "<main" in html and "profile-layout-v2" not in html[:html.find("<main") + 300]:
        html = html.replace("<main", '<main class="profile-layout-v2"', 1)

    if ordered:
        if "</main>" in html:
            html = html.replace("</main>", ordered + "\n</main>", 1)
        else:
            html += ordered

    html += "\n<!-- vpn-access-profile-layout-v2 original_len=%s new_len=%s -->\n" % (original_len, len(html))
    return html



def _access_passport_stage_layout_v2(client, user, html):
    try:
        return _vpn_profile_v2_apply(html)
    except Exception as e:
        print(f"access_profile_layout_v2_error={e!r}", flush=True)
        return html

# /vpn-access-profile-layout-v2


# vpn-access-profile-visual-v3

def _vpn_profile_visual_v3(html):
    if "vpn-access-profile-visual-v3" in html:
        return html

    import re as _re

    # Убираем внутренние дубли заголовков там, где уже есть внешний красивый заголовок группы.
    html = _re.sub(
        r'(<section class="card access-matches-card-v1[^>]*>)\s*<h2>Связанные доступы</h2>\s*<p class="muted"[^>]*>.*?</p>',
        r'\1',
        html,
        count=1,
        flags=_re.S
    )

    html = _re.sub(
        r'(<section class="card passport-history-card[^>]*>)\s*<h2>История сессий и IP</h2>',
        r'\1',
        html,
        count=1,
        flags=_re.S
    )

    # В “Известной сети” пояснение уже написано в группе, внутри оно лишнее.
    html = _re.sub(
        r'(<section class="card access-known-networks-card-v1[^>]*>\s*<h2>Известная клиентская сеть</h2>)\s*<p class="muted"[^>]*>.*?</p>',
        r'\1',
        html,
        count=1,
        flags=_re.S
    )

    css = """
<style>
/* vpn-access-profile-visual-v3 */

/* Общий ритм: меньше воздуха, меньше гигантских кирпичей */
body{
  --v3-card-pad:14px;
  --v3-radius:18px;
}

main.profile-layout-v2{
  gap:10px!important;
}

main.profile-layout-v2 > .card{
  padding:var(--v3-card-pad)!important;
  border-radius:var(--v3-radius)!important;
  margin-bottom:10px!important;
}

main.profile-layout-v2 > .card h1,
main.profile-layout-v2 > .card h2{
  letter-spacing:-.04em!important;
}

/* Верхняя именная карточка */
main.profile-layout-v2 > .card:nth-of-type(1){
  padding:14px 16px!important;
}

main.profile-layout-v2 > .card:nth-of-type(1) h2,
main.profile-layout-v2 > .card:nth-of-type(1) h3{
  font-size:20px!important;
  margin-bottom:6px!important;
}

/* Состояние: было вертикальной простынёй, делаем админскую плитку */
main.profile-layout-v2 > .card:nth-of-type(2){
  display:grid!important;
  grid-template-columns:repeat(4,minmax(0,1fr))!important;
  gap:8px!important;
  align-items:stretch!important;
}

main.profile-layout-v2 > .card:nth-of-type(2) > h2{
  grid-column:1/-1!important;
  margin:0 0 2px 0!important;
}

main.profile-layout-v2 > .card:nth-of-type(2) > *:not(h2){
  border:1px solid rgba(148,163,184,.13)!important;
  background:rgba(255,255,255,.024)!important;
  border-radius:14px!important;
  padding:9px 10px!important;
  margin:0!important;
  min-width:0!important;
}

main.profile-layout-v2 > .card:nth-of-type(2) hr,
main.profile-layout-v2 > .card:nth-of-type(2) br{
  display:none!important;
}

/* Трафик тоже плиткой */
main.profile-layout-v2 > .card:nth-of-type(3){
  display:grid!important;
  grid-template-columns:repeat(4,minmax(0,1fr))!important;
  gap:8px!important;
}

main.profile-layout-v2 > .card:nth-of-type(3) > h2{
  grid-column:1/-1!important;
  margin:0 0 2px 0!important;
}

main.profile-layout-v2 > .card:nth-of-type(3) > *:not(h2){
  border:1px solid rgba(148,163,184,.13)!important;
  background:rgba(255,255,255,.024)!important;
  border-radius:14px!important;
  padding:9px 10px!important;
  margin:0!important;
  min-width:0!important;
}

main.profile-layout-v2 > .card:nth-of-type(3) hr,
main.profile-layout-v2 > .card:nth-of-type(3) br{
  display:none!important;
}

/* Группы */
.profile-v2-group{
  padding:14px!important;
  border-radius:18px!important;
}

.profile-v2-group-head{
  margin-bottom:9px!important;
}

.profile-v2-group-head h2{
  font-size:22px!important;
}

.profile-v2-subtitle{
  font-size:13px!important;
  line-height:1.3!important;
  opacity:.82!important;
}

/* Убираем матрёшку: внутренние карточки в группах должны быть легче */
.profile-v2-group-grid > section.card{
  padding:11px!important;
  border-radius:15px!important;
  background:rgba(255,255,255,.018)!important;
  border-color:rgba(148,163,184,.11)!important;
}

.profile-v2-group-grid > section.card > h2{
  font-size:17px!important;
  margin-bottom:4px!important;
}

.profile-v2-group-grid > section.card > p.muted{
  display:none!important;
}

/* Сети доступа: известная сеть сверху, дальше две колонки поведение/гео */
.profile-v2-networks .profile-v2-group-grid{
  grid-template-columns:minmax(0,1fr) minmax(0,1fr)!important;
  gap:9px!important;
}

.profile-v2-networks .access-known-networks-card-v1{
  grid-column:1/-1!important;
}

.known-net-grid-v1,
.behavior-grid-v1,
.geo-grid-v1,
.matches-grid-v1{
  gap:7px!important;
}

/* Карточки внутри сетей */
.behavior-place-card-v1,
.geo-card-v1,
.known-net-card-v1,
.match-card-v1{
  padding:9px!important;
  border-radius:13px!important;
}

.behavior-place-card-v1 strong,
.geo-top-v1 strong,
.known-top-v1 strong,
.match-top-v1 strong{
  font-size:13px!important;
  line-height:1.15!important;
}

.known-ip-v1{
  font-size:20px!important;
  margin-bottom:2px!important;
}

.known-host-v1,
.known-customer-v1,
.known-note-v1,
.geo-note-v1,
.geo-flags-v1,
.match-provider-v1,
.match-examples-v1{
  font-size:11px!important;
  line-height:1.28!important;
}

/* Пояснялки, которые превращали страницу в мануал */
.match-examples-v1,
.access-known-networks-card-v1 .known-note-v1:last-child,
.geo-note-v1:last-child{
  display:none!important;
}

/* Поведение — 2 колонки, но без огромных карточек */
.access-behavior-card .behavior-grid-v1{
  grid-template-columns:repeat(2,minmax(0,1fr))!important;
}

.behavior-place-card-v1 .place-facts-v1,
.behavior-facts-v1,
.geo-facts-v1,
.known-facts-v1,
.match-facts-v1{
  gap:4px!important;
}

.behavior-place-card-v1 span,
.geo-facts-v1 span,
.known-facts-v1 span,
.match-facts-v1 span{
  font-size:10px!important;
  padding:3px 6px!important;
}

/* Связанные доступы: это список, а не второй экран */
.profile-v2-related .profile-v2-group-grid{
  gap:0!important;
}

.profile-v2-related .access-matches-card-v1{
  padding:0!important;
  background:transparent!important;
  border:0!important;
}

.profile-v2-related .matches-grid-v1{
  grid-template-columns:repeat(2,minmax(0,1fr))!important;
}

.profile-v2-related .match-card-v1{
  min-height:0!important;
}

.profile-v2-related .match-label-v1{
  font-size:13px!important;
  margin-bottom:5px!important;
}

/* Админка ниже: делаем проще и спокойнее */
.profile-v2-service .profile-v2-group-grid{
  grid-template-columns:1.3fr .9fr .9fr!important;
}

.profile-v2-service .profile-v2-group-grid > section.card{
  background:rgba(255,255,255,.015)!important;
}

.profile-v2-service .profile-v2-group-grid > section.card > h2{
  font-size:16px!important;
}

.profile-v2-service button,
.profile-v2-service a,
.profile-v2-service select{
  border-radius:12px!important;
}

/* История: самое важное. Убираем ощущение километровой анкеты */
.profile-v2-history .profile-v2-group-grid > section.card{
  padding:0!important;
  background:transparent!important;
  border:0!important;
}

.profile-v2-history .passport-history-card{
  padding:0!important;
}

.profile-v2-history .passport-history-card > p.muted{
  display:none!important;
}

.profile-v2-history article,
.profile-v2-history .session-card,
.profile-v2-history [class*="session-card"]{
  padding:9px!important;
  border-radius:13px!important;
  margin-bottom:7px!important;
}

.profile-v2-history article > *,
.profile-v2-history .session-card > *,
.profile-v2-history [class*="session-card"] > *{
  margin-top:3px!important;
  margin-bottom:3px!important;
}

.profile-v2-history article{
  display:grid!important;
  grid-template-columns:130px repeat(4,minmax(0,1fr))!important;
  gap:6px!important;
  align-items:center!important;
}

.profile-v2-history article strong,
.profile-v2-history article b{
  font-size:14px!important;
}

.profile-v2-history article div,
.profile-v2-history article p,
.profile-v2-history article span{
  font-size:12px!important;
}

/* Если история собрана не article, всё равно сжимаем вложенные поля */
.profile-v2-history .passport-history-card .card,
.profile-v2-history .passport-history-card div[class*="row"],
.profile-v2-history .passport-history-card div[class*="item"]{
  border-radius:12px!important;
}

/* Печатный/PDF вид тоже компактнее */
@media print{
  body{
    background:#fff!important;
  }
  main.profile-layout-v2{
    max-width:100%!important;
  }
  main.profile-layout-v2 > .card,
  .profile-v2-group{
    break-inside:avoid;
  }
  .profile-v2-history article,
  .profile-v2-history .session-card{
    break-inside:avoid;
  }
}

/* Адаптив */
@media(max-width:980px){
  main.profile-layout-v2 > .card:nth-of-type(2),
  main.profile-layout-v2 > .card:nth-of-type(3),
  .profile-v2-networks .profile-v2-group-grid,
  .profile-v2-service .profile-v2-group-grid,
  .profile-v2-related .matches-grid-v1{
    grid-template-columns:1fr!important;
  }

  .profile-v2-subtitle{
    text-align:left!important;
  }
}

@media(max-width:640px){
  main.profile-layout-v2 > .card,
  .profile-v2-group{
    padding:12px!important;
  }

  .access-behavior-card .behavior-grid-v1,
  .geo-grid-v1,
  .known-net-grid-v1,
  .matches-grid-v1{
    grid-template-columns:1fr!important;
  }
}

/* /vpn-access-profile-visual-v3 */
</style>
"""

    if "</head>" in html:
        html = html.replace("</head>", css + "\n</head>", 1)
    else:
        html = css + html

    html += "\n<!-- vpn-access-profile-visual-v3 -->\n"
    return html



def _access_passport_stage_visual_v3(client, user, html):
    try:
        return _vpn_profile_visual_v3(html)
    except Exception as e:
        print(f"access_profile_visual_v3_error={e!r}", flush=True)
        return html

# /vpn-access-profile-visual-v3


# vpn-access-profile-clean-v4

def _v4_table_exists(con, name):
    try:
        return con.execute(
            "select 1 from sqlite_master where type='table' and name=?",
            (name,),
        ).fetchone() is not None
    except Exception:
        return False


def _v4_cols(con, table):
    try:
        return [r["name"] for r in con.execute(f'pragma table_info("{table}")')]
    except Exception:
        return []


def _v4_row_get(row, *names, default=""):
    if not row:
        return default
    for n in names:
        try:
            v = row[n]
            if v is not None and str(v) != "":
                return v
        except Exception:
            pass
    return default


def _v4_ts(v):
    import datetime as _dt
    if v is None or v == "":
        return None
    try:
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return None
            if s.isdigit():
                x = int(s)
            else:
                for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
                    try:
                        return int(_dt.datetime.strptime(s[:26], fmt).timestamp())
                    except Exception:
                        pass
                return None
        else:
            x = int(v)
        if x > 10_000_000_000:
            x = int(x / 1000)
        return x
    except Exception:
        return None


def _v4_fmt_ts(v, short=False):
    import datetime as _dt
    ts = _v4_ts(v)
    if not ts:
        return "—"
    d = _dt.datetime.fromtimestamp(ts)
    return d.strftime("%d.%m %H:%M") if short else d.strftime("%d.%m.%Y %H:%M")


def _v4_duration(a, b):
    ta = _v4_ts(a)
    tb = _v4_ts(b)
    if not ta:
        return "—"
    if not tb:
        import time as _time
        tb = int(_time.time())
    sec = max(0, tb - ta)
    if sec < 60:
        return f"{sec}с"
    m = sec // 60
    if m < 60:
        return f"{m}м"
    h = m // 60
    mm = m % 60
    if h < 24:
        return f"{h}ч {mm}м"
    d = h // 24
    hh = h % 24
    return f"{d}д {hh}ч"


def _v4_human_meta(row, client):
    if not row:
        return client
    bits = []
    for k in ("person_name", "device_label"):
        v = _v4_row_get(row, k)
        if v:
            bits.append(str(v))
    return " · ".join(bits) if bits else client


def _v4_plain_text(html):
    import re as _re
    import html as _html
    x = _re.sub(r"(?is)<script.*?</script>", " ", html or "")
    x = _re.sub(r"(?is)<style.*?</style>", " ", x)
    x = _re.sub(r"(?s)<[^>]+>", " ", x)
    x = _html.unescape(x)
    x = _re.sub(r"\s+", " ", x).strip()
    return x


def _v4_between(text, a, b_list):
    if not text or a not in text:
        return ""
    start = text.find(a) + len(a)
    end = len(text)
    for b in b_list:
        pos = text.find(b, start)
        if pos != -1:
            end = min(end, pos)
    return text[start:end].strip(" ·:-")


def _v4_extract_links(old_html):
    import re as _re
    import html as _html

    out = []
    seen = set()

    for m in _re.finditer(r'<a\b[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', old_html or "", _re.S | _re.I):
        href = _html.unescape(m.group(1))
        label = _v4_plain_text(m.group(2))
        low = label.lower()
        if "скачать" not in low:
            continue
        if not any(x in low for x in ("iphone", "ipad", "android", "windows", "zip", "файл")):
            continue
        key = (href, label)
        if key in seen:
            continue
        seen.add(key)
        out.append((label, href))

    return out[:6]




def _v4_load_profile_data(client, old_html):
    import json as _json
    import sqlite3 as _sqlite3
    import time as _time

    client = safe_client_name(client or "")

    data = {
        "client": client,
        "title": client,
        "subtitle": "",
        "meta": None,
        "latest": None,
        "is_online": False,
        "current_ip": "—",
        "current_provider": "—",
        "last_seen": "—",
        "duration": "—",
        "cert_status": "—",
        "cert_until": "—",
        "files_status": "—",
        "traffic": {},
        "links": _v4_extract_links(old_html),
        "places": [],
        "known": [],
        "geo": [],
        "matches": [],
        "sessions": [],
    }

    plain = _v4_plain_text(old_html)

    data["cert_status"] = _v4_between(plain, "СЕРТИФИКАТ", ["ДЕЙСТВУЕТ ДО", "ФАЙЛЫ"]) or "—"
    data["cert_until"] = _v4_between(plain, "ДЕЙСТВУЕТ ДО", ["ФАЙЛЫ", "СЕЙЧАС"]) or "—"
    data["files_status"] = _v4_between(plain, "ФАЙЛЫ", ["СЕЙЧАС", "ПОСЛЕДНИЙ ВХОД"]) or "—"

    data["traffic"]["current"] = _v4_between(plain, "ТЕКУЩАЯ СЕССИЯ", ["ВСЕГО В ТЕКУЩЕМ СЕАНСЕ"]) or "—"
    data["traffic"]["session_total"] = _v4_between(plain, "ВСЕГО В ТЕКУЩЕМ СЕАНСЕ", ["СЕГОДНЯ"]) or "—"
    data["traffic"]["today"] = _v4_between(plain, "СЕГОДНЯ", ["7 ДНЕЙ"]) or "—"
    data["traffic"]["week"] = _v4_between(plain, "7 ДНЕЙ", ["30 ДНЕЙ"]) or "—"
    data["traffic"]["month"] = _v4_between(plain, "30 ДНЕЙ", ["Файлы профиля", "Сети доступа", "Управление"]) or "—"

    try:
        con = _sqlite3.connect(DB_PATH)
        try:
            con.row_factory = _sqlite3.Row

            if _v4_table_exists(con, "vpn_client_meta"):
                meta = con.execute("""
                    select client, person_name, device_label, device_type, group_name
                    from vpn_client_meta
                    where client=?
                    limit 1
                """, (client,)).fetchone()
                data["meta"] = meta
                data["title"] = _v4_row_get(meta, "person_name", default=client) or client
                dev = _v4_row_get(meta, "device_label", "device_type", default="")
                if dev:
                    data["subtitle"] = f"{dev} · {client}"
                else:
                    data["subtitle"] = client

            if _v4_table_exists(con, "vpn_sessions"):
                latest = con.execute("""
                    select *
                    from vpn_sessions
                    where client=?
                    order by coalesce(last_seen, first_seen) desc
                    limit 1
                """, (client,)).fetchone()

                data["latest"] = latest

                if latest:
                    ip = _v4_row_get(latest, "remote_ip", "ip", "client_ip", default="—")
                    data["current_ip"] = str(ip or "—")
                    data["current_provider"] = _v4_provider_for_ip(con, data["current_ip"])

                    first_seen = _v4_row_get(latest, "first_seen", "started_at", "start_ts")
                    last_seen = _v4_row_get(latest, "last_seen", "updated_at", "seen_at", default=first_seen)

                    data["last_seen"] = _v4_fmt_ts(last_seen, short=True)
                    data["duration"] = _v4_duration(first_seen, last_seen)

                    lts = _v4_ts(last_seen)
                    if lts and int(_time.time()) - lts < 900:
                        data["is_online"] = True

                for r in con.execute("""
                    select *
                    from vpn_sessions
                    where client=?
                    order by coalesce(last_seen, first_seen) desc
                    limit 10
                """, (client,)):
                    ip = str(_v4_row_get(r, "remote_ip", "ip", "client_ip", default="—") or "—")
                    first_seen = _v4_row_get(r, "first_seen", "started_at", "start_ts")
                    last_seen = _v4_row_get(r, "last_seen", "updated_at", "seen_at", default=first_seen)
                    data["sessions"].append({
                        "start": _v4_fmt_ts(first_seen, short=True),
                        "last": _v4_fmt_ts(last_seen, short=True),
                        "ip": ip,
                        "provider": _v4_provider_for_ip(con, ip),
                        "duration": _v4_duration(first_seen, last_seen),
                        "online": bool(_v4_ts(last_seen) and int(_time.time()) - _v4_ts(last_seen) < 900),
                    })

            if _v4_table_exists(con, "vpn_behavior_places"):
                for r in con.execute("""
                    select place_label, provider, confidence, sessions, days, ips,
                           main_ip, shared_clients, work_pct, evening_pct, night_pct, weekend_pct
                    from vpn_behavior_places
                    where client=?
                    order by confidence desc, sessions desc
                    limit 6
                """, (client,)):
                    data["places"].append(r)

            if _v4_table_exists(con, "known_client_networks") and _v4_table_exists(con, "vpn_behavior_places"):
                for r in con.execute("""
                    select k.ip, k.host, k.title, k.customer, k.object_name, k.status,
                           p.place_label, p.provider, p.confidence, p.sessions, p.days
                    from vpn_behavior_places p
                    join known_client_networks k on k.ip = p.main_ip
                    where p.client=?
                    order by p.confidence desc, p.sessions desc
                    limit 4
                """, (client,)):
                    data["known"].append(r)

            if _v4_table_exists(con, "ip_geo_cache") and _v4_table_exists(con, "vpn_behavior_places"):
                for r in con.execute("""
                    select p.place_label, p.provider, p.confidence, p.sessions, p.days, p.main_ip,
                           g.country_code, g.region, g.city, g.isp, g.org, g.mobile, g.proxy, g.hosting
                    from vpn_behavior_places p
                    join ip_geo_cache g on g.ip=p.main_ip and g.status='success'
                    where p.client=?
                    order by p.confidence desc, p.sessions desc
                    limit 5
                """, (client,)):
                    data["geo"].append(r)

            if _v4_table_exists(con, "vpn_behavior_matches"):
                meta_map = {}
                if _v4_table_exists(con, "vpn_client_meta"):
                    for m in con.execute("""
                        select client, person_name, device_label, device_type, group_name
                        from vpn_client_meta
                    """):
                        meta_map[m["client"]] = m

                for r in con.execute("""
                    select client_a, client_b, score, label,
                           shared_ip_count, stable_ip_count, mobile_ip_count,
                           max_clients_on_ip, pair_sessions, providers_json
                    from vpn_behavior_matches
                    where (client_a=? or client_b=?)
                      and score >= 50
                    order by score desc, shared_ip_count desc, pair_sessions desc
                    limit 5
                """, (client, client)):
                    other = r["client_b"] if r["client_a"] == client else r["client_a"]
                    data["matches"].append({
                        "row": r,
                        "other": other,
                        "name": _v4_human_meta(meta_map.get(other), other),
                    })

        finally:
            con.close()

    except Exception as e:
        print(f"v4_load_profile_error={e!r}", flush=True)

    return run_profile_data_pipeline(
        client,
        old_html,
        data,
        (
            _v4_profile_stage_v43,
            _v4_profile_stage_v44,
            _v4_profile_stage_geo,
            _v4_profile_stage_online,
            _v4_profile_stage_normalize,
        ),
    )


def _v4_badge(text, cls=""):
    return f'<span class="v4-badge {esc(cls)}">{esc(text)}</span>'


def _v4_render_profile(client, user=None, old_html=""):
    import json as _json
    import urllib.parse as _urlparse

    d = _v4_load_profile_data(client, old_html)
    client = d["client"]

    online_cls = "ok" if d["is_online"] else "muted"
    online_text = "подключён сейчас" if d["is_online"] else "не онлайн"

    link_buttons = ""
    if d["links"]:
        for label, href in d["links"]:
            link_buttons += f'<a class="v4-btn" href="{esc(href)}">{esc(label)}</a>'
    else:
        link_buttons = '<span class="v4-muted">ссылки скачивания не найдены в старом шаблоне</span>'

    known_html = ""
    for r in d["known"]:
        host = f'<span>{esc(r["host"])}</span>' if r["host"] else ""
        known_html += f"""
        <div class="v4-known">
          <div>
            <strong>{esc(r["title"] or "Известная сеть")}</strong>
            <small>{esc(r["customer"] or "—")} · {esc(r["object_name"] or "—")}</small>
            <small>{esc(r["ip"] or "—")} {host}</small>
          </div>
          <b>{esc(r["status"] or "active")}</b>
        </div>
        """

    places_html = ""
    for r in d["places"]:
        label = r["place_label"] or "место"
        provider = r["provider"] or "—"
        conf = int(r["confidence"] or 0)
        sessions = int(r["sessions"] or 0)
        days = int(r["days"] or 0)
        ips = int(r["ips"] or 0)
        main_ip = r["main_ip"] or "—"
        shared = int(r["shared_clients"] or 0)

        extra = []
        for key, label2 in (("work_pct", "рабочее"), ("evening_pct", "вечер"), ("weekend_pct", "выходные")):
            try:
                v = int(r[key] or 0)
                if v >= 50:
                    extra.append(f"{label2} {v}%")
            except Exception:
                pass

        shared_s = f" · общий с {shared}" if shared >= 2 else ""

        places_html += f"""
        <div class="v4-place">
          <div class="v4-place-head">
            <strong>{esc(provider)}</strong>
            <span>{conf}/5</span>
          </div>
          <small>{esc(label)} · {esc(main_ip)}{esc(shared_s)}</small>
          <div class="v4-pills">
            {_v4_badge(str(sessions) + " сесс.")}
            {_v4_badge(str(days) + " дн.")}
            {_v4_badge(str(ips) + " IP")}
            {''.join(_v4_badge(x) for x in extra[:2])}
          </div>
        </div>
        """

    geo_html = ""
    for r in d["geo"]:
        loc = " · ".join([x for x in (r["country_code"], r["region"], r["city"]) if x]) or "—"
        isp = r["isp"] or r["org"] or r["provider"] or "—"
        flags = []
        for key, text in (("mobile", "mobile"), ("proxy", "proxy"), ("hosting", "hosting")):
            try:
                if int(r[key] or 0):
                    flags.append(text)
            except Exception:
                pass
        geo_html += f"""
        <div class="v4-geo-row">
          <strong>{esc(loc)}</strong>
          <span>{esc(isp)}</span>
          <small>{esc(r["main_ip"] or "—")} · {esc(" · ".join(flags))}</small>
        </div>
        """

    matches_html = ""
    if d["matches"]:
        for m in d["matches"]:
            r = m["row"]
            other = m["other"]
            href = "/access?client=" + _urlparse.quote(other)
            try:
                providers = _json.loads(r["providers_json"] or "{}")
            except Exception:
                providers = {}
            provider_line = ", ".join([
                f"{p}×{c}" if int(c or 0) > 1 else str(p)
                for p, c in list(providers.items())[:3]
            ]) or "—"

            matches_html += f"""
            <a class="v4-match" href="{esc(href)}">
              <div>
                <strong>{esc(m["name"])}</strong>
                <small>{esc(other)}</small>
                <small>{esc(provider_line)}</small>
              </div>
              <b>{int(r["score"] or 0)}/100</b>
            </a>
            """
    else:
        matches_html = '<div class="v4-empty">Уверенных связей от 50/100 пока нет.</div>'

    sessions_html = ""
    for s in d["sessions"]:
        cls = " online" if s["online"] else ""
        sessions_html += f"""
        <tr class="{cls}">
          <td>{esc("онлайн" if s["online"] else "завершена")}</td>
          <td>{esc(s["start"])}</td>
          <td>{esc(s["last"])}</td>
          <td>{esc(s["duration"])}</td>
          <td><code>{esc(s["ip"])}</code></td>
          <td>{esc(s["provider"])}</td>
        </tr>
        """

    if not sessions_html:
        sessions_html = '<tr><td colspan="6">История пока пустая.</td></tr>'

    traffic = d["traffic"]

    body = f"""
<style>
/* vpn-access-profile-clean-v4 */
.v4-page{{display:grid;gap:14px}}
.v4-hero{{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:18px;border:1px solid rgba(148,163,184,.16);background:linear-gradient(180deg,rgba(255,255,255,.045),rgba(255,255,255,.02));border-radius:24px}}
.v4-hero h1{{margin:0;font-size:34px;letter-spacing:-.06em;line-height:.98}}
.v4-hero p{{margin:7px 0 0;color:var(--muted);font-weight:800}}
.v4-status{{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end}}
.v4-badge{{display:inline-flex;align-items:center;gap:5px;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.14);border-radius:999px;padding:5px 8px;font-size:12px;font-weight:900;color:var(--muted);white-space:nowrap}}
.v4-badge.ok{{color:#58d178;background:rgba(88,209,120,.1);border-color:rgba(88,209,120,.22)}}
.v4-badge.warn{{color:#ffd166;background:rgba(255,209,102,.09);border-color:rgba(255,209,102,.2)}}
.v4-badge.danger{{color:#ff8a8a;background:rgba(255,90,90,.1);border-color:rgba(255,90,90,.22)}}
.v4-grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}}
.v4-card{{border:1px solid rgba(148,163,184,.15);background:rgba(255,255,255,.026);border-radius:20px;padding:14px;min-width:0}}
.v4-card h2{{margin:0 0 10px;font-size:22px;letter-spacing:-.04em}}
.v4-card h3{{margin:0 0 8px;font-size:16px}}
.v4-metric small,.v4-muted{{display:block;color:var(--muted);font-size:12px;font-weight:850;letter-spacing:.04em;text-transform:uppercase}}
.v4-metric strong{{display:block;margin-top:5px;font-size:22px;line-height:1.05;overflow-wrap:anywhere}}
.v4-metric span{{display:block;margin-top:4px;color:var(--muted);font-size:12px;line-height:1.25}}
.v4-main{{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(0,.85fr);gap:10px}}
.v4-actions{{display:flex;gap:8px;flex-wrap:wrap}}
.v4-btn{{display:inline-flex;align-items:center;justify-content:center;text-decoration:none;color:var(--text);border:1px solid rgba(148,163,184,.18);background:rgba(255,255,255,.045);border-radius:14px;padding:10px 12px;font-weight:950;font-size:13px}}
.v4-btn.primary{{background:rgba(90,145,255,.16);border-color:rgba(90,145,255,.28);color:#bcd5ff}}
.v4-known{{display:flex;justify-content:space-between;gap:10px;border:1px solid rgba(82,210,115,.24);background:rgba(82,210,115,.06);border-radius:16px;padding:11px;margin-bottom:8px}}
.v4-known strong,.v4-place strong,.v4-match strong,.v4-geo-row strong{{display:block;font-size:15px;line-height:1.15}}
.v4-known small,.v4-place small,.v4-match small,.v4-geo-row small{{display:block;color:var(--muted);font-size:12px;margin-top:4px;overflow-wrap:anywhere}}
.v4-known b,.v4-match b{{align-self:flex-start;border:1px solid rgba(255,255,255,.1);background:rgba(0,0,0,.14);border-radius:999px;padding:5px 8px;color:var(--muted);font-size:12px}}
.v4-places{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}}
.v4-place{{border:1px solid rgba(148,163,184,.14);background:rgba(255,255,255,.022);border-radius:16px;padding:10px}}
.v4-place-head{{display:flex;justify-content:space-between;gap:8px}}
.v4-place-head span{{color:var(--muted);font-weight:950;font-size:12px}}
.v4-pills{{display:flex;gap:5px;flex-wrap:wrap;margin-top:8px}}
.v4-geo{{display:grid;gap:7px}}
.v4-geo-row{{border:1px solid rgba(148,163,184,.13);background:rgba(255,255,255,.02);border-radius:15px;padding:9px}}
.v4-geo-row span{{display:block;color:var(--muted);font-size:12px;margin-top:4px}}
.v4-matches{{display:grid;gap:7px}}
.v4-match{{display:flex;justify-content:space-between;gap:10px;text-decoration:none;color:inherit;border:1px solid rgba(255,209,102,.18);background:rgba(255,209,102,.035);border-radius:15px;padding:10px}}
.v4-empty{{border:1px dashed rgba(148,163,184,.22);background:rgba(148,163,184,.035);border-radius:15px;padding:12px;color:var(--muted)}}
.v4-table-wrap{{overflow:auto;border:1px solid rgba(148,163,184,.14);border-radius:16px}}
.v4-table{{width:100%;border-collapse:collapse;font-size:13px}}
.v4-table th{{text-align:left;color:var(--muted);font-size:11px;letter-spacing:.06em;text-transform:uppercase;padding:10px;border-bottom:1px solid rgba(148,163,184,.13);white-space:nowrap}}
.v4-table td{{padding:10px;border-bottom:1px solid rgba(148,163,184,.08);vertical-align:top;white-space:nowrap}}
.v4-table tr:last-child td{{border-bottom:0}}
.v4-table tr.online td:first-child{{color:#58d178;font-weight:950}}
.v4-table code{{font-family:inherit;font-weight:900;color:var(--text)}}
.v4-admin{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
.v4-note{{color:var(--muted);font-size:13px;line-height:1.35}}
@media(max-width:980px){{.v4-grid,.v4-main,.v4-admin{{grid-template-columns:1fr 1fr}}.v4-hero{{display:block}}.v4-status{{justify-content:flex-start;margin-top:12px}}}}
@media(max-width:640px){{.v4-grid,.v4-main,.v4-admin,.v4-places{{grid-template-columns:1fr}}.v4-hero h1{{font-size:30px}}.v4-table{{font-size:12px}}}}
/* /vpn-access-profile-clean-v4 */
</style>

<div class="v4-page vpn-access-profile-clean-v4">
  <section class="v4-hero">
    <div>
      <h1>{esc(d["title"])}</h1>
      <p>{esc(d["subtitle"])}</p>
    </div>
    <div class="v4-status">
      {_v4_badge(online_text, online_cls)}
      {_v4_badge("сертификат: " + str(d["cert_status"]).split()[0])}
      {_v4_badge("файлы: " + str(d["files_status"]).split()[0])}
    </div>
  </section>

  <section class="v4-grid">
    <div class="v4-card v4-metric">
      <small>Внешний IP</small>
      <strong>{esc(d["current_ip"])}</strong>
      <span>{esc(d["current_provider"])}</span>
    </div>
    <div class="v4-card v4-metric">
      <small>Последний вход</small>
      <strong>{esc(d["last_seen"])}</strong>
      <span>длительность: {esc(d["duration"])}</span>
    </div>
    <div class="v4-card v4-metric">
      <small>Сертификат</small>
      <strong>{esc(str(d["cert_until"]).split()[0] if d["cert_until"] else "—")}</strong>
      <span>{esc(d["cert_status"])}</span>
    </div>
    <div class="v4-card v4-metric">
      <small>30 дней</small>
      <strong>{esc(str(traffic.get("month") or "—").split("↓")[0].strip())}</strong>
      <span>{esc(traffic.get("week") or "7 дней: —")}</span>
    </div>
  </section>

  <section class="v4-card">
    <h2>Файлы профиля</h2>
    <div class="v4-actions">
      {link_buttons}
    </div>
  </section>

  <section class="v4-main">
    <div class="v4-card">
      <h2>Сети доступа</h2>
      {known_html}
      <div class="v4-places">
        {places_html or '<div class="v4-empty">Поведение ещё не собрано.</div>'}
      </div>
    </div>

    <div class="v4-card">
      <h2>География</h2>
      <div class="v4-geo">
        {geo_html or '<div class="v4-empty">Гео по основным IP пока не определено.</div>'}
      </div>
    </div>
  </section>

  <section class="v4-main">
    <div class="v4-card">
      <h2>Связанные доступы</h2>
      <div class="v4-matches">
        {matches_html}
      </div>
    </div>

    <div class="v4-card">
      <h2>Трафик</h2>
      <div class="v4-grid" style="grid-template-columns:1fr 1fr">
        <div class="v4-metric">
          <small>Текущая сессия</small>
          <strong>{esc(traffic.get("session_total") or "—")}</strong>
          <span>{esc(traffic.get("current") or "")}</span>
        </div>
        <div class="v4-metric">
          <small>Сегодня</small>
          <strong>{esc(str(traffic.get("today") or "—").split("↓")[0].strip())}</strong>
          <span>{esc(traffic.get("today") or "")}</span>
        </div>
      </div>
    </div>
  </section>

  <section class="v4-card">
    <h2>История сессий</h2>
    <div class="v4-table-wrap">
      <table class="v4-table">
        <thead>
          <tr>
            <th>Статус</th>
            <th>Начало</th>
            <th>Последний раз</th>
            <th>Длит.</th>
            <th>IP</th>
            <th>Сеть</th>
          </tr>
        </thead>
        <tbody>{sessions_html}</tbody>
      </table>
    </div>
  </section>

  <section class="v4-card">
    <h2>Админка</h2>
    <p class="v4-note">Группа доступа и удаление оставлены в старом техническом шаблоне. После утверждения нового вида перенесём сюда формы аккуратно, без старой верстки.</p>
  </section>
</div>
"""

    return support_shell_page(d["title"], body, d["subtitle"])



def _access_passport_stage_clean_v4(client, user, html):
    try:
        old_html = (
            access_passport_page_before_clean_v4(client, user)
            if html is None
            else html
        )
        return _v4_render_profile(client, user, old_html)
    except Exception as e:
        print(f"access_profile_clean_v4_error={e!r}", flush=True)
        return access_passport_page_before_clean_v4(client, user)

# /vpn-access-profile-clean-v4


# vpn-known-network-dedupe-v1

def _vpn_dedupe_find_div_end_v1(html, start):
    import re as _re

    depth = 0
    pos = start

    for m in _re.finditer(r'</?div\b[^>]*>', html[start:], _re.I):
        token = m.group(0)
        abs_start = start + m.start()
        abs_end = start + m.end()

        if token.startswith("</"):
            depth -= 1
            if depth <= 0:
                return abs_end
        else:
            depth += 1

        pos = abs_end

    return -1


def _vpn_dedupe_remove_blocks_with_ip_v1(html, block_class, known_ips):
    if not html or not known_ips:
        return html

    out = []
    pos = 0
    needle = f'<div class="{block_class}"'

    while True:
        start = html.find(needle, pos)
        if start == -1:
            out.append(html[pos:])
            break

        out.append(html[pos:start])

        end = _vpn_dedupe_find_div_end_v1(html, start)
        if end == -1:
            out.append(html[start:])
            break

        block = html[start:end]
        if any(ip in block for ip in known_ips):
            # выкидываем дублирующую карточку
            pass
        else:
            out.append(block)

        pos = end

    return "".join(out)


def _vpn_dedupe_known_networks_v1(html, client, old_html):
    if "vpn-access-profile-clean-v4" not in html:
        return html

    try:
        d = _v4_load_profile_data(client, old_html)
        known_ips = []

        for r in d.get("known") or []:
            ip = str(r["ip"] or "").strip()
            if ip:
                known_ips.append(ip)

        known_ips = sorted(set(known_ips))
        if not known_ips:
            return html

        # Если IP уже подписан как клиентский MikroTik, не показываем второй раз
        # как поведение провайдера и третий раз как гео провайдера.
        html = _vpn_dedupe_remove_blocks_with_ip_v1(html, "v4-place", known_ips)
        html = _vpn_dedupe_remove_blocks_with_ip_v1(html, "v4-geo-row", known_ips)

        # Добавляем в карточку известной сети короткую строку, что поведенческие
        # данные по этому IP намеренно поглощены этой карточкой.
        for ip in known_ips:
            marker = ip
            p = html.find(marker)
            if p == -1:
                continue

            block_start = html.rfind('<div class="v4-known"', 0, p)
            if block_start == -1:
                continue

            block_end = _vpn_dedupe_find_div_end_v1(html, block_start)
            if block_end == -1:
                continue

            block = html[block_start:block_end]
            if "v4-known-source" in block:
                continue

            note = '<small class="v4-known-source">основное имя сети из Pulse; дубль провайдера скрыт</small>'
            insert_at = block.find("</div>")
            if insert_at != -1:
                block = block[:insert_at] + note + block[insert_at:]
                html = html[:block_start] + block + html[block_end:]

        css = """
<style>
/* vpn-known-network-dedupe-v1 */
.v4-known-source{
  color:#8fb69a!important;
  margin-top:5px!important;
}
</style>
"""
        if "</head>" in html:
            html = html.replace("</head>", css + "\n</head>", 1)
        else:
            html = css + html

        html += "\n<!-- vpn-known-network-dedupe-v1 -->\n"

    except Exception as e:
        print(f"known_network_dedupe_error={e!r}", flush=True)

    return html



def _access_passport_stage_known_dedupe(client, user, html):
    old_html = ""
    try:
        if html is None:
            html = access_passport_page_through_clean_v4(client, user)
        try:
            old_html = access_passport_page_before_clean_v4(client, user)
        except Exception:
            old_html = html
        return _vpn_dedupe_known_networks_v1(html, client, old_html)
    except Exception as e:
        print(f"known_network_dedupe_wrapper_error={e!r}", flush=True)
        return access_passport_page_through_clean_v4(client, user)

# /vpn-known-network-dedupe-v1


# vpn-known-network-neutral-v1

def _vpn_known_neutral_find_div_end_v1(html, start):
    import re as _re

    depth = 0

    for m in _re.finditer(r'</?div\b[^>]*>', html[start:], _re.I):
        token = m.group(0)
        abs_end = start + m.end()

        if token.startswith("</"):
            depth -= 1
            if depth <= 0:
                return abs_end
        else:
            depth += 1

    return -1


def _vpn_known_neutral_clean_blocks_v1(html):
    if "v4-known" not in html:
        return html

    out = []
    pos = 0
    needle = '<div class="v4-known"'

    while True:
        start = html.find(needle, pos)
        if start == -1:
            out.append(html[pos:])
            break

        out.append(html[pos:start])

        end = _vpn_known_neutral_find_div_end_v1(html, start)
        if end == -1:
            out.append(html[start:])
            break

        block = html[start:end]

        # Убираем сбивающий с толку бейдж active.
        block = block.replace("<b>active</b>", "")
        block = block.replace("<b>Active</b>", "")

        # Если попадётся maintenance/stale — оставляем, но по-русски.
        block = block.replace("<b>maintenance</b>", '<b class="v4-known-status-muted">обслуживание</b>')
        block = block.replace("<b>stale</b>", '<b class="v4-known-status-muted">устарело</b>')

        # Нормальная человеческая подпись вместо зелёного “основное имя сети...”
        block = block.replace(
            "основное имя сети из Pulse; дубль провайдера скрыт",
            "совпало с Pulse"
        )

        out.append(block)
        pos = end

    return "".join(out)



def _access_passport_stage_known_neutral(client, user, html):

    try:
        html = _vpn_known_neutral_clean_blocks_v1(html)

        css = """
<style>
/* vpn-known-network-neutral-v1 */

/* Известная сеть — это справочник, а не онлайн/успех. Поэтому без зелёнки. */
.v4-known{
  border-color:rgba(148,163,184,.18)!important;
  background:rgba(255,255,255,.026)!important;
}

.v4-known strong{
  color:var(--text)!important;
}

.v4-known-source{
  color:var(--muted)!important;
  font-weight:800!important;
}

.v4-known b{
  color:var(--muted)!important;
  background:rgba(0,0,0,.14)!important;
  border-color:rgba(255,255,255,.10)!important;
}

.v4-known-status-muted{
  color:var(--muted)!important;
}

/* На старых карточках, если где-то остались, тоже убираем зелёный смысл. */
.known-net-card-v1{
  border-color:rgba(148,163,184,.18)!important;
  background:rgba(255,255,255,.026)!important;
}

.known-net-card-v1 .known-top-v1 span{
  display:none!important;
}

/* /vpn-known-network-neutral-v1 */
</style>
"""

        if "</head>" in html:
            html = html.replace("</head>", css + "\n</head>", 1)
        else:
            html = css + html

        html += "\n<!-- vpn-known-network-neutral-v1 -->\n"
        return html

    except Exception as e:
        print(f"known_network_neutral_error={e!r}", flush=True)
        return html

# /vpn-known-network-neutral-v1


# vpn-known-network-rich-v1

def _vpn_known_rich_find_div_end_v1(html, start):
    import re as _re

    depth = 0

    for m in _re.finditer(r'</?div\b[^>]*>', html[start:], _re.I):
        token = m.group(0)
        abs_end = start + m.end()

        if token.startswith("</"):
            depth -= 1
            if depth <= 0:
                return abs_end
        else:
            depth += 1

    return -1


def _vpn_known_rich_label_v1(place_label, customer, object_name):
    p = str(place_label or "").strip()
    low = p.lower()

    if "офис" in low:
        return p
    if "дом" in low:
        return p
    if "мобиль" in low:
        return p

    # Раз сеть есть в Pulse как MikroTik клиента, то для VPN это минимум клиентская/офисная сеть-кандидат.
    return "🏢 клиентская сеть / офис-кандидат"


def _vpn_known_rich_load_v1(client):
    import sqlite3 as _sqlite3

    client = safe_client_name(client or "")
    if not client:
        return []

    try:
        con = _sqlite3.connect(DB_PATH)
        try:
            con.row_factory = _sqlite3.Row

            if not _v4_table_exists(con, "known_client_networks"):
                return []

            if not _v4_table_exists(con, "vpn_behavior_places"):
                return []

            rows = con.execute("""
                select
                  k.ip,
                  k.host,
                  k.title,
                  k.customer,
                  k.object_name,
                  k.status,
                  k.source,
                  p.place_label,
                  p.provider,
                  p.confidence,
                  p.sessions,
                  p.days,
                  p.ips,
                  p.main_ip,
                  p.shared_clients,
                  p.work_pct,
                  p.evening_pct,
                  p.night_pct,
                  p.weekend_pct
                from vpn_behavior_places p
                join known_client_networks k
                  on k.ip = p.main_ip
                where p.client=?
                order by p.confidence desc, p.sessions desc
                limit 6
            """, (client,)).fetchall()

            return rows
        finally:
            con.close()

    except Exception as e:
        print(f"known_rich_load_error={e!r}", flush=True)
        return []


def _vpn_known_rich_cards_v1(client):
    rows = _vpn_known_rich_load_v1(client)
    if not rows:
        return ""

    cards = []

    for r in rows:
        title = r["title"] or "Известная сеть"
        customer = r["customer"] or "—"
        obj = r["object_name"] or "—"
        ip = r["ip"] or r["main_ip"] or "—"
        host = r["host"] or ""
        provider = r["provider"] or "—"
        conf = int(r["confidence"] or 0)
        sessions = int(r["sessions"] or 0)
        days = int(r["days"] or 0)
        ips = int(r["ips"] or 0)
        shared = int(r["shared_clients"] or 0)
        status = (r["status"] or "").lower()

        label = _vpn_known_rich_label_v1(r["place_label"], customer, obj)

        chips = [
            f"{sessions} сесс.",
            f"{days} дн.",
            f"{ips} IP",
        ]

        if shared >= 2:
            chips.append(f"общий с {shared}")

        try:
            work = int(r["work_pct"] or 0)
            if work >= 50:
                chips.append(f"рабочее {work}%")
        except Exception:
            pass

        try:
            evening = int(r["evening_pct"] or 0)
            if evening >= 50:
                chips.append(f"вечер {evening}%")
        except Exception:
            pass

        try:
            weekend = int(r["weekend_pct"] or 0)
            if weekend >= 50:
                chips.append(f"выходные {weekend}%")
        except Exception:
            pass

        chips_html = "".join(_v4_badge(x) for x in chips[:6])

        status_html = ""
        if status == "maintenance":
            status_html = '<b class="v4-known-status-muted">обслуживание</b>'
        elif status == "stale":
            status_html = '<b class="v4-known-status-muted">устарело</b>'

        host_text = f" · {host}" if host else ""

        cards.append(f"""
        <div class="v4-known v4-known-rich">
          <div class="v4-known-main">
            <strong>{esc(title)}</strong>
            <small>{esc(customer)} · {esc(obj)}</small>
            <small>{esc(ip)}{esc(host_text)}</small>
            <small class="v4-known-source">Источник: Pulse · {esc(label)} · {esc(provider)}</small>
            <div class="v4-pills v4-known-pills">
              {chips_html}
            </div>
          </div>
          <b>{conf}/5</b>
          {status_html}
        </div>
        """)

    return "\n".join(cards)



def _access_passport_stage_known_rich(client, user, html):

    try:
        rich = _vpn_known_rich_cards_v1(client)
        if not rich:
            return html

        # Заменяем все старые v4-known карточки на новые богатые карточки.
        start = html.find('<div class="v4-known"')
        if start == -1:
            return html

        # Удаляем подряд идущие known-карточки.
        pos = start
        while True:
            if html.find('<div class="v4-known"', pos) != pos:
                break

            end = _vpn_known_rich_find_div_end_v1(html, pos)
            if end == -1:
                break

            # пропускаем пробелы/переводы после карточки
            pos = end
            while pos < len(html) and html[pos].isspace():
                pos += 1

        html = html[:start] + rich + "\n" + html[pos:]

        css = """
<style>
/* vpn-known-network-rich-v1 */
.v4-known-rich{
  border-color:rgba(148,163,184,.20)!important;
  background:rgba(255,255,255,.028)!important;
  align-items:flex-start!important;
}

.v4-known-rich .v4-known-main{
  min-width:0;
}

.v4-known-rich strong{
  color:var(--text)!important;
}

.v4-known-rich > b{
  flex:0 0 auto;
  color:var(--muted)!important;
  background:rgba(0,0,0,.14)!important;
  border:1px solid rgba(255,255,255,.10)!important;
  border-radius:999px!important;
  padding:5px 8px!important;
  font-size:12px!important;
}

.v4-known-pills{
  margin-top:8px!important;
}

.v4-known-source{
  color:var(--muted)!important;
  font-weight:850!important;
}

.v4-known-status-muted{
  color:var(--muted)!important;
  background:rgba(0,0,0,.14)!important;
  border:1px solid rgba(255,255,255,.10)!important;
  border-radius:999px!important;
  padding:5px 8px!important;
  font-size:12px!important;
}
/* /vpn-known-network-rich-v1 */
</style>
"""

        if "</head>" in html:
            html = html.replace("</head>", css + "\n</head>", 1)
        else:
            html = css + html

        html += "\n<!-- vpn-known-network-rich-v1 -->\n"
        return html

    except Exception as e:
        print(f"known_network_rich_error={e!r}", flush=True)
        return html

# /vpn-known-network-rich-v1


# vpn-access-profile-clean-v43

def _v43_empty(x):
    x = str(x or "").strip()
    return x in ("", "—", "-", "None", "none")


def _v43_between_ci(text, label, stops):
    text = text or ""
    low = text.lower()
    lab = label.lower()

    pos = low.find(lab)
    if pos == -1:
        return ""

    start = pos + len(label)
    end = len(text)

    for stop in stops:
        p = low.find(stop.lower(), start)
        if p != -1:
            end = min(end, p)

    out = text[start:end].replace("·", " ")
    out = " ".join(out.split())
    return out.strip(" :-")




def _v43_is_mobile(provider, place_label=""):
    x = (str(provider or "") + " " + str(place_label or "")).lower()
    return any(w in x for w in (
        "билайн", "vimpelcom", "beeline", "as16345",
        "мегафон", "megafon",
        "мтс", "mts", "mobile telesystems",
        "tele2", "t2", "yota", "йота",
        "мобиль"
    ))






def _v4_profile_stage_v43(client, old_html, d):

    try:
        import sqlite3 as _sqlite3

        plain = _v4_plain_text(old_html)

        cert_status = _v43_between_ci(plain, "СЕРТИФИКАТ", ["ДЕЙСТВУЕТ ДО", "ФАЙЛЫ"])
        cert_until = _v43_between_ci(plain, "ДЕЙСТВУЕТ ДО", ["ФАЙЛЫ", "СЕЙЧАС"])
        files_status = _v43_between_ci(plain, "ФАЙЛЫ", ["СЕЙЧАС", "ПОСЛЕДНИЙ ВХОД"])

        if _v43_empty(d.get("cert_status")) and cert_status:
            d["cert_status"] = cert_status
        if _v43_empty(d.get("cert_until")) and cert_until:
            d["cert_until"] = cert_until
        if _v43_empty(d.get("files_status")) and files_status:
            d["files_status"] = files_status

        top_network = _v43_between_ci(plain, "СЕТЬ", ["ДЛИТЕЛЬНОСТЬ", "Трафик", "ТРАФИК"])
        if top_network and len(top_network) < 40 and (
            _v43_empty(d.get("current_provider"))
            or str(d.get("current_provider")).lower().startswith("as")
            or "vimpelcom" in str(d.get("current_provider")).lower()
        ):
            d["current_provider"] = top_network

        traffic = dict(d.get("traffic") or {})
        vals = {
            "current": _v43_between_ci(plain, "ТЕКУЩАЯ СЕССИЯ", ["ВСЕГО В ТЕКУЩЕМ СЕАНСЕ"]),
            "session_total": _v43_between_ci(plain, "ВСЕГО В ТЕКУЩЕМ СЕАНСЕ", ["СЕГОДНЯ"]),
            "today": _v43_between_ci(plain, "СЕГОДНЯ", ["7 ДНЕЙ"]),
            "week": _v43_between_ci(plain, "7 ДНЕЙ", ["30 ДНЕЙ"]),
            "month": _v43_between_ci(plain, "30 ДНЕЙ", ["Файлы профиля", "Сети доступа", "Управление", "Профиль и админка"]),
        }

        for k, v in vals.items():
            if _v43_empty(traffic.get(k)) and v:
                traffic[k] = v

        d["traffic"] = traffic
        d["current_provider"] = _v43_nice_provider(d.get("current_provider"))

        for sess in d.get("sessions") or []:
            sess["provider"] = _v43_nice_provider(sess.get("provider"))

        # Нормализуем и склеиваем мобильные места.
        # Билайн + “— место-кандидат” с тем же ASN превращаются в одну мобильную карточку.
        con = None
        try:
            con = _sqlite3.connect(DB_PATH)
            con.row_factory = _sqlite3.Row
        except Exception:
            con = None

        try:
            merged = {}

            for r in d.get("places") or []:
                raw_provider = r["provider"] or "—"
                main_ip = r["main_ip"] or ""
                place_label = r["place_label"] or "место"

                provider = _v43_nice_provider(raw_provider)

                if _v43_empty(provider) and con is not None:
                    provider = _v4_provider_for_ip(con, main_ip)

                if _v43_empty(provider):
                    provider = "—"

                mobile = _v43_is_mobile(provider, place_label)

                if mobile:
                    key = ("mobile", provider if provider != "—" else "мобильная сеть")
                    label = "📱 мобильная сеть"
                else:
                    key = ("normal", provider, place_label)
                    label = place_label

                item = merged.setdefault(key, {
                    "provider": provider,
                    "place_label": label,
                    "confidence": 0,
                    "sessions": 0,
                    "days": 0,
                    "ips": 0,
                    "main_ip": "",
                    "main_ips": [],
                    "shared_clients": 0,
                    "work_pct": 0,
                    "evening_pct": 0,
                    "night_pct": 0,
                    "weekend_pct": 0,
                })

                item["confidence"] = max(item["confidence"], int(r["confidence"] or 0))
                item["sessions"] += int(r["sessions"] or 0)
                item["days"] += int(r["days"] or 0)
                item["ips"] += int(r["ips"] or 0)
                item["shared_clients"] = max(item["shared_clients"], int(r["shared_clients"] or 0))

                for pct in ("work_pct", "evening_pct", "night_pct", "weekend_pct"):
                    try:
                        item[pct] = max(item[pct], int(r[pct] or 0))
                    except Exception:
                        pass

                if main_ip and main_ip not in item["main_ips"]:
                    item["main_ips"].append(main_ip)

        finally:
            if con is not None:
                try:
                    con.close()
                except Exception:
                    pass

        places = []
        for item in merged.values():
            if item["main_ips"]:
                item["main_ip"] = " · ".join(item["main_ips"][:3])
            places.append(item)

        d["places"] = sorted(
            places,
            key=lambda x: (-x["confidence"], -x["sessions"], x["provider"])
        )

    except Exception as e:
        print(f"v43_load_fix_error={e!r}", flush=True)

    return d



def _access_passport_stage_clean_v43(client, user, html):

    try:
        css = """
<style>
/* vpn-access-profile-clean-v43 */

/* Прячем внешний H1 shell-страницы: внутри v4 уже есть нормальная шапка профиля */
body:has(.vpn-access-profile-clean-v4) main > h1:first-of-type,
body:has(.vpn-access-profile-clean-v4) main > h1:first-of-type + p{
  display:none!important;
}

/* На телефоне метрики не должны быть огромными вертикальными плитами */
@media(max-width:640px){
  .vpn-access-profile-clean-v4 .v4-grid{
    grid-template-columns:1fr 1fr!important;
  }

  .vpn-access-profile-clean-v4 .v4-card{
    padding:12px!important;
    border-radius:18px!important;
  }

  .vpn-access-profile-clean-v4 .v4-metric strong{
    font-size:18px!important;
  }

  .vpn-access-profile-clean-v4 .v4-hero h1{
    font-size:32px!important;
  }
}

/* Кнопки файлов компактнее */
.vpn-access-profile-clean-v4 .v4-actions{
  gap:8px!important;
}

.vpn-access-profile-clean-v4 .v4-btn{
  padding:9px 11px!important;
  font-size:13px!important;
}

/* /vpn-access-profile-clean-v43 */
</style>
"""
        if "</head>" in html:
            html = html.replace("</head>", css + "\n</head>", 1)
        else:
            html = css + html

        html += "\n<!-- vpn-access-profile-clean-v43 -->\n"
        return html

    except Exception as e:
        print(f"clean_v43_render_error={e!r}", flush=True)
        return html

# /vpn-access-profile-clean-v43


# vpn-access-profile-clean-v44

def _v44_ip24(ip):
    import re as _re
    m = _re.match(r"^\s*(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}\s*$", str(ip or ""))
    if not m:
        return ""
    return ".".join(m.groups())


def _v44_split_ips(x):
    import re as _re
    return _re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(x or ""))


def _v44_mobile_provider(provider):
    p = str(provider or "").lower()
    return any(w in p for w in (
        "билайн", "vimpelcom", "beeline", "as16345",
        "мегафон", "megafon",
        "мтс", "mts", "mobile telesystems",
        "tele2", "t2", "yota", "йота",
    ))


def _v44_clean_provider(provider):
    try:
        return _v43_nice_provider(provider)
    except Exception:
        return str(provider or "—").strip() or "—"


def _v44_is_empty(x):
    x = str(x or "").strip()
    return x in ("", "—", "-", "None", "none")



def _v4_profile_stage_v44(client, old_html, d):

    try:
        # Карта мобильных /24 по уже распознанным сессиям этого же доступа.
        # Пример: 176.15.164.8 = Билайн, значит 176.15.164.163 тоже считаем Билайном.
        prefix_provider = {}

        cur_ip = d.get("current_ip")
        cur_provider = _v44_clean_provider(d.get("current_provider"))
        if _v44_mobile_provider(cur_provider):
            pref = _v44_ip24(cur_ip)
            if pref:
                prefix_provider[pref] = cur_provider

        for sess in d.get("sessions") or []:
            ip = sess.get("ip")
            provider = _v44_clean_provider(sess.get("provider"))
            if _v44_mobile_provider(provider):
                pref = _v44_ip24(ip)
                if pref:
                    prefix_provider[pref] = provider

        # Если в местах уже есть мобильная карточка, тоже используем её IP как подсказку.
        for p in d.get("places") or []:
            provider = _v44_clean_provider(p.get("provider"))
            label = p.get("place_label") or ""
            if _v44_mobile_provider(provider) or "мобиль" in str(label).lower():
                for ip in _v44_split_ips(p.get("main_ip")) + list(p.get("main_ips") or []):
                    pref = _v44_ip24(ip)
                    if pref and provider != "—":
                        prefix_provider[pref] = provider

        merged = {}

        for p in d.get("places") or []:
            provider = _v44_clean_provider(p.get("provider"))
            label = p.get("place_label") or "место"
            main_ips = _v44_split_ips(p.get("main_ip")) + list(p.get("main_ips") or [])

            # Если провайдер неизвестен, но IP попал в мобильную /24 — назначаем мобильного провайдера.
            if _v44_is_empty(provider):
                for ip in main_ips:
                    pref = _v44_ip24(ip)
                    if pref in prefix_provider:
                        provider = prefix_provider[pref]
                        break

            mobile = _v44_mobile_provider(provider) or "мобиль" in str(label).lower()

            if mobile:
                key = ("mobile", provider if provider != "—" else "мобильная сеть")
                label2 = "📱 мобильная сеть"
            else:
                key = ("normal", provider, label)
                label2 = label

            item = merged.setdefault(key, {
                "provider": provider,
                "place_label": label2,
                "confidence": 0,
                "sessions": 0,
                "days": 0,
                "ips": 0,
                "main_ip": "",
                "main_ips": [],
                "shared_clients": 0,
                "work_pct": 0,
                "evening_pct": 0,
                "night_pct": 0,
                "weekend_pct": 0,
            })

            item["confidence"] = max(item["confidence"], int(p.get("confidence") or 0))
            item["sessions"] += int(p.get("sessions") or 0)
            item["days"] += int(p.get("days") or 0)
            item["ips"] += int(p.get("ips") or 0)
            item["shared_clients"] = max(item["shared_clients"], int(p.get("shared_clients") or 0))

            for pct in ("work_pct", "evening_pct", "night_pct", "weekend_pct"):
                try:
                    item[pct] = max(item[pct], int(p.get(pct) or 0))
                except Exception:
                    pass

            for ip in main_ips:
                if ip and ip not in item["main_ips"]:
                    item["main_ips"].append(ip)

        places = []
        for item in merged.values():
            if item["main_ips"]:
                item["main_ip"] = " · ".join(item["main_ips"][:3])
            places.append(item)

        d["places"] = sorted(
            places,
            key=lambda x: (-x["confidence"], -x["sessions"], x["provider"])
        )

    except Exception as e:
        print(f"v44_mobile_merge_error={e!r}", flush=True)

    return d



def _access_passport_stage_clean_v44(client, user, html):
    try:
        html += "\n<!-- vpn-access-profile-clean-v44 -->\n"
    except Exception:
        pass
    return html

# /vpn-access-profile-clean-v44


# vpn-access-profile-top-v46-safe
import re as _vpn_v46s_re

def _v46s_section_end(html, start):
    depth = 0
    for m in _vpn_v46s_re.finditer(r'</?section\b[^>]*>', html[start:], _vpn_v46s_re.I):
        tag = m.group(0)
        end = start + m.end()
        if tag.startswith("</"):
            depth -= 1
            if depth <= 0:
                return end
        else:
            depth += 1
    return -1

def _v46s_remove_section(html, start):
    end = _v46s_section_end(html, start)
    if end == -1:
        return html
    return html[:start] + html[end:]

def _v46s_short_file(label):
    x = str(label or "")
    low = x.lower()
    if "iphone" in low or "ipad" in low or "zip" in low:
        return "iPhone / iPad ZIP"
    if "android" in low:
        return "Android"
    if "windows" in low:
        return "Windows"
    return x.replace("Скачать для ", "").replace("Скачать ", "")

def _v46s_first(x):
    x = str(x or "—").strip()
    return x.split("↓")[0].strip() if "↓" in x else x


# native-profile-card-v2
def _vpn_v46s_duration_suffix_v2(duration, is_online):
    duration = (duration or "").strip()
    if not duration or duration == "—":
        return ""
    if not is_online:
        return ""
    return " · текущая сессия " + duration

def _v46s_top_html(client, user, fallback_html):
    try:
        old_html = access_passport_page_before_clean_v4(client, user)
    except Exception:
        old_html = fallback_html

    d = _v4_load_profile_data(client, old_html)
    tr = d.get("traffic") or {}

    title = d.get("title") or client
    subtitle = d.get("subtitle") or client
    online = "подключён" if d.get("is_online") else "не онлайн"
    online_cls = "ok" if d.get("is_online") else "off"
    ip = d.get("current_ip") or "—"
    provider = d.get("current_provider") or "—"
    _provider_key = str(provider or "").strip().upper()
    _provider_map = {
        "TBANK JSC": "Т-Банк",
        "T-BANK JSC": "Т-Банк",
        "TINKOFF BANK": "Т-Банк",
        "TINKOFF": "Т-Банк",
    }
    provider = _provider_map.get(_provider_key, provider)

    network_caption = "сейчас в сети" if d.get("is_online") else "последняя сеть"
    provider_line = network_caption if not provider or provider == "—" else f"{network_caption} · {provider}"

    last_caption = "видели онлайн" if d.get("is_online") else "последний раз видели"
    last_seen = d.get("last_seen") or "—"
    duration = d.get("duration") or "—"
    duration_suffix = _vpn_v46s_duration_suffix_v2(duration, bool(d.get("is_online")))
    cert = d.get("cert_until") or d.get("cert_status") or "—"
    month = _v46s_first(tr.get("month") or "—")
    today = _v46s_first(tr.get("today") or "—")

    links = ""
    for label, href in (d.get("links") or [])[:3]:
        links += f'<a class="v46s-file" href="{esc(href)}">{esc(_v46s_short_file(label))}</a>'
    if not links:
        links = '<span class="v46s-muted">файлы не найдены</span>'

    return f"""
<section class="v46s-top vpn-access-profile-top-v46-safe">
  <div class="v46s-head">
    <div>
      <h1>{esc(title)}</h1>
      <p>{esc(subtitle)}</p>
    </div>
    <div class="v46s-badges">
      <span class="{esc(online_cls)}">{esc(online)}</span>
      <span>сертификат до {esc(str(cert).split()[0])}</span>
      <span>файлы готовы</span>
    </div>
  </div>

  <div class="v46s-line">
    <strong>{esc(ip)}</strong>
    <span>{esc(provider_line)}</span>
    <em>{esc(last_caption)}: {esc(last_seen)}{esc(duration_suffix)}</em>
  </div>

  <div class="v46s-facts">
    <span>30 дней: {esc(month)}</span>
    <span>сегодня: {esc(today)}</span>
  </div>

  <div class="v46s-files">
    {links}
  </div>
</section>
"""

def _v46s_apply(html, client, user=None):
    if "vpn-access-profile-top-v46-safe" in html:
        return html
    if "vpn-access-profile-clean-v4" not in html:
        return html

    try:
        top = _v46s_top_html(client, user, html)

        # Убрать внешний shell-заголовок над профилем.
        html = _vpn_v46s_re.sub(
            r'(<main\b[^>]*>)\s*<h1\b[^>]*>.*?</h1>\s*<p\b[^>]*>.*?</p>',
            r'\1',
            html,
            count=1,
            flags=_vpn_v46s_re.S
        )

        # Заменить старую hero-карточку на новую компактную.
        pos = html.find('<section class="v4-hero"')
        if pos != -1:
            end = _v46s_section_end(html, pos)
            if end != -1:
                html = html[:pos] + top + html[end:]

        # Убрать старые 4 плитки метрик.
        pos = html.find('<section class="v4-grid"')
        if pos != -1:
            html = _v46s_remove_section(html, pos)

        # Убрать отдельный жирный блок файлов.
        h = html.find("<h2>Файлы профиля</h2>")
        if h != -1:
            sec = html.rfind("<section", 0, h)
            if sec != -1:
                html = _v46s_remove_section(html, sec)

        css = """
<style>
/* vpn-access-profile-top-v46-safe */
.v46s-top{
  border:1px solid rgba(148,163,184,.16);
  background:rgba(13,18,31,.88);
  border-radius:22px;
  padding:14px;
  display:grid;
  gap:11px;
}
.v46s-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.v46s-head h1{margin:0;font-size:32px;line-height:1.02;letter-spacing:-.055em}
.v46s-head p{margin:6px 0 0;color:var(--muted);font-weight:850}
.v46s-badges,.v46s-facts{display:flex;gap:6px;flex-wrap:wrap}
.v46s-badges{justify-content:flex-end}
.v46s-badges span,.v46s-facts span{
  border:1px solid rgba(255,255,255,.09);
  background:rgba(0,0,0,.14);
  color:var(--muted);
  border-radius:999px;
  padding:5px 8px;
  font-size:12px;
  font-weight:900;
}
.v46s-badges .ok{color:#58d178;background:rgba(88,209,120,.09);border-color:rgba(88,209,120,.22)}
.v46s-line{border:1px solid rgba(148,163,184,.12);background:rgba(255,255,255,.02);border-radius:16px;padding:10px}
.v46s-line strong{display:block;font-size:23px;line-height:1.05}
.v46s-line span{display:block;color:var(--muted);margin-top:4px;font-size:14px}
.v46s-line em{display:block;color:var(--muted);font-style:normal;margin-top:4px;font-size:12px}
.v46s-files{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}
.v46s-file{
  text-decoration:none;color:var(--text);
  border:1px solid rgba(148,163,184,.18);
  background:rgba(255,255,255,.045);
  border-radius:14px;
  padding:10px 9px;
  font-size:13px;
  font-weight:950;
  text-align:center;
}
.v46s-file:first-child{background:rgba(90,145,255,.14);border-color:rgba(90,145,255,.25);color:#c8dcff}
.v46s-muted{color:var(--muted);font-size:13px}
body:has(.vpn-access-profile-top-v46-safe) main > h1:first-of-type,
body:has(.vpn-access-profile-top-v46-safe) main > h1:first-of-type + p{display:none!important}
@media(max-width:640px){
  .v46s-head{display:block}
  .v46s-badges{justify-content:flex-start;margin-top:10px}
  .v46s-files{grid-template-columns:1fr}
  .v46s-file{text-align:left;padding:10px 12px}
}

/* access-profile-ui-v1: профиль относится к разделу “Доступы” */
body:has(.vpn-access-profile-top-v46-safe) a[href="/"],
body:has(.vpn-access-profile-top-v46-safe) a[href="/dashboard"]{
  background:transparent!important;
  box-shadow:none!important;
  color:var(--muted)!important;
}
body:has(.vpn-access-profile-top-v46-safe) a[href="/access"],
body:has(.vpn-access-profile-top-v46-safe) a[href="/accesses"],
body:has(.vpn-access-profile-top-v46-safe) a[href^="/access/"]{
  background:rgba(76,126,201,.35)!important;
  box-shadow:inset 0 0 0 1px rgba(128,170,240,.25)!important;
  color:var(--text)!important;
}

/* /vpn-access-profile-top-v46-safe */
</style>
"""
        html = html.replace("</head>", css + "\n</head>", 1) if "</head>" in html else css + html
        return html + "\n<!-- vpn-access-profile-top-v46-safe -->\n"

    except Exception as e:
        print(f"v46s_top_error={e!r}", flush=True)
        return html


def _access_passport_stage_top_v46_safe(client, user, html):
    return _v46s_apply(html, client, user)

# /vpn-access-profile-top-v46-safe


# vpn-remove-users-groups-v1

# Owner видит клиентские профили по явной owner-only политике из access_policy.py.
# Групповая модель пока остаётся только для сводок и создания доступов.


def _vpn_strip_groups_from_html_v1(html):
    import re as _re

    if not html:
        return html

    # Убираем старые секции группы доступа.
    html = _re.sub(
        r'<section[^>]*>\s*<h2>\s*Группа доступа\s*</h2>.*?</section>',
        '',
        html,
        flags=_re.S | _re.I
    )

    # Убираем v41/v42 формы группы, если попали внутрь админки.
    html = _re.sub(
        r'<section class="card"[^>]*>\s*<h2>\s*Группа доступа\s*</h2>.*?</section>',
        '',
        html,
        flags=_re.S | _re.I
    )

    # Убираем любые фразы про текущую группу в новом/старом профиле.
    html = _re.sub(
        r'<p[^>]*>[^<]*Текущая группа:.*?</p>',
        '',
        html,
        flags=_re.S | _re.I
    )

    html = html.replace("Группа доступа и удаление", "Удаление")
    html = html.replace("Группа доступа", "")
    html = html.replace("группа доступа", "")
    html = html.replace("группы доступа", "")

    return html



def _access_passport_stage_remove_groups(client, user, html):
    try:
        html = _vpn_strip_groups_from_html_v1(html)

        css = """
<style>
/* vpn-remove-users-groups-v1 */

/* Любые остатки группы/селектов групп прячем на всякий случай */
select[name*="group" i],
input[name*="group" i],
button[name*="group" i],
.group-card,
.access-group,
[data-group],
[class*="group-access"]{
  display:none!important;
}

/* Админка после удаления групп компактнее */
.v41-admin-forms,
.v42-admin-forms{
  grid-template-columns:1fr!important;
}

/* /vpn-remove-users-groups-v1 */
</style>
"""
        html = html.replace("</head>", css + "\n</head>", 1) if "</head>" in html else css + html
        return html + "\n<!-- vpn-remove-users-groups-v1 -->\n"
    except Exception as e:
        print(f"remove_groups_profile_error={e!r}", flush=True)
        return html


# Прячем/глушим страницы управления пользователями и группами, если такие маршруты были.
try:
    _vpn_original_handler_do_GET_remove_users_groups_v1 = Handler.do_GET

    def _vpn_handler_do_GET_remove_users_groups_v1(self):
        import urllib.parse as _urlparse
        parsed = _urlparse.urlparse(self.path)
        path = parsed.path

        blocked = (
            "/users", "/user", "/admins", "/admin-users",
            "/groups", "/access-groups", "/group", "/permissions"
        )

        if path in blocked or path.startswith("/users/") or path.startswith("/groups/"):
            if not require_app_auth(self, path):
                return
            body = """
<section class="card">
  <h1>Пользователи и группы отключены</h1>
  <p class="muted">В панели оставлен один owner-логин. Группы доступа больше не используются.</p>
  <p><a class="btn" href="/">На главную</a></p>
</section>
"""
            self.send_text(200, support_shell_page("Пользователи отключены", body, APP_NAME), "text/html; charset=utf-8")
            return

        return _vpn_original_handler_do_GET_remove_users_groups_v1(self)

    Handler.do_GET = _vpn_handler_do_GET_remove_users_groups_v1
except Exception:
    pass

# /vpn-remove-users-groups-v1


# vpn-access-profile-admin-delete-v47
import re as _vpn_v47_re

def _v47_section_end(html, start):
    depth = 0
    for m in _vpn_v47_re.finditer(r'</?section\b[^>]*>', html[start:], _vpn_v47_re.I):
        tag = m.group(0)
        end = start + m.end()
        if tag.startswith("</"):
            depth -= 1
            if depth <= 0:
                return end
        else:
            depth += 1
    return -1

def _v47_remove_section(html, start):
    end = _v47_section_end(html, start)
    if end == -1:
        return html
    return html[:start] + html[end:]

def _v47_strip_old_admin(html):
    needles = (
        "<h2>Админка</h2>",
        "<h2>Удаление</h2>",
        "<h2>Группа доступа</h2>",
        "Группа доступа и удаление",
    )

    for needle in needles:
        guard = 0
        while needle in html and guard < 20:
            guard += 1
            pos = html.find(needle)
            sec = html.rfind("<section", 0, pos)
            if sec == -1:
                html = html.replace(needle, "")
                continue
            html = _v47_remove_section(html, sec)

    return html

def _v47_add_form_class(form):
    if _vpn_v47_re.search(r'<form\b[^>]*class=', form, _vpn_v47_re.I):
        return _vpn_v47_re.sub(
            r'(<form\b[^>]*class=["\'])',
            r'\1v47-delete-form ',
            form,
            count=1,
            flags=_vpn_v47_re.I
        )
    return _vpn_v47_re.sub(
        r'<form\b',
        '<form class="v47-delete-form"',
        form,
        count=1,
        flags=_vpn_v47_re.I
    )

def _v47_extract_delete_ui(client, user, current_html):
    try:
        legacy_html = access_passport_page_before_clean_v4(client, user)
    except Exception:
        legacy_html = current_html

    forms = _vpn_v47_re.findall(r'<form\b[^>]*>.*?</form>', legacy_html, _vpn_v47_re.S | _vpn_v47_re.I)

    best = None
    best_score = -999

    for form in forms:
        plain = _vpn_v47_re.sub(r'<[^>]+>', ' ', form)
        low = (plain + " " + form).lower()

        score = 0
        if "удал" in low:
            score += 20
        if "delete" in low or "remove" in low or "revoke" in low:
            score += 12
        if "client" in low or "profile" in low or "access" in low:
            score += 3
        if "group" in low or "групп" in low:
            score -= 12
        if "password" in low or "парол" in low:
            score -= 20

        if score > best_score:
            best_score = score
            best = form

    if best and best_score > 0:
        best = _v47_add_form_class(best)
        return f'<div class="v47-delete-ui">{best}</div>'

    # fallback: если удаление было ссылкой, а не формой
    links = _vpn_v47_re.findall(r'<a\b[^>]*href=["\'][^"\']+["\'][^>]*>.*?</a>', legacy_html, _vpn_v47_re.S | _vpn_v47_re.I)
    for a in links:
        low = (_vpn_v47_re.sub(r'<[^>]+>', ' ', a) + " " + a).lower()
        if ("удал" in low or "delete" in low or "remove" in low) and "group" not in low:
            a = _vpn_v47_re.sub(r'<a\b', '<a class="v47-delete-link"', a, count=1, flags=_vpn_v47_re.I)
            return f'<div class="v47-delete-ui">{a}</div>'

    return '<div class="v47-delete-ui v47-missing">Форма удаления не найдена в старом шаблоне.</div>'

def _v47_admin_html(client, user, html):
    delete_ui = _v47_extract_delete_ui(client, user, html)

    return f"""
<section class="v47-admin vpn-access-profile-admin-delete-v47">
  <div class="v47-admin-head">
    <h2>Админка</h2>
    <span>только удаление профиля</span>
  </div>

  <div class="v47-danger-box">
    <strong>Опасная зона</strong>
    <p>Удаление отключит этот VPN-доступ и уберёт профиль из панели.</p>
    {delete_ui}
  </div>
</section>
"""

def _v47_apply(html, client, user=None):
    if "vpn-access-profile-admin-delete-v47" in html:
        return html
    if "vpn-access-profile-clean-v4" not in html:
        return html

    try:
        html = _v47_strip_old_admin(html)
        admin = _v47_admin_html(client, user, html)

        pos = html.rfind("</main>")
        if pos != -1:
            html = html[:pos] + admin + "\n" + html[pos:]
        else:
            html += admin

        css = """
<style>
/* vpn-access-profile-admin-delete-v47 */
.v47-admin{
  max-width:1120px;
  margin:10px auto 0;
  border:1px solid rgba(148,163,184,.16);
  background:rgba(13,18,31,.88);
  border-radius:22px;
  padding:14px;
}
.v47-admin-head{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:12px;
  margin-bottom:10px;
}
.v47-admin-head h2{
  margin:0;
  font-size:22px;
  line-height:1.1;
}
.v47-admin-head span{
  color:var(--muted);
  font-size:12px;
  font-weight:900;
  border:1px solid rgba(255,255,255,.09);
  background:rgba(0,0,0,.14);
  border-radius:999px;
  padding:5px 8px;
}
.v47-danger-box{
  border:1px solid rgba(239,68,68,.25);
  background:rgba(239,68,68,.06);
  border-radius:18px;
  padding:12px;
}
.v47-danger-box strong{
  display:block;
  color:#fecaca;
  font-size:15px;
  margin-bottom:4px;
}
.v47-danger-box p{
  color:var(--muted);
  margin:0 0 10px;
  font-size:13px;
  line-height:1.35;
}
.v47-delete-ui form{
  margin:0!important;
  display:flex!important;
  gap:8px!important;
  flex-wrap:wrap!important;
}
.v47-delete-ui button,
.v47-delete-ui input[type="submit"],
.v47-delete-link{
  appearance:none!important;
  border:1px solid rgba(239,68,68,.36)!important;
  background:rgba(239,68,68,.16)!important;
  color:#fecaca!important;
  border-radius:14px!important;
  padding:10px 12px!important;
  font-size:14px!important;
  font-weight:950!important;
  text-decoration:none!important;
  cursor:pointer!important;
}
.v47-delete-ui select,
.v47-delete-ui input[type="text"],
.v47-delete-ui input[type="search"]{
  display:none!important;
}
.v47-missing{
  color:#fecaca;
  font-size:13px;
  font-weight:900;
}
/* /vpn-access-profile-admin-delete-v47 */
</style>
<script>
(function(){
  if(window.vpnV47DeleteConfirm) return;
  window.vpnV47DeleteConfirm = true;
  document.addEventListener('submit', function(e){
    var box = e.target && e.target.closest ? e.target.closest('.v47-admin') : null;
    if(!box) return;
    if(!confirm('Удалить этот VPN-профиль?')) e.preventDefault();
  }, true);
})();
</script>
"""
        html = html.replace("</head>", css + "\n</head>", 1) if "</head>" in html else css + html
        return html + "\n<!-- vpn-access-profile-admin-delete-v47 -->\n"

    except Exception as e:
        print(f"v47_admin_delete_error={e!r}", flush=True)
        return html


def _access_passport_stage_admin_delete_v47(client, user, html):
    return _v47_apply(html, client, user)

# /vpn-access-profile-admin-delete-v47


_ACCESS_PASSPORT_PRE_CLEAN_STAGES = (
    _access_passport_stage_behavior,
    _access_passport_stage_matches,
    _access_passport_stage_geo,
    _access_passport_stage_known_networks,
    _access_passport_stage_layout_v2,
    _access_passport_stage_visual_v3,
)

_ACCESS_PASSPORT_AFTER_DEDUPE_STAGES = (
    _access_passport_stage_known_neutral,
    _access_passport_stage_known_rich,
    _access_passport_stage_clean_v43,
    _access_passport_stage_clean_v44,
    _access_passport_stage_top_v46_safe,
    _access_passport_stage_remove_groups,
    _access_passport_stage_admin_delete_v47,
)


def access_passport_page_before_clean_v4(client, user=None):
    return run_access_passport_pipeline(
        client,
        user,
        _access_passport_base_page(client, user),
        _ACCESS_PASSPORT_PRE_CLEAN_STAGES,
    )


def access_passport_page_through_clean_v4(client, user=None):
    return _access_passport_stage_clean_v4(client, user, None)


def access_passport_page_through_known_dedupe(client, user=None):
    return _access_passport_stage_known_dedupe(client, user, None)


def access_passport_page(client, user=None):
    return run_access_passport_pipeline(
        client,
        user,
        access_passport_page_through_known_dedupe(client, user),
        _ACCESS_PASSPORT_AFTER_DEDUPE_STAGES,
    )


# vpn-networks-v2
import sqlite3 as _vpn_n2_sqlite3
import json as _vpn_n2_json
import re as _vpn_n2_re
import html as _vpn_n2_html

_VPN_N2_DB = str(DB_PATH)

def _n2_e(x):
    try:
        return esc(str(x if x is not None else ""))
    except Exception:
        return _vpn_n2_html.escape(str(x if x is not None else ""))

def _n2_conn():
    con = _vpn_n2_sqlite3.connect(_VPN_N2_DB)
    con.row_factory = _vpn_n2_sqlite3.Row
    return con

def _n2_table(con, name):
    try:
        return con.execute("select 1 from sqlite_master where type='table' and name=?", (name,)).fetchone() is not None
    except Exception:
        return False

def _n2_rows(con, table):
    if not _n2_table(con, table):
        return []
    try:
        return [dict(r) for r in con.execute(f'select * from "{table}"')]
    except Exception:
        return []

def _n2_pick(row, *names, default=""):
    low = {str(k).lower(): k for k in row.keys()}
    for n in names:
        k = low.get(str(n).lower())
        if k is not None:
            v = row.get(k)
            if v is not None and str(v).strip() != "":
                return v
    return default

def _n2_int(v, default=0):
    try:
        return int(float(str(v).replace(",", ".").strip()))
    except Exception:
        return default


def _n2_parse_list(v):
    if not v:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v]
    s = str(v).strip()
    try:
        obj = _vpn_n2_json.loads(s)
        if isinstance(obj, list):
            return [str(x) for x in obj]
        if isinstance(obj, dict):
            return [str(x) for x in obj.values()]
    except Exception:
        pass
    return [x.strip() for x in _vpn_n2_re.split(r'[,;\n]+', s) if x.strip()]

def _n2_known_map(known_rows):
    out = {}
    for r in known_rows:
        ip = str(_n2_pick(r, "ip", "main_ip", "wan_ip", "address")).strip()
        if not ip:
            continue
        title = _n2_pick(r, "title", "label", "name", "display_name")
        client = _n2_pick(r, "client_name", "client", "company")
        obj = _n2_pick(r, "object_name", "object", "site", "target_name")
        if not title:
            title = " · ".join([str(x) for x in (client, obj) if x]) or ip
        out[ip] = {
            "title": str(title),
            "client": str(client or ""),
            "object": str(obj or ""),
            "host": str(_n2_pick(r, "hostname", "host", "fqdn", "dns_name")),
            "source": str(_n2_pick(r, "source", default="Pulse")),
        }
    return out

def _n2_usage_by_ip(shared_rows, place_rows):
    usage = {}
    for r in shared_rows:
        ip = str(_n2_pick(r, "ip", "main_ip", "remote_ip")).strip()
        if not ip:
            continue
        usage[ip] = {
            "access": max(_n2_int(_n2_pick(r, "access_count", "client_count", "clients_count", "profiles_count")), 0),
            "sessions": max(_n2_int(_n2_pick(r, "session_count", "sessions", "total_sessions")), 0),
        }

    for r in place_rows:
        ip = str(_n2_pick(r, "main_ip", "ip", "remote_ip")).strip()
        if not ip:
            continue
        u = usage.setdefault(ip, {"access": 0, "sessions": 0})
        u["sessions"] += max(_n2_int(_n2_pick(r, "session_count", "sessions", "total_sessions")), 0)
        if u["access"] == 0:
            u["access"] = 1

    return usage


def _n2_provider(r):
    return str(_n2_pick(r, "provider", "brand", "isp", "org", "asn_org", "network_name", default="—"))

def _n2_clients(r):
    for k in ("clients_json", "client_names_json", "profiles_json", "accesses_json", "members_json", "clients", "profiles"):
        vals = _n2_parse_list(_n2_pick(r, k))
        vals = [_n2_clean_label(x) for x in vals if _n2_clean_label(x)]
        if vals:
            return vals[:5]
    return []

def _n2_chip(x):
    return f'<span>{_n2_e(x)}</span>'





def _vpn_networks_v2_body():
    con = _n2_conn()
    try:
        known = _n2_rows(con, "known_client_networks")
        shared = _n2_rows(con, "vpn_behavior_shared_ips")
        places = _n2_rows(con, "vpn_behavior_places")
        matches = _n2_rows(con, "vpn_behavior_matches")
        geo = _n2_rows(con, "ip_geo_cache")
    finally:
        con.close()

    usage = _n2_usage_by_ip(shared, places)
    known_used = sum(1 for ip in _n2_known_map(known).keys() if usage.get(ip, {}).get("sessions", 0) > 0)
    strong_matches = sum(1 for r in matches if _n2_int(_n2_pick(r, "score", "match_score", "confidence")) >= 70)
    shared_count = sum(1 for r in shared if _n2_int(_n2_pick(r, "access_count", "client_count", "clients_count", "profiles_count")) >= 2)

    return f"""
<style>
/* vpn-networks-v2 */
body:has(.vpn-networks-v2) main > h1:first-of-type,
body:has(.vpn-networks-v2) main > h1:first-of-type + p{{display:none!important}}

.vpn-networks-v2{{max-width:1120px;margin:0 auto;display:grid;gap:14px}}
.n2-hero,.n2-section{{
  border:1px solid rgba(148,163,184,.16);
  background:rgba(13,18,31,.88);
  border-radius:24px;
  padding:16px;
}}
.n2-hero h1{{margin:0;font-size:34px;line-height:1.02;letter-spacing:-.055em}}
.n2-hero p,.n2-section>p{{color:var(--muted);margin:7px 0 0;line-height:1.35}}
.n2-actions{{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}}
.n2-actions a{{text-decoration:none;color:var(--text);font-weight:900;border:1px solid rgba(148,163,184,.18);border-radius:999px;padding:8px 11px;background:rgba(255,255,255,.04)}}
.n2-stats{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}}
.n2-stat{{border:1px solid rgba(148,163,184,.14);background:rgba(255,255,255,.025);border-radius:18px;padding:12px}}
.n2-stat strong{{display:block;font-size:24px}}
.n2-stat span{{color:var(--muted);font-size:12px;font-weight:900}}
.n2-section h2{{font-size:25px;margin:0 0 5px}}
.n2-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:12px}}
.n2-card,.n2-match,.n2-city{{border:1px solid rgba(148,163,184,.14);background:rgba(255,255,255,.025);border-radius:18px;padding:12px;min-width:0}}
.n2-card-top{{display:flex;justify-content:space-between;gap:10px;align-items:flex-start}}
.n2-card strong,.n2-match strong,.n2-city strong{{font-size:16px;line-height:1.2}}
.n2-card em{{font-style:normal;color:var(--muted);font-size:11px;font-weight:900;border:1px solid rgba(255,255,255,.08);border-radius:999px;padding:4px 7px;white-space:nowrap}}
.n2-used em{{color:#9ee6b0;border-color:rgba(88,209,120,.22);background:rgba(88,209,120,.08)}}
.n2-card p{{color:var(--muted);margin:7px 0 0;line-height:1.25}}
.n2-card code{{display:block;color:var(--text);font-weight:900;background:transparent;margin-top:7px;overflow-wrap:anywhere}}
.n2-chips{{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}}
.n2-chips span{{border:1px solid rgba(255,255,255,.08);background:rgba(0,0,0,.14);color:var(--muted);border-radius:999px;padding:5px 8px;font-size:12px;font-weight:900}}
.n2-clients{{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}}
.n2-clients b{{font-size:12px;border-radius:999px;background:rgba(255,255,255,.045);padding:5px 8px}}
.n2-matches{{display:grid;gap:8px;margin-top:12px}}
.n2-match{{display:grid;grid-template-columns:70px 1fr;gap:10px}}
.n2-score{{font-weight:950;color:#c8dcff;border:1px solid rgba(90,145,255,.22);background:rgba(90,145,255,.08);border-radius:999px;padding:6px 8px;text-align:center;height:max-content}}
.n2-match p{{color:var(--muted);margin:5px 0 0}}
.n2-cities{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:8px;margin-top:12px}}
.n2-city span{{display:block;color:var(--muted);margin-top:5px}}
.n2-empty{{color:var(--muted);padding:10px;border:1px dashed rgba(148,163,184,.2);border-radius:16px;margin-top:10px}}

@media(max-width:720px){{
  .n2-stats{{grid-template-columns:1fr 1fr}}
  .n2-grid,.n2-cities{{grid-template-columns:1fr}}
  .n2-match{{grid-template-columns:1fr}}
  .n2-hero h1{{font-size:31px}}
}}
/* /vpn-networks-v2 */
</style>

<div class="vpn-networks-v2">
  <section class="n2-hero">
    <h1>Сети и совпадения</h1>
    <p>Клиентские MikroTik из Pulse, общие внешние IP и сильные поведенческие связи. Без старых логинов, групп и слабого шума.</p>
    <div class="n2-actions">
      <a href="/">На главную</a>
      <a href="/access">Все доступы</a>
      <a href="/channel">Канал</a>
    </div>
  </section>

  <section class="n2-stats">
    <div class="n2-stat"><strong>{len(known)}</strong><span>Pulse-сетей</span></div>
    <div class="n2-stat"><strong>{known_used}</strong><span>встречались в VPN</span></div>
    <div class="n2-stat"><strong>{shared_count}</strong><span>общих IP</span></div>
    <div class="n2-stat"><strong>{strong_matches}</strong><span>связей ≥70</span></div>
  </section>

  <section class="n2-section">
    <h2>Клиентские сети</h2>
    <p>Справочник MikroTik из Pulse. Сначала сети, которые уже встречались в VPN-поведении.</p>
    <div class="n2-grid">{_n2_known_cards(known, usage)}</div>
  </section>

  <section class="n2-section">
    <h2>Города и регионы</h2>
    <p>Гео провайдера, не точный адрес человека.</p>
    <div class="n2-cities">{_n2_city_cards(geo)}</div>
  </section>

  <section class="n2-section">
    <h2>Общие сети</h2>
    <p>Топ общих IP. Массовые NAT полезны как сигнал, но слабее доказывают связь конкретной пары.</p>
    <div class="n2-grid">{_n2_shared_cards(shared, known)}</div>
  </section>

  <section class="n2-section">
    <h2>Сильные связи доступов</h2>
    <p>Показываем только связи от 70/100, чтобы не превращать страницу в свалку слабых совпадений.</p>
    <div class="n2-matches">{_n2_match_cards(matches)}</div>
  </section>
</div>

<!-- vpn-networks-v2 -->
"""

try:
    _vpn_original_handler_do_GET_networks_v2 = Handler.do_GET

    def _vpn_handler_do_GET_networks_v2(self):
        import urllib.parse as _n2_urlparse
        parsed = _n2_urlparse.urlparse(self.path)
        path = parsed.path

        if path == "/networks":
            if not require_app_auth(self, path):
                return
            body = _vpn_networks_v2_body()
            page = support_shell_page("Сети и совпадения", body, APP_NAME)
            self.send_text(200, page, "text/html; charset=utf-8")
            return

        return _vpn_original_handler_do_GET_networks_v2(self)

    Handler.do_GET = _vpn_handler_do_GET_networks_v2
except Exception as _n2_e:
    print(f"networks_v2_hook_error={_n2_e!r}", flush=True)

# /vpn-networks-v2


# vpn-networks-v3
import re as _vpn_n3_re

_N3_LABEL_CACHE = None

def _n3_access_label_map():
    global _N3_LABEL_CACHE
    if _N3_LABEL_CACHE is not None:
        return _N3_LABEL_CACHE

    mp = {}
    try:
        con = _n2_conn()
        tables = [r[0] for r in con.execute("select name from sqlite_master where type='table'")]
        for t in tables:
            try:
                cols = [r[1] for r in con.execute(f'pragma table_info("{t}")')]
                low = {c.lower(): c for c in cols}
                if not any(x in low for x in ("client", "username", "name", "technical_name", "login", "slug")):
                    continue

                rows = con.execute(f'select * from "{t}" limit 2000').fetchall()
                for r in rows:
                    d = dict(r)

                    keys = []
                    for k in ("client", "client_id", "username", "technical_name", "login", "slug", "name", "ike_name", "common_name"):
                        if k in low:
                            v = str(d.get(low[k]) or "").strip()
                            if v:
                                keys.append(v)

                    first = str(d.get(low.get("first_name", ""), "") or "").strip() if "first_name" in low else ""
                    last = str(d.get(low.get("last_name", ""), "") or "").strip() if "last_name" in low else ""

                    label = ""
                    for k in ("display_name", "client_label", "label", "title", "full_name"):
                        if k in low:
                            label = str(d.get(low[k]) or "").strip()
                            if label:
                                break

                    if not label and first or last:
                        label = (last + " " + first).strip()

                    if not label and "description" in low:
                        desc = str(d.get(low["description"]) or "").strip()
                        if desc and not _vpn_n3_re.fullmatch(r'[a-z0-9_.-]{3,}', desc, _vpn_n3_re.I):
                            label = desc

                    device = ""
                    for k in ("device_label", "device", "device_type", "profile_name", "comment"):
                        if k in low:
                            device = str(d.get(low[k]) or "").strip()
                            if device:
                                break

                    if label:
                        label = _vpn_n3_re.sub(r'\s*/\s*(vpn|sonya|murtuzlyao)\b', '', label, flags=_vpn_n3_re.I)
                        label = _vpn_n3_re.sub(r'\s+', ' ', label).strip(" ·/,-")

                    if label and device and device.lower() not in label.lower() and device.lower() not in ("profile", "phone", "pc", "tablet"):
                        label = label + " · " + device

                    if label:
                        for k in keys:
                            kk = k.lower()
                            if kk and kk not in ("vpn", "sonya", "murtuzlyao"):
                                mp[kk] = label
            except Exception:
                continue
        con.close()
    except Exception:
        pass

    _N3_LABEL_CACHE = mp
    return mp

def _n3_humanize_tech(x):
    raw = str(x or "").strip()
    mp = _n3_access_label_map()
    hit = mp.get(raw.lower())
    if hit:
        return hit

    # Если пришло “Имя / устройство / type / owner” — оставляем человеческую часть.
    parts = [p.strip() for p in raw.split("/") if p.strip()]
    parts = [p for p in parts if p.lower() not in ("vpn", "sonya", "murtuzlyao", "profile", "phone", "pc", "tablet", "android", "iphone")]
    if parts and not _vpn_n3_re.fullmatch(r'[a-z0-9_.-]{3,}', parts[0], _vpn_n3_re.I):
        return " · ".join(parts[:2])

    # Частые хвосты устройств прячем, но не выдумываем человека, если базы не хватило.
    x = raw
    x = _vpn_n3_re.sub(r'\s*/\s*(vpn|sonya|murtuzlyao)\b', '', x, flags=_vpn_n3_re.I)
    x = _vpn_n3_re.sub(r'\b(vpn|sonya|murtuzlyao)\b', '', x, flags=_vpn_n3_re.I)
    x = _vpn_n3_re.sub(r'\s+', ' ', x).strip(" ·/,-")
    return x or "доступ"


def _n2_clean_label(x):
    return _n3_humanize_tech(x)

def _n2_geo_label(r):
    country = str(_n2_pick(r, "country", "country_code")).strip()
    region = str(_n2_pick(r, "region", "region_name", "regionName")).strip()
    city = str(_n2_pick(r, "city")).strip()

    repl = {
        "Russia": "RU",
        "Russian Federation": "RU",
        "St.-Petersburg": "Санкт-Петербург",
        "St Petersburg": "Санкт-Петербург",
        "Smolensk Oblast": "Смоленская обл.",
        "Smolensk": "Смоленск",
        "Karelia": "Карелия",
        "Petrozavodsk": "Петрозаводск",
        "Dagestan": "Дагестан",
        "Kaspiysk": "Каспийск",
        "Moscow": "Москва",
        "Murmansk": "Мурманск",
        "Yaroslavl Oblast": "Ярославская обл.",
        "Yaroslavl": "Ярославль",
        "Penza Oblast": "Пензенская обл.",
        "Penza": "Пенза",
        "Leningrad Oblast": "Ленинградская обл.",
        "Vsevolozhsk": "Всеволожск",
        "Shushary": "Шушары",
    }

    vals = []
    for x in (country, region, city):
        x = repl.get(x, x)
        if x and x not in vals:
            vals.append(x)

    if vals and vals[0] == "RU":
        # Для РФ оставляем короче: RU + город/регион.
        if len(vals) >= 3 and vals[-1] != vals[-2]:
            return " · ".join([vals[0], vals[-2], vals[-1]])
        return " · ".join(vals[:2])

    return " · ".join(vals)

def _n2_known_cards(known_rows, usage):
    km = _n2_known_map(known_rows)
    used, idle = [], []

    for ip, k in km.items():
        u = usage.get(ip, {"access": 0, "sessions": 0})
        is_used = u["sessions"] > 0 or u["access"] > 1
        item = (k["title"].lower(), ip, k, u, is_used)
        (used if is_used else idle).append(item)

    used.sort()
    idle.sort()
    items = used[:8] + idle[:4]

    cards = ""
    for _, ip, k, u, is_used in items:
        meta = " · ".join([x for x in (k["client"], k["object"]) if x])
        host = f' · {k["host"]}' if k["host"] else ""

        chips = [_n2_chip("Pulse")]
        chips.append(_n2_chip(f'VPN: {u["access"]} доступов · {u["sessions"]} сессий') if is_used else _n2_chip("только справочник"))

        cards += f"""
<div class="n2-card {'n2-used' if is_used else 'n2-idle'}">
  <div class="n2-card-top">
    <strong>{_n2_e(k["title"].replace(" active", ""))}</strong>
    <em>{'встречалась' if is_used else 'не встречалась'}</em>
  </div>
  <p>{_n2_e(meta or "клиентская сеть")}</p>
  <code>{_n2_e(ip)}{_n2_e(host)}</code>
  <div class="n2-chips">{''.join(chips)}</div>
</div>
"""
    return cards or '<div class="n2-empty">Клиентские сети не найдены.</div>'

def _n2_shared_cards(shared_rows, known_rows):
    known = _n2_known_map(known_rows)
    rows = []
    for r in shared_rows:
        ip = str(_n2_pick(r, "ip", "main_ip", "remote_ip")).strip()
        access = _n2_int(_n2_pick(r, "access_count", "client_count", "clients_count", "profiles_count"))
        sessions = _n2_int(_n2_pick(r, "session_count", "sessions", "total_sessions"))
        if ip and access >= 2:
            rows.append((access, sessions, ip, r))

    rows.sort(key=lambda x: (x[0], x[1]), reverse=True)

    cards = ""
    for access, sessions, ip, r in rows[:10]:
        k = known.get(ip)
        provider = k["title"] if k else _n2_provider(r)
        if provider == "—":
            provider = "Общая сеть"

        kind = "массовая сеть" if access >= 8 else "общая сеть"
        if "mobile" in str(r).lower():
            kind = "мобильный NAT"

        clients = _n2_clients(r)
        client_html = "".join(f'<b>{_n2_e(x)}</b>' for x in clients[:4])

        cards += f"""
<div class="n2-card">
  <div class="n2-card-top">
    <strong>{_n2_e(provider)}</strong>
    <em>{_n2_e(kind)}</em>
  </div>
  <code>{_n2_e(ip)}</code>
  <div class="n2-chips">
    {_n2_chip(str(access) + " доступов")}
    {_n2_chip(str(sessions) + " сессий")}
  </div>
  <div class="n2-clients">{client_html}</div>
</div>
"""
    return cards or '<div class="n2-empty">Общие сети не найдены.</div>'

def _n2_match_cards(match_rows):
    rows = []
    for r in match_rows:
        score = _n2_int(_n2_pick(r, "score", "match_score", "confidence"))
        if score >= 70:
            rows.append((score, r))
    rows.sort(key=lambda x: x[0], reverse=True)

    cards = ""
    for score, r in rows[:12]:
        a = _n2_clean_label(_n2_pick(r, "client_a_label", "a_label", "client1_label", "left_label", "client_a", "client1", "left_client"))
        b = _n2_clean_label(_n2_pick(r, "client_b_label", "b_label", "client2_label", "right_label", "client_b", "client2", "right_client"))
        common = _n2_int(_n2_pick(r, "common_ip_count", "shared_ip_count", "common_ips", "shared_ips"))
        stable = _n2_int(_n2_pick(r, "stable_ip_count", "stable_ips"))
        mobile = _n2_int(_n2_pick(r, "mobile_ip_count", "mobile_ips"))
        sessions = _n2_int(_n2_pick(r, "pair_sessions", "session_count", "sessions"))
        level = "сильная" if score >= 80 else "средняя"

        cards += f"""
<div class="n2-match">
  <div class="n2-score">{score}/100</div>
  <div>
    <strong>{_n2_e(a)} <span>↔</span> {_n2_e(b)}</strong>
    <p>{_n2_e(level)} связь</p>
    <div class="n2-chips">
      {_n2_chip(str(common) + " общих IP")}
      {_n2_chip(str(stable) + " стабильных")}
      {_n2_chip(str(mobile) + " мобильных")}
      {_n2_chip(str(sessions) + " сессий пары")}
    </div>
  </div>
</div>
"""
    return cards or '<div class="n2-empty">Сильные связи не найдены.</div>'


try:
    _vpn_original_handler_do_GET_networks_v3 = Handler.do_GET

    def _vpn_handler_do_GET_networks_v3(self):
        import urllib.parse as _n3_urlparse
        parsed = _n3_urlparse.urlparse(self.path)
        if parsed.path == "/networks":
            if not require_app_auth(self, parsed.path):
                return
            body = _vpn_networks_v2_body()
            page = support_shell_page("Сети и совпадения", body, APP_NAME)
            page = _n3_page_cleanup(page)
            self.send_text(200, page, "text/html; charset=utf-8")
            return
        return _vpn_original_handler_do_GET_networks_v3(self)

    Handler.do_GET = _vpn_handler_do_GET_networks_v3
except Exception as _n3_e:
    print(f"networks_v3_hook_error={_n3_e!r}", flush=True)

# /vpn-networks-v3


# vpn-networks-v4-lite



# /vpn-networks-v4-lite


# vpn-networks-title-fix-v1



# /vpn-networks-title-fix-v1




# vpn-geo-city-provider-merge-v1
# В профиле доступа блок "География": одна карточка = один город, провайдеры внутри города.

def _vpn_geo_v1_pick(row, *keys, default=""):
    for key in keys:
        try:
            v = row[key]
        except Exception:
            try:
                v = row.get(key)
            except Exception:
                v = None

        if v is not None and str(v).strip() != "":
            return v

    return default


def _vpn_geo_v1_int(value, default=0):
    try:
        if value is None or str(value).strip() == "":
            return default
        return int(float(str(value).replace(",", ".").strip()))
    except Exception:
        return default


def _vpn_geo_v1_provider(value):
    p = str(value or "").strip()

    if not p or p in {"—", "-", "None", "none", "null"}:
        return "провайдер не определён"

    try:
        p = _v43_nice_provider(p)
    except Exception:
        try:
            p = pretty_provider_name(p)
        except Exception:
            pass

    p = str(p or "").strip()
    low = p.lower()

    aliases = [
        ("severen", "Северен-Телеком"),
        ("северен", "Северен-Телеком"),
        ("megafon", "МегаФон"),
        ("мегафон", "МегаФон"),
        ("mobile telesystems", "МТС"),
        ("mts", "МТС"),
        ("мтс", "МТС"),
        ("rostelecom", "Ростелеком"),
        ("ростелеком", "Ростелеком"),
        ("skynet", "SkyNet"),
        ("citylink", "CityLink"),
        ("er-telecom", "Дом.ru"),
        ("er telecom", "Дом.ru"),
        ("z-telecom", "Дом.ru"),
        ("ztelecom", "Дом.ru"),
        ("koltushsky", "Колтушский интернет"),
        ("kolt-as", "Колтушский интернет"),
        ("vimpelcom", "Билайн"),
        ("beeline", "Билайн"),
        ("билайн", "Билайн"),
        ("tele2", "Т2"),
        ("t2 mobile", "Т2"),
    ]

    for needle, label in aliases:
        if needle in low:
            return label

    if p in {"—", "-"}:
        return "провайдер не определён"

    return p


def _vpn_geo_v1_city(country_code, region, city):
    cc = str(country_code or "").strip().upper()
    reg = str(region or "").strip()
    c = str(city or "").strip()

    raw = " ".join([cc, reg, c]).lower()
    raw = raw.replace(".", " ").replace("-", " ")

    if any(x in raw for x in ("st petersburg", "saint petersburg", "санкт петербург", "spb")):
        return "Санкт-Петербург"

    if "moscow" in raw or "москва" in raw:
        return "Москва"

    if "petrozavodsk" in raw or "петрозаводск" in raw:
        return "Петрозаводск"

    label = c or reg or cc or "Локация не определена"

    if not label or label in {"—", "-"}:
        return "Локация не определена"

    return label


def _vpn_geo_v1_merge_rows(rows):
    from collections import Counter as _Counter

    grouped = {}

    for r in rows or []:
        city = _vpn_geo_v1_city(
            _vpn_geo_v1_pick(r, "country_code", "country"),
            _vpn_geo_v1_pick(r, "region"),
            _vpn_geo_v1_pick(r, "city"),
        )

        key = city.lower()

        item = grouped.setdefault(key, {
            "city": city,
            "providers": _Counter(),
            "ips": set(),
            "sessions": 0,
            "mobile": 0,
            "proxy": 0,
            "hosting": 0,
        })

        # Гео-провайдер первым: он чинит случаи, где p.provider был "—",
        # но ip_geo_cache уже знает MegaFon / MTS / SkyNet / Rostelecom.
        provider = _vpn_geo_v1_provider(
            _vpn_geo_v1_pick(r, "isp", "org", "as_name", "provider", default="")
        )

        sessions = _vpn_geo_v1_int(_vpn_geo_v1_pick(r, "sessions", default=0), 0)
        if sessions <= 0:
            sessions = 1

        ip = str(_vpn_geo_v1_pick(r, "main_ip", "ip", "query", default="")).strip()

        if ip:
            item["ips"].add(ip)

        item["providers"][provider] += sessions
        item["sessions"] += sessions

        for flag in ("mobile", "proxy", "hosting"):
            if _vpn_geo_v1_int(_vpn_geo_v1_pick(r, flag, default=0), 0):
                item[flag] = 1

    out = []

    for item in grouped.values():
        providers = [
            f"{provider} — {count} сесс."
            for provider, count in sorted(item["providers"].items(), key=lambda x: (-x[1], x[0]))
        ]

        more = len(providers) - 5
        provider_line = " · ".join(providers[:5])

        if more > 0:
            provider_line += f" · ещё {more}"

        ip_count = len(item["ips"])
        total_sessions = item["sessions"]

        main_ip = f"{ip_count} IP · {total_sessions} сесс." if ip_count else f"{total_sessions} сесс."

        out.append({
            "country_code": "",
            "region": "",
            "city": item["city"],
            "isp": provider_line or "провайдер не определён",
            "org": "",
            "provider": provider_line or "провайдер не определён",
            "main_ip": main_ip,
            "mobile": item["mobile"],
            "proxy": item["proxy"],
            "hosting": item["hosting"],
            "_sessions": total_sessions,
            "_ips": ip_count,
        })

    out.sort(
        key=lambda x: (
            -_vpn_geo_v1_int(x.get("_sessions"), 0),
            x.get("city") or "",
        )
    )

    return out


try:

    def _v4_profile_stage_geo(client, old_html, d):

        try:
            d["geo"] = _vpn_geo_v1_merge_rows(d.get("geo") or [])
        except Exception as e:
            print(f"geo_city_provider_merge_v1_error={e!r}", flush=True)

        return d

except Exception as _vpn_geo_v1_hook_e:
    print(f"geo_city_provider_merge_v1_hook_error={_vpn_geo_v1_hook_e!r}", flush=True)


try:

    def _n2_city_cards(geo_rows):
        rows = _vpn_geo_v1_merge_rows(geo_rows)

        if not rows:
            return '<div class="n2-empty">География пока не собрана.</div>'

        cards = ""

        for r in rows[:8]:
            cards += f"""
<div class="n2-city">
  <strong>{_n2_e(r.get('city') or 'Локация не определена')}</strong>
  <span>{_n2_e(r.get('main_ip') or '—')}</span>
  <span>{_n2_e(r.get('isp') or 'провайдер не определён')}</span>
</div>
"""

        return cards

except Exception as _vpn_geo_v1_n2_hook_e:
    print(f"geo_city_provider_merge_v1_n2_hook_error={_vpn_geo_v1_n2_hook_e!r}", flush=True)

# /vpn-geo-city-provider-merge-v1

# vpn-v4-online-active-db-v1
# В новом профиле доступа онлайн определяется только по реальной активной сессии в vpn_sessions.
# Старое правило "last_seen свежее 15 минут = онлайн" больше не используется.

def _vpn_v4_online_v1_pick(row, *keys, default=None):
    for key in keys:
        try:
            v = row[key]
        except Exception:
            try:
                v = row.get(key)
            except Exception:
                v = None

        if v is not None and str(v).strip() != "":
            return v

    return default


def _vpn_v4_online_v1_is_active(row):
    if not row:
        return False

    active = _vpn_v4_online_v1_pick(row, "active", default=0)
    disconnected = _vpn_v4_online_v1_pick(row, "disconnected_at", default=None)

    try:
        active_ok = int(active or 0) == 1
    except Exception:
        active_ok = str(active).strip().lower() in {"1", "true", "yes", "active"}

    disconnected_s = str(disconnected or "").strip().lower()
    disconnected_ok = disconnected_s in {"", "0", "none", "null"}

    return bool(active_ok and disconnected_ok)


try:

    def _v4_profile_stage_online(client, old_html, d):
        import sqlite3 as _sqlite3

        client = safe_client_name(client or "")

        if not client:
            return d

        try:
            con = _sqlite3.connect(DB_PATH)
            try:
                con.row_factory = _sqlite3.Row

                if not _v4_table_exists(con, "vpn_sessions"):
                    return d

                active_row = con.execute("""
                    select *
                    from vpn_sessions
                    where client=?
                      and active=1
                      and (disconnected_at is null or disconnected_at=0 or disconnected_at='')
                    order by coalesce(last_seen, first_seen) desc
                    limit 1
                """, (client,)).fetchone()

                latest_row = con.execute("""
                    select *
                    from vpn_sessions
                    where client=?
                    order by coalesce(last_seen, first_seen) desc
                    limit 1
                """, (client,)).fetchone()

                row_for_status = active_row or latest_row

                d["is_online"] = bool(active_row)
                d["online_source"] = "vpn_sessions.active"

                if row_for_status:
                    ip = _vpn_v4_online_v1_pick(row_for_status, "remote_ip", "ip", "client_ip", default="—")
                    first_seen = _vpn_v4_online_v1_pick(row_for_status, "first_seen", "started_at", "start_ts")
                    last_seen = _vpn_v4_online_v1_pick(row_for_status, "last_seen", "updated_at", "seen_at", default=first_seen)

                    d["current_ip"] = str(ip or "—")
                    d["current_provider"] = _v4_provider_for_ip(con, d["current_ip"])
                    d["last_seen"] = _v4_fmt_ts(last_seen, short=True)
                    d["duration"] = _v4_duration(first_seen, last_seen)

                fixed_sessions = []

                for r in con.execute("""
                    select *
                    from vpn_sessions
                    where client=?
                    order by coalesce(last_seen, first_seen) desc
                    limit 10
                """, (client,)):
                    ip = str(_vpn_v4_online_v1_pick(r, "remote_ip", "ip", "client_ip", default="—") or "—")
                    first_seen = _vpn_v4_online_v1_pick(r, "first_seen", "started_at", "start_ts")
                    last_seen = _vpn_v4_online_v1_pick(r, "last_seen", "updated_at", "seen_at", default=first_seen)

                    fixed_sessions.append({
                        "start": _v4_fmt_ts(first_seen, short=True),
                        "last": _v4_fmt_ts(last_seen, short=True),
                        "ip": ip,
                        "provider": _v4_provider_for_ip(con, ip),
                        "duration": _v4_duration(first_seen, last_seen),
                        "online": _vpn_v4_online_v1_is_active(r),
                    })

                d["sessions"] = fixed_sessions

            finally:
                con.close()

        except Exception as e:
            try:
                print(f"v4_online_active_db_v1_error={e!r}", flush=True)
            except Exception:
                pass

        return d

except Exception as _vpn_v4_online_v1_hook_e:
    print(f"v4_online_active_db_v1_hook_error={_vpn_v4_online_v1_hook_e!r}", flush=True)

# /vpn-v4-online-active-db-v1

# vpn-provider-normalize-wide-v2
# Нормализация провайдеров в отображении.
# V3: одиночные провайдеры нормализуем, но агрегированные строки географии
# вида "МегаФон — 44 сесс. · SkyNet — 30 сесс." НЕ схлопываем до одного провайдера.
# Финальная нормализация profile data остаётся отдельной стадией ниже.



try:

    def _v4_profile_stage_normalize(client, old_html, d):
        return _vpn_provider_norm_data_v2(d)

except Exception as _vpn_provider_norm_v2_data_e:
    print(f"provider_normalize_wide_v2_data_hook_error={_vpn_provider_norm_v2_data_e!r}", flush=True)





# /vpn-provider-normalize-wide-v2

# vpn-safe-pulse-json-v1

def _vpn_pulse_server_metrics_v1():
    try:
        stat = os.statvfs("/")
        total = float(stat.f_blocks * stat.f_frsize)
        available = float(stat.f_bavail * stat.f_frsize)
        disk_percent = ((total - available) / total * 100.0) if total > 0 else 0.0
    except Exception:
        disk_percent = 0.0

    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        load1 = load5 = load15 = 0.0

    return {
        "disk_percent": disk_percent,
        "load1": load1,
        "load5": load5,
        "load15": load15,
    }


def _vpn_pulse_payload_v1():
    return build_pulse_status(
        summary_cached(),
        {
            "panel": service_state(PANEL_SERVICE_NAME),
            "caddy": service_state(CADDY_SERVICE_NAME),
            "ipsec": service_state(IPSEC_SERVICE_NAME),
            "xl2tpd": service_state(L2TP_SERVICE_NAME),
        },
        _vpn_pulse_server_metrics_v1(),
        host=os.uname().nodename,
        events=[],
    )


_vpn_original_handler_do_GET_pulse_v1 = Handler.do_GET


def _vpn_handler_do_GET_pulse_v1(self):
    parsed = urlparse(self.path)
    if PULSE_ENDPOINT_ENABLED and parsed.path == "/pulse.json":
        try:
            payload = _vpn_pulse_payload_v1()
        except Exception:
            payload = build_pulse_status(
                {},
                {
                    "panel": "unknown",
                    "caddy": "unknown",
                    "ipsec": "unknown",
                    "xl2tpd": "unknown",
                },
                {},
                host=os.uname().nodename,
            )
            payload["summary"] = "VPN статус неизвестен"
            payload["issue_label"] = "VPN статус неизвестен: pulse build failed"
            payload["error"] = "pulse_build_failed"

        body = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        self.send_text(200, body, "application/json; charset=utf-8")
        return

    return _vpn_original_handler_do_GET_pulse_v1(self)


Handler.do_GET = _vpn_handler_do_GET_pulse_v1

# /vpn-safe-pulse-json-v1

if __name__ == "__main__":
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"{APP_NAME} listening on http://{HOST}:{PORT}", flush=True)
    httpd.serve_forever()
