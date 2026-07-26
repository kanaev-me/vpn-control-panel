#!/usr/bin/env python3
# VPN IP geo cache v1
# Fetches approximate country/region/city for VPN remote IPs.
# Uses ip-api.com batch endpoint. No UI changes here.

import ipaddress
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request

from runtime_config import CONFIG

DB = str(CONFIG.db_path)
SOURCE = "ip-api.com"
BATCH_URL = "http://ip-api.com/batch"
FIELDS = ",".join([
    "status",
    "message",
    "country",
    "countryCode",
    "regionName",
    "city",
    "zip",
    "lat",
    "lon",
    "timezone",
    "isp",
    "org",
    "as",
    "asname",
    "mobile",
    "proxy",
    "hosting",
    "query",
])

DEFAULT_LIMIT = int(os.environ.get("GEO_LIMIT", "100"))
STALE_DAYS = int(os.environ.get("GEO_STALE_DAYS", "30"))

def now_ts():
    return int(time.time())

def is_public_ip(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return not (
            obj.is_private
            or obj.is_loopback
            or obj.is_link_local
            or obj.is_multicast
            or obj.is_reserved
            or obj.is_unspecified
        )
    except Exception:
        return False

def table_exists(con, name):
    return con.execute(
        "select 1 from sqlite_master where type='table' and name=?",
        (name,),
    ).fetchone() is not None

def create_tables(con):
    con.executescript("""
    create table if not exists ip_geo_cache (
      ip text primary key,
      status text not null default '',
      country text,
      country_code text,
      region text,
      city text,
      zip text,
      lat real,
      lon real,
      timezone text,
      isp text,
      org text,
      as_text text,
      as_name text,
      mobile integer not null default 0,
      proxy integer not null default 0,
      hosting integer not null default 0,
      source text not null default 'ip-api.com',
      message text,
      raw_json text not null default '{}',
      first_seen integer,
      last_seen integer,
      sessions integer not null default 0,
      fetched_at integer not null,
      updated_at integer not null
    );

    create index if not exists idx_ip_geo_cache_city
      on ip_geo_cache(country_code, region, city);

    create index if not exists idx_ip_geo_cache_updated
      on ip_geo_cache(updated_at);

    create index if not exists idx_ip_geo_cache_sessions
      on ip_geo_cache(sessions desc);
    """)

def collect_candidate_ips(con, limit):
    ip_stats = {}

    if table_exists(con, "vpn_sessions"):
        for r in con.execute("""
            select remote_ip,
                   count(*) as sessions,
                   min(first_seen) as first_seen,
                   max(coalesce(last_seen, first_seen)) as last_seen,
                   count(distinct client) as clients
            from vpn_sessions
            where remote_ip is not null
              and remote_ip != ''
            group by remote_ip
        """):
            ip = r["remote_ip"]
            if not is_public_ip(ip):
                continue
            ip_stats[ip] = {
                "ip": ip,
                "sessions": int(r["sessions"] or 0),
                "first_seen": int(r["first_seen"] or 0) or None,
                "last_seen": int(r["last_seen"] or 0) or None,
                "clients": int(r["clients"] or 0),
                "shared_clients": 0,
                "shared_sessions": 0,
            }

    if table_exists(con, "vpn_behavior_shared_ips"):
        for r in con.execute("""
            select remote_ip, clients_count, sessions
            from vpn_behavior_shared_ips
        """):
            ip = r["remote_ip"]
            if not is_public_ip(ip):
                continue
            item = ip_stats.setdefault(ip, {
                "ip": ip,
                "sessions": 0,
                "first_seen": None,
                "last_seen": None,
                "clients": 0,
                "shared_clients": 0,
                "shared_sessions": 0,
            })
            item["shared_clients"] = max(item["shared_clients"], int(r["clients_count"] or 0))
            item["shared_sessions"] = max(item["shared_sessions"], int(r["sessions"] or 0))

    stale_before = now_ts() - STALE_DAYS * 86400

    existing = {}
    for r in con.execute("select ip, updated_at, status from ip_geo_cache"):
        existing[r["ip"]] = {
            "updated_at": int(r["updated_at"] or 0),
            "status": r["status"] or "",
        }

    candidates = []
    for ip, item in ip_stats.items():
        old = existing.get(ip)
        if old and old["updated_at"] >= stale_before and old["status"] == "success":
            continue

        priority = (
            item["shared_clients"] * 100000
            + item["clients"] * 10000
            + item["sessions"]
            + item["shared_sessions"] * 2
        )

        candidates.append((priority, item))

    candidates.sort(key=lambda x: (-x[0], x[1]["ip"]))
    return [item for _priority, item in candidates[:limit]]

def fetch_batch(items):
    if not items:
        return []

    body = [
        {
            "query": item["ip"],
            "fields": FIELDS,
        }
        for item in items
    ]

    req = urllib.request.Request(
        BATCH_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"{CONFIG.service_prefix}/geo-cache-v1",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        raise SystemExit(f"HTTP_ERROR {e.code}: {raw[:500]}")
    except Exception as e:
        raise SystemExit(f"FETCH_ERROR: {e!r}")

def save_results(con, items, results):
    ts = now_ts()
    item_by_ip = {item["ip"]: item for item in items}
    saved = 0
    failed = 0

    rows = []

    for res in results:
        ip = res.get("query")
        if not ip:
            continue

        item = item_by_ip.get(ip, {})
        status = res.get("status") or "unknown"
        if status == "success":
            saved += 1
        else:
            failed += 1

        rows.append((
            ip,
            status,
            res.get("country"),
            res.get("countryCode"),
            res.get("regionName"),
            res.get("city"),
            res.get("zip"),
            res.get("lat"),
            res.get("lon"),
            res.get("timezone"),
            res.get("isp"),
            res.get("org"),
            res.get("as"),
            res.get("asname"),
            1 if res.get("mobile") else 0,
            1 if res.get("proxy") else 0,
            1 if res.get("hosting") else 0,
            SOURCE,
            res.get("message"),
            json.dumps(res, ensure_ascii=False),
            item.get("first_seen"),
            item.get("last_seen"),
            int(item.get("sessions") or 0),
            ts,
            ts,
        ))

    with con:
        con.executemany("""
            insert into ip_geo_cache (
              ip, status, country, country_code, region, city, zip,
              lat, lon, timezone, isp, org, as_text, as_name,
              mobile, proxy, hosting, source, message, raw_json,
              first_seen, last_seen, sessions, fetched_at, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            on conflict(ip) do update set
              status=excluded.status,
              country=excluded.country,
              country_code=excluded.country_code,
              region=excluded.region,
              city=excluded.city,
              zip=excluded.zip,
              lat=excluded.lat,
              lon=excluded.lon,
              timezone=excluded.timezone,
              isp=excluded.isp,
              org=excluded.org,
              as_text=excluded.as_text,
              as_name=excluded.as_name,
              mobile=excluded.mobile,
              proxy=excluded.proxy,
              hosting=excluded.hosting,
              source=excluded.source,
              message=excluded.message,
              raw_json=excluded.raw_json,
              first_seen=coalesce(ip_geo_cache.first_seen, excluded.first_seen),
              last_seen=excluded.last_seen,
              sessions=excluded.sessions,
              fetched_at=excluded.fetched_at,
              updated_at=excluded.updated_at
        """, rows)

    return saved, failed

def print_summary(con):
    print()
    print("=== GEO CACHE SUMMARY ===")

    total = con.execute("select count(*) from ip_geo_cache").fetchone()[0]
    ok = con.execute("select count(*) from ip_geo_cache where status='success'").fetchone()[0]
    fail = con.execute("select count(*) from ip_geo_cache where status!='success'").fetchone()[0]

    print("total:", total)
    print("success:", ok)
    print("failed:", fail)

    print()
    print("top cities:")
    for r in con.execute("""
        select country_code, region, city, count(*) as c, sum(sessions) as s
        from ip_geo_cache
        where status='success'
        group by country_code, region, city
        order by s desc, c desc
        limit 20
    """):
        country = r["country_code"] or "—"
        region = r["region"] or "—"
        city = r["city"] or "—"
        print(f"  {country} · {region} · {city} · ips={r['c']} · sessions={r['s'] or 0}")

    print()
    print("sample IPs:")
    for r in con.execute("""
        select ip, country_code, region, city, isp, org, mobile, proxy, hosting, sessions
        from ip_geo_cache
        where status='success'
        order by sessions desc
        limit 25
    """):
        flags = []
        if r["mobile"]:
            flags.append("mobile")
        if r["proxy"]:
            flags.append("proxy")
        if r["hosting"]:
            flags.append("hosting")
        flag_s = ", ".join(flags) if flags else "normal"
        loc = " · ".join([x for x in (r["country_code"], r["region"], r["city"]) if x]) or "—"
        print(f"  {r['ip']:15} | {loc:35} | {r['isp'] or r['org'] or '—'} | {flag_s} | sessions={r['sessions']}")

def main():
    limit = DEFAULT_LIMIT
    if len(sys.argv) > 1:
        limit = int(sys.argv[1])

    con = sqlite3.connect(DB)
    try:
        con.row_factory = sqlite3.Row
        create_tables(con)

        candidates = collect_candidate_ips(con, limit)
        print("geo_candidates:", len(candidates))
        if not candidates:
            print("nothing_to_fetch")
            print_summary(con)
            return

        # ip-api batch officially accepts up to 100 items per request. Keep margin.
        if len(candidates) > 100:
            candidates = candidates[:100]

        print("fetching:", len(candidates))
        for item in candidates[:20]:
            print(f"  {item['ip']} sessions={item.get('sessions', 0)} clients={item.get('clients', 0)} shared={item.get('shared_clients', 0)}")

        results = fetch_batch(candidates)
        saved, failed = save_results(con, candidates, results)

        print()
        print("geo_fetch_ok")
        print("saved:", saved)
        print("failed:", failed)

        print_summary(con)
    finally:
        con.close()

if __name__ == "__main__":
    main()
