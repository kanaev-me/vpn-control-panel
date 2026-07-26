#!/usr/bin/env python3
# VPN behavior core v1
# Builds behavioral aggregates from vpn_sessions + ip_asn_cache.
# Existing VPN/session tables are not modified.

import json
import os
import sqlite3
import time
from collections import defaultdict, Counter
from datetime import datetime

from runtime_config import CONFIG

DB = str(CONFIG.db_path)

MOBILE_WORDS = (
    "мегафон", "megafon", "mfone",
    "мтс", "mts", "mobile telesystems",
    "билайн", "beeline", "vimpelcom",
    "tele2", "t2", "yota", "йота",
)

def now_ts():
    return int(time.time())

def clean(x):
    x = (x or "").strip()
    return x if x else "—"

def dt(ts):
    try:
        ts = int(ts or 0)
        if ts <= 0:
            return None
        return datetime.fromtimestamp(ts)
    except Exception:
        return None

def pct(a, b):
    return int(round(100 * a / b)) if b else 0

def is_mobile_provider(provider):
    low = (provider or "").lower()
    return any(w in low for w in MOBILE_WORDS)

def classify(provider, sessions, days, ips, shared_clients, work_pct, evening_pct, night_pct, weekend_pct):
    if is_mobile_provider(provider):
        if ips >= 8:
            return "mobile_changing_ip", "📱 мобильная сеть / часто меняет IP"
        return "mobile", "📱 мобильная сеть"

    if shared_clients >= 3:
        return "shared_office_candidate", "🏢 общая сеть / офис-кандидат"

    if days >= 3 and ips <= 3:
        if evening_pct + night_pct >= 55 and work_pct < 60:
            return "home_candidate", "🏠 дом-кандидат"
        if work_pct >= 55 and weekend_pct <= 40:
            return "work_candidate", "🏢 работа-кандидат"
        return "stable_network", "📍 стабильная сеть"

    if ips >= 10:
        return "many_ips_unknown", "🌐 много разных IP / место неясно"

    return "place_candidate", "📍 место-кандидат"

def confidence(sessions, days, ips, shared_clients):
    score = 0
    if sessions >= 5:
        score += 1
    if sessions >= 20:
        score += 1
    if days >= 3:
        score += 1
    if days >= 7:
        score += 1
    if ips <= 3:
        score += 1
    if shared_clients >= 3:
        score += 1
    return min(score, 5)

def table_exists(con, name):
    return con.execute(
        "select 1 from sqlite_master where type='table' and name=?",
        (name,),
    ).fetchone() is not None

def main():
    if not os.path.exists(DB):
        raise SystemExit("DB not found: " + DB)

    con = sqlite3.connect(DB)
    try:
        con.row_factory = sqlite3.Row

        required = ["vpn_sessions", "ip_asn_cache"]
        missing = [t for t in required if not table_exists(con, t)]
        if missing:
            raise SystemExit("Missing tables: " + ", ".join(missing))

        con.executescript("""
        create table if not exists vpn_behavior_places (
          client text not null,
          provider text not null,
          place_code text not null,
          place_label text not null,
          confidence integer not null,
          sessions integer not null,
          days integer not null,
          ips integer not null,
          main_ip text,
          main_ip_sessions integer not null,
          shared_clients integer not null,
          first_seen integer,
          last_seen integer,
          work_pct integer not null,
          evening_pct integer not null,
          night_pct integer not null,
          weekend_pct integer not null,
          updated_at integer not null,
          sample_ips_json text not null default '[]',
          primary key (client, provider, place_code, main_ip)
        );

        create table if not exists vpn_behavior_shared_ips (
          remote_ip text primary key,
          provider text not null,
          clients_count integer not null,
          sessions integer not null,
          first_seen integer,
          last_seen integer,
          clients_json text not null,
          updated_at integer not null
        );

        create table if not exists vpn_behavior_client_summary (
          client text primary key,
          total_sessions integer not null,
          total_days integer not null,
          total_ips integer not null,
          top_place_label text,
          top_provider text,
          top_confidence integer not null default 0,
          mobile_sessions integer not null default 0,
          shared_network_sessions integer not null default 0,
          unknown_provider_sessions integer not null default 0,
          first_seen integer,
          last_seen integer,
          updated_at integer not null
        );

        create index if not exists idx_vpn_behavior_places_client
          on vpn_behavior_places(client, confidence desc, days desc, sessions desc);

        create index if not exists idx_vpn_behavior_places_place_code
          on vpn_behavior_places(place_code, confidence desc);

        create index if not exists idx_vpn_behavior_shared_clients
          on vpn_behavior_shared_ips(clients_count desc, sessions desc);
        """)

        ip_provider = {}
        for r in con.execute("select ip, asn, provider, label from ip_asn_cache"):
            provider = clean(r["label"] or r["provider"] or r["asn"])
            ip_provider[r["ip"]] = provider

        rows = []
        for r in con.execute("""
            select client, vpn_ip, remote_ip, first_seen, last_seen, disconnected_at, active
            from vpn_sessions
            where client is not null
              and client != ''
              and client != 'имя не определено'
              and remote_ip is not null
              and remote_ip != ''
        """):
            x = dict(r)
            x["provider"] = ip_provider.get(x["remote_ip"], "—")
            x["dt"] = dt(x["first_seen"])
            rows.append(x)

        clients_by_ip = defaultdict(set)
        sessions_by_ip = Counter()
        provider_by_ip = {}
        first_by_ip = {}
        last_by_ip = {}

        for x in rows:
            client = x["client"]
            ip = x["remote_ip"]
            provider = x["provider"]
            first_seen = int(x["first_seen"] or 0)
            last_seen = int(x["last_seen"] or x["first_seen"] or 0)

            clients_by_ip[ip].add(client)
            sessions_by_ip[ip] += 1
            provider_by_ip[ip] = provider

            if first_seen:
                first_by_ip[ip] = min(first_by_ip.get(ip, first_seen), first_seen)
            if last_seen:
                last_by_ip[ip] = max(last_by_ip.get(ip, last_seen), last_seen)

        by_client = defaultdict(list)
        for x in rows:
            by_client[x["client"]].append(x)

        updated = now_ts()

        places = []
        summaries = []
        shared_rows = []

        for ip, clients in clients_by_ip.items():
            if len(clients) >= 2:
                shared_rows.append((
                    ip,
                    provider_by_ip.get(ip, "—"),
                    len(clients),
                    sessions_by_ip[ip],
                    first_by_ip.get(ip),
                    last_by_ip.get(ip),
                    json.dumps(sorted(clients), ensure_ascii=False),
                    updated,
                ))

        for client, items in by_client.items():
            total_sessions = len(items)
            total_days_set = {x["dt"].date().isoformat() for x in items if x["dt"]}
            total_ips_set = {x["remote_ip"] for x in items}
            first_seen_values = [int(x["first_seen"] or 0) for x in items if int(x["first_seen"] or 0) > 0]
            last_seen_values = [int(x["last_seen"] or x["first_seen"] or 0) for x in items if int(x["last_seen"] or x["first_seen"] or 0) > 0]

            by_provider = defaultdict(list)
            for x in items:
                by_provider[x["provider"]].append(x)

            client_places = []

            for provider, gr in by_provider.items():
                dts = [x["dt"] for x in gr if x["dt"]]
                if not dts:
                    continue

                days_set = {d.date().isoformat() for d in dts}
                ips_counter = Counter(x["remote_ip"] for x in gr)
                if not ips_counter:
                    continue

                # Не засоряем агрегат совсем случайными одноразовыми местами.
                if len(gr) < 3 and len(days_set) < 2:
                    continue

                main_ip, main_ip_sessions = ips_counter.most_common(1)[0]

                work = sum(1 for d in dts if 9 <= d.hour <= 18)
                evening = sum(1 for d in dts if 18 <= d.hour <= 23)
                night = sum(1 for d in dts if d.hour >= 22 or d.hour <= 6)
                weekend = sum(1 for d in dts if d.weekday() >= 5)

                work_p = pct(work, len(dts))
                evening_p = pct(evening, len(dts))
                night_p = pct(night, len(dts))
                weekend_p = pct(weekend, len(dts))

                shared_clients = max((len(clients_by_ip[ip]) for ip in ips_counter), default=1)

                place_code, place_label = classify(
                    provider=provider,
                    sessions=len(gr),
                    days=len(days_set),
                    ips=len(ips_counter),
                    shared_clients=shared_clients,
                    work_pct=work_p,
                    evening_pct=evening_p,
                    night_pct=night_p,
                    weekend_pct=weekend_p,
                )

                conf = confidence(len(gr), len(days_set), len(ips_counter), shared_clients)

                first_seen = min((int(x["first_seen"] or 0) for x in gr if int(x["first_seen"] or 0) > 0), default=None)
                last_seen = max((int(x["last_seen"] or x["first_seen"] or 0) for x in gr if int(x["last_seen"] or x["first_seen"] or 0) > 0), default=None)

                sample_ips = [ip for ip, _cnt in ips_counter.most_common(8)]

                row = (
                    client,
                    provider,
                    place_code,
                    place_label,
                    conf,
                    len(gr),
                    len(days_set),
                    len(ips_counter),
                    main_ip,
                    main_ip_sessions,
                    shared_clients,
                    first_seen,
                    last_seen,
                    work_p,
                    evening_p,
                    night_p,
                    weekend_p,
                    updated,
                    json.dumps(sample_ips, ensure_ascii=False),
                )
                places.append(row)
                client_places.append({
                    "place_label": place_label,
                    "provider": provider,
                    "confidence": conf,
                    "sessions": len(gr),
                    "days": len(days_set),
                    "place_code": place_code,
                })

            client_places.sort(key=lambda p: (-p["confidence"], -p["days"], -p["sessions"]))

            top = client_places[0] if client_places else None
            mobile_sessions = sum(1 for x in items if is_mobile_provider(x["provider"]))
            unknown_provider_sessions = sum(1 for x in items if x["provider"] == "—")
            shared_network_sessions = sum(1 for x in items if len(clients_by_ip[x["remote_ip"]]) >= 3)

            summaries.append((
                client,
                total_sessions,
                len(total_days_set),
                len(total_ips_set),
                top["place_label"] if top else None,
                top["provider"] if top else None,
                int(top["confidence"]) if top else 0,
                mobile_sessions,
                shared_network_sessions,
                unknown_provider_sessions,
                min(first_seen_values) if first_seen_values else None,
                max(last_seen_values) if last_seen_values else None,
                updated,
            ))

        with con:
            con.execute("delete from vpn_behavior_places")
            con.execute("delete from vpn_behavior_shared_ips")
            con.execute("delete from vpn_behavior_client_summary")

            con.executemany("""
                insert into vpn_behavior_shared_ips (
                  remote_ip, provider, clients_count, sessions, first_seen, last_seen, clients_json, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
            """, shared_rows)

            con.executemany("""
                insert into vpn_behavior_places (
                  client, provider, place_code, place_label, confidence,
                  sessions, days, ips, main_ip, main_ip_sessions, shared_clients,
                  first_seen, last_seen,
                  work_pct, evening_pct, night_pct, weekend_pct,
                  updated_at, sample_ips_json
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, places)

            con.executemany("""
                insert into vpn_behavior_client_summary (
                  client, total_sessions, total_days, total_ips,
                  top_place_label, top_provider, top_confidence,
                  mobile_sessions, shared_network_sessions, unknown_provider_sessions,
                  first_seen, last_seen, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, summaries)

        print("behavior_build_ok")
        print("sessions_read=", len(rows))
        print("clients=", len(by_client))
        print("places=", len(places))
        print("shared_ips=", len(shared_rows))
        print("summaries=", len(summaries))
        print("updated_at=", updated)

        print()
        print("top shared networks:")
        for r in con.execute("""
            select remote_ip, provider, clients_count, sessions
            from vpn_behavior_shared_ips
            order by clients_count desc, sessions desc
            limit 10
        """):
            print(f"  {r['remote_ip']:15} | {r['provider'][:24]:24} | clients={r['clients_count']:2d} | sessions={r['sessions']:4d}")

        print()
        print("top client summaries:")
        for r in con.execute("""
            select client, total_sessions, total_days, total_ips, top_place_label, top_provider, top_confidence
            from vpn_behavior_client_summary
            order by total_sessions desc
            limit 15
        """):
            print(
                f"  {r['client'][:28]:28} | sessions={r['total_sessions']:4d} | "
                f"days={r['total_days']:2d} | ips={r['total_ips']:3d} | "
                f"conf={r['top_confidence']}/5 | {r['top_place_label'] or '—'} | {r['top_provider'] or '—'}"
            )

    finally:
        con.close()

if __name__ == "__main__":
    main()
