#!/usr/bin/env python3
# VPN behavior matches v1
# Builds smart pair matches from shared VPN remote IP history.

import json
import os
import re
import sqlite3
import time
from collections import Counter, defaultdict

from runtime_config import CONFIG

DB = str(CONFIG.db_path)

MOBILE_WORDS = (
    "мегафон", "megafon", "mfone",
    "мтс", "mts", "mobile telesystems",
    "билайн", "beeline", "vimpelcom",
    "tele2", "t2", "yota", "йота",
)

def is_mobile(provider):
    p = (provider or "").lower()
    return any(x in p for x in MOBILE_WORDS)

def clean(x):
    return (x or "").strip()

def norm_name(x):
    x = clean(x).lower()
    x = re.sub(r"[^a-zа-яё0-9]+", " ", x, flags=re.I).strip()
    return re.sub(r"\s+", " ", x)

def client_root(client):
    c = (client or "").lower()
    c = re.sub(r"[^a-z0-9а-яё_-]+", "", c)
    for suffix in (
        "-phone", "-iphone", "-android", "-tablet", "-ipad", "-pc",
        "-new", "-profile", "-computer", "-komp", "-macbook",
        "-2", "-3", "-4", "-5", "-6",
    ):
        if c.endswith(suffix):
            c = c[: -len(suffix)]
    return c.strip("-_")

def table_exists(con, name):
    return con.execute(
        "select 1 from sqlite_master where type='table' and name=?",
        (name,),
    ).fetchone() is not None

def confidence_label(score, stable_ip_count, mobile_ip_count, max_clients_on_ip):
    if score >= 75:
        return "🟢 сильная связь"
    if score >= 50:
        return "🟡 средняя связь"
    if stable_ip_count == 0 and mobile_ip_count:
        return "⚪ мобильный шум"
    if max_clients_on_ip >= 6:
        return "🔵 общий офис / массовая сеть"
    return "⚪ слабая связь"

def pair_score(item, meta_a, meta_b, client_a, client_b):
    shared_ip_count = item["shared_ip_count"]
    stable_ip_count = item["stable_ip_count"]
    mobile_ip_count = item["mobile_ip_count"]
    max_clients_on_ip = item["max_clients_on_ip"]
    pair_sessions = item["pair_sessions"]

    score = 0

    if shared_ip_count >= 2:
        score += 25
    if shared_ip_count >= 3:
        score += 20
    if stable_ip_count >= 1:
        score += 25
    if stable_ip_count >= 2:
        score += 20
    if pair_sessions >= 20:
        score += 10
    if pair_sessions >= 60:
        score += 10

    name_a = norm_name(meta_a.get("person_name"))
    name_b = norm_name(meta_b.get("person_name"))
    if name_a and name_b and name_a == name_b:
        score += 25

    root_a = client_root(client_a)
    root_b = client_root(client_b)
    if root_a and root_b:
        if root_a == root_b:
            score += 15
        elif len(root_a) >= 5 and len(root_b) >= 5 and (root_a.startswith(root_b) or root_b.startswith(root_a)):
            score += 10

    group_a = clean(meta_a.get("group_name"))
    group_b = clean(meta_b.get("group_name"))
    if group_a and group_b and group_a == group_b:
        score += 5

    if max_clients_on_ip >= 9:
        score -= 25
    elif max_clients_on_ip >= 6:
        score -= 20
    elif max_clients_on_ip >= 4:
        score -= 10

    if mobile_ip_count and stable_ip_count == 0:
        score -= 30

    return max(0, min(100, score))

def main():
    if not os.path.exists(DB):
        raise SystemExit("DB not found: " + DB)

    con = sqlite3.connect(DB)
    try:
        con.row_factory = sqlite3.Row

        if not table_exists(con, "vpn_behavior_shared_ips"):
            raise SystemExit("Missing vpn_behavior_shared_ips. Run behavior_build.py first.")

        con.executescript("""
        create table if not exists vpn_behavior_matches (
          client_a text not null,
          client_b text not null,
          score integer not null,
          label text not null,
          shared_ip_count integer not null,
          stable_ip_count integer not null,
          mobile_ip_count integer not null,
          unknown_ip_count integer not null,
          max_clients_on_ip integer not null,
          pair_sessions integer not null,
          providers_json text not null default '{}',
          examples_json text not null default '[]',
          updated_at integer not null,
          primary key (client_a, client_b)
        );

        create index if not exists idx_vpn_behavior_matches_score
          on vpn_behavior_matches(score desc, shared_ip_count desc, pair_sessions desc);

        create index if not exists idx_vpn_behavior_matches_a
          on vpn_behavior_matches(client_a, score desc);

        create index if not exists idx_vpn_behavior_matches_b
          on vpn_behavior_matches(client_b, score desc);
        """)

        meta = defaultdict(dict)

        if table_exists(con, "vpn_client_meta"):
            for r in con.execute("""
                select client, person_name, device_label, device_type, group_name
                from vpn_client_meta
            """):
                meta[r["client"]] = {
                    "person_name": clean(r["person_name"]),
                    "device_label": clean(r["device_label"]),
                    "device_type": clean(r["device_type"]),
                    "group_name": clean(r["group_name"]),
                }

        client_ip_sessions = defaultdict(Counter)

        for r in con.execute("""
            select client, remote_ip, count(*) as c
            from vpn_sessions
            where client is not null
              and client != ''
              and client != 'имя не определено'
              and remote_ip is not null
              and remote_ip != ''
            group by client, remote_ip
        """):
            client_ip_sessions[r["remote_ip"]][r["client"]] = int(r["c"] or 0)

        pairs = {}

        shared_rows = con.execute("""
            select remote_ip, provider, clients_count, sessions, clients_json
            from vpn_behavior_shared_ips
            where clients_count >= 2
        """).fetchall()

        for r in shared_rows:
            ip = r["remote_ip"]
            provider = r["provider"] or "—"
            clients_count = int(r["clients_count"] or 0)
            sessions = int(r["sessions"] or 0)
            clients = json.loads(r["clients_json"] or "[]")

            mobile = is_mobile(provider)
            stable = (not mobile) and provider != "—"

            for i in range(len(clients)):
                for j in range(i + 1, len(clients)):
                    a, b = sorted((clients[i], clients[j]))
                    key = (a, b)

                    item = pairs.setdefault(key, {
                        "shared_ip_count": 0,
                        "stable_ip_count": 0,
                        "mobile_ip_count": 0,
                        "unknown_ip_count": 0,
                        "max_clients_on_ip": 0,
                        "pair_sessions": 0,
                        "providers": Counter(),
                        "examples": [],
                    })

                    a_count = client_ip_sessions[ip].get(a, 0)
                    b_count = client_ip_sessions[ip].get(b, 0)
                    pair_sessions_here = a_count + b_count

                    item["shared_ip_count"] += 1
                    item["stable_ip_count"] += 1 if stable else 0
                    item["mobile_ip_count"] += 1 if mobile else 0
                    item["unknown_ip_count"] += 1 if provider == "—" else 0
                    item["max_clients_on_ip"] = max(item["max_clients_on_ip"], clients_count)
                    item["pair_sessions"] += pair_sessions_here
                    item["providers"][provider] += 1
                    item["examples"].append({
                        "ip": ip,
                        "provider": provider,
                        "clients_count": clients_count,
                        "sessions_total_on_ip": sessions,
                        "pair_sessions_on_ip": pair_sessions_here,
                        "a_sessions": a_count,
                        "b_sessions": b_count,
                        "mobile": mobile,
                    })

        rows = []
        updated = int(time.time())

        for (a, b), item in pairs.items():
            score = pair_score(item, meta[a], meta[b], a, b)

            label = confidence_label(
                score,
                item["stable_ip_count"],
                item["mobile_ip_count"],
                item["max_clients_on_ip"],
            )

            if score < 20 and item["stable_ip_count"] == 0:
                continue

            examples = sorted(
                item["examples"],
                key=lambda e: (
                    e["mobile"],
                    -e["pair_sessions_on_ip"],
                    -e["sessions_total_on_ip"],
                    e["provider"],
                    e["ip"],
                ),
            )[:8]

            providers = dict(item["providers"].most_common(8))

            rows.append((
                a,
                b,
                score,
                label,
                item["shared_ip_count"],
                item["stable_ip_count"],
                item["mobile_ip_count"],
                item["unknown_ip_count"],
                item["max_clients_on_ip"],
                item["pair_sessions"],
                json.dumps(providers, ensure_ascii=False),
                json.dumps(examples, ensure_ascii=False),
                updated,
            ))

        rows.sort(key=lambda r: (-r[2], -r[4], -r[9], r[0], r[1]))

        with con:
            con.execute("delete from vpn_behavior_matches")
            con.executemany("""
                insert into vpn_behavior_matches (
                  client_a, client_b, score, label,
                  shared_ip_count, stable_ip_count, mobile_ip_count,
                  unknown_ip_count, max_clients_on_ip, pair_sessions,
                  providers_json, examples_json, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

        print("behavior_matches_ok")
        print("raw_pairs=", len(pairs))
        print("stored_pairs=", len(rows))
        print("updated_at=", updated)
        print()
        print("top matches:")

        for r in con.execute("""
            select client_a, client_b, score, label,
                   shared_ip_count, stable_ip_count, mobile_ip_count,
                   max_clients_on_ip, pair_sessions, providers_json
            from vpn_behavior_matches
            order by score desc, shared_ip_count desc, pair_sessions desc
            limit 30
        """):
            providers = json.loads(r["providers_json"] or "{}")
            providers_s = ", ".join([
                f"{p}×{c}" if c > 1 else p
                for p, c in list(providers.items())[:4]
            ])

            print(
                f"  {r['label']} score={r['score']:3d} | "
                f"{r['client_a']} <-> {r['client_b']} | "
                f"ips={r['shared_ip_count']} stable={r['stable_ip_count']} "
                f"mobile={r['mobile_ip_count']} pair_sessions={r['pair_sessions']} "
                f"max_ip_clients={r['max_clients_on_ip']} | {providers_s}"
            )

    finally:
        con.close()

if __name__ == "__main__":
    main()
