#!/usr/bin/env python3
import json
import sqlite3
import sys
import time

from runtime_config import CONFIG

def main():
    DB = str(CONFIG.db_path)

    path = sys.argv[1]
    with open(path, "r", encoding="utf-8") as f:
        rows = json.load(f)

    now = int(time.time())

    con = sqlite3.connect(DB)
    try:
        con.row_factory = sqlite3.Row

        con.executescript("""
        create table if not exists known_client_networks (
          ip text primary key,
          host text not null default '',
          title text not null,
          customer text not null default '',
          object_name text not null default '',
          kind text not null default 'network',
          status text not null default '',
          source text not null default 'manual',
          note text not null default '',
          created_at integer not null,
          updated_at integer not null
        );

        create index if not exists idx_known_client_networks_customer
          on known_client_networks(customer, object_name);

        create index if not exists idx_known_client_networks_title
          on known_client_networks(title);
        """)

        payload = []
        seen_ips = []

        for r in rows:
            ip = (r.get("ip") or "").strip()
            if not ip:
                continue

            seen_ips.append(ip)

            host = (r.get("host") or "").strip()
            title = (r.get("title") or r.get("name") or ip).strip()
            customer = (r.get("customer") or "").strip()
            object_name = (r.get("object_name") or "").strip()
            kind = (r.get("kind") or "mikrotik").strip()
            status = (r.get("status") or "active").strip()
            source = (r.get("source") or "pulse-auto").strip()

            note_bits = []
            if r.get("note"):
                note_bits.append(str(r.get("note")))
            if r.get("source_id"):
                note_bits.append("id=" + str(r.get("source_id")))
            if host:
                note_bits.append("host=" + host)
            note = " · ".join(note_bits)

            payload.append((
                ip, host, title, customer, object_name, kind, status, source, note, now, now
            ))

        with con:
            con.executemany("""
                insert into known_client_networks (
                  ip, host, title, customer, object_name, kind, status, source, note,
                  created_at, updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(ip) do update set
                  host=excluded.host,
                  title=case
                    when known_client_networks.source in ('manual','pulse-manual')
                     and known_client_networks.title != ''
                    then known_client_networks.title
                    else excluded.title
                  end,
                  customer=case
                    when known_client_networks.source in ('manual','pulse-manual')
                     and known_client_networks.customer != ''
                    then known_client_networks.customer
                    else excluded.customer
                  end,
                  object_name=case
                    when known_client_networks.source in ('manual','pulse-manual')
                     and known_client_networks.object_name != ''
                    then known_client_networks.object_name
                    else excluded.object_name
                  end,
                  kind=excluded.kind,
                  status=excluded.status,
                  source='pulse-auto',
                  note=excluded.note,
                  updated_at=excluded.updated_at
            """, payload)

            if seen_ips:
                q = ",".join(["?"] * len(seen_ips))
                con.execute(f"""
                    update known_client_networks
                       set status='stale',
                           note='не найдено в последнем Pulse sync',
                           updated_at=?
                     where source='pulse-auto'
                       and ip not in ({q})
                """, [now] + seen_ips)

        print("pulse_known_networks_import_ok")
        print("received:", len(rows))
        print("imported:", len(payload))
        print("known_total:", con.execute("select count(*) from known_client_networks").fetchone()[0])
        print()

        for r in con.execute("""
            select ip, host, title, customer, object_name, status, source
            from known_client_networks
            order by customer, object_name, ip
        """):
            host = f" / {r['host']}" if r["host"] else ""
            print(f"{r['ip']}{host} — {r['title']} — {r['customer']} / {r['object_name']} / {r['status']} / {r['source']}")

    finally:
        con.close()


if __name__ == "__main__":
    main()
