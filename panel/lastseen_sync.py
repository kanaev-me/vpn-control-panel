#!/usr/bin/env python3
import datetime
import sqlite3
import time

from live_session_collector import collect_live_sessions
from runtime_config import CONFIG


def main():
    DB = str(CONFIG.db_path)
    NOW = int(time.time())
    live_connections = collect_live_sessions()

    def ts(v):
        if v is None or v == "":
            return 0
        s = str(v).strip()
        try:
            n = int(float(s))
            return n if n > 1000000000 else 0
        except Exception:
            pass
        try:
            return int(datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
        except Exception:
            return 0

    def q(x):
        return '"' + x.replace('"', '""') + '"'

    con = sqlite3.connect(DB)
    try:
        con.row_factory = sqlite3.Row

        tables = {
            r["name"]
            for r in con.execute("select name from sqlite_master where type='table'")
        }
        if "vpn_sessions" not in tables:
            # A new panel may not have collected any live-session data yet.
            # This is a normal empty state, not a failed background job.
            print("vpn_sessions_missing=1")
            print("live_connections:", live_connections)
            print("latest_clients: 0")
            print("summary_updates: 0")
            print("place_updates: 0")
            return

        latest_client = {}
        latest_place = {}

        for r in con.execute(
            "select client, remote_ip, last_seen from vpn_sessions "
            "where client is not null and last_seen is not null"
        ):
            client = str(r["client"] or "").strip()
            ip = str(r["remote_ip"] or "").strip()
            t = ts(r["last_seen"])
            if not client or not t:
                continue
            latest_client[client] = max(latest_client.get(client, 0), t)
            if ip:
                latest_place[(client, ip)] = max(latest_place.get((client, ip), 0), t)

        summary_updates = 0
        place_updates = 0

        if "vpn_behavior_client_summary" in tables:
            cols = {
                x["name"]
                for x in con.execute('pragma table_info("vpn_behavior_client_summary")')
            }
            if {"client", "last_seen"} <= cols:
                for client, t in latest_client.items():
                    cur = con.execute(
                        "select last_seen from vpn_behavior_client_summary where client=?",
                        (client,),
                    ).fetchone()
                    if cur and t > ts(cur["last_seen"]):
                        changed_before = con.total_changes
                        con.execute(
                            "update vpn_behavior_client_summary "
                            "set last_seen=?, updated_at=? where client=?",
                            (t, NOW, client),
                        )
                        summary_updates += con.total_changes - changed_before

        if "vpn_behavior_places" in tables:
            cols = {
                x["name"]
                for x in con.execute('pragma table_info("vpn_behavior_places")')
            }
            ipcol = "main_ip" if "main_ip" in cols else ("ip" if "ip" in cols else None)
            if {"client", "last_seen"} <= cols and ipcol:
                changed_before = con.total_changes
                for (client, ip), t in latest_place.items():
                    cur = con.execute(
                        f'select last_seen from "vpn_behavior_places" '
                        f'where client=? and {q(ipcol)}=?',
                        (client, ip),
                    ).fetchone()
                    if cur and t > ts(cur["last_seen"]):
                        con.execute(
                            f'update "vpn_behavior_places" '
                            f'set last_seen=?, updated_at=? '
                            f'where client=? and {q(ipcol)}=?',
                            (t, NOW, client, ip),
                        )
                place_updates = con.total_changes - changed_before

        con.commit()

        print("live_connections:", live_connections)
        print("latest_clients:", len(latest_client))
        print("summary_updates:", summary_updates)
        print("place_updates:", place_updates)

    finally:
        con.close()


if __name__ == "__main__":
    main()
