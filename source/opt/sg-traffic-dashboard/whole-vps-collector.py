#!/usr/bin/env python3
"""Poll five verified VPSes without changing their routing or applications."""

import concurrent.futures
import json
import os
import sqlite3
import subprocess
import time


DB = os.environ.get("WHOLE_TRAFFIC_DB", "/var/lib/sg-traffic-dashboard/whole.db")
AGENT = "/opt/sg-traffic-dashboard/host-traffic-sample.py"
HOSTS = {
    "DMIT": ["python3", AGENT],
    "BWH": ["ssh", "-i", "/root/.ssh/id_ed25519_migrate", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", "-p", "26274",
            "root@45.78.70.23", "python3", "/root/host-traffic-sample.py"],
    "ByteVirt-HK ISP": ["ssh", "-i", "/root/.ssh/hk-submerge-transfer",
                          "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                          "-o", "ConnectTimeout=8", "-p", "8586", "root@61.15.36.199",
                          "python3", "/root/host-traffic-sample.py"],
    "NoSLA": ["ssh", "-i", "/root/.ssh/dmit-nosla-rathole-forward",
              "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
              "-o", "ConnectTimeout=8", "root@216.23.117.226",
              "python3", "/root/host-traffic-sample.py"],
    "Lazycat-SG": ["ssh", "-i", "/root/.ssh/dmit-lazycat-test",
                   "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                   "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8",
                   "-o", "UserKnownHostsFile=/root/.ssh/lazycat-test-known-hosts",
                   "-p", "44328", "root@216.195.195.125",
                   "/bin/sh", "/root/host-traffic-sample.sh"],
    "Lazycat-HKT": ["ssh", "-i", "/root/.ssh/dmit-lazycat-hkt",
                    "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                    "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8",
                    "-o", "UserKnownHostsFile=/root/.ssh/known_hosts-lazycat-hkt-readonly",
                    "-p", "31998", "root@149.104.4.71",
                    "/bin/sh", "/root/host-traffic-sample.sh"],
    "GoMami": ["ssh", "-i", "/root/.ssh/dmit-gomami-dashboard",
               "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8",
               "-o", "UserKnownHostsFile=/root/.ssh/gomami-known-hosts",
               "root@103.26.8.100", "gomami-sample"],
}
EXPORT = "/root/dashboard-record-export.py"
RECORD_HOSTS = {
    "dmit": ["python3", EXPORT, "dmit"],
    "bwh": ["ssh", "-i", "/root/.ssh/id_ed25519_migrate", "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", "-p", "26274",
            "root@45.78.70.23", "python3", EXPORT, "bwh"],
    "hk": ["ssh", "-i", "/root/.ssh/hk-submerge-transfer", "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8", "-p", "8586",
           "root@61.15.36.199", "python3", EXPORT, "hk"],
    "gomami": ["ssh", "-i", "/root/.ssh/dmit-gomami-dashboard",
               "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=8",
               "-o", "UserKnownHostsFile=/root/.ssh/gomami-known-hosts",
               "root@103.26.8.100", "gomami-export"],
}
START = int(os.environ.get("TRAFFIC_START_TS", "1790831700"))


def connect():
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS samples (
      server TEXT NOT NULL, ts INTEGER NOT NULL, boot TEXT NOT NULL,
      rx INTEGER NOT NULL, tx INTEGER NOT NULL,
      delta_rx INTEGER NOT NULL, delta_tx INTEGER NOT NULL,
      sui_json TEXT NOT NULL, hk_json TEXT NOT NULL, nosla_json TEXT NOT NULL,
      PRIMARY KEY(server,ts)
    );
    CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
    CREATE TABLE IF NOT EXISTS sample_errors (
      server TEXT PRIMARY KEY, ts INTEGER NOT NULL, error_type TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS categories (
      server TEXT NOT NULL, ts INTEGER NOT NULL,
      proxy_wire INTEGER NOT NULL DEFAULT 0,
      mapping_wire INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY(server,ts)
    );
    CREATE TABLE IF NOT EXISTS static_wire_samples (
      server TEXT NOT NULL, ts INTEGER NOT NULL,
      totals_json TEXT NOT NULL, discontinuities INTEGER NOT NULL,
      started_at INTEGER NOT NULL,
      PRIMARY KEY(server,ts)
    );
    CREATE TABLE IF NOT EXISTS unified_records (
      origin TEXT NOT NULL, id TEXT NOT NULL, changed INTEGER NOT NULL,
      user TEXT NOT NULL, source TEXT, destination TEXT,
      ingress TEXT NOT NULL, route_type TEXT NOT NULL, relay TEXT NOT NULL,
      started INTEGER NOT NULL, ended INTEGER,
      upload INTEGER NOT NULL, download INTEGER NOT NULL,
      status TEXT NOT NULL, traffic_known INTEGER NOT NULL,
      PRIMARY KEY(origin,id)
    );
    CREATE INDEX IF NOT EXISTS idx_unified_started ON unified_records(started DESC);
    CREATE INDEX IF NOT EXISTS idx_unified_user ON unified_records(user,started DESC);
    CREATE INDEX IF NOT EXISTS idx_unified_ingress ON unified_records(ingress,started DESC);
    CREATE INDEX IF NOT EXISTS idx_unified_hk_firsthop_cover
      ON unified_records(started DESC,ingress,user,upload,download)
      WHERE origin='hk' AND traffic_known=1 AND route_type IN ('直连','中转');
    CREATE INDEX IF NOT EXISTS idx_unified_unverified_count
      ON unified_records(ingress,started DESC)
      WHERE traffic_known=1 AND route_type='待核实';
    CREATE TABLE IF NOT EXISTS sync_cursors (
      origin TEXT PRIMARY KEY, changed INTEGER NOT NULL, id TEXT NOT NULL
    );
    """)
    return conn


def sample(item):
    server, cmd = item
    try:
        output = subprocess.check_output(cmd, text=True, timeout=17, stderr=subprocess.DEVNULL)
        value = json.loads(output)
        if abs(int(time.time()) - int(value["ts"])) > 120:
            raise ValueError("stale host clock")
        return server, value, ""
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            ValueError, KeyError, json.JSONDecodeError) as exc:
        return server, None, type(exc).__name__


def store(conn, server, item, error):
    if error:
        conn.execute("INSERT INTO sample_errors(server,ts,error_type) VALUES(?,?,?) "
                     "ON CONFLICT(server) DO UPDATE SET ts=excluded.ts,error_type=excluded.error_type",
                     (server, int(time.time()), error))
        return
    ts = int(item["ts"])
    boot = str(item["boot"])
    rx, tx = (int(item["nic"][key]) for key in ("rx", "tx"))
    if rx < 0 or tx < 0:
        raise ValueError("negative NIC counter")
    previous = conn.execute(
        "SELECT boot,rx,tx,nosla_json FROM samples WHERE server=? ORDER BY ts DESC LIMIT 1",
        (server,),
    ).fetchone()
    dr = dt = 0
    if previous and previous[0] == boot:
        dr = max(0, rx - int(previous[1]))
        dt = max(0, tx - int(previous[2]))
    sui_outbound = dict(item.get("sui_outbound", {}))
    for provider, total in item.get("static_egress", {}).items():
        if provider not in ("nexip_sg", "ip2up", "proxyhive") or int(total) < 0:
            raise ValueError("unexpected static egress counter")
        sui_outbound["stage:" + provider] = int(total)
    wire = item.get("static_wire")
    if wire is not None:
        if server not in ("DMIT", "BWH"):
            raise ValueError("wire sample on unexpected server")
        keys = {f"{provider}-{direction}" for provider in
                ("nexip", "ip2up", "proxyhive") for direction in ("rx", "tx")}
        totals = wire.get("totals", {})
        if set(totals) != keys or any(
                not isinstance(totals[key], int) or totals[key] < 0 for key in keys):
            raise ValueError("invalid static wire totals")
        measured_at = int(wire["ts"])
        if measured_at > ts + 120 or measured_at < ts - 120:
            raise ValueError("stale static wire totals")
        discontinuities = int(wire["discontinuities"])
        if discontinuities < 0:
            raise ValueError("negative wire counter discontinuities")
        started_at = int(wire["started_at"])
        if started_at > measured_at or started_at <= 0:
            raise ValueError("invalid wire meter start time")
    conn.execute("INSERT OR REPLACE INTO samples VALUES(?,?,?,?,?,?,?,?,?,?)",
                 (server, ts, boot, rx, tx, dr, dt,
                   json.dumps(sui_outbound, separators=(",", ":")),
                  json.dumps(item.get("hk_routes", {}), separators=(",", ":")),
                  json.dumps(item.get("nosla_counters", {}), separators=(",", ":"))))
    if wire is not None:
        conn.execute("INSERT OR REPLACE INTO static_wire_samples VALUES(?,?,?,?,?)",
                     (server, measured_at, json.dumps(totals, separators=(",", ":")),
                      discontinuities, started_at))
    proxy_wire = mapping_wire = 0
    if server == "NoSLA" and previous and previous[0] == boot:
        older = json.loads(previous[3])
        newer = item.get("nosla_counters", {})
        for key, value in newer.items():
            if key not in older:
                continue
            increment = max(0, int(value) - int(older[key]))
            if key.startswith("proxy_"):
                proxy_wire += increment
            elif key.startswith("mapping_"):
                mapping_wire += increment
    conn.execute("INSERT OR REPLACE INTO categories VALUES(?,?,?,?)",
                 (server, ts, proxy_wire, mapping_wire))
    conn.execute("DELETE FROM sample_errors WHERE server=?", (server,))


def export_batch(origin, changed, record_id):
    cmd = RECORD_HOSTS[origin] + [str(changed), record_id or "-"]
    output = subprocess.check_output(cmd, text=True, timeout=20,
                                     stderr=subprocess.DEVNULL)
    return json.loads(output)


def route(origin, row):
    if origin == "gomami":
        actual = row.get("route_class")
        if actual == "direct":
            return "GoMami", "直连", "直连"
        if actual == "kookeey":
            return "GoMami", "中转", "Kookeey"
        return "GoMami", "待核实", "待核实"
    if origin in ("dmit", "bwh"):
        ingress = "DMIT" if origin == "dmit" else "BWH"
        actual = row.get("route_class")
        if actual == "direct":
            return ingress, "直连", "直连"
        if actual == "kookeey":
            return ingress, "中转", "Kookeey"
        if actual == "nexip_sg":
            return ingress, "中转", "NexIP SG"
        if actual == "ip2up":
            return ingress, "中转", "ip2up.com"
        if actual == "proxyhive":
            return ingress, "中转", "proxyhive.io"
        if actual == "bytevirt_hk_isp":
            return ingress, "中转", "ByteVirt-HK ISP"
        if origin == "dmit" and actual == "lazycat":
            return ingress, "中转", "Lazycat-SG"
        if origin == "dmit" and actual == "lazycat_hkt":
            return ingress, "中转", "Lazycat-HKT"
        return ingress, "待核实", "待核实"
    # The HK dashboard combines ByteVirt's "hk:" records with NoSLA's
    # "nosla:" records. Neither host is automatically the client's first hop.
    # A NoSLA source seen at ByteVirt can hide an earlier DMIT/BWH/GoMami hop.
    source = str(row.get("source") or "")
    peer = source.rsplit(":", 1)[0] if ":" in source else source
    ingress = {
        "179.255.136.79": "DMIT",
        "45.78.70.23": "BWH",
        "103.26.8.100": "GoMami",
    }.get(peer, "进站待核实")
    record_id = str(row.get("id") or "")
    route_class = row.get("route_class")
    destination = str(row.get("destination") or "")
    if record_id.startswith("hk:"):
        # ByteVirt is the observed egress. Only an identified previous hop
        # proves this was a relay; an unknown peer might be a direct client.
        if ingress != "进站待核实" or peer == "216.23.117.226":
            return ingress, "中转", "ByteVirt-HK ISP"
        return ingress, "待核实", "ByteVirt-HK ISP"
    if record_id.startswith("nosla:"):
        if route_class == "nosla" or (
                route_class is None and destination and
                not destination.startswith("61.15.36.199:2443")):
            # This record observes NoSLA's final egress, not ByteVirt's.
            # A known DMIT/BWH/GoMami source proves a relay via NoSLA;
            # another source may be a client or an unobserved prior hop.
            kind = "中转" if ingress != "进站待核实" else "待核实"
            return ingress, kind, "NoSLA"
        if route_class == "bytevirt_hk_isp" or (
                route_class is None and
                destination.startswith("61.15.36.199:2443")):
            # This is the NoSLA upstream half of a ByteVirt path.
            return ingress, "中转", "NoSLA"
    # Older records without a reliable host-prefixed ID remain visible but
    # cannot be assigned to either egress by a route tag alone.
    return ingress, "待核实", "出站待核实"


def sync_records(conn, origin):
    cursor = conn.execute("SELECT changed,id FROM sync_cursors WHERE origin=?",
                          (origin,)).fetchone()
    high_water = cursor if cursor else (START - 1, "")
    # Rows may be inserted or finalized seconds after a poll. Replay a bounded
    # window and UPSERT by (origin,id) so equal-second keyset ordering cannot
    # permanently skip short sessions or late journal fallback records.
    changed, record_id = max(START - 1, high_water[0] - 120), ""
    for _ in range(20):
        try:
            payload = export_batch(origin, changed, record_id)
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
                ValueError, KeyError, json.JSONDecodeError):
            return
        rows = payload.get("rows", [])
        for row in rows:
            ingress, route_type, relay = route(origin, row)
            conn.execute(
                "INSERT INTO unified_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(origin,id) DO UPDATE SET changed=excluded.changed,"
                "user=excluded.user,source=excluded.source,destination=excluded.destination,"
                "ingress=excluded.ingress,route_type=excluded.route_type,relay=excluded.relay,"
                "started=excluded.started,ended=excluded.ended,upload=excluded.upload,"
                "download=excluded.download,status=excluded.status,"
                "traffic_known=excluded.traffic_known",
                (origin, str(row["id"]), int(row["changed"]), str(row["user"]),
                 row.get("source"), row.get("destination"), ingress, route_type, relay,
                 int(row["started"]), row.get("ended"), int(row.get("upload") or 0),
                 int(row.get("download") or 0), str(row["status"]),
                 int(origin == "hk" or bool(row.get("traffic_known")))),
            )
        if rows:
            next_cursor = (int(payload["next_ts"]), str(payload["next_id"]))
            if next_cursor <= (changed, record_id):
                return
            changed, record_id = next_cursor
            if next_cursor > high_water:
                high_water = next_cursor
                conn.execute("INSERT INTO sync_cursors(origin,changed,id) VALUES(?,?,?) "
                             "ON CONFLICT(origin) DO UPDATE SET "
                             "changed=excluded.changed,id=excluded.id",
                             (origin, changed, record_id))
            conn.commit()
        if not payload.get("has_more"):
            break


def prune_unified_records(conn, cutoff):
    conn.execute(
        "DELETE FROM unified_records WHERE started<? AND ("
        "id NOT GLOB 'static:*' OR "
        "(status='closed' AND COALESCE(ended,started)<?) OR "
        "(status='active' AND changed<?))",
        (cutoff, cutoff, cutoff))


def main():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    conn = connect()
    while True:
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(HOSTS)) as pool:
            for server, item, error in pool.map(sample, HOSTS.items()):
                try:
                    store(conn, server, item, error)
                except (ValueError, TypeError, KeyError):
                    store(conn, server, None, "InvalidSample")
        for origin in RECORD_HOSTS:
            sync_records(conn, origin)
        conn.execute("DELETE FROM samples WHERE ts<?", (int(time.time()) - 31 * 86400,))
        conn.execute("DELETE FROM categories WHERE ts<?", (int(time.time()) - 31 * 86400,))
        conn.execute("DELETE FROM static_wire_samples WHERE ts<?", (int(time.time()) - 31 * 86400,))
        cutoff = int(time.time()) - 31 * 86400
        prune_unified_records(conn, cutoff)
        conn.commit()
        time.sleep(max(1, 60 - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
